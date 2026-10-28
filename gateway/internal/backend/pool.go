package backend

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"syscall"
	"time"

	"github.com/lidofinance/tee-signer/attestation-verify/runnerclient"
	"github.com/lidofinance/tee-signer/gateway/internal/certreload"
	proto "github.com/lidofinance/tee-signer/signer-protocol"
)

// maxConnections bounds the connections to one signer.
const maxConnections = 16

// runner is what the gateway asks of one TEE signer.
type runner interface {
	PublicKeys(ctx context.Context) ([]proto.ValidatorKey, error)
	Sign(ctx context.Context, req proto.SignRequest) (proto.Signature, error)
	Close() error
}

// certSource is where a node gets the client certificate for a new
// client (certreload.Watcher).
type certSource interface {
	// Current is the pair in force.
	Current() *certreload.Pair
	// Usable fails once the pair in force has expired.
	Usable() error
	// Subscribe returns a channel that receives after each swap.
	Subscribe() <-chan struct{}
}

// poolConfig says how a node keeps its connections.
type poolConfig struct {
	// size is the number of connections (1 to maxConnections).
	size int
	// certs, if set, is the client certificate the connections present.
	// Without it they present the files the connection settings name, read
	// once.
	certs certSource
	// warm bounds the check of a new connection when the node moves it to
	// a new certificate (default 30 s).
	warm time.Duration
	// retry is the wait after a failed move before the next try (default
	// 5 s).
	retry time.Duration
	log   *slog.Logger
}

// slot is one place in a node's pool. pair is the client certificate its
// client presents (nil without certs).
type slot struct {
	c    runner
	pair *certreload.Pair
}

// node is one TEE signer behind a few runner clients. Each client holds
// one connection and sends one request at a time on it. It dials when it
// has none, and runnerclient checks every new connection before a request
// goes on it: TLS 1.3 with the client certificate, the build flavour and
// the chain mark of the signer's certificate, IDENTITY with a fresh nonce,
// the attestation document with its verifier and the setup pins, and the
// TLS key the attested identity names (and tls_key_pin, if set). A client
// drops its connection after an I/O error or a timeout, so a restarted
// signer goes through every check again. A request takes an idle client
// and gives it back.
//
// When the client certificate changes (certs), the node moves its clients
// to the new one in the background, one at a time: it makes a client with
// the new certificate, which dials and passes every check above, and only
// then puts it in the place of an idle client of an older certificate and
// closes that one. The pool never has fewer than size clients ready, and a
// request in flight ends on its own connection. A failed move leaves the
// old client and is tried again after retry.
type node struct {
	addr string
	pc   poolConfig
	// mk makes a client that presents pair. It does not connect.
	mk func(pair *certreload.Pair) (runner, error)
	// now is the clock of the expiry check in acquire.
	now func() time.Time

	// avail holds one token per idle slot.
	avail chan struct{}
	mu    sync.Mutex
	idle  []*slot
	all   []*slot
	// released is closed and replaced when a slot goes back to idle.
	released chan struct{}

	stop context.CancelFunc
	done chan struct{}
}

// newNode makes the clients for conn. It does not connect.
func newNode(conn runnerclient.Connection, pc poolConfig, opts ...runnerclient.Option) (*node, error) {
	mk := func(p *certreload.Pair) (runner, error) {
		if p == nil {
			return conn.New(opts...)
		}
		var c *runnerclient.Client
		err := p.Files(func(certPath, keyPath string) error {
			cc := conn
			cc.ClientCert, cc.ClientKey = certPath, keyPath
			var err error
			c, err = cc.New(opts...)

			return err
		})
		if err != nil {
			return nil, fmt.Errorf("client certificate serial %s: %w", p.Serial(), err)
		}

		return c, nil
	}

	return newPool(conn.Address, pc, mk)
}

func newPool(addr string, pc poolConfig, mk func(*certreload.Pair) (runner, error)) (*node, error) {
	if pc.size < 1 || pc.size > maxConnections {
		return nil, fmt.Errorf("connections must be 1 to %d", maxConnections)
	}
	if pc.warm == 0 {
		pc.warm = 30 * time.Second
	}
	if pc.retry == 0 {
		pc.retry = 5 * time.Second
	}
	if pc.log == nil {
		pc.log = slog.New(slog.DiscardHandler)
	}
	n := &node{addr: addr, pc: pc, mk: mk, now: time.Now, avail: make(chan struct{}, pc.size), released: make(chan struct{})}
	var pair *certreload.Pair
	if pc.certs != nil {
		pair = pc.certs.Current()
	}
	for range pc.size {
		c, err := mk(pair)
		if err != nil {
			_ = n.Close()

			return nil, err
		}
		s := &slot{c: c, pair: pair}
		n.all = append(n.all, s)
		n.idle = append(n.idle, s)
		n.avail <- struct{}{}
	}
	if pc.certs != nil {
		ctx, cancel := context.WithCancel(context.Background())
		n.stop, n.done = cancel, make(chan struct{})
		go n.follow(ctx, pc.certs.Subscribe())
	}

	return n, nil
}

// acquire takes an idle slot. A slot whose certificate expired while the
// node could not move it (its signer was down, say) gets a client of the
// pair in force first; that client dials, with every check, at the
// request.
func (n *node) acquire(ctx context.Context) (*slot, error) {
	select {
	case <-n.avail:
	case <-ctx.Done():
		return nil, fmt.Errorf("%s: no idle connection: %w", n.addr, ctx.Err())
	}
	n.mu.Lock()
	s := n.idle[0]
	n.idle = n.idle[1:]
	n.mu.Unlock()
	if n.pc.certs == nil || s.pair == nil || !n.now().After(s.pair.NotAfter()) {
		return s, nil
	}
	cur := n.pc.certs.Current()
	if cur == s.pair {
		return s, nil
	}
	c, err := n.mk(cur)
	if err != nil {
		n.pc.log.Warn("new client for an expired certificate failed", "address", n.addr, "err", err.Error())

		return s, nil
	}
	n.mu.Lock()
	old := s.c
	s.c, s.pair = c, cur
	n.mu.Unlock()
	go old.Close()
	n.pc.log.Info("connection moved to the new client certificate", "address", n.addr, "serial", cur.Serial(),
		"reason", "old certificate expired")

	return s, nil
}

func (n *node) release(s *slot) {
	n.mu.Lock()
	n.idle = append(n.idle, s)
	close(n.released)
	n.released = make(chan struct{})
	n.mu.Unlock()
	n.avail <- struct{}{}
}

// do runs f on an idle client. A call that failed on the connection
// itself (the signer closed it or reset it, as after a restart) runs once
// more on another client, which dials and checks a new connection when it
// has none. The signer signs an exact repeat of an attestation or block
// again with the same signature, so a SIGN may go twice. A refusal, a
// failed check, a timeout or the end of ctx is not tried again. With an
// expired client certificate f does not run.
func (n *node) do(ctx context.Context, f func(runner) error) error {
	if n.pc.certs != nil {
		if err := n.pc.certs.Usable(); err != nil {
			return fmt.Errorf("%s: %w", n.addr, err)
		}
	}
	for attempt := 1; ; attempt++ {
		s, err := n.acquire(ctx)
		if err != nil {
			return err
		}
		err = f(s.c)
		n.release(s)
		if err == nil || attempt == 2 || ctx.Err() != nil || !connectionLost(err) {
			return err
		}
	}
}

// follow moves the clients to each new client certificate until ctx
// ends.
func (n *node) follow(ctx context.Context, swapped <-chan struct{}) {
	defer close(n.done)
	for {
		select {
		case <-ctx.Done():
			return
		case <-swapped:
		}
		n.move(ctx)
	}
}

// move replaces the clients of older certificates, one at a time, until
// none is left or ctx ends.
func (n *node) move(ctx context.Context) {
	lastErr := ""
	for ctx.Err() == nil {
		cur := n.pc.certs.Current()
		if !n.hasOld(cur) {
			return
		}
		c, err := n.mk(cur)
		if err == nil {
			wctx, cancel := context.WithTimeout(ctx, n.pc.warm)
			_, err = c.PublicKeys(wctx)
			cancel()
			if err != nil {
				_ = c.Close()
			}
		}
		if err != nil {
			if err.Error() != lastErr {
				lastErr = err.Error()
				n.pc.log.Warn("connection on the new client certificate failed, keeping the old one", "address", n.addr,
					"serial", cur.Serial(), "err", lastErr)
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(n.pc.retry):
			}

			continue
		}
		if !n.swapIn(ctx, c, cur) {
			_ = c.Close()
		}
	}
}

// hasOld reports whether a slot holds a client of another pair than cur.
func (n *node) hasOld(cur *certreload.Pair) bool {
	n.mu.Lock()
	defer n.mu.Unlock()

	return n.hasOldLocked(cur)
}

func (n *node) hasOldLocked(cur *certreload.Pair) bool {
	for _, s := range n.all {
		if s.pair != cur {
			return true
		}
	}

	return false
}

// swapIn puts c, a checked client of cur, in the place of an idle client
// of an older pair and closes that one. It waits for a request to give
// one back if all are busy. It returns false if none is left to replace
// or ctx ends.
func (n *node) swapIn(ctx context.Context, c runner, cur *certreload.Pair) bool {
	for {
		n.mu.Lock()
		for _, s := range n.idle {
			if s.pair == cur {
				continue
			}
			old := s.c
			s.c, s.pair = c, cur
			n.mu.Unlock()
			_ = old.Close()
			n.pc.log.Info("connection moved to the new client certificate", "address", n.addr, "serial", cur.Serial())

			return true
		}
		if !n.hasOldLocked(cur) {
			n.mu.Unlock()

			return false
		}
		released := n.released
		n.mu.Unlock()
		select {
		case <-released:
		case <-ctx.Done():
			return false
		}
	}
}

// connectionLost reports whether err says the connection ended under the
// request: the signer closed or reset it.
func connectionLost(err error) bool {
	var refused *proto.RefusedError
	if errors.As(err, &refused) {
		return false
	}

	return errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, net.ErrClosed) ||
		errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE)
}

func (n *node) PublicKeys(ctx context.Context) ([]proto.ValidatorKey, error) {
	var keys []proto.ValidatorKey
	err := n.do(ctx, func(c runner) error {
		var err error
		keys, err = c.PublicKeys(ctx)

		return err
	})

	return keys, err
}

func (n *node) Sign(ctx context.Context, req proto.SignRequest) (proto.Signature, error) {
	var sig proto.Signature
	err := n.do(ctx, func(c runner) error {
		var err error
		sig, err = c.Sign(ctx, req)

		return err
	})

	return sig, err
}

// Close stops the moves to a new certificate and closes every connection.
// A request on one ends first.
func (n *node) Close() error {
	if n.stop != nil {
		n.stop()
		<-n.done
	}
	n.mu.Lock()
	clients := make([]runner, 0, len(n.all))
	for _, s := range n.all {
		clients = append(clients, s.c)
	}
	n.mu.Unlock()
	var errs []error
	for _, c := range clients {
		errs = append(errs, c.Close())
	}

	return errors.Join(errs...)
}
