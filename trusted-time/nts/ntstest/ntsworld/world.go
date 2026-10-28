//go:build nts

// Package ntsworld is a virtual world for tests of the NTS client: the
// host operations of the core (ntscore.HostOps) on a clock the test moves,
// with servers that answer, lose, lie, send a Kiss-o'-Death or hang as the
// test says. It is the network and nothing more, like the real wrapper:
// every answer is a real datagram from ntstest's server code (with NTS:
// authenticated with the keys of a key exchange the world played, without
// TLS), which the core checks and measures as it does any other. No
// sample, time or quorum is ever handed to the core.
//
// It is its own package, not a file of ntstest, because the core's tests
// import ntstest and this imports the core.
package ntsworld

import (
	"context"
	"crypto/rand"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/lidofinance/tee-signer/trusted-time/nts/ntstest"
	ntscore "github.com/lidofinance/tee-signer/trusted-time/ntscore/go"
)

// Ask is one contact with a server: a key exchange or an NTP query.
type Ask struct {
	Peer     int    // the server's place in the client's list
	Operator string // as named by Name or seen at its key exchange; else Host without ".test"
	Host     string
	Addr     string // the address dialed (a query)
	At       int64  // the world's local time, ns
	Plain    bool   // a plain NTP request (a query)
}

// Reply is what a server does with a query. The zero Reply is an honest
// answer.
type Reply struct {
	Lose bool // no answer: the query runs into its timeout
	Hang bool // no answer, and the query blocks until the poll's context ends
	// Kiss answers with this Kiss-o'-Death. Under NTS it is authenticated,
	// as an honest server's RATE, DENY or RSTR (never NTSN), unless
	// KissForged.
	Kiss       string
	KissForged bool
	Offset     time.Duration // the server's clock is this far from real time
	// RootDelay and RootDisp go into the sample's bound (half the delay,
	// the whole dispersion): the world answers in no time, so they are how
	// a test makes a sample wide.
	RootDelay, RootDisp time.Duration
}

// World is the virtual world. Query and KE are set before the first poll.
//
// Time: the local clock moves only when the test moves it (Set, Advance)
// and at Settle. An answer takes no time. A lost answer costs the query's
// timeout, but not at once: polls of one round run in parallel and must
// all see the round's start time whatever order they run in, so the cost
// is kept and Settle, called between rounds, moves the clock past it.
type World struct {
	// Query says what a server does with a query; nil: an honest answer.
	// KE says whether a key exchange fails (the error is the host's); nil:
	// none does. Both are called without the world's lock, possibly from
	// several polls at once.
	Query func(Ask) Reply
	KE    func(Ask) error

	mu      sync.Mutex
	now     int64 // local ns
	pending int64 // the local time lost answers have used up, applied by Settle
	off     int64 // real Unix ns minus local ns
	store   *ntstest.Store
	names   map[string]string // host -> operator
	ctxs    map[int]context.Context
}

// New is a world whose local clock reads local when real time is real.
func New(local int64, real time.Time) *World {
	return &World{now: local, off: real.UnixNano() - local, store: ntstest.NewStore(), names: map[string]string{}, ctxs: map[int]context.Context{}}
}

// Server is a server of operator in this world: host operator.test.
func (w *World) Server(operator string) ntscore.Server {
	host := operator + ".test"
	w.Name(host, operator)
	return ntscore.Server{Operator: operator, Host: host}
}

// Name says which operator runs host, for Ask.Operator.
func (w *World) Name(host, operator string) {
	w.mu.Lock()
	w.names[host] = operator
	w.mu.Unlock()
}

// Local is the local clock, ns. It is the core's monotonic clock.
func (w *World) Local() int64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.now
}

// Set moves the local clock to local, unless it is past it already.
func (w *World) Set(local int64) {
	w.mu.Lock()
	w.now = max(w.now, local)
	w.mu.Unlock()
}

// Advance moves the local clock d ahead.
func (w *World) Advance(d time.Duration) {
	w.mu.Lock()
	w.now += int64(d)
	w.mu.Unlock()
}

// Settle moves the local clock past the timeouts of the answers lost
// since the last call. Not during a poll.
func (w *World) Settle() {
	w.mu.Lock()
	w.now = max(w.now, w.pending)
	w.mu.Unlock()
}

// Real is real time now. Jump moves real time against the local clock:
// Jump(-d) is a host that steps the local counter d ahead.
func (w *World) Real() time.Time {
	w.mu.Lock()
	defer w.mu.Unlock()
	return time.Unix(0, w.now+w.off)
}

func (w *World) Jump(d time.Duration) {
	w.mu.Lock()
	w.off += int64(d)
	w.mu.Unlock()
}

// Forget drops every cookie of every server: the next NTS request gets an
// NTSN.
func (w *World) Forget() { w.store.Forget() }

// SetContext binds peer's operations to the context of its poll
// (nts.Client calls it); a nil ctx unbinds.
func (w *World) SetContext(peer int, ctx context.Context) {
	w.mu.Lock()
	if ctx == nil {
		delete(w.ctxs, peer)
	} else {
		w.ctxs[peer] = ctx
	}
	w.mu.Unlock()
}

func (w *World) context(peer int) context.Context {
	w.mu.Lock()
	defer w.mu.Unlock()
	if ctx, ok := w.ctxs[peer]; ok {
		return ctx
	}
	return context.Background()
}

// cancelled is err, as the caller's doing if the context of peer's poll
// has ended.
func (w *World) cancelled(peer int, err error) error {
	if err != nil && w.context(peer).Err() != nil {
		return fmt.Errorf("%w: %w", ntscore.ErrHostCancelled, err)
	}
	return err
}

func (w *World) operator(host string) string {
	if op, ok := w.names[host]; ok {
		return op
	}
	return strings.TrimSuffix(host, ".test")
}

// Random is the CSPRNG of the host.
func (w *World) Random(buf []byte) error {
	_, err := rand.Read(buf)
	return err
}

// Monotonic is the local clock.
func (w *World) Monotonic() int64 { return w.Local() }

// KeyExchange plays one NTS-KE session without TLS: fresh keys, as the
// exporter of a session would give, and the records of ntstest's server
// with eight cookies for them. It takes no time.
func (w *World) KeyExchange(peer int, srv *ntscore.Server, validity time.Time, timeout time.Duration, req, resp []byte) (int, []byte, []byte, time.Duration, error) {
	w.mu.Lock()
	w.names[srv.Host] = srv.Operator
	ask := Ask{Peer: peer, Operator: srv.Operator, Host: srv.Host, At: w.now}
	w.mu.Unlock()
	if err := w.context(peer).Err(); err != nil {
		return 0, nil, nil, 0, w.cancelled(peer, fmt.Errorf("nts-ke %s: %w", srv.Host, err))
	}
	if w.KE != nil {
		if err := w.KE(ask); err != nil {
			return 0, nil, nil, 0, w.cancelled(peer, fmt.Errorf("nts-ke %s: %w", srv.Host, err))
		}
	}
	c2s, s2c := make([]byte, ntscore.KeyLen), make([]byte, ntscore.KeyLen)
	_, _ = rand.Read(c2s)
	_, _ = rand.Read(s2c)
	// The store keeps its own copy of the keys: the core's binding wipes
	// the ones returned.
	records := ntstest.KEResponse(w.store, ntstest.KEOptions{}, append([]byte(nil), c2s...), append([]byte(nil), s2c...))
	return copy(resp, records), c2s, s2c, 0, nil
}

// UDPOpen is a socket to the server at addr.
func (w *World) UDPOpen(peer int, addr string, timeout time.Duration) (ntscore.UDPConn, error) {
	if err := w.context(peer).Err(); err != nil {
		return nil, w.cancelled(peer, fmt.Errorf("ntp %s: %w", addr, err))
	}
	return &conn{w: w, peer: peer, addr: addr}, nil
}

type conn struct {
	w         *World
	peer      int
	addr      string
	sent      int64    // local time of the send
	reply     Reply    // of the request sent
	in        [][]byte // datagrams not yet read
	delivered bool     // a datagram was read
}

type timeoutError struct{ addr string }

func (e *timeoutError) Error() string   { return "ntp " + e.addr + ": i/o timeout" }
func (e *timeoutError) Timeout() bool   { return true }
func (e *timeoutError) Temporary() bool { return true }

var _ net.Error = (*timeoutError)(nil)

func (c *conn) Send(p []byte) error {
	w := c.w
	host, _, err := net.SplitHostPort(c.addr)
	if err != nil {
		host = c.addr
	}
	w.mu.Lock()
	ask := Ask{Peer: c.peer, Operator: w.operator(host), Host: host, Addr: c.addr, At: w.now, Plain: len(p) == ntscore.PlainRequestLen}
	real := time.Unix(0, w.now+w.off)
	w.mu.Unlock()
	c.sent = ask.At
	if w.Query != nil {
		c.reply = w.Query(ask)
	}
	if r := c.reply; !r.Lose && !r.Hang {
		c.in = ntstest.Respond(w.store, p, ntstest.NTPOptions{Offset: r.Offset, RootDelay: r.RootDelay, RootDisp: r.RootDisp,
			Kiss: r.Kiss, KissPlain: r.KissForged, Clock: func() time.Time { return real }})
	}
	return nil
}

func (c *conn) Recv(buf []byte, wait time.Duration) (int, error) {
	if len(c.in) > 0 {
		n := copy(buf, c.in[0])
		c.in, c.delivered = c.in[1:], true
		return n, nil
	}
	if c.reply.Hang {
		ctx := c.w.context(c.peer)
		if ctx.Done() != nil {
			<-ctx.Done()
			return 0, c.w.cancelled(c.peer, fmt.Errorf("ntp %s: %w", c.addr, ctx.Err()))
		}
	}
	// Reading on after a datagram (the grace after a Kiss-o'-Death) costs
	// nothing here; a lost answer costs the wait.
	if !c.delivered {
		c.w.mu.Lock()
		c.w.pending = max(c.w.pending, c.sent+int64(wait))
		c.w.mu.Unlock()
	}
	return 0, &timeoutError{c.addr}
}

func (c *conn) Close() {}
