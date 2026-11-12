// Package forward is the network entry of an AWS signer: a plain byte
// forwarder that runs on the parent EC2 instance. It accepts TCP
// connections (where the signing client connects) and copies each one to a new
// connection to the enclave (vsock). It is not trusted and holds no
// secret: the mutual TLS 1.3 of the runner ends inside the enclave, and
// the forwarder only sees the TLS records. It never terminates TLS, has no
// certificate, no key and no CA, reads no request and answers none. It can
// drop or delay traffic, as any network part can. Replacing it with socat
// or a load balancer in TCP mode changes nothing about what is trusted.
//
// It bounds the connections open at once, and those from one source IP
// address that are still in their handshake window: the enclave sees every
// connection come from the parent, so this is where one outside peer is
// told from another. A hostile parent can skip the bound, but it can drop
// the traffic anyway; the bound protects an honest parent's enclave from
// outside peers.
package forward

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// Forwarder copies connections from a listener to the address Dial opens.
type Forwarder struct {
	// Dial opens the connection to the other side, for example transport.Dial
	// to the enclave's vsock address.
	Dial func(ctx context.Context) (net.Conn, error)
	// MaxConns bounds the connections open at once. Zero means 256. A
	// connection over the bound is closed at once.
	MaxConns int
	// MaxConnsPerSource bounds the connections from one source IP address
	// that are within their handshake window (HandshakeWindow after the
	// accept). Zero means 16, the most one signing client pool dials at
	// once and the runner's own cap on handshakes in progress per address
	// on a TCP listener; negative means no bound. The enclave sees every
	// connection come from the parent's vsock address, so it cannot tell
	// one outside peer from another: without this bound one peer that
	// connects and says nothing could hold every handshake slot of the
	// enclave. A connection over the bound is closed at once. Past its
	// window a connection counts against MaxConns only, so a client that
	// handshaked keeps its connections whatever its address opens later.
	// A peer without an IP address (a unix socket) is not counted.
	MaxConnsPerSource int
	// HandshakeWindow is how long a connection counts against its source
	// address. Zero means the runner's handshake deadline (10 s from the
	// enclave's accept) plus DialTimeout.
	//
	// The forwarder sees TLS records and cannot tell from them that the
	// handshake is done: a count of flights in each direction is matched
	// by a peer that stalls after its ClientHello, or after the second one
	// a HelloRetryRequest asks for. The runner's deadline is sound: a
	// connection still open past it has handshaked, or the runner is
	// closing it this moment. The cost is a cap on dials, not handshakes:
	// one pool of 16 fits; a second pool from the same address within one
	// window of the first has its later dials closed at accept.
	HandshakeWindow time.Duration
	// DialTimeout bounds Dial. Zero means 5 s.
	DialTimeout time.Duration
	Log         *slog.Logger

	// perSource counts the connections within their handshake window of
	// each source IP address.
	mu        sync.Mutex
	perSource map[string]int

	accepted, refusedMax, refusedSource, dialFailed atomic.Uint64
	open                                            atomic.Int64

	// When each kind of refusal last logged, so a flood logs once per
	// logEvery.
	logMax, logSource, logDial logThrottle
}

// logEvery: a refused connection or a failed dial is logged at most this
// often for each kind, with the count since start, so one outside peer
// that keeps connecting does not fill the parent's log. The metrics have
// the exact counts.
const logEvery = 10 * time.Second

// clockStart is the base of logThrottle's monotonic times: a step of the
// wall clock must not silence the log.
var clockStart = time.Now()

// logThrottle holds when one kind of line last logged, in nanoseconds
// since clockStart; 0 for never.
type logThrottle struct{ last atomic.Int64 }

// due reports whether a line may be logged now, and if so takes the slot.
func (t *logThrottle) due() bool {
	now := int64(time.Since(clockStart)) + 1 // never 0
	last := t.last.Load()
	return (last == 0 || now-last >= int64(logEvery)) && t.last.CompareAndSwap(last, now)
}

// Stats are the forwarder's counts since it started.
type Stats struct {
	Accepted         uint64 // connections accepted, refused ones included
	Open             int64  // connections being forwarded now
	RefusedMaxConns  uint64 // closed at accept: MaxConns reached
	RefusedPerSource uint64 // closed at accept: MaxConnsPerSource reached
	DialFailures     uint64 // Dial to the other side failed
}

// Stats returns the counts so far.
func (f *Forwarder) Stats() Stats {
	return Stats{
		Accepted:         f.accepted.Load(),
		Open:             f.open.Load(),
		RefusedMaxConns:  f.refusedMax.Load(),
		RefusedPerSource: f.refusedSource.Load(),
		DialFailures:     f.dialFailed.Load(),
	}
}

// runnerHandshakeTimeout is server.handshakeTimeout of tee-signer: the
// runner closes a connection whose TLS handshake is not done this long
// after it accepted the connection.
const runnerHandshakeTimeout = 10 * time.Second

func (f *Forwarder) maxConns() int {
	if f.MaxConns > 0 {
		return f.MaxConns
	}
	return 256
}

func (f *Forwarder) maxConnsPerSource() int {
	if f.MaxConnsPerSource != 0 {
		return f.MaxConnsPerSource
	}
	return 16
}

// sourceOf is the IP address of a TCP peer, "" for any other peer.
func sourceOf(c net.Conn) string {
	if a, ok := c.RemoteAddr().(*net.TCPAddr); ok {
		return a.IP.String()
	}
	return ""
}

// takeSource counts one more connection from src if that stays within
// the bound per source, and reports whether it did.
func (f *Forwarder) takeSource(src string) bool {
	limit := f.maxConnsPerSource()
	if src == "" || limit < 0 {
		return true
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.perSource[src] >= limit {
		return false
	}
	if f.perSource == nil {
		f.perSource = map[string]int{}
	}
	f.perSource[src]++
	return true
}

// giveSource gives back what takeSource counted.
func (f *Forwarder) giveSource(src string) {
	if src == "" || f.maxConnsPerSource() < 0 {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.perSource[src]--; f.perSource[src] <= 0 {
		delete(f.perSource, src)
	}
}

func (f *Forwarder) dialTimeout() time.Duration {
	if f.DialTimeout > 0 {
		return f.DialTimeout
	}
	return 5 * time.Second
}

func (f *Forwarder) handshakeWindow() time.Duration {
	if f.HandshakeWindow > 0 {
		return f.HandshakeWindow
	}
	return runnerHandshakeTimeout + f.dialTimeout()
}

// Serve accepts connections on l until ctx ends or l fails. On ctx it
// closes l and every open connection, and returns nil.
func (f *Forwarder) Serve(ctx context.Context, l net.Listener) error {
	if f.Log == nil {
		f.Log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	slots := make(chan struct{}, f.maxConns())
	var wg sync.WaitGroup
	go func() {
		<-ctx.Done()
		l.Close()
	}()
	defer wg.Wait()
	for {
		c, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		f.accepted.Add(1)
		src := sourceOf(c)
		if !f.takeSource(src) {
			n := f.refusedSource.Add(1)
			if f.logSource.due() {
				f.Log.Warn("too many connections in their handshake window from one address, closing", "remote", c.RemoteAddr().String(), "max_per_source", f.maxConnsPerSource(), "window", f.handshakeWindow().String(), "refused_since_start", n)
			}
			c.Close()
			continue
		}
		select {
		case slots <- struct{}{}:
		default:
			n := f.refusedMax.Add(1)
			if f.logMax.due() {
				f.Log.Warn("too many connections, closing", "remote", c.RemoteAddr().String(), "max", f.maxConns(), "refused_since_start", n)
			}
			f.giveSource(src)
			c.Close()
			continue
		}
		wg.Add(1)
		f.open.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-slots }()
			defer f.open.Add(-1)
			// The count per source ends with the handshake window or with
			// the connection, whichever comes first; exactly one of the
			// two gives it back.
			window := time.AfterFunc(f.handshakeWindow(), func() { f.giveSource(src) })
			defer func() {
				if window.Stop() {
					f.giveSource(src)
				}
			}()
			f.handle(ctx, c)
		}()
	}
}

// closeWriter is a connection that can half-close: TCP, unix and vsock.
type closeWriter interface{ CloseWrite() error }

func (f *Forwarder) handle(ctx context.Context, client net.Conn) {
	defer client.Close()
	dctx, cancel := context.WithTimeout(ctx, f.dialTimeout())
	target, err := f.Dial(dctx)
	cancel()
	if err != nil {
		n := f.dialFailed.Add(1)
		if f.logDial.due() {
			f.Log.Warn("dial failed, closing the client", "remote", client.RemoteAddr().String(), "err", err, "failed_since_start", n)
		}
		return
	}
	defer target.Close()

	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			client.Close()
			target.Close()
		case <-done:
		}
	}()

	// One goroutine per direction. When the client half-closes, pass the
	// half-close on and let the target answer. When the target side ends,
	// close both: the runner never half-closes on purpose, and waiting for
	// the client would hold the slot for as long as the client stays idle.
	// On an error close both.
	res := make(chan error, 2)
	go func() {
		_, err := io.Copy(target, client)
		if err == nil {
			if cw, ok := target.(closeWriter); ok {
				err = cw.CloseWrite()
			} else {
				err = errors.New("no half-close")
			}
		}
		res <- err
	}()
	go func() {
		io.Copy(client, target)
		res <- errors.New("target closed")
	}()
	if err := <-res; err != nil {
		client.Close()
		target.Close()
	}
	<-res
}
