package server

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/signer-protocol/wire"
	"github.com/lidofinance/tee-signer/tee-signer/attls"
)

// serveOn runs s.Serve on a loopback listener (wrapped by wrap, if set)
// until the test ends, and returns its address.
func serveOn(t *testing.T, s *Server, wrap func(net.Listener) net.Listener) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	if wrap != nil {
		l = wrap(l)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		_ = s.Serve(ctx, l)
		close(done)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	return addr
}

// dialN opens n TCP connections to addr that send nothing.
func dialN(t *testing.T, addr string, n int) []net.Conn {
	t.Helper()
	out := make([]net.Conn, 0, n)
	for range n {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		out = append(out, c)
	}
	return out
}

// closedBy reports whether the server closed c within d: a read ends in
// EOF or a reset, not in the deadline.
func closedBy(c net.Conn, d time.Duration) bool {
	_ = c.SetReadDeadline(time.Now().Add(d))
	_, err := c.Read(make([]byte, 1))
	return err != nil && !errors.Is(err, os.ErrDeadlineExceeded)
}

// health sends HEALTH on a new plain connection and reports whether an
// answer came.
func health(t *testing.T, addr string) error {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		return err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if err := wire.WriteFrame(c, wire.Frame{Type: wire.MsgType(0x7f), ID: 1}); err != nil {
		return err
	}
	_, err = wire.ReadFrame(c)
	return err
}

// ATTEST-BUDGET-01: the runner holds at most 256 connections (the default
// cap); the next one is closed at once, and the open ones stay.
func TestConnectionCap(t *testing.T) {
	s := &Server{Log: quiet}
	addr := serveOn(t, s, nil)
	held := dialN(t, addr, 256)
	// Every one of them is in the frame loop: a frame on the last one is
	// answered.
	last := held[len(held)-1]
	_ = last.SetDeadline(time.Now().Add(5 * time.Second))
	if err := wire.WriteFrame(last, wire.Frame{Type: wire.MsgType(0x7f), ID: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := wire.ReadFrame(last); err != nil {
		t.Fatalf("connection 256: %v", err)
	}
	extra := dialN(t, addr, 1)[0]
	if !closedBy(extra, 2*time.Second) {
		t.Fatal("connection 257 stays open over the cap of 256")
	}
	if closedBy(held[0], 100*time.Millisecond) {
		t.Fatal("an open connection was closed")
	}
}

// ATTEST-BUDGET-01: at most 32 TLS handshakes run at once (the default
// handshake budget). Peers that connect and say nothing hold them; the
// next peer is closed at once instead of holding a goroutine for the
// handshake timeout too.
func TestHandshakeBudget(t *testing.T) {
	cfg, _, err := attls.ServerConfig(selfSignedCA(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{Log: quiet}
	addr := serveOn(t, s, func(l net.Listener) net.Listener { return tls.NewListener(l, cfg) })
	silent := dialN(t, addr, 32)
	// Wait until the server has taken all 32 into their handshakes.
	for deadline := time.Now().Add(10 * time.Second); s.handshakes.n.Load() < 32; {
		if time.Now().After(deadline) {
			t.Fatalf("%d handshakes running, want 32", s.handshakes.n.Load())
		}
		time.Sleep(5 * time.Millisecond)
	}
	extra := dialN(t, addr, 1)[0]
	if !closedBy(extra, 2*time.Second) {
		t.Fatal("handshake 33 waits over the budget of 32")
	}
	if closedBy(silent[0], 100*time.Millisecond) {
		t.Fatal("a handshake within the budget was closed")
	}
}

// ATTEST-BUDGET-01: large frames that stall hold at most 64 MiB together
// (the default in-flight byte cap, on top of 64 KiB per frame that every
// frame may hold). A peer that goes past it loses its connection, and a
// small request on another connection is still answered.
func TestInflightBytesCap(t *testing.T) {
	s := &Server{Log: quiet}
	addr := serveOn(t, s, nil)
	// A MaxFrame frame without its last byte: the server holds the rest.
	frame := make([]byte, 4+wire.MaxFrame-1)
	frame[1] = 0x10 // length 0x00100000 = MaxFrame
	frame[4] = wire.Version
	stalled := dialN(t, addr, 70)
	closed := map[int]bool{}
	for i, c := range stalled {
		_ = c.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if _, err := c.Write(frame); err != nil {
			closed[i] = true // the server closed it: over the cap
		}
	}
	// A write ends once the kernel has the bytes, before the server read
	// them: wait until the server has read enough to close one.
	for deadline := time.Now().Add(15 * time.Second); len(closed) == 0 && time.Now().Before(deadline); {
		for i, c := range stalled {
			if !closed[i] && closedBy(c, 5*time.Millisecond) {
				closed[i] = true
			}
		}
	}
	if len(closed) == 0 {
		t.Fatal("70 stalled frames of 1 MiB are all held: no in-flight byte cap")
	}
	if n := s.inflight.n.Load(); n > DefaultMaxInflight {
		t.Fatalf("%d bytes counted, over the cap of %d", n, DefaultMaxInflight)
	}
	if err := health(t, addr); err != nil && !errors.Is(err, io.EOF) {
		t.Fatalf("a small request while the big frames hold the cap: %v", err)
	} else if err != nil {
		t.Fatal("a small request while the big frames hold the cap: closed")
	}
}

// A large frame that was answered gives its bytes back, and a closed
// connection its slot: the limits count what is held now, not what was.
func TestLimitsGiveBack(t *testing.T) {
	s := &Server{Log: quiet, Limits: Limits{MaxConns: 2, MaxInflight: 2 << 20}}
	addr := serveOn(t, s, nil)
	payload := make([]byte, 900<<10)
	for i := range 5 {
		c := dialN(t, addr, 1)[0]
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		if err := wire.WriteFrame(c, wire.Frame{Type: wire.MsgType(0x7f), ID: 1, Payload: payload}); err != nil {
			t.Fatalf("round %d: %v", i, err)
		}
		if _, err := wire.ReadFrame(c); err != nil {
			t.Fatalf("round %d: %v", i, err)
		}
		c.Close()
		// Five rounds of 900 KiB through a cap of 2 MiB, and of one
		// connection each through a cap of 2: each round must give back.
		deadline := time.Now().Add(2 * time.Second)
		for s.conns.n.Load() != 0 || s.inflight.n.Load() != 0 {
			if time.Now().After(deadline) {
				t.Fatalf("round %d closed: %d connections, %d bytes still held", i, s.conns.n.Load(), s.inflight.n.Load())
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
}

// With an idle timeout, a connection that sends nothing after its last
// answer closes; one that keeps sending stays.
func TestIdleTimeout(t *testing.T) {
	s := &Server{Log: quiet, Limits: Limits{IdleTimeout: 300 * time.Millisecond}}
	addr := serveOn(t, s, nil)
	busy, idle := dialN(t, addr, 1)[0], dialN(t, addr, 1)[0]
	for i := range 6 {
		_ = busy.SetDeadline(time.Now().Add(5 * time.Second))
		if err := wire.WriteFrame(busy, wire.Frame{Type: wire.MsgType(0x7f), ID: uint32(i)}); err != nil {
			t.Fatal(err)
		}
		if _, err := wire.ReadFrame(busy); err != nil {
			t.Fatalf("busy connection, frame %d: %v", i, err)
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !closedBy(idle, 2*time.Second) {
		t.Fatal("an idle connection outlived the idle timeout")
	}
}
