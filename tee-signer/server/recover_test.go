package server

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/platform"
	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/wire"
)

// serveOne runs handleConn on one end of a pipe and returns the other end
// and a channel that closes when handleConn returns.
func serveOne(s *Server) (net.Conn, chan struct{}) {
	peer, srvSide := net.Pipe()
	done := make(chan struct{})
	go func() {
		s.handleConn(context.Background(), srvSide)
		close(done)
	}()
	return peer, done
}

// A panic in a request (SHH-03: a truncated carry in IMPORT_HANDOVER) is
// a bug, never a way to stop the runner: that connection closes, and the
// runner goes on answering on other connections. Here PUBLIC_KEYS on a
// server without a signer panics on the nil signer.
func TestPanicInARequestClosesOnlyItsConnection(t *testing.T) {
	s := &Server{Log: quiet, State: constState(backend.SetupState{SetupHash: backend.Root{1}}),
		Platform: &platform.Platform{Name: "nitro", Attester: fakeAttester{}}}

	peer, done := serveOne(s)
	defer peer.Close()
	peer.SetDeadline(time.Now().Add(5 * time.Second))
	if err := wire.WriteFrame(peer, wire.Frame{Type: wire.TypePublicKeys, ID: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := wire.ReadFrame(peer); !errors.Is(err, io.EOF) {
		t.Fatalf("after a panic the connection gave %v, want it closed", err)
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("handleConn did not return after the panic")
	}

	// Another connection still gets IDENTITY.
	peer2, done2 := serveOne(s)
	peer2.SetDeadline(time.Now().Add(5 * time.Second))
	nonce := bytes.Repeat([]byte{7}, 32)
	p, _ := wire.EncodeAttest(nonce)
	if err := wire.WriteFrame(peer2, wire.Frame{Type: wire.TypeIdentity, ID: 2, Payload: p}); err != nil {
		t.Fatal(err)
	}
	f, err := wire.ReadFrame(peer2)
	if err != nil {
		t.Fatal(err)
	}
	body, err := wire.DecodeResponse(f.Payload)
	if err != nil {
		t.Fatalf("IDENTITY after a panic on another connection: %v", err)
	}
	if _, err := wire.DecodeIdentity(body); err != nil {
		t.Fatal(err)
	}
	peer2.Close()
	<-done2
	if n := s.Panics(); n != 1 {
		t.Fatalf("%d panics counted, want 1", n)
	}
}

// A panic that leaves a lock of the server held wedges the runner: the
// check after the panic finds the lock still held and calls OnWedged.
func TestPanicThatLeavesALockHeldIsWedged(t *testing.T) {
	old := panicProbeTimeout
	panicProbeTimeout = 200 * time.Millisecond
	t.Cleanup(func() { panicProbeTimeout = old })
	wedged := make(chan error, 1)
	s := &Server{Log: quiet, OnWedged: func(err error) { wedged <- err }}
	s.blockedMu.Lock() // the lock a panicking request did not release
	defer s.blockedMu.Unlock()
	peer, done := serveOne(s)
	defer peer.Close()
	if err := wire.WriteFrame(peer, wire.Frame{Type: wire.TypePublicKeys, ID: 1}); err != nil {
		t.Fatal(err)
	}
	<-done
	select {
	case <-wedged:
	case <-time.After(5 * time.Second):
		t.Fatal("OnWedged did not run with a lock still held after the panic")
	}
}

// After a panic that released its locks, OnWedged does not run.
func TestPanicThatReleasesItsLocksIsNotWedged(t *testing.T) {
	old := panicProbeTimeout
	panicProbeTimeout = 2 * time.Second
	t.Cleanup(func() { panicProbeTimeout = old })
	wedged := make(chan error, 1)
	s := &Server{Log: quiet, OnWedged: func(err error) { wedged <- err }}
	peer, done := serveOne(s)
	defer peer.Close()
	if err := wire.WriteFrame(peer, wire.Frame{Type: wire.TypePublicKeys, ID: 1}); err != nil {
		t.Fatal(err)
	}
	<-done
	select {
	case err := <-wedged:
		t.Fatalf("OnWedged ran: %v", err)
	case <-time.After(3 * time.Second):
	}
}
