package server

import (
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/signer-protocol/wire"
)

// A frame that starts and stalls is dropped after frameTimeout: the peer
// does not hold the connection's goroutine and buffer for good
// (ATTEST-BUDGET-01). An idle connection between frames is not.
func TestStalledFrameIsDropped(t *testing.T) {
	old := frameTimeout
	frameTimeout = 200 * time.Millisecond
	t.Cleanup(func() { frameTimeout = old })
	s := &Server{Log: quiet}

	peer, done := serveOne(s)
	defer peer.Close()
	// A length of MaxFrame, then a few bytes of the body.
	if _, err := peer.Write([]byte{0, 0x10, 0, 0, 1, 1, 0, 0}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("handleConn still waits for a frame that stalled")
	}

	idle, idleDone := serveOne(s)
	defer idle.Close()
	select {
	case <-idleDone:
		t.Fatal("an idle connection was dropped")
	case <-time.After(3 * frameTimeout):
	}
	// It still answers after the idle time.
	idle.SetDeadline(time.Now().Add(5 * time.Second))
	if err := wire.WriteFrame(idle, wire.Frame{Type: wire.MsgType(0x7f), ID: 3}); err != nil {
		t.Fatal(err)
	}
	if _, err := wire.ReadFrame(idle); err != nil {
		t.Fatalf("after idling: %v", err)
	}
}

// A frame that goes over the in-flight cap closes its connection, even
// when each Read fills the buffer io.ReadFull asked for (net.Pipe does):
// the refusal is latched, so ReadFull cannot drop it. The server reads
// little past the free part of the frame and answers nothing.
func TestInflightRefusalClosesConnection(t *testing.T) {
	s := &Server{Log: quiet}
	full := s.Limits.maxInflight()
	s.inflight.n.Store(full) // other connections hold the whole cap
	peer, done := serveOne(s)
	defer peer.Close()

	frame := make([]byte, 4+wire.MaxFrame)
	frame[1] = 0x10 // length 0x00100000 = MaxFrame
	frame[4] = wire.Version
	frame[5] = 0x7f
	wrote := make(chan int, 1)
	go func() {
		n, _ := peer.Write(frame)
		wrote <- n
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the connection over the cap is still open")
	}
	peer.Close()
	if n := <-wrote; n > 2*FreeFrameBytes {
		t.Fatalf("the server read %d bytes of a frame over the cap, want at most %d", n, 2*FreeFrameBytes)
	}
	if n := s.inflight.n.Load(); n != full {
		t.Fatalf("gauge at %d after the close, want %d", n, full)
	}
}
