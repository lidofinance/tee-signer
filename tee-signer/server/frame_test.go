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
