package server

import (
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/signer-protocol/wire"
)

// TEE-BUDGET-02: a peer that sends a large frame and stops reading loses
// the connection once the answer's write stalls for frameTimeout, with or
// without an idle timeout, and its frame bytes go back to the gauge.
func TestStalledResponseWriteIsDropped(t *testing.T) {
	old := frameTimeout
	frameTimeout = 200 * time.Millisecond
	t.Cleanup(func() { frameTimeout = old })
	for _, idle := range []time.Duration{0, time.Hour} {
		s := &Server{Log: quiet, Limits: Limits{IdleTimeout: idle}}
		peer, done := serveOne(s)
		n := 2 * FreeFrameBytes
		frame := make([]byte, 4+n)
		frame[1], frame[2] = byte(n>>16), byte(n>>8)
		frame[4] = wire.Version
		frame[5] = 0x7f
		if _, err := peer.Write(frame); err != nil {
			t.Fatal(err)
		}
		// The peer reads nothing: the answer's write blocks.
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Fatalf("idle %v: handleConn still waits on a write the peer does not read", idle)
		}
		if b := s.inflight.n.Load(); b != 0 {
			t.Fatalf("idle %v: %d frame bytes still held", idle, b)
		}
		peer.Close()
	}
}
