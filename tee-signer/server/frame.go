package server

import (
	"net"
	"time"
)

// frameTimeout bounds the read of one frame once its first byte is in, and
// the write of each answer: a peer that declares a frame and stalls, or
// stops reading the answer, loses the connection (ATTEST-BUDGET-01,
// TEE-BUDGET-02). A variable so a test can shorten it.
var frameTimeout = 30 * time.Second

// frameConn sets the read deadlines of a connection's frames and counts
// their large bytes against the server's in-flight cap (limits.go).
// Before a frame's first byte the deadline is the idle timeout (none if
// zero); from that byte on, frameTimeout. A connection that takes no
// deadline reads as before: the errors of SetReadDeadline are dropped.
type frameConn struct {
	net.Conn
	timeout time.Duration
	idle    time.Duration
	started bool

	// inflight is the server's gauge of large frame bytes, maxInflight
	// its cap. read counts the bytes of the current frame, held the part
	// of them taken from the gauge.
	inflight    *gauge
	maxInflight int64
	read, held  int64
	// refused latches a refusal of the gauge: every later Read fails
	// without reading. io.ReadFull drops an error that comes with the
	// bytes that fill its buffer, so the refusal must not depend on the
	// Read that saw it.
	refused bool
}

// next readies the connection for the next frame: the bytes of the last
// one go back to the gauge, and the idle deadline runs until the first
// byte.
func (f *frameConn) next() {
	f.release()
	f.started = false
	var dl time.Time
	if f.idle > 0 {
		dl = time.Now().Add(f.idle)
	}
	_ = f.Conn.SetReadDeadline(dl)
}

// release gives the current frame's counted bytes back.
func (f *frameConn) release() {
	if f.inflight != nil && f.held > 0 {
		f.inflight.give(f.held)
	}
	f.read, f.held = 0, 0
}

func (f *frameConn) Read(p []byte) (int, error) {
	if f.refused {
		return 0, errInflight
	}
	n, err := f.Conn.Read(p)
	if n > 0 && !f.started {
		f.started = true
		_ = f.Conn.SetReadDeadline(time.Now().Add(f.timeout))
	}
	if n > 0 && f.inflight != nil {
		f.read += int64(n)
		if over := f.read - FreeFrameBytes - f.held; over > 0 {
			if !f.inflight.take(over, f.maxInflight) {
				// The bytes are dropped with the frame: the connection
				// closes.
				f.refused = true
				return 0, errInflight
			}
			f.held += over
		}
	}
	return n, err
}
