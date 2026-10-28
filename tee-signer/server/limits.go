package server

import (
	"errors"
	"sync/atomic"
	"time"
)

// Connection limits (ATTEST-BUDGET-01, docs/protocol.md "Framing"). A
// direct TCP listener (Azure's public entry, GCP) takes connections from
// any address, and only the TLS handshake tells a client from a stranger.
// These bounds keep what connections can hold to a fixed amount, so a
// flood of connections, handshakes or large stalled frames costs the
// runner no more than that. They are about availability only: no limit
// here decides what a client may do.
//
// The defaults, and why:
//
//   - DefaultMaxConns 256 open connections, handshakes included: the cap
//     of the Nitro forwarder (forward.go) on the other route. The Dirk
//     fork opens at most 16 per runner, so 256 leaves room for a dozen
//     Dirk forks or gateways plus the prover, the dashboard and admin
//     tools. One idle connection costs a goroutine and the TLS buffers,
//     some tens of KiB.
//   - DefaultMaxHandshakes 32 TLS handshakes at once. A handshake takes
//     about a millisecond of CPU; a client pool dials 16 at once at most.
//     A stranger who opens connections and says nothing holds at most 32
//     slots for handshakeTimeout each, and never reaches the frame reader.
//   - DefaultMaxInflight 64 MiB of large frames at once. Every frame may
//     hold its first FreeFrameBytes (64 KiB) without counting, so SIGN,
//     HEALTH, IDENTITY and ATTEST (all far below that) are never refused
//     for memory. Only the bytes past 64 KiB of a frame count: share
//     imports, handover pages and big config updates. 64 MiB holds 64
//     frames of the full 1 MiB at once; with 256 connections times 64 KiB
//     the frame buffers stay below 80 MiB, against the 1 GiB of the Azure
//     container.
//   - DefaultIdleTimeout 0: no limit between frames. The Dirk fork's pool
//     reuses the connection freed last, so in a quiet hour most of its 16
//     connections sit idle, and it does not dial again when a request
//     finds its connection closed: that request fails. An idle timeout on
//     every runner at once would fail the first burst after a quiet time
//     on all of them. Turn it on (-idle-timeout) once the clients redial a
//     connection the runner closed; the connection cap bounds idle
//     connections until then.
const (
	DefaultMaxConns      = 256
	DefaultMaxHandshakes = 32
	DefaultMaxInflight   = 64 << 20
	DefaultIdleTimeout   = time.Duration(0)
	// FreeFrameBytes is the part of each frame that does not count
	// against MaxInflight.
	FreeFrameBytes = 64 << 10
)

// Limits are the connection limits of a server. A zero field takes its
// default; a negative MaxConns, MaxHandshakes or MaxInflight turns that
// limit off (tests).
type Limits struct {
	MaxConns      int
	MaxHandshakes int
	MaxInflight   int64
	// IdleTimeout closes a connection that sends no frame for this long
	// after its last answer. Zero: no limit.
	IdleTimeout time.Duration
}

func (l Limits) maxConns() int64 {
	if l.MaxConns == 0 {
		return DefaultMaxConns
	}
	return int64(l.MaxConns)
}

func (l Limits) maxHandshakes() int64 {
	if l.MaxHandshakes == 0 {
		return DefaultMaxHandshakes
	}
	return int64(l.MaxHandshakes)
}

func (l Limits) maxInflight() int64 {
	if l.MaxInflight == 0 {
		return DefaultMaxInflight
	}
	return l.MaxInflight
}

// gauge counts what is in use against a limit. The zero value is ready.
type gauge struct{ n atomic.Int64 }

// take adds k if the sum stays within limit, or always for a negative
// limit, and reports whether it did.
func (g *gauge) take(k, limit int64) bool {
	if limit < 0 {
		g.n.Add(k)
		return true
	}
	for {
		cur := g.n.Load()
		if cur+k > limit {
			return false
		}
		if g.n.CompareAndSwap(cur, cur+k) {
			return true
		}
	}
}

func (g *gauge) give(k int64) { g.n.Add(-k) }

// errInflight closes a connection whose frame would go over the
// in-flight byte cap.
var errInflight = errors.New("server: the runner holds its cap of large frame bytes; connection closed (ATTEST-BUDGET-01)")

// limitLogEvery: a limit that refuses says so in the log at most this
// often, with the count since start, so a flood does not fill the log.
const limitLogEvery = 10 * time.Second

type limitNote struct {
	refused atomic.Int64
	last    atomic.Int64 // unix nanoseconds of the last log line
}

// note counts one refusal and returns the count to log, 0 if this one
// is not logged.
func (n *limitNote) note() int64 {
	c := n.refused.Add(1)
	now := time.Now().UnixNano()
	last := n.last.Load()
	if now-last < int64(limitLogEvery) || !n.last.CompareAndSwap(last, now) {
		return 0
	}
	return c
}
