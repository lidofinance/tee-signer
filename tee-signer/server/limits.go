package server

import (
	"errors"
	"net"
	"sync"
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
//     of the Nitro forwarder (forward.go) on the other route. The signing
//     client opens at most 16 per runner, so 256 leaves room for a dozen
//     signing clients or gateways plus the prover, the dashboard and admin
//     tools. One idle connection costs a goroutine and the TLS buffers,
//     some tens of KiB.
//   - DefaultMaxHandshakes: as many TLS handshakes at once as connections,
//     256. A handshake takes about a millisecond of CPU and its goroutine
//     is one the connection cap already counts, so a smaller budget does
//     not save anything; it only makes a handshake flood cheaper. It was
//     32 once: on vsock (every Nitro connection; the forwarder on the
//     parent copies TCP to vsock, so the enclave sees no client address
//     and the cap per address below never applies) 32 peers that connect,
//     send a byte and stall held every slot, and new clients were closed
//     before their ClientHello. A stranger who opens connections and says
//     nothing never reaches the frame reader: such a connection ends after
//     attls.FirstByteTimeout if no byte arrives, and a slow one after
//     handshakeTimeout. -max-handshakes still lowers the budget.
//   - DefaultMaxHandshakesPerAddr 16 of those handshakes from one IP
//     address, the most one client pool dials at once. So one address
//     alone cannot hold the whole budget. A unix socket or vsock peer has
//     no IP address and only the global budget applies; on Nitro the
//     forwarder caps, per source address, the connections in their first
//     15 s instead (platform-aws/forward, -max-conns-per-source, 16 as
//     well): it sees no handshake, only that handshakeTimeout has passed,
//     and a connection past that window counts against its 256 only.
//   - DefaultMaxInflight 64 MiB of large frames at once. Every frame may
//     hold its first FreeFrameBytes (64 KiB) without counting, so SIGN,
//     HEALTH, IDENTITY and ATTEST (all far below that) are never refused
//     for memory. Only the bytes past 64 KiB of a frame count: share
//     imports and big config updates. 64 MiB holds 64
//     frames of the full 1 MiB at once; with 256 connections times 64 KiB
//     the frame buffers stay below 80 MiB. The smallest runner is a Nitro
//     enclave of 512 MiB (MEMORY_MIB in parent-run.sh), whose Go memory
//     limit is under 384 MiB (tee-signer/memlimit.go); the Azure
//     container has 1 GiB. Answers do not count here. The largest, PUBLIC_KEYS (up to 1 MiB at
//     10,082 keys), is built once per key set and every connection writes
//     the same bytes (pubkeys.go), so a peer that stops reading holds no
//     copy of it.
//   - DefaultIdleTimeout 0: no limit between frames. The signing client's pool
//     reuses the connection freed last, so in a quiet hour most of its 16
//     connections sit idle, and it does not dial again when a request
//     finds its connection closed: that request fails. An idle timeout on
//     every runner at once would fail the first burst after a quiet time
//     on all of them. Turn it on (-idle-timeout) once the clients redial a
//     connection the runner closed; the connection cap bounds idle
//     connections until then.
//
// The cap is global, not per certificate. Any certificate under the client
// CA, an attest-only one included, can hold all 256 connections idle and
// keep them after it expires (dates are checked when a frame arrives), and
// a few certificates of a role can use up that role's budget of fresh
// attestations (limit.go). Both stop new clients of that role until those
// connections close or the runner restarts. Issue client certificates only
// to clients you run.
const (
	DefaultMaxConns      = 256
	DefaultMaxHandshakes = DefaultMaxConns
	DefaultMaxInflight   = 64 << 20
	DefaultIdleTimeout   = time.Duration(0)
	// DefaultMaxHandshakesPerAddr is the handshakes one IP address may
	// run at once.
	DefaultMaxHandshakesPerAddr = 16
	// FreeFrameBytes is the part of each frame that does not count
	// against MaxInflight.
	FreeFrameBytes = 64 << 10
)

// Limits are the connection limits of a server. A zero field takes its
// default; a negative MaxConns, MaxHandshakes, MaxHandshakesPerAddr or
// MaxInflight turns that limit off (tests).
type Limits struct {
	MaxConns             int
	MaxHandshakes        int
	MaxHandshakesPerAddr int
	MaxInflight          int64
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

func (l Limits) maxHandshakesPerAddr() int64 {
	if l.MaxHandshakesPerAddr == 0 {
		return DefaultMaxHandshakesPerAddr
	}
	return int64(l.MaxHandshakesPerAddr)
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

// addrGauge counts handshakes per source IP address. The zero value is
// ready.
type addrGauge struct {
	mu sync.Mutex
	n  map[string]int64
}

// addrOf is the IP address of a TCP peer, "" for any other peer.
func addrOf(c net.Conn) string {
	if a, ok := c.RemoteAddr().(*net.TCPAddr); ok {
		return a.IP.String()
	}
	return ""
}

// take adds one for addr if its count stays within limit, and reports
// whether it did. An empty addr or a negative limit always passes.
func (g *addrGauge) take(addr string, limit int64) bool {
	if addr == "" || limit < 0 {
		return true
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.n[addr] >= limit {
		return false
	}
	if g.n == nil {
		g.n = map[string]int64{}
	}
	g.n[addr]++
	return true
}

func (g *addrGauge) give(addr string, limit int64) {
	if addr == "" || limit < 0 {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.n[addr]--; g.n[addr] <= 0 {
		delete(g.n, addr)
	}
}

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
