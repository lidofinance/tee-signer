//go:build nts

package nts

import (
	"context"
	"fmt"
	"net"
	"sync"
	"syscall"
	"time"
	"unsafe"

	ntscore "github.com/lidofinance/tee-signer/trusted-time/ntscore/go"
)

// Limits of the client.
const (
	// RhoPPM is how fast the local clock may drift, in parts per million
	// (RFC 5905 MAXFREQ). Bounds grow by this much of their age.
	RhoPPM = ntscore.RhoPPM
	// KEPort is the NTS-KE port (RFC 8915 section 4).
	KEPort = ntscore.KEPort
	// ExchangeTimeout bounds one NTS-KE session or one NTP query; a query
	// gets half the poll interval if that is shorter.
	ExchangeTimeout = 5 * time.Second
	// KissGrace is how long a query reads on after a Kiss-o'-Death for the
	// real answer: a forged KoD sent before it must not end the query. The
	// real answer follows within a round trip; this is far more.
	KissGrace = 500 * time.Millisecond
	// DriftBaselinePolls times the interval is the baseline of the drift
	// check: the check also compares each quorum with the oldest quorum
	// kept, at least this old.
	DriftBaselinePolls = 64
)

// Limits and rules of the core, named here for the clock, the runner and
// their tests. The values and the code are the core's (ntscore).
const (
	// MaxServers is the most servers of one client (and of one quorum).
	MaxServers = ntscore.MaxServers
	// MaxOperatorLen is the longest operator label, in octets.
	MaxOperatorLen = ntscore.MaxOperatorLen
	// MaxSampleBound is the widest bound a sample may have (RFC 5905
	// MAXDIST, 1 s), and so the most Config.MaxSampleBound takes.
	MaxSampleBound = ntscore.MaxSampleBound
	// PlainRequestLen is the length of a plain NTP request: the header.
	PlainRequestLen = ntscore.PlainRequestLen
	// KEAfterLost is how many queries in a row may go unanswered before
	// the core runs NTS-KE again, once per such streak.
	KEAfterLost = ntscore.KEAfterLost
)

// Protocol is what the core asks the servers with; it is configuration
// (Config.Protocol, Client.SetPolicy).
type Protocol = ntscore.Protocol

const (
	ProtocolNTS = ntscore.ProtocolNTS
	ProtocolNTP = ntscore.ProtocolNTP
)

// Interval and QuorumResult are the input and the result of Quorum.
type (
	Interval     = ntscore.Interval
	QuorumResult = ntscore.QuorumResult
)

// MajorityWrong is the most wrong servers the majority rule allows among
// n: (n - 1) / 2, rounded down (the core's nts_majority_wrong).
func MajorityWrong(n int) int { return ntscore.MajorityWrong(n) }

// QuorumWrong is the most wrong servers the core allows among n fresh
// samples: MajorityWrong(n), but never so many that fewer than 3 agree
// (nts_quorum_wrong). The core's combine applies it itself; it is here
// for tests and for what is shown.
func QuorumWrong(n int) int { return ntscore.QuorumWrong(n) }

// Quorum is the core's quorum of intervals (nts_quorum), for tests. The
// client's own quorum is formed inside the core, from its own samples.
func Quorum(in []Interval, now int64, maxWrong int) (QuorumResult, error) {
	return ntscore.Quorum(in, now, maxWrong)
}

// Drift is how far a bound grows over d: RhoPPM of d, rounded up
// (nts_drift). AddBound is a + b for two bounds, saturated.
func Drift(d time.Duration) time.Duration       { return ntscore.Drift(d) }
func AddBound(a, b time.Duration) time.Duration { return ntscore.AddBound(a, b) }

// FloorTime is a time known to be in the past when this code was built. It
// fixes the NTP era (RFC 5905 section 6: 136 years long, the current one
// ending in 2036) that server timestamps are read in, for the 68 years
// after it, so that no input of the host can move the time by an era. Move
// it forward with the releases.
var FloorTime = time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)

// Error codes: what refused an exchange.
const (
	CodeKE       = 1 // the key exchange: TLS, ALPN, the records
	CodeNTP      = 2 // the NTP response: not authentic, not ours, malformed
	CodeSample   = 3 // the measurement (RFC 5905 checks)
	CodeQuorum   = 4 // the quorum
	CodeNoCookie = 5 // no cookie left for a request
)

// Error is a refusal with the code of the step that refused.
type Error struct {
	Code int
	Err  error
}

func (e *Error) Error() string { return "nts: " + e.Err.Error() }
func (e *Error) Unwrap() error { return e.Err }

// Is matches another *Error with the same code, so errors.Is(err,
// &Error{Code: CodeNTP}) tests the code alone.
func (e *Error) Is(target error) bool {
	t, ok := target.(*Error)
	return ok && t.Code == e.Code
}

// KissError is a Kiss-o'-Death response (RFC 5905 section 7.4). Code is
// the reference ID as the server sent it, 4 octets: "RATE", "NTSN",
// "DENY", "RSTR" or another. Authentic is true when the KoD carried an
// authenticator that verifies with the S2C key: only such a KoD is known
// to come from the server, since the fields a KoD must match travel in
// the clear and anyone on the path can forge one (RFC 8915 sections 5.7
// and 8.5). A server sends NTSN without one, so NTSN is never authentic.
type KissError struct {
	Code      string
	Authentic bool
}

func (k *KissError) Error() string {
	if k.Authentic {
		return fmt.Sprintf("nts: Kiss-o'-Death %q", k.Code)
	}
	return fmt.Sprintf("nts: Kiss-o'-Death %q (not authenticated)", k.Code)
}

// Version names this NTS client: the C core of trusted-time/ntscore under
// the Go wrapper.
func Version() string { return "signer-nts c 1" }

// DialFunc opens a connection. Go owns every socket of NTS: TCP for NTS-KE
// and UDP for NTP. Tests and a vsock proxy plug in here.
type DialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// Sample is one measurement: real Unix time minus Monotonic, with its
// error bound at T4.
type Sample = ntscore.Sample

// Server is one NTS server and the operator who runs it, with the
// operator's pinned roots (PEM).
type Server = ntscore.Server

// clockMonotonicRaw is CLOCK_MONOTONIC_RAW of Linux (linux/time.h).
const clockMonotonicRaw = 4

var monoStart = time.Now()

func rawNanos() (int64, bool) {
	var ts syscall.Timespec
	_, _, e := syscall.Syscall(syscall.SYS_CLOCK_GETTIME, clockMonotonicRaw, uintptr(unsafe.Pointer(&ts)), 0)
	return ts.Nano(), e == 0
}

// rawOK is whether CLOCK_MONOTONIC_RAW can be read, decided once: a
// process never switches clocks, since the two have different epochs and
// rates. The call fails only for a clock the kernel does not know
// (EINVAL), the same answer every time.
var rawOK = sync.OnceValue(func() bool { _, ok := rawNanos(); return ok })

// MonotonicRaw is whether Monotonic reads CLOCK_MONOTONIC_RAW, which
// every Linux kernel since 2.6.28 has; without it, Go's monotonic reading
// serves for the whole run.
func MonotonicRaw() bool { return rawOK() }

// Monotonic is nanoseconds on CLOCK_MONOTONIC_RAW. Samples, bounds and the
// quorum all use it; NTS never reads the host's wall clock.
//
// Not Go's monotonic reading: that is CLOCK_MONOTONIC, whose rate an NTP
// daemon in the same kernel slews (adjtimex), by far more than RhoPPM on
// some hosts. CLOCK_MONOTONIC_RAW follows the hardware counter only.
func Monotonic() int64 {
	if rawOK() {
		ns, _ := rawNanos()
		return ns
	}
	return int64(time.Since(monoStart))
}
