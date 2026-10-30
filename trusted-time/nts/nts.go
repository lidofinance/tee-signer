//go:build nts

package nts

import (
	"context"
	"fmt"
	"net"
	"syscall"
	"time"
	"unsafe"

	"github.com/lidofinance/tee-signer/trusted-time/ntscore"
)

// Limits of the client.
const (
	// RhoPPM is how fast the local clock may drift, in parts per million
	// (RFC 5905 MAXFREQ). Bounds grow by this much of their age.
	RhoPPM = ntscore.RhoPPM
	// MaxSampleBound is RFC 5905 MAXDIST: a sample with a larger bound is refused.
	MaxSampleBound = time.Duration(ntscore.MaxSampleBoundNs)
	// KEPort is the NTS-KE port (RFC 8915 section 4).
	KEPort = ntscore.KEPort
	// MaxCookies is how many cookies the client keeps (RFC 8915 section
	// 4.1.6: servers SHOULD send 8).
	MaxCookies = ntscore.MaxCookies
	// MinServers is the smallest quorum, MaxServers the largest.
	MinServers = ntscore.MinServers
	MaxServers = ntscore.MaxServers
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
	DriftBaselinePolls = 32
)

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

// timeoutOf is the time left in ctx, or d without a deadline.
func timeoutOf(ctx context.Context, d time.Duration) time.Duration {
	if dl, ok := ctx.Deadline(); ok {
		return max(min(time.Until(dl), d), time.Millisecond)
	}
	return d
}

// Drift is how far a bound grows over d: RhoPPM of d, rounded up,
// saturated at the largest Duration (TIME-BOUND-01).
func Drift(d time.Duration) time.Duration { return ntscore.Drift(d) }

// AddBound is a + b for two error bounds of zero or more, saturated at the
// largest Duration instead of wrapping to a negative one.
func AddBound(a, b time.Duration) time.Duration { return ntscore.AddBound(a, b) }

// clockMonotonicRaw is CLOCK_MONOTONIC_RAW of Linux (linux/time.h).
const clockMonotonicRaw = 4

var monoStart = time.Now()

// Monotonic is nanoseconds on CLOCK_MONOTONIC_RAW. Samples, bounds and the
// quorum all use it; NTS never reads the host's wall clock.
//
// Not Go's monotonic reading: that is CLOCK_MONOTONIC, whose rate an NTP
// daemon in the same kernel slews (adjtimex), by far more than RhoPPM on
// some hosts. CLOCK_MONOTONIC_RAW follows the hardware counter only. If the
// call fails, Go's monotonic reading is the fallback.
func Monotonic() int64 {
	var ts syscall.Timespec
	if _, _, e := syscall.Syscall(syscall.SYS_CLOCK_GETTIME, clockMonotonicRaw, uintptr(unsafe.Pointer(&ts)), 0); e != 0 {
		return int64(time.Since(monoStart))
	}
	return ts.Nano()
}
