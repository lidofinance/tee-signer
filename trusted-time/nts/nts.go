//go:build nts

package nts

import (
	"context"
	"fmt"
	"math"
	"math/bits"
	"net"
	"syscall"
	"time"
	"unsafe"
)

// Limits of the client.
const (
	// RhoPPM is how fast the local clock may drift, in parts per million
	// (RFC 5905 MAXFREQ). Bounds grow by this much of their age.
	RhoPPM = 500
	// MaxSampleBound is RFC 5905 MAXDIST: a sample with a larger bound is refused.
	MaxSampleBound = time.Second
	// KEPort is the NTS-KE port (RFC 8915 section 4).
	KEPort = 4460
	// exchangeTimeout bounds an NTS-KE or NTP exchange whose context has no
	// deadline.
	exchangeTimeout = 10 * time.Second
	// kissGrace is how long a query reads on after a Kiss-o'-Death for the
	// real answer: a forged KoD sent before it must not end the query. The
	// real answer follows within a round trip; this is far more.
	kissGrace = 500 * time.Millisecond
)

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

// Version names this NTS client: the Go port of the signer's NTS core on
// the standard library alone.
func Version() string { return "signer-nts go 1" }

// DialFunc opens a connection. Go owns every socket of NTS: TCP for NTS-KE
// and UDP for NTP. Tests and a vsock proxy plug in here.
type DialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// timeoutOf is the time left in ctx, or exchangeTimeout without a deadline.
func timeoutOf(ctx context.Context) time.Duration {
	if dl, ok := ctx.Deadline(); ok {
		return max(time.Until(dl), time.Millisecond)
	}
	return exchangeTimeout
}

// Drift is how far a bound grows over d: RhoPPM of d, rounded up. The
// product takes 128 bits: in int64 it overflowed past about 213.5 days and
// went negative (TIME-BOUND-01). The result saturates at the largest
// Duration.
func Drift(d time.Duration) time.Duration {
	if d <= 0 {
		return 0
	}
	hi, lo := bits.Mul64(uint64(d), uint64(RhoPPM))
	lo, carry := bits.Add64(lo, 999_999, 0)
	// hi < RhoPPM / 2 < 1_000_000, so Div64 does not panic.
	q, _ := bits.Div64(hi+carry, lo, 1_000_000)
	if q > math.MaxInt64 {
		return math.MaxInt64
	}
	return time.Duration(q)
}

// AddBound is a + b for two error bounds of zero or more, saturated at the
// largest Duration instead of wrapping to a negative one.
func AddBound(a, b time.Duration) time.Duration {
	if a < 0 || b < 0 || a > math.MaxInt64-b {
		return math.MaxInt64
	}
	return a + b
}

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

func wrapf(code int, format string, args ...any) error {
	return &Error{Code: code, Err: fmt.Errorf(format, args...)}
}
