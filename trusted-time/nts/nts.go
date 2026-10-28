//go:build nts

package nts

import (
	"context"
	"fmt"
	"math"
	"math/bits"
	"net"
	"runtime/debug"
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
	// deadline, and the key exchange the library runs again by itself when
	// its cookies run out.
	exchangeTimeout = 10 * time.Second
)

// Error codes: what refused an exchange.
const (
	CodeKE     = 1 // the key exchange: TLS, ALPN, the records
	CodeNTP    = 2 // the NTP response: not authentic, not ours, malformed
	CodeSample = 3 // the measurement (RFC 5905 checks)
	CodeQuorum = 4 // the quorum
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

// KissError is a Kiss-o'-Death response (RFC 5905 section 7.4).
type KissError struct{ Code string }

func (k *KissError) Error() string { return "nts: Kiss-o'-Death " + k.Code }

// Version names the NTS library this build links, for example
// "beevik/nts v0.3.3".
func Version() string {
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, d := range bi.Deps {
			if d.Path == "github.com/beevik/nts" {
				return "beevik/nts " + d.Version
			}
		}
	}
	return "beevik/nts"
}

// DialFunc opens a connection. Go owns every socket of NTS: TCP for NTS-KE
// and UDP for NTP. Tests and a vsock proxy plug in here.
type DialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

func dialWith(dial DialFunc, ctx context.Context, network, addr string) (net.Conn, error) {
	if dial != nil {
		return dial(ctx, network, addr)
	}
	var d net.Dialer
	// A connected UDP socket: the kernel drops datagrams from other
	// addresses.
	return d.DialContext(ctx, network, addr)
}

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

// monoTime is Monotonic as a time.Time: what the NTP library takes as the
// local clock for T1 and T4, so every offset it measures is real time minus
// Monotonic, as the samples define it.
func monoTime() time.Time { return time.Unix(0, Monotonic()) }

func wrapf(code int, format string, args ...any) error {
	return &Error{Code: code, Err: fmt.Errorf(format, args...)}
}
