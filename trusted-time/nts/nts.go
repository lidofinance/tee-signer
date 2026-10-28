//go:build nts

package nts

/*
#cgo CFLAGS: -I${SRCDIR}/../rust/include
#cgo linux,amd64 LDFLAGS: -L${SRCDIR}/../../build/nts/x86_64/lib -lsigner_nts -lpthread -ldl -lm
#cgo linux,arm64 LDFLAGS: -L${SRCDIR}/../../build/nts/aarch64/lib -lsigner_nts -lpthread -ldl -lm
#include "signer_nts.h"
*/
import "C"

import (
	"errors"
	"fmt"
	"math"
	"math/bits"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

// Sizes and limits of the library (signer_nts.h).
const (
	KeyLen            = C.SNTS_KEY_LEN
	RequestRandomLen  = C.SNTS_REQUEST_RANDOM_LEN
	KEMaxResponseLen  = C.SNTS_KE_MAX_RESPONSE_LEN
	NTPMaxRequestLen  = C.SNTS_NTP_MAX_REQUEST_LEN
	NTPMaxResponseLen = C.SNTS_NTP_MAX_RESPONSE_LEN
	MaxOperatorLen    = C.SNTS_MAX_OPERATOR_LEN
	MaxServers        = C.SNTS_MAX_SERVERS
	// RhoPPM is how fast the local clock may drift, in parts per million
	// (RFC 5905 MAXFREQ). Bounds grow by this much of their age.
	RhoPPM = C.SNTS_RHO_PPM
	// MaxSampleBound is RFC 5905 MAXDIST: a sample with a larger bound is refused.
	MaxSampleBound = time.Duration(C.SNTS_MAX_BOUND_NS)
)

// Return codes of the library (SNTS_* in signer_nts.h).
const (
	codeOK       = C.SNTS_OK
	codeKiss     = C.SNTS_KISS
	codeMore     = C.SNTS_MORE
	CodeNull     = C.SNTS_E_NULL
	CodeBuffer   = C.SNTS_E_BUFFER
	CodeArg      = C.SNTS_E_ARG
	CodeKE       = C.SNTS_E_KE
	CodeNoCookie = C.SNTS_E_NO_COOKIE
	CodeNTP      = C.SNTS_E_NTP
	CodeSample   = C.SNTS_E_SAMPLE
	CodeQuorum   = C.SNTS_E_QUORUM
)

// Version is the name and version of the Rust library, for example
// "signer-nts 0.0.3".
func Version() string { return C.GoString(C.snts_version()) }

// AESSIVSelfTest runs the AES-SIV-CMAC-256 test vector of RFC 5297 appendix
// A.1 in the Rust library. It returns nil if the library's output matches
// the RFC.
func AESSIVSelfTest() error {
	if step := int(C.snts_aes_siv_selftest()); step != 0 {
		return fmt.Errorf("AES-SIV self-test of the RFC 5297 A.1 vector failed at step %d", step)
	}
	return nil
}

// Error is a refusal from the library: the return code, and for the codes
// that carry one, the reason (kind << 16 | value).
type Error struct {
	Code   int
	Reason uint32
}

func (e *Error) Error() string {
	s := "nts: " + C.GoString(C.snts_reason_text(C.int(e.Code), C.uint32_t(e.Reason)))
	if v := e.Reason & 0xffff; v != 0 {
		s += fmt.Sprintf(": %d", v)
	}
	return s
}

// Kind is the error variant within its code (1 and up), 0 if none.
func (e *Error) Kind() int { return int(e.Reason >> 16) }

// Is lets errors.Is match on the code: errors.Is(err, &Error{Code: CodeNoCookie}).
func (e *Error) Is(target error) bool {
	t, ok := target.(*Error)
	return ok && t.Code == e.Code && (t.Reason == 0 || t.Reason == e.Reason)
}

func check(rc C.int, reason C.uint32_t) error {
	if rc == codeOK {
		return nil
	}
	return &Error{Code: int(rc), Reason: uint32(reason)}
}

// ptr is the address of the first octet of b, or nil for an empty slice.
func ptr(b []byte) *C.uint8_t {
	if len(b) == 0 {
		return nil
	}
	return (*C.uint8_t)(unsafe.Pointer(&b[0]))
}

// ALPN is the NTS-KE ALPN protocol ID (RFC 8915 section 4).
func ALPN() string { return C.GoString(C.snts_ke_alpn()) }

// ExporterLabel is the TLS exporter label of the two keys (RFC 8915 section 5.1).
func ExporterLabel() string { return C.GoString(C.snts_ke_exporter_label()) }

// ExporterContext is the 5-octet TLS exporter context (RFC 8915 section 5.1)
// of the C2S key (s2c false) or the S2C key (s2c true).
func ExporterContext(s2c bool) []byte {
	dir := C.int(0)
	if s2c {
		dir = 1
	}
	out := make([]byte, 8)
	var n C.size_t
	if rc := C.snts_ke_exporter_context(dir, ptr(out), C.size_t(len(out)), &n); rc != codeOK {
		panic(check(rc, 0)) // fixed inputs; cannot happen
	}
	return out[:n]
}

// KERequest is the NTS-KE request (RFC 8915 section 4).
func KERequest() []byte {
	out := make([]byte, 32)
	var n C.size_t
	if rc := C.snts_ke_request(ptr(out), C.size_t(len(out)), &n); rc != codeOK {
		panic(check(rc, 0)) // fixed inputs; cannot happen
	}
	return out[:n]
}

// KEResponseLength returns the length of the response at the start of buf
// and true once End of Message is in it, false if more octets are needed.
func KEResponseLength(buf []byte) (int, bool, error) {
	var n C.size_t
	var reason C.uint32_t
	switch rc := C.snts_ke_response_length(ptr(buf), C.size_t(len(buf)), &n, &reason); rc {
	case codeOK:
		return int(n), true, nil
	case codeMore:
		return 0, false, nil
	default:
		return 0, false, check(rc, reason)
	}
}

// Association holds the keys and cookies of one NTS-KE session, in Rust
// memory. Close wipes them. The methods are safe for concurrent use.
type Association struct {
	mu sync.Mutex
	p  *C.snts_assoc
	// Server and Port are the NTP server and port the KE server named
	// (RFC 8915 sections 4.1.7, 4.1.8). Server is "" if it named none.
	Server string
	Port   uint16
}

// NewAssociation checks a whole NTS-KE response and keeps the two keys
// exported from the TLS session. The caller wipes its copies of the keys.
func NewAssociation(response, c2s, s2c []byte) (*Association, error) {
	var p *C.snts_assoc
	var reason C.uint32_t
	rc := C.snts_assoc_new(ptr(response), C.size_t(len(response)), ptr(c2s), C.size_t(len(c2s)),
		ptr(s2c), C.size_t(len(s2c)), &p, &reason)
	if err := check(rc, reason); err != nil {
		return nil, err
	}
	a := &Association{p: p, Port: uint16(C.snts_assoc_port(p))}
	buf := make([]byte, 256)
	var n C.size_t
	if rc := C.snts_assoc_server(p, ptr(buf), C.size_t(len(buf)), &n); rc == codeOK {
		a.Server = string(buf[:n])
	}
	return a, nil
}

// Close frees the association and wipes its keys and cookies.
func (a *Association) Close() {
	a.mu.Lock()
	defer a.mu.Unlock()
	C.snts_assoc_free(a.p)
	a.p = nil
}

// Cookies is the number of cookies held, 0 after Close.
func (a *Association) Cookies() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return int(C.snts_assoc_cookies(a.p))
}

// Request is one NTP request waiting for its response.
type Request struct {
	a *Association
	p *C.snts_request
}

// NewRequest builds an NTP request with the next cookie. random is
// RequestRandomLen octets from a CSPRNG.
func (a *Association) NewRequest(random []byte) ([]byte, *Request, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.p == nil {
		return nil, nil, errors.New("nts: association closed")
	}
	out := make([]byte, NTPMaxRequestLen)
	var n C.size_t
	var r *C.snts_request
	rc := C.snts_ntp_request(a.p, ptr(random), C.size_t(len(random)), ptr(out), C.size_t(len(out)), &n, &r)
	if err := check(rc, 0); err != nil {
		return nil, nil, err
	}
	return out[:n], &Request{a: a, p: r}, nil
}

// Close frees the request.
func (r *Request) Close() {
	C.snts_request_free(r.p)
	r.p = nil
}

// Sample is one measurement. Offset is real Unix time minus Monotonic(), in
// nanoseconds; the bound holds at T4 on the Monotonic clock.
type Sample struct {
	Offset          int64
	Delay           time.Duration
	Bound           time.Duration
	T4              int64
	RootDelay       time.Duration
	RootDispersion  time.Duration
	Stratum         int
	Precision       int
	Leap            int
	CookiesReceived int
	CookiesHeld     int
}

// KissError is a Kiss-o'-Death response (RFC 5905 section 7.4).
type KissError struct{ Code string }

func (k *KissError) Error() string { return "nts: Kiss-o'-Death " + k.Code }

// Verify checks a response to r and measures it. t1 and t4 are Monotonic()
// just before sending and just after receiving; pivot is any time within 68
// years, for the NTP era. A Kiss-o'-Death gives a *KissError. An *Error with
// CodeNTP leaves r open for the real response.
func (r *Request) Verify(packet []byte, t1, t4 int64, pivot time.Time) (Sample, error) {
	r.a.mu.Lock()
	defer r.a.mu.Unlock()
	if r.a.p == nil || r.p == nil {
		return Sample{}, errors.New("nts: association or request closed")
	}
	var out C.snts_sample
	var reason C.uint32_t
	rc := C.snts_ntp_verify(r.a.p, r.p, ptr(packet), C.size_t(len(packet)), C.int64_t(t1), C.int64_t(t4),
		C.int64_t(pivot.UnixNano()), &out, &reason)
	if rc == codeKiss {
		k := C.GoBytes(unsafe.Pointer(&out.kiss[0]), 4)
		return Sample{CookiesHeld: int(out.cookies_held)}, &KissError{Code: string(k)}
	}
	if err := check(rc, reason); err != nil {
		return Sample{}, err
	}
	return Sample{
		Offset:          int64(out.offset_ns),
		Delay:           time.Duration(out.delay_ns),
		Bound:           time.Duration(out.bound_ns),
		T4:              int64(out.t4_local_ns),
		RootDelay:       time.Duration(out.root_delay_ns),
		RootDispersion:  time.Duration(out.root_dispersion_ns),
		Stratum:         int(out.stratum),
		Precision:       int(out.precision),
		Leap:            int(out.leap),
		CookiesReceived: int(out.cookies_received),
		CookiesHeld:     int(out.cookies_held),
	}, nil
}

// Interval is one server's measurement for the quorum.
type Interval struct {
	Operator string
	Offset   int64
	Bound    time.Duration
	T4       int64
}

// QuorumResult is the combined offset at the quorum's `now`.
type QuorumResult struct {
	Offset int64
	Bound  time.Duration
	Lo, Hi int64
}

// Quorum combines 3 to MaxServers intervals from distinct operators, one of
// which may be wrong, at the Monotonic time now.
func Quorum(in []Interval, now int64) (QuorumResult, error) {
	if len(in) > MaxServers {
		return QuorumResult{}, fmt.Errorf("nts: %d servers, at most %d", len(in), MaxServers)
	}
	cs := make([]C.snts_interval, len(in))
	for i, v := range in {
		if len(v.Operator) == 0 || len(v.Operator) > MaxOperatorLen {
			return QuorumResult{}, fmt.Errorf("nts: operator label %q: 1 to %d octets", v.Operator, MaxOperatorLen)
		}
		for j := 0; j < len(v.Operator); j++ {
			cs[i].operator_label[j] = C.uint8_t(v.Operator[j])
		}
		cs[i].operator_len = C.uint32_t(len(v.Operator))
		cs[i].offset_ns = C.int64_t(v.Offset)
		cs[i].bound_ns = C.int64_t(v.Bound)
		cs[i].t4_local_ns = C.int64_t(v.T4)
	}
	var first *C.snts_interval
	if len(cs) > 0 {
		first = &cs[0]
	}
	var out C.snts_quorum_result
	var reason C.uint32_t
	if err := check(C.snts_quorum(first, C.size_t(len(cs)), C.int64_t(now), &out, &reason), reason); err != nil {
		return QuorumResult{}, err
	}
	return QuorumResult{Offset: int64(out.offset_ns), Bound: time.Duration(out.bound_ns), Lo: int64(out.lo_ns), Hi: int64(out.hi_ns)}, nil
}

// Drift is how far a bound grows over d: RhoPPM of d, rounded up, as
// drift_ns in the Rust core. The product takes 128 bits: in int64 it
// overflowed past about 213.5 days and went negative (TIME-BOUND-01). The
// result saturates at the largest Duration, as drift_ns does.
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
// some hosts. CLOCK_MONOTONIC_RAW
// follows the hardware counter only. If the call fails, Go's monotonic
// reading is the fallback.
func Monotonic() int64 {
	var ts syscall.Timespec
	if _, _, e := syscall.Syscall(syscall.SYS_CLOCK_GETTIME, clockMonotonicRaw, uintptr(unsafe.Pointer(&ts)), 0); e != 0 {
		return int64(time.Since(monoStart))
	}
	return ts.Nano()
}

// The sizes of the C structs as cgo sees them, and as the header states;
// a test compares them.
var (
	cSizes      = [3]uintptr{unsafe.Sizeof(C.snts_sample{}), unsafe.Sizeof(C.snts_interval{}), unsafe.Sizeof(C.snts_quorum_result{})}
	headerSizes = [3]uintptr{C.SNTS_SAMPLE_SIZE, C.SNTS_INTERVAL_SIZE, C.SNTS_QUORUM_RESULT_SIZE}
)
