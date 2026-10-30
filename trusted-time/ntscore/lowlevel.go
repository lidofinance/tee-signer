//go:build nts

package ntscore

/*
#cgo CFLAGS: -std=c11 -O2 -Wall -I${SRCDIR}
#include <stdlib.h>
#include <string.h>
#include "nts_core.h"

// The associated data strings of AES-SIV come from Go as one buffer and
// the lengths, since a Go array of Go pointers may not cross into C.
static size_t siv_seal_flat(const nts_siv_key *k, const uint8_t *ads, const size_t *lens, size_t n, const uint8_t *pt, size_t ptlen, uint8_t *out)
{
	const uint8_t *p[8];
	if (n > 8)
		return 0;
	for (size_t i = 0; i < n; i++) {
		p[i] = ads;
		ads += lens[i];
	}
	return nts_siv_seal(k, p, lens, n, pt, ptlen, out);
}

static int siv_open_flat(const nts_siv_key *k, const uint8_t *ads, const size_t *lens, size_t n, const uint8_t *ct, size_t ctlen, uint8_t *pt)
{
	const uint8_t *p[8];
	if (n > 8)
		return 0;
	for (size_t i = 0; i < n; i++) {
		p[i] = ads;
		ads += lens[i];
	}
	return nts_siv_open(k, p, lens, n, ct, ctlen, pt) ? 1 : 0;
}

// The operator labels of a quorum, the same way.
static int quorum_flat(const uint8_t *ops, const size_t *oplens, const int64_t *offsets, const int64_t *bounds, const int64_t *t4s, size_t n,
		       int64_t now, nts_quorum_result *r)
{
	nts_interval in[NTS_QUORUM_MAX_SERVERS + 1];
	if (n > NTS_QUORUM_MAX_SERVERS + 1)
		return NTS_ERR_TOO_MANY;
	for (size_t i = 0; i < n; i++) {
		in[i].op = (const char *)ops;
		in[i].oplen = oplens[i];
		in[i].offset = offsets[i];
		in[i].bound = bounds[i];
		in[i].t4 = t4s[i];
		ops += oplens[i];
	}
	return nts_quorum(in, n, now, r);
}
*/
import "C"

import (
	"sync"
	"time"
	"unsafe"
)

// Limits of the protocol, as nts_core.h has them.
const (
	KeyLen            = C.NTS_KEY_LEN
	UniqueIDLen       = C.NTS_UID_LEN
	NonceLen          = C.NTS_NONCE_LEN
	SIVTagLen         = C.NTS_SIV_TAG_LEN
	MaxPlaceholders   = C.NTS_MAX_PLACEHOLDERS
	NTPMaxRequestLen  = C.NTS_MAX_REQUEST_LEN
	NTPMaxResponseLen = C.NTS_MAX_RESPONSE_LEN
	RequestRandomLen  = C.NTS_REQUEST_RANDOM_LEN
	MaxCookies        = C.NTS_MAX_COOKIES
	MaxCookieLen      = C.NTS_MAX_COOKIE_LEN
	KEPort            = C.NTS_KE_PORT
	KEMaxResponseLen  = C.NTS_KE_MAX_RESPONSE_LEN
	KEMaxRecords      = C.NTS_KE_MAX_RECORDS
	KEMaxBody         = C.NTS_KE_MAX_BODY
	MaxServerName     = C.NTS_MAX_SERVER_NAME
	RhoPPM            = C.NTS_RHO_PPM
	MaxSampleBoundNs  = C.NTS_MAX_SAMPLE_BOUND_NS
	F                 = C.NTS_QUORUM_F
	MinServers        = C.NTS_QUORUM_MIN_SERVERS
	MaxServers        = C.NTS_QUORUM_MAX_SERVERS
	MaxOperatorLen    = C.NTS_MAX_OPERATOR_LEN
	MaxRootsLen       = C.NTS_MAX_ROOTS_LEN
	aeadSIVCMAC256    = 15
	// ALPN is the application protocol of NTS-KE, ExporterLabel the TLS
	// exporter label of its keys (RFC 8915 sections 4 and 5.1).
	ALPN          = "ntske/1"
	ExporterLabel = "EXPORTER-network-time-security"
)

// Extension field types of NTS (RFC 8915 section 7.5).
const (
	ExtUniqueID    = 0x0104
	ExtCookie      = 0x0204
	ExtPlaceholder = 0x0304
	ExtAuth        = 0x0404
)

// NTS-KE record types (RFC 8915 section 4.1).
const (
	RecEOM          = 0
	RecNextProtocol = 1
	RecError        = 2
	RecWarning      = 3
	RecAEAD         = 4
	RecCookie       = 5
	RecServer       = 6
	RecPort         = 7
	RecCritical     = 0x8000
	AEADSIVCMAC256  = aeadSIVCMAC256
)

var setupOnce sync.Once

// setup computes the core's tables once, before any thread uses them.
func setup() { setupOnce.Do(func() { C.nts_setup() }) }

func init() { setup() }

// A pointer C may read n octets through, never nil: a Go slice may be
// empty and have no backing array.
var dummy [1]byte

func bptr(b []byte) *C.uint8_t {
	if len(b) == 0 {
		return (*C.uint8_t)(unsafe.Pointer(&dummy[0]))
	}
	return (*C.uint8_t)(unsafe.Pointer(&b[0]))
}

func flat(ad [][]byte) ([]byte, []C.size_t) {
	var buf []byte
	lens := make([]C.size_t, len(ad))
	for i, a := range ad {
		buf = append(buf, a...)
		lens[i] = C.size_t(len(a))
	}
	return buf, lens
}

func sptr(l []C.size_t) *C.size_t {
	if len(l) == 0 {
		return nil
	}
	return &l[0]
}

// ---- AES-SIV-CMAC-256 ----

// SIVKey is one AES-SIV-CMAC-256 key, expanded once.
type SIVKey struct{ k C.nts_siv_key }

// NewSIVKey expands a key of exactly KeyLen octets.
func NewSIVKey(key []byte) (*SIVKey, error) {
	k := &SIVKey{}
	if rc := C.nts_siv_init(&k.k, bptr(key), C.size_t(len(key))); rc != 0 {
		return nil, CodeError(int(rc), 0)
	}
	return k, nil
}

// Seal returns V || C over the associated data strings ad and the
// plaintext (RFC 5297 sections 2.6, 6.1).
func (k *SIVKey) Seal(ad [][]byte, plaintext []byte) []byte {
	buf, lens := flat(ad)
	out := make([]byte, SIVTagLen+len(plaintext))
	n := C.siv_seal_flat(&k.k, bptr(buf), sptr(lens), C.size_t(len(lens)), bptr(plaintext), C.size_t(len(plaintext)), bptr(out))
	return out[:n]
}

// Open checks and decrypts V || C (RFC 5297 section 2.7).
func (k *SIVKey) Open(ad [][]byte, ct []byte) ([]byte, bool) {
	if len(ct) < SIVTagLen {
		return nil, false
	}
	buf, lens := flat(ad)
	pt := make([]byte, len(ct)-SIVTagLen)
	ok := C.siv_open_flat(&k.k, bptr(buf), sptr(lens), C.size_t(len(lens)), bptr(ct), C.size_t(len(ct)), bptr(pt))
	if ok != 1 {
		return nil, false
	}
	return pt, true
}

// ---- NTP time formats ----

// NTPTimestamp is seconds since the start of its era in the high 32 bits,
// the fraction of a second (2^-32 s units) in the low 32.
type NTPTimestamp uint64

// NTPFromUnixNanos is the NTP timestamp of nanoseconds since the Unix
// epoch: the era dropped, the fraction rounded up.
func NTPFromUnixNanos(n int64) NTPTimestamp {
	return NTPTimestamp(C.nts_ntp_from_unix_nanos(C.int64_t(n)))
}

// UnixNanos is nanoseconds since the Unix epoch, rounded down, in the era
// nearest the pivot; false if that does not fit an int64.
func (t NTPTimestamp) UnixNanos(pivot int64) (int64, bool) {
	var out C.int64_t
	ok := C.nts_unix_nanos(C.uint64_t(t), C.int64_t(pivot), &out)
	return int64(out), bool(ok)
}

// Sub is t - earlier, modulo 2^64, read as signed: right as long as the
// two are less than 68 years apart.
func (t NTPTimestamp) Sub(earlier NTPTimestamp) NTPDuration {
	return NTPDuration(C.nts_ntp_sub(C.uint64_t(t), C.uint64_t(earlier)))
}

// NTPDuration is a signed difference of timestamps in 2^-32 s units.
type NTPDuration int64

// Nanos is the duration in nanoseconds, rounded toward minus infinity.
func (d NTPDuration) Nanos() int64 { return int64(C.nts_duration_nanos(C.int64_t(d))) }

// NTPShort is the 32-bit short format: 16 bits of seconds, 16 of fraction.
type NTPShort uint32

// Nanos is the value in nanoseconds, rounded down.
func (s NTPShort) Nanos() int64 { return int64(C.nts_short_nanos(C.uint32_t(s))) }

// PrecisionNs is 2^precision seconds in nanoseconds, rounded up, for
// every int8; at most 2^7 s.
func PrecisionNs(precision int8) int64 { return int64(C.nts_precision_ns(C.int8_t(precision))) }

// ---- The request and the response ----

// FieldLen is the length of an extension field with a body of n octets,
// RequestLen that of a request with a cookie of cookieLen octets and
// placeholders placeholders, MaxPlaceholdersFor the most placeholders such
// a request can carry within NTPMaxRequestLen.
func FieldLen(n int) int { return int(C.nts_field_len(C.size_t(n))) }
func RequestLen(cookieLen, placeholders int) int {
	return int(C.nts_request_len(C.size_t(cookieLen), C.int(placeholders)))
}
func MaxPlaceholdersFor(cookieLen int) int { return int(C.nts_max_placeholders(C.size_t(cookieLen))) }

// RequestInput is what a request is built from: the caller's random
// values and the cookie.
type RequestInput struct {
	Transmit     NTPTimestamp // random, not the local clock
	UniqueID     [UniqueIDLen]byte
	Nonce        [NonceLen]byte
	Cookie       []byte
	Placeholders int
}

// PendingRequest is a request that was built and may be waiting for its
// response. Verify checks responses and accepts at most one.
type PendingRequest struct{ p C.nts_pending }

func (r *PendingRequest) Transmit() NTPTimestamp { return NTPTimestamp(r.p.transmit) }
func (r *PendingRequest) Answered() bool         { return bool(r.p.answered) }
func (r *PendingRequest) Placeholders() int      { return int(r.p.placeholders) }

// BuildRequest builds a client request (RFC 8915 section 5.7) and the
// state that checks its response.
func BuildRequest(c2s *SIVKey, in *RequestInput) ([]byte, *PendingRequest, error) {
	out := make([]byte, NTPMaxRequestLen)
	var n C.size_t
	req := &PendingRequest{}
	rc := C.nts_build_request(&c2s.k, C.uint64_t(in.Transmit), (*C.uint8_t)(&in.UniqueID[0]), (*C.uint8_t)(&in.Nonce[0]),
		bptr(in.Cookie), C.size_t(len(in.Cookie)), C.int(in.Placeholders), bptr(out), C.size_t(len(out)), &n, &req.p)
	if rc != 0 {
		return nil, nil, CodeError(int(rc), 0)
	}
	return out[:n], req, nil
}

// TimeResponse is the fields of an authentic server response, as on the
// wire (RFC 5905 section 7.3). The error bound is computed by Measure.
type TimeResponse struct {
	Leap           uint8
	Stratum        uint8
	Precision      int8
	RootDelay      NTPShort
	RootDispersion NTPShort
	Reference      NTPTimestamp
	Origin         NTPTimestamp
	Receive        NTPTimestamp
	Transmit       NTPTimestamp
	Cookies        [][]byte
}

// Verdict is what a valid response gives: a Kiss-o'-Death code (no time),
// or a time response.
type Verdict struct {
	// Kiss is the reference ID of a Kiss-o'-Death as 4 octets, "" for a
	// time response. KissAuthentic says whether it carried an
	// authenticator that verifies with the S2C key.
	Kiss          string
	KissAuthentic bool
	Time          *TimeResponse
}

func timeFromC(t *C.nts_time_response) *TimeResponse {
	out := &TimeResponse{
		Leap: uint8(t.leap), Stratum: uint8(t.stratum), Precision: int8(t.precision),
		RootDelay: NTPShort(t.root_delay), RootDispersion: NTPShort(t.root_dispersion),
		Reference: NTPTimestamp(t.reference), Origin: NTPTimestamp(t.origin), Receive: NTPTimestamp(t.receive), Transmit: NTPTimestamp(t.transmit),
	}
	for i := 0; i < int(t.ncookies); i++ {
		n := int(t.cookie_len[i])
		out.Cookies = append(out.Cookies, C.GoBytes(unsafe.Pointer(&t.cookies[i][0]), C.int(n)))
	}
	return out
}

func timeToC(t *TimeResponse, out *C.nts_time_response) bool {
	*out = C.nts_time_response{}
	out.leap, out.stratum, out.precision = C.uint8_t(t.Leap), C.uint8_t(t.Stratum), C.int8_t(t.Precision)
	out.root_delay, out.root_dispersion = C.uint32_t(t.RootDelay), C.uint32_t(t.RootDispersion)
	out.reference, out.origin, out.receive, out.transmit = C.uint64_t(t.Reference), C.uint64_t(t.Origin), C.uint64_t(t.Receive), C.uint64_t(t.Transmit)
	if len(t.Cookies) > MaxCookies {
		return false
	}
	for i, c := range t.Cookies {
		if len(c) > MaxCookieLen {
			return false
		}
		copy(unsafe.Slice((*byte)(unsafe.Pointer(&out.cookies[i][0])), MaxCookieLen), c)
		out.cookie_len[i] = C.size_t(len(c))
	}
	out.ncookies = C.int(len(t.Cookies))
	return true
}

// Verify checks a response to this request with the S2C key. A refused
// response changes nothing, so the real response can still come. After
// one is accepted every further one is refused as a replay.
func (r *PendingRequest) Verify(s2c *SIVKey, packet []byte) (Verdict, error) {
	v := new(C.nts_verdict)
	rc := C.nts_verify_response(&r.p, &s2c.k, bptr(packet), C.size_t(len(packet)), v)
	if rc != 0 {
		return Verdict{}, CodeError(int(rc), int(v.detail))
	}
	if v.kind == C.NTS_KIND_KISS {
		return Verdict{Kiss: C.GoStringN(&v.kiss[0], 4), KissAuthentic: bool(v.kiss_authentic)}, nil
	}
	return Verdict{Time: timeFromC(&v.time)}, nil
}

// ---- The measurement ----

// Sample is one measurement. Offset is real Unix time minus the monotonic
// clock, in nanoseconds; the bound holds at T4 on the monotonic clock.
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

func sampleFromC(s *C.nts_sample) Sample {
	return Sample{
		Offset: int64(s.offset), Delay: time.Duration(s.delay), Bound: time.Duration(s.bound), T4: int64(s.t4),
		RootDelay: time.Duration(s.root_delay), RootDispersion: time.Duration(s.root_dispersion),
		Stratum: int(s.stratum), Precision: int(s.precision), Leap: int(s.leap),
		CookiesReceived: int(s.cookies_received), CookiesHeld: int(s.cookies_held),
	}
}

// Measure is the offset, delay and error bound of an authentic response:
// t1 and t4 from the monotonic clock around the exchange, the pivot any
// Unix time within 68 years of now, which picks the NTP era of T2 and T3.
func Measure(t *TimeResponse, t1, t4, pivot int64) (Sample, error) {
	ct := new(C.nts_time_response)
	if !timeToC(t, ct) {
		return Sample{}, ErrTooManyCookies
	}
	s := new(C.nts_sample)
	if rc := C.nts_measure(ct, C.int64_t(t1), C.int64_t(t4), C.int64_t(pivot), s); rc != 0 {
		return Sample{}, CodeError(int(rc), int(s.detail))
	}
	return sampleFromC(s), nil
}

// Drift is how far a bound grows over d: RhoPPM of d, rounded up,
// saturated at the largest Duration; 0 for d <= 0.
func Drift(d time.Duration) time.Duration { return time.Duration(C.nts_drift(C.int64_t(d))) }

// AddBound is a + b for two error bounds of zero or more, saturated at
// the largest Duration instead of wrapping to a negative one.
func AddBound(a, b time.Duration) time.Duration {
	return time.Duration(C.nts_add_bound(C.int64_t(a), C.int64_t(b)))
}

// ---- The quorum ----

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

// Quorum combines MinServers to MaxServers intervals from distinct
// operators, F of which may be wrong, at the monotonic time now. Each
// bound first grows by RhoPPM of its age at now.
func Quorum(in []Interval, now int64) (QuorumResult, error) {
	if len(in) > MaxServers+1 {
		return QuorumResult{}, CodeError(codeQuorumTooMany, 0)
	}
	var ops []byte
	n := len(in)
	oplens, offsets, bounds, t4s := make([]C.size_t, n+1), make([]C.int64_t, n+1), make([]C.int64_t, n+1), make([]C.int64_t, n+1)
	for i, s := range in {
		ops = append(ops, s.Operator...)
		oplens[i], offsets[i], bounds[i], t4s[i] = C.size_t(len(s.Operator)), C.int64_t(s.Offset), C.int64_t(s.Bound), C.int64_t(s.T4)
	}
	var r C.nts_quorum_result
	rc := C.quorum_flat(bptr(ops), &oplens[0], &offsets[0], &bounds[0], &t4s[0], C.size_t(n), C.int64_t(now), &r)
	if rc != 0 {
		return QuorumResult{}, CodeError(int(rc), 0)
	}
	return QuorumResult{Offset: int64(r.offset), Bound: time.Duration(r.bound), Lo: int64(r.lo), Hi: int64(r.hi)}, nil
}

// ---- NTS-KE records ----

// KERequest is the request this client sends: Next Protocol NTPv4, AEAD
// 15, End of Message, all critical.
func KERequest() []byte {
	out := make([]byte, C.NTS_KE_REQUEST_LEN)
	C.nts_ke_request(bptr(out))
	return out
}

// ExporterContext is the exporter context of the C2S (false) or S2C
// (true) key: protocol 0, AEAD 15, the direction (RFC 8915 section 5.1).
func ExporterContext(s2c bool) []byte {
	out := make([]byte, 5)
	C.nts_ke_exporter_context(C.bool(s2c), bptr(out))
	return out
}

// KEComplete walks the records read so far: the length of the response
// once End of Message arrived, or false while it has not. It checks only
// the framing and the caps; ParseKEResponse does the rest.
func KEComplete(buf []byte) (int, bool, error) {
	var n C.size_t
	var done C.bool
	if rc := C.nts_ke_complete(bptr(buf), C.size_t(len(buf)), &n, &done); rc != 0 {
		return 0, false, CodeError(int(rc), 0)
	}
	return int(n), bool(done), nil
}

// KEResponse is what a parsed NTS-KE response holds.
type KEResponse struct {
	Cookies [][]byte // the first MaxCookies, in the server's order; at least one
	Dropped int      // further valid cookies, not kept
	Server  string   // the NTP server named (RFC 8915 section 4.1.7), "" for none
	Port    uint16   // the NTP port named (section 4.1.8), 0 for none
}

// ParseKEResponse checks a whole response (RFC 8915 section 4.1).
func ParseKEResponse(buf []byte) (*KEResponse, error) {
	r := new(C.nts_ke_response)
	if rc := C.nts_ke_parse(bptr(buf), C.size_t(len(buf)), r); rc != 0 {
		return nil, CodeError(int(rc), int(r.detail))
	}
	out := &KEResponse{Dropped: int(r.dropped), Server: C.GoStringN(&r.server[0], C.int(r.server_len)), Port: uint16(r.port)}
	for i := 0; i < int(r.ncookies); i++ {
		out.Cookies = append(out.Cookies, C.GoBytes(unsafe.Pointer(&r.cookies[i][0]), C.int(r.cookie_len[i])))
	}
	return out, nil
}

// CoarseRefused is the coarse check: diff is the NTS time minus the
// coarse time, both at the same local instant; res the resolution of the
// coarse reading.
func CoarseRefused(diff, limit, res time.Duration) bool {
	return bool(C.nts_coarse_refused(C.int64_t(diff), C.int64_t(limit), C.int64_t(res)))
}
