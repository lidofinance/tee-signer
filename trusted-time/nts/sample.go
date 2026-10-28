//go:build nts

package nts

import (
	"errors"
	"fmt"
	"math/big"
	"time"
)

// Offset, delay and error bound of one server response (RFC 5905 section
// 8), and the checks of RFC 5905 that need no state from earlier
// responses. T1 and T4 are Monotonic readings, in nanoseconds from any
// fixed start; T2 and T3 are the server's wall-clock times. So the offset
// says how far real time is ahead of the local monotonic clock: real Unix
// time at the local instant x is x + offset, give or take the bound. The
// host clock is never read. The arithmetic runs in big.Int, as the Rust
// core ran it in i128: no input can overflow it.

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
	Precision       int // log2 seconds, as the server states it
	Leap            int
	CookiesReceived int
	CookiesHeld     int
}

// Why a response gives no measurement. Query wraps them in an *Error with
// CodeSample.
var (
	errLocalTimesReversed     = errors.New("local receive time before local send time")
	errServerTimesReversed    = errors.New("server transmit time before its receive time")
	errNegativeDelay          = errors.New("negative round-trip delay")
	errSampleStratum          = errors.New("stratum outside 1 to 15")
	errNeverSynchronized      = errors.New("reference timestamp is zero")
	errZeroTimestamp          = errors.New("receive or transmit timestamp is zero")
	errReferenceAfterTransmit = errors.New("reference timestamp after transmit timestamp")
	errTimestampOutOfRange    = errors.New("timestamp out of range")
	errBoundTooLarge          = fmt.Errorf("error bound over %d ns (MAXDIST)", int64(MaxSampleBound))
)

const (
	// roundingNs is the slack added to every bound: each of T2 and T3
	// loses less than 1 ns when it becomes nanoseconds, and the halving of
	// the offset loses less than 1 ns.
	roundingNs = 3
	ppm        = 1_000_000
)

// precisionNs is 2^precision seconds in nanoseconds, rounded up (RFC 5905
// section 7.3: precision is a signed log2 of seconds). Capped at 2^7 s,
// which is far over MaxSampleBound anyway; 2^-64 s and below round up to 1
// ns. Every int8 value is taken: -128 gives 1 ns, not a shift by 128.
func precisionNs(precision int8) *big.Int {
	p := int(precision)
	if p >= 0 {
		return new(big.Int).Lsh(bigNanos, uint(min(p, 7)))
	}
	return ceilDivBig(bigNanos, new(big.Int).Lsh(big.NewInt(1), uint(min(-p, 64))))
}

// measure is the offset, delay and error bound of an authentic response.
//
// t1 is Monotonic just before the request left, t4 just after the
// response arrived. pivot is any Unix time within 68 years of now, in
// nanoseconds; it only picks the NTP era of T2 and T3 (RFC 5905 section 6).
//
// With T1 to T4 as in RFC 5905 section 8:
//
//   - delay = (T4 - T1) - (T3 - T2)
//   - offset = ((T2 - T1) + (T3 - T4)) / 2
//   - bound = delay/2 + rootdelay/2 + rootdisp + 2^precision + rho (T4 - T1) + roundingNs
//
// The bound is the root distance of RFC 5905 section 11.2 with our rho in
// place of PHI and the server's precision for epsilon. Refused: stratum
// outside 1 to 15, a zero reference, receive or transmit timestamp, a
// reference after T3, T4 before T1, T3 before T2, a negative delay, and a
// bound over MAXDIST.
func measure(s *timeResponse, t1, t4, pivot int64) (Sample, error) {
	if s.stratum < 1 || s.stratum > maxStratum {
		return Sample{}, fmt.Errorf("%w: stratum %d", errSampleStratum, s.stratum)
	}
	if s.reference == 0 {
		return Sample{}, errNeverSynchronized
	}
	// RFC 5905 section 8, the packet sanity tests: a zero transmit
	// timestamp is invalid, and a zero receive timestamp with it. Without
	// this a zero resolves to the start of an era near the pivot and
	// measures years off with a tight bound.
	if s.receive == 0 || s.transmit == 0 {
		return Sample{}, errZeroTimestamp
	}
	if s.transmit.sub(s.reference) < 0 {
		return Sample{}, errReferenceAfterTransmit
	}
	if t4 < t1 {
		return Sample{}, errLocalTimesReversed
	}
	// T3 - T2 from the NTP values, so an era boundary between them does
	// not matter (RFC 5905 section 6).
	serverNs := s.transmit.sub(s.receive).nanos()
	if serverNs < 0 {
		return Sample{}, errServerTimesReversed
	}
	t2, ok := s.receive.unixNanos(pivot)
	if !ok {
		return Sample{}, errTimestampOutOfRange
	}
	t3, ok := s.transmit.unixNanos(pivot)
	if !ok {
		return Sample{}, errTimestampOutOfRange
	}
	b := big.NewInt
	roundTrip := new(big.Int).Sub(b(t4), b(t1))
	delay := new(big.Int).Sub(roundTrip, b(serverNs))
	if delay.Sign() < 0 {
		return Sample{}, errNegativeDelay
	}
	// Div is Euclidean, so the halving rounds toward minus infinity.
	offset := new(big.Int).Add(new(big.Int).Sub(b(t2), b(t1)), new(big.Int).Sub(b(t3), b(t4)))
	offset.Div(offset, b(2))

	bound := ceilDivBig(delay, b(2))
	bound.Add(bound, ceilDivBig(b(s.rootDelay.nanos()), b(2)))
	bound.Add(bound, b(s.rootDispersion.nanos()))
	// nanos of ntpShort rounds down by less than 1 ns each.
	bound.Add(bound, b(2))
	bound.Add(bound, precisionNs(s.precision))
	bound.Add(bound, ceilDivBig(new(big.Int).Mul(roundTrip, b(RhoPPM)), b(ppm)))
	bound.Add(bound, b(roundingNs))
	if bound.Cmp(b(int64(MaxSampleBound))) > 0 {
		return Sample{}, errBoundTooLarge
	}
	for _, v := range []*big.Int{offset, delay, bound} {
		if !v.IsInt64() {
			return Sample{}, errTimestampOutOfRange
		}
	}
	return Sample{
		Offset:          offset.Int64(),
		Delay:           time.Duration(delay.Int64()),
		Bound:           time.Duration(bound.Int64()),
		T4:              t4,
		RootDelay:       time.Duration(s.rootDelay.nanos()),
		RootDispersion:  time.Duration(s.rootDispersion.nanos()),
		Stratum:         int(s.stratum),
		Precision:       int(s.precision),
		Leap:            int(s.leap),
		CookiesReceived: len(s.cookies),
	}, nil
}
