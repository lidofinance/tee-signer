//go:build nts

package nts

import (
	"errors"
	"fmt"
	"math"
	"math/big"
	"time"

	"github.com/beevik/ntp"
)

// Offset, delay and error bound of one server response (RFC 5905 section
// 8), and the checks of RFC 5905 that need no state from earlier
// responses. T1 and T4 are Monotonic readings, in nanoseconds from any
// fixed start; T2 and T3 are the server's wall-clock times. So the offset
// says how far real time is ahead of the local monotonic clock: real Unix
// time at the local instant x is x + offset, give or take the bound. The
// host clock is never read.

// ntpEra0 is the start of NTP era 0, what a zero reference timestamp reads as.
var ntpEra0 = time.Date(1900, 1, 1, 0, 0, 0, 0, time.UTC)

const (
	roundingNs = 3
	nanos      = 1_000_000_000
)

func ceilDiv(n, d *big.Int) *big.Int {
	q, m := new(big.Int).DivMod(n, d, new(big.Int))
	if m.Sign() > 0 {
		q.Add(q, big.NewInt(1))
	}
	return q
}

// precisionNs is 2^precision seconds in nanoseconds, rounded up, for the
// precision exponent the server states (-20 is about a microsecond).
func precisionNs(p int) *big.Int {
	if p >= 0 {
		return new(big.Int).Lsh(big.NewInt(nanos), uint(min(p, 7)))
	}
	return ceilDiv(big.NewInt(nanos), new(big.Int).Lsh(big.NewInt(1), uint(min(-p, 64))))
}

// precisionExponent recovers the server's precision field from the
// library's 2^p seconds.
func precisionExponent(d time.Duration) int {
	if d <= 0 {
		return -64
	}
	return int(math.Round(math.Log2(d.Seconds())))
}

// measure checks a response and measures it. The library already checked
// the authenticator, our Unique Identifier and the origin timestamp.
func measure(r *ntp.Response) (Sample, error) {
	t1, t2, t3, t4 := r.Timestamps.ClientXmit, r.Timestamps.ServerRecv, r.Timestamps.ServerXmit, r.Timestamps.ClientRecv
	if r.Stratum < 1 || r.Stratum > 15 {
		return Sample{}, fmt.Errorf("stratum %d outside 1 to 15", r.Stratum)
	}
	if r.Leap == ntp.LeapNotInSync {
		return Sample{}, errors.New("leap indicator 3: the server is not synchronized")
	}
	if !r.ReferenceTime.After(ntpEra0) {
		return Sample{}, errors.New("reference timestamp is zero")
	}
	if r.ReferenceTime.After(t3) {
		return Sample{}, errors.New("reference timestamp after transmit timestamp")
	}
	if t4.Before(t1) {
		return Sample{}, errors.New("local receive time before local send time")
	}
	if t3.Before(t2) {
		return Sample{}, errors.New("server transmit time before its receive time")
	}
	n := func(t time.Time) *big.Int { return big.NewInt(t.UnixNano()) }
	roundTrip := new(big.Int).Sub(n(t4), n(t1))
	server := new(big.Int).Sub(n(t3), n(t2))
	delay := new(big.Int).Sub(roundTrip, server)
	if delay.Sign() < 0 {
		return Sample{}, errors.New("negative round-trip delay")
	}
	// offset = ((T2 - T1) + (T3 - T4)) / 2, rounded down.
	offset := new(big.Int).Add(new(big.Int).Sub(n(t2), n(t1)), new(big.Int).Sub(n(t3), n(t4)))
	offset.Div(offset, big.NewInt(2))
	two, ppm := big.NewInt(2), big.NewInt(1_000_000)
	precision := precisionExponent(r.Precision)
	bound := ceilDiv(delay, two)
	bound.Add(bound, ceilDiv(big.NewInt(int64(r.RootDelay)), two))
	bound.Add(bound, big.NewInt(int64(r.RootDispersion)))
	bound.Add(bound, two)
	bound.Add(bound, precisionNs(precision))
	bound.Add(bound, ceilDiv(new(big.Int).Mul(roundTrip, big.NewInt(RhoPPM)), ppm))
	bound.Add(bound, big.NewInt(roundingNs))
	if bound.Cmp(big.NewInt(int64(MaxSampleBound))) > 0 {
		return Sample{}, fmt.Errorf("error bound over %d ns (MAXDIST)", int64(MaxSampleBound))
	}
	for _, v := range []*big.Int{offset, delay, bound} {
		if !v.IsInt64() {
			return Sample{}, errors.New("timestamp out of range")
		}
	}
	return Sample{
		Offset:         offset.Int64(),
		Delay:          time.Duration(delay.Int64()),
		Bound:          time.Duration(bound.Int64()),
		T4:             t4.UnixNano(),
		RootDelay:      r.RootDelay,
		RootDispersion: r.RootDispersion,
		Stratum:        int(r.Stratum),
		Precision:      precision,
		Leap:           int(r.Leap),
	}, nil
}
