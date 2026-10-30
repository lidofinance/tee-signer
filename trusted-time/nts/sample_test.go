//go:build nts

package nts

import (
	"errors"
	"math"
	"testing"
	"time"
)

// The sample tests of the Rust core's sample.rs, before the port.

const (
	sec = int64(time.Second)
	ms  = int64(time.Millisecond)
	// testNow is 2026-10-17 00:00:00 UTC.
	testNow = 1_792_195_200 * sec
)

func sampleAt(t2Unix, t3Unix int64) *timeResponse {
	return &timeResponse{
		stratum: 2, precision: -20,
		reference: ntpFromUnixNanos(t2Unix - 10*sec),
		origin:    1,
		receive:   ntpFromUnixNanos(t2Unix),
		transmit:  ntpFromUnixNanos(t3Unix),
	}
}

func TestSymmetricPath(t *testing.T) {
	// Local clock reads 1000 s at T1; real time is NOW + 1000 s + 5 ms.
	// 20 ms round trip, 1 ms in the server.
	t1 := 1000 * sec
	realT1 := testNow + t1 + 5*ms
	s := sampleAt(realT1+9_500_000, realT1+10_500_000)
	m, err := measure(s, t1, t1+20*ms, testNow)
	if err != nil {
		t.Fatal(err)
	}
	if m.Delay != 19*time.Millisecond {
		t.Fatalf("delay %v", m.Delay)
	}
	if d := m.Offset - (testNow + 5*ms); d < -1 || d > 1 {
		t.Fatalf("offset %d", m.Offset)
	}
	// 9.5 ms + 2^-20 s (ceil(1e9 / 2^20) = 953.67 -> 954 ns) + 500 ppm of
	// 20 ms (10 us) + slack.
	if m.Bound != time.Duration(9_500_000+2+954+10_000+3) {
		t.Fatalf("bound %d", m.Bound)
	}
	if m.T4 != t1+20*ms || m.Stratum != 2 || m.Precision != -20 || m.Leap != 0 {
		t.Fatalf("sample %+v", m)
	}
}

func TestRootValuesAddToTheBound(t *testing.T) {
	s := sampleAt(testNow+5*ms, testNow+5*ms)
	s.rootDelay = 0x0000_0100      // 1/256 s = 3,906,250 ns
	s.rootDispersion = 0x0000_0200 // 7,812,500 ns
	m, err := measure(s, 0, 10*ms, testNow)
	if err != nil {
		t.Fatal(err)
	}
	base, err := measure(sampleAt(testNow+5*ms, testNow+5*ms), 0, 10*ms, testNow)
	if err != nil {
		t.Fatal(err)
	}
	if m.Bound-base.Bound != time.Duration(1_953_125+7_812_500) {
		t.Fatalf("root values added %v", m.Bound-base.Bound)
	}
	if m.RootDelay != 3_906_250 || m.RootDispersion != 7_812_500 {
		t.Fatalf("root values %v %v", m.RootDelay, m.RootDispersion)
	}
}

func TestTheTrueTimeIsInsideTheBoundForAnyPathAsymmetry(t *testing.T) {
	// The request takes up ns, the server holds it 1 ms, the reply takes
	// down ns. Whatever the split, |offset - true| <= bound.
	realOffset := testNow + 123*ms
	for _, c := range [][2]int64{{0, 40 * ms}, {40 * ms, 0}, {20 * ms, 20 * ms}, {1, 1}, {0, 0}} {
		up, down := c[0], c[1]
		t1 := 77 * sec
		t2 := t1 + up + realOffset
		t3 := t2 + ms
		t4 := t1 + up + ms + down
		m, err := measure(sampleAt(t2, t3), t1, t4, testNow)
		if err != nil {
			t.Fatal(err)
		}
		if d := m.Offset - realOffset; d > int64(m.Bound) || -d > int64(m.Bound) {
			t.Fatalf("up %d down %d: offset off by %d, bound %v", up, down, d, m.Bound)
		}
	}
}

func TestSampleRefusals(t *testing.T) {
	ok := sampleAt(testNow, testNow+ms)
	if _, err := measure(ok, 0, 10*ms, testNow); err != nil {
		t.Fatal(err)
	}
	check := func(what string, s *timeResponse, t1, t4 int64, want error) {
		t.Helper()
		if _, err := measure(s, t1, t4, testNow); !errors.Is(err, want) {
			t.Fatalf("%s: got %v, want %v", what, err, want)
		}
	}
	check("local reversed", ok, 10, 9, errLocalTimesReversed)
	check("server reversed", sampleAt(testNow+ms, testNow), 0, 10*ms, errServerTimesReversed)
	// The server held the request 2 ms; our round trip was 1 ms.
	check("negative delay", sampleAt(testNow, testNow+2*ms), 0, ms, errNegativeDelay)
	for _, stratum := range []uint8{0, 16, 255} {
		s := *ok
		s.stratum = stratum
		check("stratum", &s, 0, ms, errSampleStratum)
	}
	s := *ok
	s.reference = 0
	check("zero reference", &s, 0, 10*ms, errNeverSynchronized)
	// Zero receive or transmit timestamps (RFC 5905 section 8) with a good
	// reference: refused, not read as the start of an era.
	for _, zero := range []func(*timeResponse){func(r *timeResponse) { r.receive = 0 }, func(r *timeResponse) { r.transmit = 0 }, func(r *timeResponse) { r.receive, r.transmit = 0, 0 }} {
		z := *ok
		zero(&z)
		check("zero timestamp", &z, 0, 10*ms, errZeroTimestamp)
	}
	s.reference = ntpFromUnixNanos(testNow + sec)
	check("reference after transmit", &s, 0, 10*ms, errReferenceAfterTransmit)
	s = *ok
	s.rootDispersion = 0x0001_0000 // 1 s
	check("dispersion", &s, 0, 10*ms, errBoundTooLarge)
	s = *ok
	s.precision = 1 // 2 s
	check("precision", &s, 0, 10*ms, errBoundTooLarge)
	// A 2.1 s round trip: delay/2 alone is over 1 s.
	check("round trip", ok, 0, 2_100*ms, errBoundTooLarge)
}

func TestExtremeInputsDoNotPanic(t *testing.T) {
	s := sampleAt(testNow, testNow)
	for _, c := range [][2]int64{{math.MinInt64, math.MaxInt64}, {math.MinInt64, math.MinInt64}, {math.MaxInt64, math.MaxInt64}, {0, math.MaxInt64}} {
		for _, pivot := range []int64{math.MinInt64, 0, math.MaxInt64} {
			_, _ = measure(s, c[0], c[1], pivot)
		}
	}
	for _, p := range []int8{math.MinInt8, -64, -1, 0, 7, 8, math.MaxInt8} {
		c := *s
		c.precision = p
		_, _ = measure(&c, 0, 1, testNow)
	}
	c := *s
	c.rootDelay, c.rootDispersion = math.MaxUint32, math.MaxUint32
	if _, err := measure(&c, 0, 1, testNow); !errors.Is(err, errBoundTooLarge) {
		t.Fatalf("largest root values: %v", err)
	}
}

// Every int8 precision gives a bound: -128 is 1 ns, not a crash, and the
// error bound never comes out too small (the Rust core's values).
func TestPrecisionAndDrift(t *testing.T) {
	for _, c := range []struct {
		p    int8
		want int64
	}{{0, 1_000_000_000}, {-1, 500_000_000}, {-20, 954}, {-29, 2}, {-30, 1}, {-31, 1}, {-64, 1}, {-128, 1}, {1, 2_000_000_000}, {7, 128_000_000_000}, {127, 128_000_000_000}} {
		if got := precisionNs(c.p); got.Int64() != c.want || !got.IsInt64() {
			t.Errorf("precisionNs(%d) = %v, want %d", c.p, got, c.want)
		}
	}
	// A sample from a server that states precision -128 measures with a 1
	// ns term, where a shift by 128 would have been undefined.
	s := sampleAt(testNow, testNow+ms)
	s.precision = -128
	m, err := measure(s, 0, 10*ms, testNow)
	if err != nil || m.Precision != -128 {
		t.Fatalf("precision -128: %+v %v", m, err)
	}
	base, _ := measure(sampleAt(testNow, testNow+ms), 0, 10*ms, testNow)
	if base.Bound-m.Bound != 954-1 {
		t.Fatalf("precision -128 bound %v, -20 bound %v", m.Bound, base.Bound)
	}
	for _, c := range []struct{ d, want time.Duration }{{32 * time.Second, 16 * time.Millisecond}, {1, 1}, {-5, 0}, {math.MaxInt64, 4_611_686_018_427_388}} {
		if got := Drift(c.d); got != c.want {
			t.Errorf("Drift(%d) = %d, want %d", c.d, got, c.want)
		}
	}
}
