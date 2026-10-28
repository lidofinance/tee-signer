//go:build nts

package ntscore

import (
	"math"
	"math/big"
	"testing"
)

// The time format tests of the Rust core's time.rs, before the port.

// unixEpochNTPSeconds is from the NTP prime epoch (1900-01-01 00:00 UTC,
// era 0) to the Unix epoch 1970-01-01 (RFC 5905 section 6, figure 4).
const unixEpochNTPSeconds = 2_208_988_800

// era1Unix is the first second of era 1: 2036-02-07 06:28:16 UTC.
const era1Unix = (1 << 32) - unixEpochNTPSeconds

func TestUnixEpochIs2208988800(t *testing.T) {
	ts := NTPFromUnixNanos(0)
	if uint64(ts) != unixEpochNTPSeconds<<32 {
		t.Fatalf("%#x", uint64(ts))
	}
	if n, ok := ts.UnixNanos(0); !ok || n != 0 {
		t.Fatalf("%d %v", n, ok)
	}
}

func TestHalfASecondIsHalfTheFraction(t *testing.T) {
	ts := NTPFromUnixNanos(sec / 2)
	if uint64(ts) != unixEpochNTPSeconds<<32|0x8000_0000 {
		t.Fatalf("%#x", uint64(ts))
	}
	b := make([]byte, 8)
	for i := range b {
		b[i] = byte(uint64(ts) >> (56 - 8*i))
	}
	if string(b) != "\x83\xaa\x7e\x80\x80\x00\x00\x00" {
		t.Fatalf("%x", b)
	}
}

func TestEraBoundary2036(t *testing.T) {
	// One second after the wrap the wire seconds are 1.
	ts := NTPFromUnixNanos((era1Unix + 1) * sec)
	if uint64(ts) != 1<<32 {
		t.Fatalf("%#x", uint64(ts))
	}
	// A pivot in 2026 or in 2100 puts it in era 1.
	for _, pivot := range []int64{1_790_000_000 * sec, 4_102_444_800 * sec} {
		if n, ok := ts.UnixNanos(pivot); !ok || n != (era1Unix+1)*sec {
			t.Fatalf("pivot %d: %d %v", pivot, n, ok)
		}
	}
	// The last second of era 0, read with a pivot in era 1.
	u := NTPFromUnixNanos((era1Unix - 1) * sec)
	if uint64(u) != 0xffff_ffff_0000_0000 {
		t.Fatalf("%#x", uint64(u))
	}
	if n, ok := u.UnixNanos((era1Unix + 100) * sec); !ok || n != (era1Unix-1)*sec {
		t.Fatalf("%d %v", n, ok)
	}
	// Two seconds apart across the wrap.
	if ts.Sub(u) != 2<<32 || u.Sub(ts).Nanos() != -2*sec {
		t.Fatalf("%d %d", ts.Sub(u), u.Sub(ts).Nanos())
	}
}

func TestRoundTripWithAPivotUpTo68YearsAway(t *testing.T) {
	// A fixed list plus a deterministic spread over 1900 to 2262.
	x := uint64(0x9e37_79b9_7f4a_7c15)
	values := []int64{-2_208_988_800 * sec, -1, 0, 1, 999_999_999, era1Unix * sec, math.MaxInt64 / 2}
	for i := 0; i < 10_000; i++ {
		x ^= x << 13
		x ^= x >> 7
		x ^= x << 17
		values = append(values, int64(x>>1)-math.MaxInt64/2)
	}
	maxOffset := int64(68 * 365 * 86_400 * sec)
	sat := func(a, b int64) int64 { // a + b, saturated
		s := a + b
		if (b > 0 && s < a) || (b < 0 && s > a) {
			if b > 0 {
				return math.MaxInt64
			}
			return math.MinInt64
		}
		return s
	}
	for i, n := range values {
		ts := NTPFromUnixNanos(n)
		offset := (int64(i) * 7_777_777_777_777) % maxOffset
		for _, pivot := range []int64{n, sat(n, -offset), sat(n, offset)} {
			d := new(big.Int).Sub(big.NewInt(pivot), big.NewInt(n))
			if d.Abs(d).Cmp(big.NewInt(maxOffset)) < 0 {
				if got, ok := ts.UnixNanos(pivot); !ok || got != n {
					t.Fatalf("n %d pivot %d: %d %v", n, pivot, got, ok)
				}
			}
		}
	}
}

func TestFarFromThePivotGivesAnotherEra(t *testing.T) {
	// 1970 read with a pivot in 2110 is 2106 (era 1), 136 years later.
	got, ok := NTPFromUnixNanos(0).UnixNanos(4_420_000_000 * sec)
	if !ok || got != (1<<32)*sec {
		t.Fatalf("%d %v", got, ok)
	}
}

func TestOverflowIsFalseNotAPanic(t *testing.T) {
	// About 50 years past 2262 and before 1677: outside int64 nanoseconds.
	if _, ok := NTPTimestamp(math.MaxUint64).UnixNanos(math.MaxInt64); ok {
		t.Fatal("past 2262 fit")
	}
	if _, ok := NTPTimestamp(0).UnixNanos(math.MinInt64); ok {
		t.Fatal("before 1677 fit")
	}
	for _, bits := range []uint64{0, 1, math.MaxUint64 / 2, math.MaxUint64} {
		for _, pivot := range []int64{math.MinInt64, -1, 0, math.MaxInt64} {
			_, _ = NTPTimestamp(bits).UnixNanos(pivot)
		}
	}
	_ = NTPFromUnixNanos(math.MinInt64)
	_ = NTPFromUnixNanos(math.MaxInt64)
}

func TestDurationsAndShortFormat(t *testing.T) {
	for _, c := range []struct {
		d    NTPDuration
		want int64
	}{{1 << 32, sec}, {-(1 << 31), -sec / 2}, {1, 0}, {-1, -1}} {
		if got := c.d.Nanos(); got != c.want {
			t.Errorf("%d units = %d ns, want %d", c.d, got, c.want)
		}
	}
	if NTPDuration(math.MaxInt64).Nanos() <= 0 || NTPDuration(math.MinInt64).Nanos() >= 0 {
		t.Fatal("the extreme durations lost their sign")
	}
	for _, c := range []struct {
		s    NTPShort
		want int64
	}{{0x0001_8000, 1_500_000_000}, {0x0000_0001, 15_258}, {math.MaxUint32, 65_535_999_984_741}} {
		if got := c.s.Nanos(); got != c.want {
			t.Errorf("short %#x = %d ns, want %d", c.s, got, c.want)
		}
	}
}
