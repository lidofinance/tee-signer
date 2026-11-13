//go:build nts

package ntscore

import (
	"math"
	"testing"
	"time"
)

// TIME-BOUND-01: Drift is the Rust core's drift_ns for every age, and
// never negative. d*RhoPPM in int64 overflowed past about 213.5 days.
func TestDriftLongOutage(t *testing.T) {
	const day = 24 * time.Hour
	for _, tc := range []struct {
		d, want time.Duration
	}{
		{32 * time.Second, 16 * time.Millisecond},
		{1, 1},
		{-5, 0},
		{213 * day, 9_201_600_000_000},
		{214 * day, 9_244_800_000_000},
		{10 * 365 * day, 157_680_000_000_000},
		{math.MaxInt64, 4_611_686_018_427_388}, // drift_ns(i64::MAX) in the Rust core's sample.rs, before the port
	} {
		if got := Drift(tc.d); got != tc.want {
			t.Errorf("Drift(%v) = %v (%d ns), want %d ns", tc.d, got, int64(got), int64(tc.want))
		}
	}
	for d := time.Duration(1); d > 0 && d <= math.MaxInt64/2; d *= 3 {
		if Drift(d) < 0 || Drift(d) < Drift(d/3) {
			t.Fatalf("Drift(%v) = %v: negative or smaller than at a third of the age", d, Drift(d))
		}
	}
}
