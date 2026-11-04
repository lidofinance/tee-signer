package main

import (
	"testing"
	"time"
)

// With a setup, the state copy is written again before its oldest object
// can leave the lock's retention, whatever -state-refresh says.
func TestStateRefreshFollowsLockDays(t *testing.T) {
	const day = 24 * time.Hour
	for _, c := range []struct {
		flag     time.Duration
		lockDays uint32
		want     time.Duration
	}{
		{24 * time.Hour, 1, 10 * time.Hour}, // the default flag with a 1-day lock
		{0, 1, 10 * time.Hour},
		{48 * time.Hour, 1, 10 * time.Hour},
		{6 * time.Hour, 1, 6 * time.Hour}, // the flag can only make it shorter
		{24 * time.Hour, 365, 24 * time.Hour},
		{24 * time.Hour, 0, 24 * time.Hour}, // no setup: the flag
		{0, 0, 0},
	} {
		got := refreshAge(c.flag, c.lockDays)
		if got != c.want {
			t.Errorf("refreshAge(%v, %d) = %v, want %v", c.flag, c.lockDays, got, c.want)
		}
		// The oldest object is at most age plus one tick old when refresh
		// replaces it, and a restart may come half the retention after the
		// stop; that must stay inside the retention.
		if ret := time.Duration(c.lockDays) * day; c.lockDays > 0 && got+refreshTick(got)+ret/2 >= ret {
			t.Errorf("lock %d days: refresh at %v plus tick %v plus half the retention reaches the retention", c.lockDays, got, refreshTick(got))
		}
	}
}
