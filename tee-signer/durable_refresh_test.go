package main

import (
	"context"
	"errors"
	"log/slog"
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

// Each refresh reports its result: a failure, then nil once one succeeds.
func TestRefreshLoopReports(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	results := []error{errors.New("store down"), nil}
	got := make(chan error, len(results))
	n := 0
	do := func(context.Context) error {
		if n == len(results) {
			cancel()
			return nil
		}
		n++
		return results[n-1]
	}
	go refreshLoop(ctx, 4*time.Millisecond, do, slog.New(slog.DiscardHandler), func(err error) {
		if ctx.Err() == nil {
			got <- err
		}
	})
	for i, want := range results {
		select {
		case err := <-got:
			if (err == nil) != (want == nil) {
				t.Fatalf("report %d: %v, want %v", i, err, want)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("report %d: none", i)
		}
	}
}
