//go:build nts

package clock

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/trusted-time/nts"
)

// joinAge with the defaults: MaxAge less a tick of Run and the longest
// Refresh (one NTS-KE and one query). The core applies it: ntscore's
// TestJoinAgeBoundary pins the boundary, TestLossyServerKeepsTimeServed
// runs a day of Run's schedule with a server that loses half its answers.
func TestNTSClockJoinAge(t *testing.T) {
	if got, want := (&NTS{}).joinAge(), 46*time.Second; got != want {
		t.Fatalf("join age %v, want %v (60 s - 4 s tick - 2 x 5 s exchange)", got, want)
	}
	// Under the shift schedule: no 4 x Interval cap, and the tick's deadline
	// in place of the longest Refresh. It is the join age the clock hands
	// the core (nts.Config.JoinAge), whose one age rule it is.
	shifts := &NTS{Shifts: true}
	if got, want := shifts.joinAge(), 76*time.Second; got != want || shifts.sampleMaxAge() != want {
		t.Fatalf("shift join age %v, sample max age %v, want %v (90 s - 4 s tick - 10 s tick deadline)",
			got, shifts.sampleMaxAge(), want)
	}
	// Without it the join age is also at most 4 x Interval.
	if got := (&NTS{Interval: 8 * time.Second}).sampleMaxAge(); got != 32*time.Second {
		t.Fatalf("sample max age %v with an 8 s interval, want 32 s", got)
	}
}

// The join age reaches the core: with the servers out of reach, a sample
// older than it enters no quorum, while the quorum in force, with the same
// sample, still serves (it is under MaxAge).
func TestNTSClockJoinAgeReachesTheCore(t *testing.T) {
	fs := newServers(t, nil, "a", "b", "c")
	n := newNTS(fs, &coarseClock{})
	// joinAge = MaxAge - Interval/4 - 10 s = 400 ms, under 4 x Interval.
	n.Interval, n.MaxAge = 400*time.Millisecond, 10*time.Second+500*time.Millisecond
	if got := n.joinAge(); got != 400*time.Millisecond {
		t.Fatalf("join age %v", got)
	}
	var ahead atomic.Int64
	var blocked atomic.Bool
	n.Local = func() int64 { return nts.Monotonic() + ahead.Load() }
	n.Dial = func(ctx context.Context, network, addr string) (net.Conn, error) {
		if blocked.Load() {
			return nil, errors.New("blocked")
		}
		var d net.Dialer
		return d.DialContext(ctx, network, addr)
	}
	if err := refresh(t, n); err != nil {
		t.Fatal(err)
	}
	blocked.Store(true)
	// Under the join age (and under the poll interval: nothing is asked):
	// the samples form a quorum again.
	ahead.Store(int64(300 * time.Millisecond))
	if err := refresh(t, n); err != nil {
		t.Fatalf("samples 300 ms old: %v", err)
	}
	// Over it: the polls fail and the samples enter no quorum; the quorum
	// in force serves on, its samples well under MaxAge.
	ahead.Store(int64(600 * time.Millisecond))
	if err := refresh(t, n); err == nil || !strings.Contains(err.Error(), "0 fresh samples") {
		t.Fatalf("samples 600 ms old: %v", err)
	}
	if _, err := n.Now(); err != nil {
		t.Fatalf("Now with the quorum 600 ms old: %v", err)
	}
}

// A MaxAge no longer than a tick and the longest Refresh would let no
// sample join: Refresh refuses it before it contacts any server, and a
// corrected MaxAge takes.
func TestNTSClockRefusesMaxAgeTooShort(t *testing.T) {
	fs := newServers(t, nil, "a", "b", "c")
	n := newNTS(fs, &coarseClock{})
	n.Interval, n.MaxAge = NTSInterval, 14*time.Second
	if err := refresh(t, n); err == nil || !strings.Contains(err.Error(), "MaxAge 14s is too short") ||
		!strings.Contains(err.Error(), "over 14s") {
		t.Fatalf("MaxAge 14 s: %v", err)
	}
	for _, f := range fs {
		if f.ke.Sessions.Load() != 0 {
			t.Fatal("contacted a server with a MaxAge it cannot serve")
		}
	}
	if _, err := n.Now(); err == nil || !strings.Contains(err.Error(), "too short") {
		t.Fatalf("Now: %v", err)
	}
	if sum := n.NTSSummary(); sum.Quorum || !strings.Contains(sum.Refused, "too short") {
		t.Fatalf("summary %+v", sum)
	}
	// 1 ns over the minimum is accepted.
	n.MaxAge = 14*time.Second + 1
	if err := refresh(t, n); err != nil && strings.Contains(err.Error(), "too short") {
		t.Fatalf("MaxAge just over the minimum: %v", err)
	}
}
