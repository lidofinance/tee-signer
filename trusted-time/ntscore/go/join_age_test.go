//go:build nts

package ntscore

import (
	"errors"
	"math/rand/v2"
	"slices"
	"testing"
	"time"
)

// A sample joins a quorum only while it is at most JoinAge old, though the
// quorum it joined serves until that sample is MaxAge old: the room between
// the two is the host's, for its next Combine, so the quorum stays under
// MaxAge until the next one can replace it.
func TestJoinAgeBoundary(t *testing.T) {
	// The join age is the one age rule: the core no longer caps it at 4
	// intervals (8 s here), so a join age of 9 s lets a sample of 8.9 s in
	// (the shift schedule's 76 s against 4 x 16 s), as one of 6 s keeps a
	// sample of 6.01 s out.
	for _, c := range []struct {
		maxAge, joinAge, age time.Duration
		join                 bool
	}{
		{10 * time.Second, 6 * time.Second, 6*time.Second - 10*time.Millisecond, true},
		{10 * time.Second, 6 * time.Second, 6*time.Second + 10*time.Millisecond, false},
		{10 * time.Second, 9 * time.Second, 9*time.Second - 100*time.Millisecond, true},
		{10 * time.Second, 9 * time.Second, 9*time.Second + 10*time.Millisecond, false},
		{40 * time.Second, 0, 39 * time.Second, true},
	} {
		maxAge := c.maxAge
		w, core := newHonestCore(t, 4, func(cfg *Config) { cfg.MaxAge, cfg.JoinAge = c.maxAge, c.joinAge })
		if err := w.round(core); err != nil {
			t.Fatal(err)
		}
		t0 := core.Peer(3).Sample.T4
		// Three servers answer again; the fourth's sample is `age` old.
		w.now = t0 + int64(c.age)
		for i := 0; i < 3; i++ {
			if _, err := w.poll(core, i); err != nil {
				t.Fatalf("sample %v old, peer %d: %v", c.age, i, err)
			}
		}
		if err := core.Combine(w.coarseNow(), w.now); err != nil {
			t.Fatalf("sample %v old: %v", c.age, err)
		}
		members := core.Status().Members
		if slices.Contains(members, 3) != c.join {
			t.Fatalf("sample %v old: members %v, want the fourth in: %v", c.age, members, c.join)
		}
		if !c.join {
			continue
		}
		// The quorum serves until its oldest sample, the fourth's, is
		// MaxAge old.
		w.now = t0 + int64(maxAge) - int64(10*time.Millisecond)
		if _, _, err := core.Bounded(); err != nil {
			t.Fatalf("just under MaxAge: %v", err)
		}
		w.now = t0 + int64(maxAge) + int64(10*time.Millisecond)
		if _, _, err := core.Bounded(); !errors.Is(err, ErrSamplesTooOld) {
			t.Fatalf("just over MaxAge: %v", err)
		}
	}
}

// A JoinAge over MaxAge is refused; 0 is MaxAge.
func TestJoinAgeConfig(t *testing.T) {
	cfg := Config{
		Servers:  []Server{{Operator: "a", Host: "a.test"}, {Operator: "b", Host: "b.test"}, {Operator: "c", Host: "c.test"}},
		Interval: time.Second, MinPoll: time.Second, MaxPoll: time.Minute, MaxBound: time.Second, MaxAge: time.Minute,
		MaxCoarseDiff: time.Second, CoarseResolution: time.Second, ExchangeTimeout: time.Second, DriftBaselinePolls: 1,
		FloorUnix: time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC),
	}
	cfg.JoinAge = time.Minute + 1
	if _, err := New(cfg, &hostileWorld{}); !errors.Is(err, ErrBadConfig) {
		t.Fatalf("JoinAge over MaxAge: %v", err)
	}
	for _, j := range []time.Duration{0, time.Minute} {
		cfg.JoinAge = j
		core, err := New(cfg, &hostileWorld{})
		if err != nil {
			t.Fatalf("JoinAge %v: %v", j, err)
		}
		core.Close()
	}
}

// One server loses half its answers, the others answer every time. The
// test runs the clock's schedule (clock.NTS.Run: a tick every Interval/4,
// each server asked when due, a tick that comes during a refresh starts
// the next one when it ends) on the virtual clock for a day, with the
// production limits and the join age clock.NTS derives from them: MaxAge
// minus a tick and the longest refresh (one NTS-KE and one query). The
// time must never be refused once the first quorum is in force. With the
// join age at MaxAge, a quorum whose oldest sample was nearly MaxAge old
// aged out while the next refresh waited for the lossy server's answer.
func TestLossyServerKeepsTimeServed(t *testing.T) {
	const interval, maxAge, timeout = 16 * time.Second, time.Minute, 5 * time.Second
	const joinAge = maxAge - interval/4 - 2*timeout
	w, core := newHonestCore(t, 4, func(c *Config) {
		c.Interval, c.MinPoll, c.MaxAge, c.JoinAge, c.ExchangeTimeout = interval, interval, maxAge, joinAge, timeout
	})
	const lossy = 3
	rng := rand.New(rand.NewPCG(1, 2))
	tick := int64(interval / 4)
	base := w.now
	nextTickAfter := func(x int64) int64 { return base + ((x-base)/tick+1)*tick }
	served := false
	var fails, quorums, withLossy int
	// advance moves the clock to `to` in 100 ms steps and reads the time
	// at each.
	advance := func(to int64) {
		for w.now < to {
			w.now = min(w.now+int64(100*time.Millisecond), to)
			if _, _, err := core.Bounded(); served && err != nil {
				if fails == 0 {
					t.Logf("first refusal at %v: %v", time.Duration(w.now-base), err)
				}
				fails++
			}
		}
	}
	day := 24 * time.Hour
	if testing.Short() {
		day = 2 * time.Hour
	}
	for start, end := w.now, w.now+int64(day); start < end; {
		// The polls of this refresh: a lost answer costs the query timeout
		// (the polls run one after the other here; in the clock they run
		// in parallel, so a refresh is shorter).
		for _, i := range core.Due(w.now) {
			if i == lossy && rng.IntN(2) == 0 {
				w.drop = 1
			}
			w.poll(core, i)
			w.drop = 0
		}
		if err := core.Combine(w.coarseNow(), w.now); err == nil {
			served = true
			quorums++
			if slices.Contains(core.Summary().Members, lossy) {
				withLossy++
			}
		}
		next := max(nextTickAfter(start), w.now)
		advance(next)
		start = next
	}
	t.Logf("%d quorums, %d with the lossy server; the time was refused %d times", quorums, withLossy, fails)
	if fails > 0 {
		t.Fatalf("the time was refused %d times with one server losing half its answers", fails)
	}
	if withLossy == 0 || withLossy == quorums {
		t.Fatalf("the lossy server was in %d of %d quorums: the test does not reach the age limit", withLossy, quorums)
	}
}
