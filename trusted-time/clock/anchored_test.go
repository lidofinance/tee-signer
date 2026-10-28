package clock

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// localClock is a local monotonic clock a test moves by hand.
type localClock struct{ t time.Time }

func (c *localClock) now() time.Time { return c.t }
func (c *localClock) add(d time.Duration) {
	c.t = c.t.Add(d)
}

// newAnchored makes a clock with a 15 s interval and a hand-made local
// clock, and takes the first reading (base).
func newAnchored(t *testing.T, mod func(*Anchored)) (*Anchored, *fakeSource, *localClock) {
	t.Helper()
	src := &fakeSource{name: "f", t: base}
	lc := &localClock{t: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)} // unrelated to real time
	a := &Anchored{Src: src, Interval: DefaultInterval, Local: lc.now}
	if mod != nil {
		mod(a)
	}
	if err := a.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	return a, src, lc
}

func wantNow(t *testing.T, a *Anchored, want time.Time) {
	t.Helper()
	got, err := a.Now()
	if err != nil {
		t.Fatalf("Now: %v", err)
	}
	if !got.Equal(want) {
		t.Fatalf("Now is %v ahead of the reading, want %v", got.Sub(base), want.Sub(base))
	}
}

func TestAnchoredNoReadingYet(t *testing.T) {
	a := &Anchored{Src: &fakeSource{name: "f", t: base}, Interval: DefaultInterval}
	if _, err := a.Now(); err == nil {
		t.Fatal("Now before any reading must fail")
	}
}

// Between two readings the clock follows the local monotonic clock. It
// used to stand still, and the signer lagged real time by up to a whole
// interval.
func TestAnchoredAdvancesBetweenReadings(t *testing.T) {
	a, src, lc := newAnchored(t, nil)
	wantNow(t, a, base)
	lc.add(1 * time.Second)
	wantNow(t, a, base.Add(1*time.Second))
	lc.add(13 * time.Second)
	wantNow(t, a, base.Add(14*time.Second))
	// The next reading arrives 15 s after the first. It matches the advance.
	lc.add(1 * time.Second)
	src.t = base.Add(15 * time.Second)
	if err := a.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	wantNow(t, a, base.Add(15*time.Second))
	lc.add(7 * time.Second)
	wantNow(t, a, base.Add(22*time.Second))
}

// A host that runs the local timer fast gains MaxAdvance at most. The
// default is five intervals, 75 s.
func TestAnchoredAdvanceIsCapped(t *testing.T) {
	a, _, lc := newAnchored(t, func(a *Anchored) { a.MaxAge = time.Hour })
	if got := a.MaxAdvanceOrDefault(); got != 75*time.Second {
		t.Fatalf("default MaxAdvance %v, want 75s", got)
	}
	lc.add(74 * time.Second)
	wantNow(t, a, base.Add(74*time.Second))
	lc.add(2 * time.Second)
	wantNow(t, a, base.Add(75*time.Second))
	lc.add(10 * time.Minute)
	wantNow(t, a, base.Add(75*time.Second))
}

func TestAnchoredExplicitMaxAdvance(t *testing.T) {
	a, _, lc := newAnchored(t, func(a *Anchored) { a.MaxAge = time.Hour; a.MaxAdvance = 30 * time.Second })
	lc.add(time.Minute)
	wantNow(t, a, base.Add(30*time.Second))
}

// Now never goes back, not even when a reading is lower than a value Now
// already returned. It holds still until the readings catch up.
func TestAnchoredNeverGoesBack(t *testing.T) {
	a, src, lc := newAnchored(t, nil)
	lc.add(20 * time.Second)
	wantNow(t, a, base.Add(20*time.Second))

	src.t = base.Add(5 * time.Second) // a lower reading: skew or a lie
	if err := a.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	wantNow(t, a, base.Add(20*time.Second))
	lc.add(10 * time.Second) // the reading plus 10 s is 15 s: still below
	wantNow(t, a, base.Add(20*time.Second))
	lc.add(10 * time.Second) // 25 s: past the highest value
	wantNow(t, a, base.Add(25*time.Second))

	src.t = base.Add(-time.Hour)
	if err := a.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	prev, _ := a.Now()
	for i := 0; i < 20; i++ {
		lc.add(3 * time.Second)
		got, err := a.Now()
		if err != nil {
			t.Fatal(err)
		}
		if got.Before(prev) {
			t.Fatalf("Now went back from %v to %v", prev, got)
		}
		prev = got
	}
}

// With a 15 s interval four syncs in a row may fail and the signer keeps
// signing. The fifth missed sync stops it: a blocked network stops signing
// instead of freezing time.
func TestAnchoredFailsAfterFourMissedSyncs(t *testing.T) {
	a, src, lc := newAnchored(t, nil)
	if got := a.MaxAgeOrDefault(); got != 75*time.Second {
		t.Fatalf("default MaxAge %v, want 75s", got)
	}
	src.err = errors.New("host dropped the packets")
	for i := 1; i <= 4; i++ {
		lc.add(15 * time.Second)
		_ = a.Refresh(context.Background())
		if _, err := a.Now(); err != nil {
			t.Fatalf("sync %d (t0+%d s) failed and Now already fails: %v", i, 15*i, err)
		}
	}
	lc.add(14 * time.Second) // t0+74 s
	if _, err := a.Now(); err != nil {
		t.Fatalf("at t0+74 s: %v", err)
	}
	lc.add(1 * time.Second) // t0+75 s, and the fifth sync fails too
	_ = a.Refresh(context.Background())
	_, err := a.Now()
	if err == nil || !strings.Contains(err.Error(), "dropped") {
		t.Fatalf("after five missed syncs Now must fail with the last error, got %v", err)
	}
	// A reading brings it back.
	src.err = nil
	src.t = base.Add(75 * time.Second)
	if err := a.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	wantNow(t, a, base.Add(75*time.Second))
}

func TestAnchoredExplicitMaxAge(t *testing.T) {
	a, _, lc := newAnchored(t, func(a *Anchored) { a.MaxAge = 20 * time.Second })
	lc.add(19 * time.Second)
	wantNow(t, a, base.Add(19*time.Second))
	lc.add(1 * time.Second)
	if _, err := a.Now(); err == nil {
		t.Fatal("a reading MaxAge old was accepted")
	}
}

// The real monotonic clock, no fake: Now advances with it.
func TestAnchoredRealClock(t *testing.T) {
	src := &fakeSource{name: "f", t: base}
	a := &Anchored{Src: src, Interval: DefaultInterval}
	if err := a.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	time.Sleep(30 * time.Millisecond)
	got, err := a.Now()
	if err != nil || got.Sub(base) < 20*time.Millisecond || got.Sub(base) > time.Second {
		t.Fatalf("Now %v after the reading, %v", got.Sub(base), err)
	}
}

// The host runs the local timer ten times too fast while readings come
// every 15 s of real time. Now never leads real time by more than 75 s and
// never goes back.
func TestAnchoredFastLocalClockSimulation(t *testing.T) {
	const speed = 10
	real0 := base
	lc := &localClock{t: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)}
	src := &fakeSource{name: "f", t: real0}
	a := &Anchored{Src: src, Interval: DefaultInterval, MaxAge: time.Hour, Local: lc.now}
	if err := a.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	var prev time.Time
	maxLead := -time.Hour
	for sec := 1; sec <= 900; sec++ {
		real := real0.Add(time.Duration(sec) * time.Second)
		lc.add(speed * time.Second) // 10 s of local time per real second
		if sec%15 == 0 {
			src.t = real
			if err := a.Refresh(context.Background()); err != nil {
				t.Fatal(err)
			}
		}
		got, err := a.Now()
		if err != nil {
			t.Fatal(err)
		}
		lead := got.Sub(real)
		maxLead = max(maxLead, lead)
		if lead > 75*time.Second {
			t.Fatalf("at %d s the clock leads real time by %v", sec, lead)
		}
		if got.Before(prev) {
			t.Fatalf("at %d s the clock went back from %v to %v", sec, prev, got)
		}
		prev = got
	}
	if maxLead < 60*time.Second {
		t.Fatalf("the simulation never came near the cap (max lead %v): it tests nothing", maxLead)
	}
}
