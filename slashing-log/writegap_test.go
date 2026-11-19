package markstore

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// errDown is the store's answer while the host blocks the runner's route.
var errDown = errors.New("connection refused")

// cutLog is a memLog the host can cut off: while down every call fails.
// landed runs after each create that reached the store.
type cutLog struct {
	*memLog
	down     bool
	unlocked bool // the lock reads, but no longer locks (ErrNoLock)
	landed   func()
}

func (l *cutLog) Create(ctx context.Context, name string, data []byte) error {
	if l.down {
		return errDown
	}
	err := l.memLog.Create(ctx, name, data)
	if l.landed != nil {
		l.landed()
	}
	return err
}

func (l *cutLog) List(ctx context.Context, prefix string) ([]Entry, error) {
	if l.down {
		return nil, errDown
	}
	return l.memLog.List(ctx, prefix)
}

func (l *cutLog) Get(ctx context.Context, e Entry) ([]byte, error) {
	if l.down {
		return nil, errDown
	}
	return l.memLog.Get(ctx, e)
}

// Lock is a 30-day compliance lock; while down the read fails.
func (l *cutLog) Lock(context.Context) (Lock, error) {
	if l.down {
		return Lock{}, errDown
	}
	if l.unlocked {
		return Lock{Kind: "s3 object lock", Mode: "GOVERNANCE"}, nil
	}
	return Lock{Kind: "s3 object lock", Mode: "COMPLIANCE", Compliance: true, Retention: 30 * 24 * time.Hour}, nil
}

// cutRunner is a runner that claimed the log and wrote mark(10) at *now.
// Every setup checks the store's lock (Options.LockDays), so it does too:
// while cut off, that check cannot read the lock either.
func cutRunner(t *testing.T, now *time.Time) (*cutLog, *MarkLog, *Setup) {
	t.Helper()
	s := testSetup("s")
	l := &cutLog{memLog: &memLog{objs: map[string][][]byte{}}}
	m, err := New(l, "s", testKey(1), Options{Setup: s, Clock: clockAt(now), LockDays: s.RetentionDays, Log: quiet})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := m.Claim(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	if err := m.Raise(context.Background(), mark(10)); err != nil {
		t.Fatal(err)
	}
	return l, m, s
}

// rv-ic0.1: the host cuts a running runner off from its log while a clone
// claims the log and signs. Once the clone's records pass their retention
// they can be removed, and the cut-off runner's next create lands at the
// clone's version without a conflict. So a runner that has not written a
// record for half the retention writes none again: the write is refused
// and the log latches, as the claim's age check would refuse a restart.
func TestCutOffRunnerStopsAfterHalfTheRetention(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_800_000_000, 0)
	l, m, s := cutRunner(t, &now)
	_, v := m.Mark()

	// Cut off: every write and refresh fails while the clock runs on.
	l.down = true
	for end := now.Add(s.Retention()/2 + time.Hour); now.Before(end); now = now.Add(time.Hour) {
		if err := m.Raise(ctx, mark(11)); err == nil {
			t.Fatal("a write went through while the store was cut off")
		}
		_ = m.Refresh(ctx)
	}
	// The clone's records are gone and the route is open again.
	l.down = false
	if err := m.Raise(ctx, mark(11)); !errors.Is(err, ErrStale) {
		t.Fatalf("first write after half the retention without a record: %v, want ErrStale", err)
	}
	if _, ok := l.objs[Name(s.Hash, "s", v+1)]; ok {
		t.Fatalf("the runner wrote version %d after half the retention without a record", v+1)
	}
	if got, gv := m.Mark(); got != mark(10) || gv != v {
		t.Fatalf("mark %+v at %d, want the one committed before the cut", got, gv)
	}
	if !errors.Is(m.Lost(), ErrStale) || !strings.Contains(m.Status(), " STALE") {
		t.Fatalf("lost %v, status %s", m.Lost(), m.Status())
	}
	// The latch holds: refresh and every later write refuse.
	if err := m.Refresh(ctx); !errors.Is(err, ErrStale) {
		t.Fatalf("refresh after the latch: %v", err)
	}
	if err := m.Append(ctx, mark(12)); !errors.Is(err, ErrStale) {
		t.Fatalf("append after the latch: %v", err)
	}
	if _, ok := l.objs[Name(s.Hash, "s", v+1)]; ok {
		t.Fatal("a write after the latch reached the store")
	}
}

// Refresh and writes notice the gap on their own while the store, and its
// lock read, are still cut off (rv-ic0.4: the lock check used to answer
// first, ErrLockUnchecked, for the whole cut), so HEALTH shows the latch
// before the route opens again.
func TestRefreshLatchesAGapWhileCutOff(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_800_000_000, 0)
	l, m, s := cutRunner(t, &now)
	l.down = true
	if err := m.Refresh(ctx); !errors.Is(err, ErrLockUnchecked) {
		t.Fatalf("refresh cut off, within the bound: %v, want ErrLockUnchecked", err)
	}
	now = now.Add(s.Retention()/2 + time.Minute)
	if err := m.Raise(ctx, mark(11)); !errors.Is(err, ErrStale) {
		t.Fatalf("write cut off past half the retention: %v, want ErrStale", err)
	}
	if err := m.Refresh(ctx); !errors.Is(err, ErrStale) {
		t.Fatalf("refresh cut off past half the retention: %v, want ErrStale", err)
	}
	if !errors.Is(m.Lost(), ErrStale) || !strings.Contains(m.Status(), " STALE") {
		t.Fatalf("lost %v, status %s", m.Lost(), m.Status())
	}
}

// A create the host holds back until after the bound is not taken as a
// write: the record lands, but the runner does not sign on it and latches.
// The clone's records may have expired before it landed.
func TestCreateThatLandsLateLatches(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_800_000_000, 0)
	l, m, s := cutRunner(t, &now)
	l.landed = func() { now = now.Add(s.Retention()/2 + time.Minute) }
	if err := m.Raise(ctx, mark(11)); !errors.Is(err, ErrStale) {
		t.Fatalf("a create that landed past half the retention: %v, want ErrStale", err)
	}
	if !errors.Is(m.Lost(), ErrStale) {
		t.Fatalf("lost %v", m.Lost())
	}
}

// Normal gaps never latch: an outage of a day, a trusted clock that
// refuses for a while, and an outage that ends just short of half the
// retention after the last record.
func TestShortOutageDoesNotLatch(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_800_000_000, 0)
	l, m, s := cutRunner(t, &now)

	l.down = true
	for end := now.Add(24 * time.Hour); now.Before(end); now = now.Add(time.Hour) {
		_ = m.Refresh(ctx)
		_ = m.Raise(ctx, mark(11))
	}
	// The route opens; the next hourly refresh reads the lock again.
	l.down = false
	if err := m.Refresh(ctx); err != nil {
		t.Fatalf("refresh after a day's outage: %v", err)
	}
	if err := m.Raise(ctx, mark(11)); err != nil {
		t.Fatalf("write after a day's outage: %v", err)
	}

	// The trusted clock refuses (no NTS bound yet): the write fails, no latch.
	clockErr := errors.New("no trusted time")
	m.opt.Clock = func() (time.Time, error) { return time.Time{}, clockErr }
	if err := m.Raise(ctx, mark(12)); !errors.Is(err, clockErr) {
		t.Fatalf("write without trusted time: %v", err)
	}
	m.opt.Clock = clockAt(&now)
	if err := m.Raise(ctx, mark(12)); err != nil {
		t.Fatalf("write once the clock answers: %v", err)
	}

	l.down = true
	now = now.Add(s.Retention()/2 - time.Minute)
	if err := m.Refresh(ctx); errors.Is(err, ErrStale) {
		t.Fatalf("refresh just short of the bound: %v", err)
	}
	l.down = false
	if err := m.Refresh(ctx); err != nil {
		t.Fatalf("refresh just short of the bound: %v", err)
	}
	if err := m.Raise(ctx, mark(13)); err != nil {
		t.Fatalf("write just short of half the retention: %v", err)
	}
	if m.Lost() != nil {
		t.Fatalf("lost %v", m.Lost())
	}
	if got, _ := m.Mark(); got != mark(13) {
		t.Fatalf("mark %+v", got)
	}
}

// A restart after the latch runs the claim's full age check, which refuses
// a log whose newest record is older than half the retention.
func TestRestartAfterTheLatchRunsTheAgeCheck(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_800_000_000, 0)
	l, m, s := cutRunner(t, &now)
	l.down = true
	now = now.Add(s.Retention()/2 + time.Hour)
	_ = m.Refresh(ctx)
	l.down = false
	if err := m.Raise(ctx, mark(11)); err == nil {
		t.Fatal("write after half the retention without a record")
	}
	m2, err := New(l, "s", testKey(1), Options{Setup: s, Clock: clockAt(&now), Log: quiet})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := m2.Claim(ctx, true); !errors.Is(err, ErrTooOld) {
		t.Fatalf("claim after the latch: %v, want ErrTooOld", err)
	}
}

// A record that lands while the trusted clock cannot date it is not taken
// as written: the write fails, the age check still measures from the record
// before it, and a Raise to the same mark writes again.
func TestUndatedRecordKeepsTheOldBase(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_800_000_000, 0)
	l, m, _ := cutRunner(t, &now)
	base := m.Written()
	clockErr := errors.New("no trusted time")
	l.landed = func() {
		m.opt.Clock = func() (time.Time, error) { return time.Time{}, clockErr }
	}
	now = now.Add(time.Hour)
	if err := m.Raise(ctx, mark(11)); !errors.Is(err, clockErr) {
		t.Fatalf("write the clock could not date: %v", err)
	}
	if !m.Written().Equal(base) {
		t.Fatalf("written %v, want the base %v", m.Written(), base)
	}
	l.landed = nil
	m.opt.Clock = clockAt(&now)
	_, v := m.Mark()
	if err := m.Raise(ctx, mark(11)); err != nil {
		t.Fatal(err)
	}
	if _, v2 := m.Mark(); v2 != v+1 {
		t.Fatalf("Raise to the undated mark wrote nothing (version %d, was %d)", v2, v)
	}
	if !m.Written().Equal(now) {
		t.Fatalf("written %v, want %v", m.Written(), now)
	}
}

// rv-bfx.3: Refresh reads the lock even while the trusted clock fails, and
// then returns the clock error. A lock that reads again clears the pause,
// and a lock that is gone latches ErrNoLock, without waiting for the clock.
func TestRefreshChecksTheLockWhileTheClockFails(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_800_000_000, 0)
	l, m, _ := cutRunner(t, &now)
	l.down = true
	if err := m.Refresh(ctx); !errors.Is(err, ErrLockUnchecked) {
		t.Fatalf("refresh with the lock unreadable: %v, want ErrLockUnchecked", err)
	}
	clockErr := errors.New("no trusted time")
	m.opt.Clock = func() (time.Time, error) { return time.Time{}, clockErr }

	// The store and its lock read are back, the clock is not.
	l.down = false
	if err := m.Refresh(ctx); !errors.Is(err, clockErr) {
		t.Fatalf("refresh without a clock: %v, want the clock error", err)
	}
	if err := m.LockUnchecked(); err != nil {
		t.Fatalf("lock unchecked after a lock read that passed: %v", err)
	}

	// The store loses its lock while the clock still fails.
	l.unlocked = true
	if err := m.Refresh(ctx); !errors.Is(err, clockErr) {
		t.Fatalf("refresh without a clock on an unlocked store: %v, want the clock error", err)
	}
	if !errors.Is(m.Lost(), ErrNoLock) {
		t.Fatalf("lost %v, want ErrNoLock", m.Lost())
	}
}
