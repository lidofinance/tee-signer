package markstore

import (
	"context"
	"errors"
	"testing"
	"time"
)

// hidingLog is memLog with an admin who hides a name (an S3 delete marker,
// a noncurrent GCS generation): a create under a hidden name lands next to
// what is there. dropNext loses the reply of the next create that lands.
type hidingLog struct {
	*memLog
	hidden   map[string]bool
	dropNext bool
}

func (l *hidingLog) Create(ctx context.Context, name string, data []byte) error {
	if l.hidden[name] {
		delete(l.hidden, name)
		l.objs[name] = append(l.objs[name], data)
	} else if err := l.memLog.Create(ctx, name, data); err != nil {
		return err
	}
	if l.dropNext {
		l.dropNext = false
		return context.DeadlineExceeded
	}
	return nil
}

// RBRLOG-01: runner A is at version v, a clone B claims the log at v+1, the
// admin hides B's record and the host drops the reply to A's create at
// v+1. A's next append gets ErrExists, lists v+1 and finds its own record
// next to B's. A must read B's record as another instance's write and latch
// ErrLost, not take its own record and sign on.
func TestRBRLOG01ForeignRecordNextToOwnLatchesLost(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_800_000_000, 0)
	l := &hidingLog{memLog: &memLog{objs: map[string][][]byte{}}, hidden: map[string]bool{}}
	opt := Options{Setup: testSetup("signer-1"), Clock: clockAt(&now), Log: quiet}
	a, err := New(l, "signer-1", testKey(1), opt)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := a.Claim(ctx, false); err != nil {
		t.Fatal(err)
	}
	if err := a.Append(ctx, mark(10)); err != nil {
		t.Fatal(err)
	}
	_, v := a.Mark()

	b, err := New(l, "signer-1", testKey(1), opt)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := b.Claim(ctx, true); err != nil {
		t.Fatal(err)
	}
	if _, vb := b.Mark(); vb != v+1 {
		t.Fatalf("clone at version %d, want %d", vb, v+1)
	}

	l.hidden[Name(opt.Setup.Hash, "signer-1", v+1)] = true
	l.dropNext = true
	if err := a.Append(ctx, mark(11)); err == nil {
		t.Fatal("the dropped reply did not reach Append")
	}
	now = now.Add(time.Second)
	err = a.Append(ctx, mark(11))
	if !errors.Is(err, ErrLost) || !errors.Is(a.Lost(), ErrLost) {
		t.Errorf("A appended next to the clone's record at version %d: err %v, Lost %v; two instances sign on", v+1, err, a.Lost())
	}
}

// SHH-02: the day of the exit ledger never goes back: a record that would
// carry an earlier day than the one in the log is refused.
func TestSHH02ExitDayNeverGoesBack(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_800_000_000, 0)
	m, err := New(&memLog{objs: map[string][][]byte{}}, "signer-1", testKey(1), Options{Setup: testSetup("signer-1"), Clock: clockAt(&now), Log: quiet})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := m.Claim(ctx, false); err != nil {
		t.Fatal(err)
	}
	day := func(d uint64) *ExitDay {
		return &ExitDay{Day: d, Stake: 1, Exits: []ExitEntry{{ValidatorIndex: 1, ExitEpoch: 1, Stake: 1, Nonce: [32]byte{byte(d)}}}}
	}
	if err := m.RecordExits(ctx, day(20)); err != nil {
		t.Fatal(err)
	}
	if err := m.RecordExits(ctx, day(19)); err == nil {
		t.Error("the exit ledger went from day 20 back to day 19")
	}
	if d := m.Exits(); d == nil || d.Day != 20 {
		t.Errorf("ledger after the refused write: %+v", d)
	}
}
