package markstore

import (
	"context"
	"errors"
	"testing"
	"time"
)

// misread is how misreadLog answers reads of the names it lies about.
type misread int

const (
	readHonest    misread = iota
	listOmits             // every listing leaves the names out
	fullListOmits         // the listing of the log leaves them out; a listing by name shows them
	getNotFound           // listed, but GET answers ErrNotFound
	getFails              // listed, but GET fails with another error (a timeout)
)

var errReadTimeout = errors.New("injected: i/o timeout")

// misreadLog is memLog whose read answers lie about the names in lie while
// its conditional create stays truthful: a stale or lying listing, or a
// 404 for an object that exists.
type misreadLog struct {
	*memLog
	how misread
	lie map[string]bool
}

func (l *misreadLog) List(ctx context.Context, prefix string) ([]Entry, error) {
	es, err := l.memLog.List(ctx, prefix)
	if err != nil {
		return nil, err
	}
	var out []Entry
	for _, e := range es {
		if l.lie[e.Name] && (l.how == listOmits || l.how == fullListOmits && prefix != e.Name) {
			continue
		}
		out = append(out, e)
	}
	return out, nil
}

func (l *misreadLog) Get(ctx context.Context, e Entry) ([]byte, error) {
	if l.lie[e.Name] {
		switch l.how {
		case getNotFound:
			return nil, ErrNotFound
		case getFails:
			return nil, errReadTimeout
		}
	}
	return l.memLog.Get(ctx, e)
}

// A name the writer wants that is
// taken, and whose read back shows no valid record, must not be skipped.
// The object may be a clone's record that the read back missed, or an
// object an S3 admin deletes once a clone has claimed over it; either way
// a skip lets two instances write side by side. A read back that fails
// outright already stops the write without a skip.
func TestAppendNeverSkipsTakenName(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_800_000_000, 0)
	opt := Options{Setup: testSetup("signer-1"), Clock: clockAt(&now), Log: quiet}
	name := func(v uint64) string { return Name(opt.Setup.Hash, "signer-1", v) }

	for _, c := range []struct {
		name  string
		junk  bool    // version 5 holds an object that is not a record; else a clone's claim record
		how   misread // how A's read back of version 5 answers
		fails bool    // the read back fails: no skip, no latch, ErrLost once it answers
	}{
		{name: "an object that is not a record", junk: true},
		{name: "a clone's record the listing omits", how: listOmits},
		{name: "a clone's record whose GET says not found", how: getNotFound},
		{name: "a clone's record whose GET fails", how: getFails, fails: true},
	} {
		t.Run(c.name, func(t *testing.T) {
			mem := &memLog{objs: map[string][][]byte{}}
			l := &misreadLog{memLog: mem, lie: map[string]bool{}}
			a, _ := New(l, "signer-1", testKey(1), opt)
			if _, _, err := a.Claim(ctx, false); err != nil {
				t.Fatal(err)
			}
			for e := uint64(5); e < 8; e++ {
				if err := a.Append(ctx, mark(e)); err != nil {
					t.Fatal(err)
				}
			}
			if _, v := a.Mark(); v != 4 {
				t.Fatalf("A at version %d, want 4", v)
			}
			if c.junk {
				mem.objs[name(5)] = [][]byte{[]byte("not a record")}
			} else {
				b, _ := New(mem, "signer-1", testKey(1), opt)
				if _, _, err := b.Claim(ctx, true); err != nil {
					t.Fatal(err)
				}
				if _, v := b.Mark(); v != 5 {
					t.Fatalf("clone claimed version %d, want 5", v)
				}
			}
			l.how, l.lie[name(5)] = c.how, true

			err := a.Append(ctx, mark(20))
			if _, v := a.Mark(); err == nil || v != 4 || len(mem.objs[name(6)]) != 0 {
				t.Fatalf("append over the taken version 5: err %v, now at version %d; it must fail and write nothing past the taken name, "+
					"or a clone and this instance write side by side", err, v)
			}
			if !c.fails {
				return
			}
			if a.Lost() != nil {
				t.Fatalf("a read back that failed latched: %v", a.Lost())
			}
			l.how = readHonest
			if err := a.Append(ctx, mark(20)); !errors.Is(err, ErrLost) {
				t.Fatalf("once the read back answers: %v, want ErrLost", err)
			}
		})
	}
}

// A clone whose reads miss the newest
// records (a stale listing, a 404 for a listed object) must not claim
// from an older record and write on top: that rolls the mark, the config
// state and the share set back. A stale listing of the log alone is
// already caught, because the claim's create meets the newest record.
func TestClaimRefusesListedRecordsItCannotRead(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_800_000_000, 0)
	opt := Options{Setup: testSetup("signer-1"), Clock: clockAt(&now), Log: quiet}
	name := func(v uint64) string { return Name(opt.Setup.Hash, "signer-1", v) }

	for _, c := range []struct {
		name string
		how  misread
	}{
		{"the listing omits them", listOmits},
		{"GET says not found", getNotFound},
		{"only the listing of the log omits them", fullListOmits},
	} {
		t.Run(c.name, func(t *testing.T) {
			mem := &memLog{objs: map[string][][]byte{}}
			a, _ := New(mem, "signer-1", testKey(1), opt)
			if _, _, err := a.Claim(ctx, false); err != nil {
				t.Fatal(err)
			}
			for e := uint64(5); e < 8; e++ {
				if err := a.Append(ctx, mark(e)); err != nil {
					t.Fatal(err)
				}
			}
			// The clone's reads miss versions 3 and 4 (mark 6 and 7).
			l := &misreadLog{memLog: mem, how: c.how, lie: map[string]bool{name(3): true, name(4): true}}
			b, _ := New(l, "signer-1", testKey(1), opt)
			got, _, err := b.Claim(ctx, true)
			if err == nil || len(mem.objs[name(5)]) != 0 {
				t.Fatalf("clone claimed mark target %d over records it could not read (err %v): the log holds target 7; "+
					"the claim must fail and write nothing", got.TargetEpoch, err)
			}
		})
	}
}
