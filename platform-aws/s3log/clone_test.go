//go:build platform_aws

package s3log

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/platform/dev"
	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/slashing-log"
	"github.com/lidofinance/tee-signer/slashing-log/logtest"
	"github.com/lidofinance/tee-signer/slashing-log/wormfake"
)

// cloneBed is a first instance A on the S3 fake with records up to mark
// 14, and a way to open more instances of the same image and setup.
type cloneBed struct {
	srv   *wormfake.Server
	setup *markstore.Setup
	a     *markstore.MarkLog
	v     uint64 // the version of the newest record of A
}

func cloneWM(e uint64) backend.Watermark {
	return backend.Watermark{HasAttestation: true, SourceEpoch: e - 1, TargetEpoch: e, HasBlock: true, BlockSlot: e * 32}
}

func newCloneBed(t *testing.T) *cloneBed {
	t.Helper()
	srv := wormfake.New(wormfake.S3, "signer-marks")
	t.Cleanup(srv.Close)
	b := &cloneBed{srv: srv, setup: logtest.Setup(1, 30)}
	b.a = b.open(t)
	if _, _, err := b.a.Claim(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	for e := uint64(11); e <= 14; e++ {
		if err := b.a.Append(context.Background(), cloneWM(e)); err != nil {
			t.Fatal(err)
		}
	}
	_, b.v = b.a.Mark()
	return b
}

func (b *cloneBed) name(v uint64) string { return markstore.Name(b.setup.Hash, b.setup.Signer, v) }

func (b *cloneBed) open(t *testing.T) *markstore.MarkLog {
	t.Helper()
	m, err := markstore.New(openRetained(t, b.srv, 30), b.setup.Signer, dev.NewDevKeys("image-1"), markstore.Options{
		Setup: b.setup, LockDays: 30, Clock: func() (time.Time, error) { return b.srv.Now(), nil },
		Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// plantDeletable puts objects without retention under the 16 names above
// A: the bucket default is off for these puts, and back on before any
// lock check of the runners.
func (b *cloneBed) plantDeletable(t *testing.T) {
	t.Helper()
	b.srv.SetLock(wormfake.Lock{Compliance: true, NoDefault: true})
	for i := uint64(1); i <= 16; i++ {
		if !b.srv.AdminCreate(b.name(b.v+i), []byte("not a record")) {
			t.Fatal("the fake refused the admin object")
		}
	}
	b.srv.SetLock(wormfake.DefaultLock)
}

// The admin puts objects without retention under the next 16 record
// names, a clone starts, the admin deletes the objects by version, and A
// writes on. Whatever the order, the run must not end with two writers
// that both wrote past each other: a write past a deletable object is one
// that the other instance never meets.
func TestCloneDoesNotPassDeletableObjects(t *testing.T) {
	ctx := context.Background()
	b := newCloneBed(t)
	b.plantDeletable(t)

	clone := b.open(t)
	_, _, cerr := clone.Claim(ctx, true)
	for i := uint64(1); i <= 16; i++ {
		if n := b.srv.AdminDeleteVersions(b.name(b.v + i)); n != 1 {
			t.Fatalf("the admin deleted %d versions of name %d, want 1", n, b.v+i)
		}
	}
	aerr := b.a.Append(ctx, cloneWM(15))
	cloneWrites := cerr == nil
	if cloneWrites {
		cloneWrites = clone.Append(ctx, cloneWM(30)) == nil
	}
	if aerr == nil && cloneWrites {
		_, va := b.a.Mark()
		_, vc := clone.Mark()
		t.Fatalf("two live writers: A at version %d, the clone at version %d, neither met the other", va, vc)
	}
	// The rule: the clone stopped at the first deletable object and wrote
	// nothing; A, which never passed them either, writes the freed name.
	if !errors.Is(cerr, markstore.ErrNameTaken) {
		t.Fatalf("clone claim over deletable objects: %v, want ErrNameTaken", cerr)
	}
	if _, ok := b.srv.Current(b.name(b.v + 17)); ok {
		t.Fatal("the clone wrote past the deletable objects")
	}
	if aerr != nil {
		t.Fatalf("A once the names are free: %v", aerr)
	}
	// Now the clone claims on top of A, and A meets the claim.
	if _, _, err := b.open(t).Claim(ctx, true); err != nil {
		t.Fatalf("a clone claim once the names are free: %v", err)
	}
	if err := b.a.Append(ctx, cloneWM(16)); !errors.Is(err, markstore.ErrLost) {
		t.Fatalf("A after the claim: %v, want ErrLost", err)
	}
}

// Objects that nobody can delete before a record there could be (S3
// compliance retention at least as long as a record gets) still cost a
// skip each, not a stop: the clone claims past them, A meets the same
// objects, skips the same names and finds the claim.
func TestCloneSkipsLockedObjects(t *testing.T) {
	ctx := context.Background()
	b := newCloneBed(t)
	until := b.srv.Now().Add(30*day + 26*time.Hour)
	for i := uint64(1); i <= 16; i++ {
		if !b.srv.AdminCreateRetained(b.name(b.v+i), []byte("not a record"), "COMPLIANCE", until) {
			t.Fatal("the fake refused the admin object")
		}
	}
	clone := b.open(t)
	if _, _, err := clone.Claim(ctx, true); err != nil {
		t.Fatalf("clone claim past locked objects: %v", err)
	}
	if _, v := clone.Mark(); v != b.v+17 {
		t.Fatalf("clone claimed version %d, want %d", v, b.v+17)
	}
	for i := uint64(1); i <= 16; i++ {
		if n := b.srv.AdminDeleteVersions(b.name(b.v + i)); n != 0 {
			t.Fatalf("the admin deleted %d locked versions", n)
		}
	}
	if err := b.a.Append(ctx, cloneWM(15)); !errors.Is(err, markstore.ErrLost) {
		t.Fatalf("A past the same locked objects: %v, want ErrLost", err)
	}
}

// Objects that the admin can delete sooner than a record (governance mode,
// or compliance shorter than a record gets) stop the writes of every
// instance that comes to them, without a latch: once the objects are
// gone, the instance writes the freed name.
func TestShortOrGovernanceRetentionStopsWrites(t *testing.T) {
	ctx := context.Background()
	for _, c := range []struct {
		name  string
		mode  string
		until time.Duration
		wait  time.Duration // how long until the admin can delete them
	}{
		{"governance", "GOVERNANCE", 60 * day, 0},
		{"compliance for a day", "COMPLIANCE", day, day + time.Minute},
	} {
		t.Run(c.name, func(t *testing.T) {
			b := newCloneBed(t)
			until := b.srv.Now().Add(c.until)
			for i := uint64(1); i <= 16; i++ {
				if !b.srv.AdminCreateRetained(b.name(b.v+i), []byte("not a record"), c.mode, until) {
					t.Fatal("the fake refused the admin object")
				}
			}
			if _, _, err := b.open(t).Claim(ctx, true); !errors.Is(err, markstore.ErrNameTaken) {
				t.Fatalf("clone claim: %v, want ErrNameTaken", err)
			}
			if err := b.a.Append(ctx, cloneWM(15)); !errors.Is(err, markstore.ErrNameTaken) {
				t.Fatalf("A: %v, want ErrNameTaken", err)
			}
			if _, ok := b.srv.Current(b.name(b.v + 17)); ok {
				t.Fatalf("a record past the objects at version %d", b.v+17)
			}
			if b.a.Lost() != nil {
				t.Fatalf("the stop latched: %v", b.a.Lost())
			}
			b.srv.Advance(c.wait)
			for i := uint64(1); i <= 16; i++ {
				if n := b.srv.AdminDeleteVersions(b.name(b.v + i)); n != 1 {
					t.Fatalf("the admin deleted %d versions of name %d", n, b.v+i)
				}
			}
			if err := b.a.Append(ctx, cloneWM(15)); err != nil {
				t.Fatalf("A once the objects are gone: %v", err)
			}
			if _, v := b.a.Mark(); v != b.v+1 {
				t.Fatalf("A at version %d, want %d", v, b.v+1)
			}
		})
	}
}

// ObjectLock reads what the fake keeps for a version: its mode and date,
// or none.
func TestObjectLockReadsTheRetention(t *testing.T) {
	ctx := context.Background()
	srv := wormfake.New(wormfake.S3, "signer-marks")
	defer srv.Close()
	l := openRetained(t, srv, 30)
	if err := l.Create(ctx, "marks/x", []byte("r")); err != nil {
		t.Fatal(err)
	}
	until := srv.Now().Add(40 * day).Truncate(time.Second)
	srv.AdminCreateRetained("marks/g", []byte("g"), "GOVERNANCE", until)
	srv.SetLock(wormfake.Lock{Compliance: true, NoDefault: true})
	srv.AdminCreate("marks/n", []byte("n"))
	es, err := l.List(ctx, "marks/")
	if err != nil || len(es) != 3 {
		t.Fatalf("list: %v %v", es, err)
	}
	got := map[string]markstore.ObjectLock{}
	for _, e := range es {
		lk, err := l.ObjectLock(ctx, e)
		if err != nil {
			t.Fatalf("%s: %v", e.Name, err)
		}
		got[e.Name] = lk
	}
	if lk := got["marks/x"]; !lk.Compliance || lk.RetainUntil.Before(srv.Now().Add(31*day)) {
		t.Fatalf("own record: %+v", lk)
	}
	if lk := got["marks/g"]; lk.Compliance || lk.Mode != "GOVERNANCE" || !lk.RetainUntil.Equal(until) {
		t.Fatalf("governance object: %+v", lk)
	}
	if lk := got["marks/n"]; lk.Compliance || lk.Mode != "none" {
		t.Fatalf("object without retention: %+v", lk)
	}
	if _, err := l.ObjectLock(ctx, markstore.Entry{Name: "marks/x", Ref: "nope"}); err == nil {
		t.Fatal("a missing version reads as a lock")
	}
}

// The skip is safe only with the write age latch. A clone skips a locked
// object; A, cut off, comes back after the object's retention has ended
// and the admin has deleted it. A must not write the freed name beside
// the clone: half the retention after its last record it latches ErrStale
// (staleLocked), long before the object can go.
func TestSkippedObjectExpiresWhileACutOff(t *testing.T) {
	ctx := context.Background()
	b := newCloneBed(t)
	until := b.srv.Now().Add(30*day + 26*time.Hour)
	if !b.srv.AdminCreateRetained(b.name(b.v+1), []byte("not a record"), "COMPLIANCE", until) {
		t.Fatal("the fake refused the admin object")
	}
	if _, _, err := b.open(t).Claim(ctx, true); err != nil {
		t.Fatalf("clone claim past a locked object: %v", err)
	}
	b.srv.Advance(until.Sub(b.srv.Now()) + time.Minute)
	if n := b.srv.AdminDeleteVersions(b.name(b.v + 1)); n != 1 {
		t.Fatalf("the admin deleted %d versions after the retention", n)
	}
	if err := b.a.Append(ctx, cloneWM(15)); !errors.Is(err, markstore.ErrStale) {
		t.Fatalf("A after the skipped object went: %v, want ErrStale", err)
	}
	if _, ok := b.srv.Current(b.name(b.v + 1)); ok {
		t.Fatal("A wrote the freed name beside the clone")
	}
}
