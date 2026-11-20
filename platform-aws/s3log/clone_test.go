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

// On S3 the lock is per object version.
// An account admin who lifts the bucket policy's denies can put objects
// without retention under the next record names, let a clone claim over
// them and then delete them by version, so the first instance writes the
// freed names below the clone's claim and neither meets the other for up
// to maxSkips records. A clone must not claim past a taken name; once the
// names are free again, the two instances meet on one name.
func TestCloneCannotClaimPastDeletableObjects(t *testing.T) {
	ctx := context.Background()
	srv := wormfake.New(wormfake.S3, "signer-marks")
	defer srv.Close()
	setup := logtest.Setup(1, 30)
	name := func(v uint64) string { return markstore.Name(setup.Hash, setup.Signer, v) }
	wm := func(e uint64) backend.Watermark {
		return backend.Watermark{HasAttestation: true, SourceEpoch: e - 1, TargetEpoch: e, HasBlock: true, BlockSlot: e * 32}
	}
	open := func() *markstore.MarkLog {
		m, err := markstore.New(openRetained(t, srv, 30), setup.Signer, dev.NewDevKeys("image-1"), markstore.Options{
			Setup: setup, LockDays: 30, Clock: func() (time.Time, error) { return srv.Now(), nil },
			Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
		if err != nil {
			t.Fatal(err)
		}
		return m
	}

	a := open()
	if _, _, err := a.Claim(ctx, false); err != nil {
		t.Fatal(err)
	}
	for e := uint64(11); e <= 14; e++ {
		if err := a.Append(ctx, wm(e)); err != nil {
			t.Fatal(err)
		}
	}
	_, v := a.Mark()

	// The admin's objects, without retention: the bucket default is off
	// for their puts and back on before the clone's lock check.
	srv.SetLock(wormfake.Lock{Compliance: true, NoDefault: true})
	for i := uint64(1); i <= 16; i++ {
		if !srv.AdminCreate(name(v+i), []byte("not a record")) {
			t.Fatal("the fake refused the admin's object")
		}
	}
	srv.SetLock(wormfake.DefaultLock)

	// The clone starts while the host holds A's store traffic.
	_, _, err := open().Claim(ctx, true)
	if _, ok := srv.Current(name(v + 17)); err == nil || ok {
		t.Fatalf("the clone claimed past 16 names taken by objects that are not records (err %v, record at version %d: %v); "+
			"once the admin deletes them, the first instance writes those names and both sign side by side", err, v+17, ok)
	}

	// The admin deletes its objects by version; the records stay locked.
	if n := srv.AdminDeleteExpired(); n != 16 {
		t.Fatalf("the admin deleted %d versions, want its 16 objects", n)
	}
	if err := a.Append(ctx, wm(15)); err != nil {
		t.Fatalf("the first instance after the names are free again: %v", err)
	}
	if _, _, err := open().Claim(ctx, true); err != nil {
		t.Fatalf("the clone's claim once the names are free: %v", err)
	}
	if err := a.Append(ctx, wm(16)); !errors.Is(err, markstore.ErrLost) {
		t.Fatalf("the first instance's write after the clone's claim: %v, want ErrLost", err)
	}
}
