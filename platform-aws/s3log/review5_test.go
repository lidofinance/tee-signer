//go:build platform_aws

package s3log

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/platform"
	"github.com/lidofinance/tee-signer/platform/dev"
	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/slashing-log"
	"github.com/lidofinance/tee-signer/slashing-log/logtest"
	"github.com/lidofinance/tee-signer/slashing-log/wormfake"
)

// Issue #5 R3: the mark log lists versions of a name only when its
// conditional create fails. On S3 a delete marker on a clone's record makes
// the name look free: the honest runner's create succeeds and neither
// instance sees the other. The fake S3 lets a create through over a delete
// marker (wormfake current()); whether real S3's If-None-Match does the
// same is not verified here. After a create on S3 the runner must find the
// clone's record at that version and refuse (ErrLost).
func TestReview5R3DeleteMarkerHidesClone(t *testing.T) {
	ctx := context.Background()
	srv := wormfake.New(wormfake.S3, "signer-marks")
	defer srv.Close()
	creds := platform.Credentials{AccessKeyID: "AKIDENCLAVE", SecretAccessKey: "enclave"}
	open := func() markstore.Log {
		l, err := Open("bucket="+srv.Bucket+",region=eu-central-1,endpoint="+srv.URL, markstore.Env{
			HTTP: srv.Client(), AWSCreds: func(context.Context) (platform.Credentials, error) { return creds, nil }})
		if err != nil {
			t.Fatal(err)
		}
		return l
	}
	setup := logtest.Setup(1, 30)
	opt := markstore.Options{Setup: setup, Clock: func() (time.Time, error) { return srv.Now(), nil },
		Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	keys := dev.NewDevKeys("image-1")
	wm := func(e uint64) backend.Watermark {
		return backend.Watermark{HasAttestation: true, SourceEpoch: e - 1, TargetEpoch: e, HasBlock: true, BlockSlot: e * 32}
	}

	a, err := markstore.New(open(), setup.Signer, keys, opt)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := a.Claim(ctx, false); err != nil {
		t.Fatal(err)
	}
	if err := a.Append(ctx, wm(10)); err != nil {
		t.Fatal(err)
	}
	_, v := a.Mark()

	// A clone of the same image claims the log: it writes version v+1.
	b, err := markstore.New(open(), setup.Signer, keys, opt)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := b.Claim(ctx, true); err != nil {
		t.Fatal(err)
	}
	if _, vb := b.Mark(); vb != v+1 {
		t.Fatalf("clone at version %d, want %d", vb, v+1)
	}
	// The admin hides the clone's record behind a delete marker.
	if !srv.AdminDeleteMarker(markstore.Name(setup.Hash, setup.Signer, v+1)) {
		t.Fatal("delete marker refused by the fake")
	}

	err = a.Append(ctx, wm(11))
	if err == nil {
		t.Errorf("runner A wrote version %d over a delete marker on the clone's record and signs on: two live instances, neither sees the other", v+1)
	} else if !errors.Is(err, markstore.ErrLost) {
		t.Logf("refused with %v", err)
	}
}
