//go:build platform_gcp

package gcslog

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

// RBRLOG-01 on GCS with object versioning: runner A at version v, a clone
// B claims v+1, the admin makes B's record noncurrent. A's create at v+1
// then lands (ifGenerationMatch=0 sees no live object). A must find B's
// generation and latch ErrLost.
func TestRBRLOG01NoncurrentGenerationHidesClone(t *testing.T) {
	ctx := context.Background()
	srv := wormfake.New(wormfake.GCS, "signer-marks")
	defer srv.Close()
	open := func() markstore.Log {
		l, err := Open("bucket="+srv.Bucket+",endpoint="+srv.URL, markstore.Env{
			HTTP: srv.Client(), Token: func(context.Context) (string, error) { return "federated-token", nil }})
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
	b, err := markstore.New(open(), setup.Signer, keys, opt)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := b.Claim(ctx, true); err != nil {
		t.Fatal(err)
	}
	if !srv.AdminNoncurrent(markstore.Name(setup.Hash, setup.Signer, v+1)) {
		t.Fatal("noncurrent refused by the fake")
	}
	err = a.Append(ctx, wm(11))
	if !errors.Is(err, markstore.ErrLost) || !errors.Is(a.Lost(), markstore.ErrLost) {
		t.Errorf("A wrote version %d over the clone's noncurrent record: err %v, Lost %v; want ErrLost", v+1, err, a.Lost())
	}
}
