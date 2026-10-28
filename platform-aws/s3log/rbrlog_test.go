//go:build platform_aws

package s3log

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/platform"
	"github.com/lidofinance/tee-signer/platform/dev"
	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/slashing-log"
	"github.com/lidofinance/tee-signer/slashing-log/logtest"
	"github.com/lidofinance/tee-signer/slashing-log/wormfake"
)

// RBRLOG-01 on S3: runner A at version v, a clone B claims v+1, the admin
// puts a delete marker on B's record, and the host drops the reply to A's
// create at v+1 (it landed over the marker). A's retry gets 412. A must
// latch ErrLost, not find its own record and sign on.
func TestRBRLOG01DroppedReplyOverDeleteMarker(t *testing.T) {
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
	b, err := markstore.New(open(), setup.Signer, keys, opt)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := b.Claim(ctx, true); err != nil {
		t.Fatal(err)
	}
	name := markstore.Name(setup.Hash, setup.Signer, v+1)
	if !srv.AdminDeleteMarker(name) {
		t.Fatal("delete marker refused by the fake")
	}
	srv.AddFault(wormfake.Fault{Method: http.MethodPut, Match: name, Action: wormfake.ApplyThenDropReply})
	if err := a.Append(ctx, wm(11)); err == nil {
		t.Fatal("the dropped reply did not reach Append")
	}
	if srv.Hits() != 1 {
		t.Fatalf("fault plan hit %d requests, want 1", srv.Hits())
	}
	err = a.Append(ctx, wm(11))
	if !errors.Is(err, markstore.ErrLost) || !errors.Is(a.Lost(), markstore.ErrLost) {
		t.Errorf("A's retry at version %d: err %v, Lost %v; want ErrLost", v+1, err, a.Lost())
	}
}
