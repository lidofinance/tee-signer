//go:build platform_aws

package s3log

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/platform"
	"github.com/lidofinance/tee-signer/slashing-log"
	"github.com/lidofinance/tee-signer/slashing-log/logtest"
	"github.com/lidofinance/tee-signer/slashing-log/wormfake"
)

const day = 24 * time.Hour

func openRetained(t *testing.T, srv *wormfake.Server, days uint32) *Log {
	t.Helper()
	creds := platform.Credentials{AccessKeyID: "AKIDENCLAVE", SecretAccessKey: "enclave"}
	srv.Auth = verify(creds, "eu-central-1")
	l, err := Open("bucket="+srv.Bucket+",region=eu-central-1,endpoint="+srv.URL, markstore.Env{HTTP: srv.Client(),
		AWSCreds:   func(context.Context) (platform.Credentials, error) { return creds, nil },
		RetainDays: days})
	if err != nil {
		t.Fatal(err)
	}
	sl := l.(*Log)
	sl.Now = srv.Now
	return sl
}

// The whole mark log suite with per-object retention on.
func TestS3LogRetained(t *testing.T) {
	logtest.Run(t, wormfake.S3, func(t *testing.T, srv *wormfake.Server) markstore.Log {
		return openRetained(t, srv, uint32(wormfake.DefaultLock.Days))
	})
}

// The lock check reads the bucket's default retention, which the account
// admin can lower or remove at any time; compliance mode protects object
// versions, not the bucket setting. Here the admin removes the default
// after the start's check. A record written after that must still be
// locked for slashing_log_min_lock_days, so it carries its own retention.
func TestS3RecordKeepsItsRetentionWhenTheDefaultIsRemoved(t *testing.T) {
	ctx := context.Background()
	srv := wormfake.New(wormfake.S3, "signer-marks")
	defer srv.Close()
	l := openRetained(t, srv, 30)
	if err := markstore.CheckLock(ctx, l, 30); err != nil {
		t.Fatal(err)
	}
	srv.SetLock(wormfake.Lock{Compliance: true, NoDefault: true})
	name := "marks/s/00000000000000000001"
	start := srv.Now()
	if err := l.Create(ctx, name, []byte("record")); err != nil {
		t.Fatal(err)
	}
	if until := srv.RetainUntil(name); until.Before(start.Add(30 * day)) {
		t.Fatalf("retained until %v, want at least 30 days", until)
	}
	srv.Advance(10 * day)
	if n := srv.AdminDeleteExpired(); n != 0 {
		t.Fatalf("the admin deleted %d versions 10 days after the write", n)
	}
	if _, ok := srv.Current(name); !ok {
		t.Fatal("the record is gone")
	}
	srv.Advance(21 * day)
	if n := srv.AdminDeleteExpired(); n != 1 {
		t.Fatalf("%d versions expired after 31 days, want 1", n)
	}
}

// A longer bucket default than the setup's minimum, read by the lock
// check, is kept: the per-object date replaces the default, so it must not
// be shorter.
func TestS3RetentionNotShorterThanTheDefault(t *testing.T) {
	ctx := context.Background()
	srv := wormfake.New(wormfake.S3, "signer-marks")
	defer srv.Close()
	srv.SetLock(wormfake.Lock{Compliance: true, Days: 400})
	l := openRetained(t, srv, 30)
	if err := markstore.CheckLock(ctx, l, 30); err != nil {
		t.Fatal(err)
	}
	name := "marks/s/00000000000000000001"
	start := srv.Now()
	if err := l.Create(ctx, name, []byte("record")); err != nil {
		t.Fatal(err)
	}
	if until := srv.RetainUntil(name); until.Before(start.Add(400 * day)) {
		t.Fatalf("retained until %v, want at least 400 days", until)
	}
}

// A log whose lock nobody checked (the state copy in the log's bucket)
// reads the default itself before its first retained write.
func TestS3RetentionReadsTheDefaultWithoutALockCheck(t *testing.T) {
	ctx := context.Background()
	srv := wormfake.New(wormfake.S3, "signer-marks")
	defer srv.Close()
	srv.SetLock(wormfake.Lock{Compliance: true, Days: 400})
	l := openRetained(t, srv, 30)
	name := "state/s/00000000000000000001"
	start := srv.Now()
	if err := l.Create(ctx, name, []byte("commit")); err != nil {
		t.Fatal(err)
	}
	if until := srv.RetainUntil(name); until.Before(start.Add(400 * day)) {
		t.Fatalf("retained until %v, want at least 400 days", until)
	}
	if !l.defaultRead.Load() {
		t.Fatal("the default was not read")
	}
}

// The retention headers are signed (S3 refuses unsigned x-amz-* headers)
// and name compliance mode with a date at least the minimum ahead.
func TestS3RetentionHeaders(t *testing.T) {
	ctx := context.Background()
	srv := wormfake.New(wormfake.S3, "signer-marks")
	defer srv.Close()
	l := openRetained(t, srv, 30)
	var seen http.Header
	check := srv.Auth
	srv.Auth = func(r *http.Request) error {
		if r.Method == http.MethodPut {
			seen = r.Header.Clone()
		}
		return check(r)
	}
	start := srv.Now()
	if err := l.Create(ctx, "marks/s/00000000000000000001", []byte("record")); err != nil {
		t.Fatal(err)
	}
	m := authRE.FindStringSubmatch(seen.Get("Authorization"))
	want := "content-md5;content-type;host;if-none-match;x-amz-content-sha256;x-amz-date;" +
		"x-amz-object-lock-mode;x-amz-object-lock-retain-until-date"
	if m == nil || m[4] != want {
		t.Fatalf("signed headers %v", m)
	}
	if mode := seen.Get("x-amz-object-lock-mode"); mode != "COMPLIANCE" {
		t.Fatalf("mode %q", mode)
	}
	until, err := time.Parse(time.RFC3339, seen.Get("x-amz-object-lock-retain-until-date"))
	if err != nil || until.Before(start.Add(30*day)) || until.After(start.Add(31*day)) {
		t.Fatalf("retain until %q: %v", seen.Get("x-amz-object-lock-retain-until-date"), err)
	}
	// A bucket without Object Lock refuses the headers, so the write fails.
	srv.SetLock(wormfake.Lock{None: true})
	if err := l.Create(ctx, "marks/s/00000000000000000002", []byte("record")); err == nil {
		t.Fatal("a retained write to a bucket without Object Lock went through")
	}
}
