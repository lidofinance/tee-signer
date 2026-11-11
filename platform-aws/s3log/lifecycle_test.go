//go:build platform_aws

package s3log

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"testing"

	"github.com/lidofinance/tee-signer/slashing-log"
	"github.com/lidofinance/tee-signer/slashing-log/wormfake"
)

// A lifecycle rule set before the bucket policy's NoLifecycleRules deny
// keeps running. The lock check refuses a rule that moves objects to
// another storage class (an archive class makes records unreadable),
// warns once of an expiration rule, and passes a bucket without rules. A
// writer the bucket policy does not yet let read the rules (403) warns
// once and passes: the rules cost liveness only.
func TestS3LifecycleCheck(t *testing.T) {
	const (
		transition = `<Rule><ID>t</ID><Filter/><Status>Enabled</Status>` +
			`<Transition><Days>30</Days><StorageClass>DEEP_ARCHIVE</StorageClass></Transition></Rule>`
		noncurrent = `<Rule><ID>n</ID><Filter/><Status>Enabled</Status>` +
			`<NoncurrentVersionTransition><NoncurrentDays>1</NoncurrentDays><StorageClass>GLACIER</StorageClass></NoncurrentVersionTransition></Rule>`
		disabled = `<Rule><ID>d</ID><Filter/><Status>Disabled</Status>` +
			`<Transition><Days>1</Days><StorageClass>GLACIER</StorageClass></Transition></Rule>`
		expiration = `<Rule><ID>e</ID><Filter><Prefix>marks/</Prefix></Filter><Status>Enabled</Status>` +
			`<Expiration><Days>1</Days></Expiration></Rule>`
	)
	var logs bytes.Buffer
	for _, c := range []struct {
		name, rules string
		refuse      bool
		warns       int
		denied      bool
	}{
		{"none", "", false, 0, false},
		{"transition", transition, true, 0, false},
		{"noncurrent transition", expiration + noncurrent, true, 1, false},
		{"disabled transition", disabled, false, 0, false},
		{"expiration", expiration, false, 1, false},
		{"read denied", transition, false, 1, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			logs.Reset()
			srv := wormfake.New(wormfake.S3, "signer-marks")
			defer srv.Close()
			srv.SetLifecycle(c.rules)
			l := openRetained(t, srv, 30)
			l.Logger = slog.New(slog.NewTextHandler(&logs, nil))
			if auth := srv.Auth; c.denied {
				srv.Auth = func(r *http.Request) error {
					if r.URL.Query().Has("lifecycle") {
						return errors.New("AccessDenied")
					}
					return auth(r)
				}
			}
			ctx := context.Background()
			for range 2 {
				err := markstore.CheckLock(ctx, l, 30)
				if c.refuse != (err != nil) {
					t.Fatalf("lock check: %v, want refused %v", err, c.refuse)
				}
				if err != nil && !strings.Contains(err.Error(), "lifecycle rule") {
					t.Fatalf("lock check: %v, want the lifecycle rule named", err)
				}
			}
			if n := strings.Count(logs.String(), "level=WARN"); n != c.warns {
				t.Fatalf("%d warnings, want %d:\n%s", n, c.warns, logs.String())
			}
		})
	}
}
