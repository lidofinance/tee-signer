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
// refused read (any 403: a writer the bucket policy does not yet let read
// the rules, but also a request S3 finds too skewed) warns once and
// passes, so a runner under the old policy starts; a rule then goes unseen.
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
		denied      string // the 403 the read gets, if any
	}{
		{"none", "", false, 0, ""},
		{"transition", transition, true, 0, ""},
		{"noncurrent transition", expiration + noncurrent, true, 1, ""},
		{"disabled transition", disabled, false, 0, ""},
		{"expiration", expiration, false, 1, ""},
		{"read denied", transition, false, 1, "AccessDenied"},
		{"read refused as skewed", transition, false, 1, "RequestTimeTooSkewed"},
	} {
		t.Run(c.name, func(t *testing.T) {
			logs.Reset()
			srv := wormfake.New(wormfake.S3, "signer-marks")
			defer srv.Close()
			srv.SetLifecycle(c.rules)
			l := openRetained(t, srv, 30)
			l.Logger = slog.New(slog.NewTextHandler(&logs, nil))
			if auth := srv.Auth; c.denied != "" {
				srv.Auth = func(r *http.Request) error {
					if r.URL.Query().Has("lifecycle") {
						return errors.New(c.denied)
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
