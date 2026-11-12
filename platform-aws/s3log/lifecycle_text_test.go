//go:build platform_aws

package s3log

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/lidofinance/tee-signer/slashing-log"
	"github.com/lidofinance/tee-signer/slashing-log/wormfake"
)

// rv-b9e.9: the lock check's refusal of a transition rule and its warning
// of an expiration rule say that the mark bucket must have no lifecycle
// rules, and that with the bucket policy's NoLifecycleRules deny in place
// removing the rule needs a policy change first.
func TestS3LifecycleCheckSaysHowToRemoveTheRule(t *testing.T) {
	const (
		transition = `<Rule><ID>t</ID><Filter/><Status>Enabled</Status>` +
			`<Transition><Days>30</Days><StorageClass>DEEP_ARCHIVE</StorageClass></Transition></Rule>`
		expiration = `<Rule><ID>e</ID><Filter><Prefix>marks/</Prefix></Filter><Status>Enabled</Status>` +
			`<Expiration><Days>1</Days></Expiration></Rule>`
	)
	want := []string{"must have no lifecycle rules", "NoLifecycleRules", "bucket policy"}
	for _, c := range []struct{ name, rules string }{{"transition", transition}, {"expiration", expiration}} {
		var logs bytes.Buffer
		srv := wormfake.New(wormfake.S3, "signer-marks")
		srv.SetLifecycle(c.rules)
		l := openRetained(t, srv, 30)
		l.Logger = slog.New(slog.NewTextHandler(&logs, nil))
		err := markstore.CheckLock(context.Background(), l, 30)
		srv.Close()
		text := logs.String()
		if err != nil {
			text = err.Error()
		}
		for _, w := range want {
			if !strings.Contains(text, w) {
				t.Errorf("%s: %q does not say %q", c.name, text, w)
			}
		}
	}
}
