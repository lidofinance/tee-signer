package e2e

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The cloud release builds refuse to start without a setup, before the
// platform is built, even with flags that pass every other start check.
func TestE2ECloudReleaseBuildNeedsASetup(t *testing.T) {
	c := newChain(t)
	caFile, _ := testPKI(t, t.TempDir(), "setup-rule")
	tcp := fmt.Sprintf("tcp:0.0.0.0:%d", freePort(t))
	for _, tc := range []struct{ build, platform, listen string }{
		{"aws", "nitro", "vsock:any:7100"},
		{"azure", "azure", tcp},
		{"gcp", "gcp", tcp},
	} {
		state := filepath.Join(t.TempDir(), "s")
		out, err := runnerCmd(runnerBinary(t, tc.build), "-platform", tc.platform, "-config", c.path, "-state-dir", state,
			"-listen", tc.listen, "-tls-client-ca", caFile, "-mark-store", "none").CombinedOutput()
		var ee *exec.ExitError
		if !errors.As(err, &ee) || !strings.Contains(string(out), "no -setup") {
			t.Fatalf("runner-%s without a setup: err %v, output %q", tc.build, err, out)
		}
		if _, err := os.Stat(state); err == nil {
			t.Fatalf("runner-%s built its platform", tc.build)
		}
		t.Logf("runner-%s: refused at start: %s", tc.build, strings.TrimSpace(string(out)))
	}
}
