package e2e

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Release gate of the image check (docs/protocol.md, "Image check"): no
// default build takes -allow-unlisted-image, so none can serve an image the
// allowed list in force does not name. The dev release builds always run;
// the cloud release builds when make names them (RUNNER_AWS_BIN,
// RUNNER_AZURE_BIN, RUNNER_GCP_BIN).
func TestE2EImageCheckNoOverrideInReleaseBuilds(t *testing.T) {
	keys := []string{"dev"}
	for _, k := range []string{"aws", "azure", "gcp"} {
		if os.Getenv(runnerBuilds[k].env) != "" {
			keys = append(keys, k)
		}
	}
	for _, k := range keys {
		state := filepath.Join(t.TempDir(), "state")
		cmd := runnerCmd(runnerBinary(t, k), "-state-dir", state, "-listen", fmt.Sprintf("tcp:127.0.0.1:%d", freePort(t)),
			"-allow-unlisted-image")
		out, err := cmd.CombinedOutput()
		if err == nil || !strings.Contains(string(out), "flag provided but not defined: -allow-unlisted-image") {
			t.Fatalf("runner-%s took -allow-unlisted-image: %v, %s", k, err, out)
		}
		if _, err := os.Stat(state); err == nil {
			t.Fatalf("runner-%s built its platform", k)
		}
	}
	t.Logf("no override flag in %s", strings.Join(keys, ", "))
}
