package e2e

// The runner is one binary per cloud (runner/platforms.go). These tests run
// the real binaries: each has its own platform and refuses the others by
// name, and a binary built without a platform tag refuses to start.

import (
	"errors"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestE2EEachBinaryHasItsOwnPlatformOnly(t *testing.T) {
	c := newChain(t)
	all := []string{"dev", "nitro", "azure", "gcp"}
	for _, b := range []struct{ build, has string }{
		{"dev", "dev"}, {"dev-debug", "dev"}, {"aws", "nitro"}, {"azure", "azure"}, {"gcp", "gcp"},
	} {
		bin := runnerBinary(t, b.build)
		for _, p := range all {
			if p == b.has {
				continue
			}
			args := []string{"-platform", p, "-config", c.path, "-state-dir", filepath.Join(t.TempDir(), "s"), "-record", "none"}
			out, err := runnerCmd(bin, args...).CombinedOutput()
			var ee *exec.ExitError
			want := "platform \"" + p + "\" is not built into this binary (it has: " + b.has + ")"
			if !errors.As(err, &ee) || !strings.Contains(string(out), want) {
				t.Fatalf("runner-%s -platform %s: err %v, output %q, want %q", b.build, p, err, out, want)
			}
			t.Logf("runner-%s refuses -platform %s: %s", b.build, p, strings.TrimSpace(string(out)))
		}
		// The usage names the one platform it has.
		out, _ := runnerCmd(bin, "-h").CombinedOutput()
		if want := "platform of this build: " + b.has; !strings.Contains(string(out), want) {
			t.Fatalf("runner-%s -h does not say %q:\n%s", b.build, want, out)
		}
	}
}

// A binary built with none of the platform tags has nothing to run on and
// says how to build it. It is built here for the host and run natively.
func TestE2EBuiltWithoutAPlatformTagRefusesToStart(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "runner-notag")
	if err := goBuild(bin, "../../tee-signer", ""); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(bin, "-platform", "dev").CombinedOutput()
	var ee *exec.ExitError
	if !errors.As(err, &ee) || !strings.Contains(string(out), "no platform built in") || !strings.Contains(string(out), "platform_aws") {
		t.Fatalf("err %v, output %q", err, out)
	}
	t.Logf("refused to start: %s", strings.TrimSpace(string(out)))
}
