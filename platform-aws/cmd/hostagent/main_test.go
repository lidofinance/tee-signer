package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The test binary runs main when HOSTAGENT_TEST_MAIN is set, with the
// arguments after "--".
func TestMain(m *testing.M) {
	if os.Getenv("HOSTAGENT_TEST_MAIN") == "1" {
		i := 0
		for i < len(os.Args) && os.Args[i] != "--" {
			i++
		}
		os.Args = append([]string{"hostagent"}, os.Args[min(i+1, len(os.Args)):]...)
		main()
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func runAgent(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := exec.Command(os.Args[0], append([]string{"-test.run=^$", "--"}, args...)...)
	cmd.Env = append(os.Environ(), "HOSTAGENT_TEST_MAIN=1")
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func setupFile(t *testing.T, name string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "governance", "setupwire", "testdata", name+".bin"))
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "setup.bin")
	if err := os.WriteFile(p, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// -proxy-routes prints the fixed routes, which parent-run.sh starts a
// vsock-proxy for and puts on the proxies' allowlist. It refuses a setup
// for another platform.
func TestProxyRoutes(t *testing.T) {
	out, err := runAgent(t, "-setup", setupFile(t, "setup-nitro"), "-proxy-routes")
	if err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	want := "8000 kms.eu-west-1.amazonaws.com 443\n8001 sts.eu-west-1.amazonaws.com 443\n8002 www.cloudflare.com 443\n" +
		"8004 signer-marks.s3.eu-west-1.amazonaws.com 443\n8005 time.cloudflare.com 4460\n8006 nts.netnod.se 4460\n" +
		"8007 ptbtime1.ptb.de 4460\n8009 bevtime1.metrologie.at 4460\n8010 nts1.ntp.hr 4460\n" +
		"8011 nts.meta.com 4460\n8015 ntp1.wiktel.com 4460\n"
	if out != want {
		t.Fatalf("routes:\n%s\nwant\n%s", out, want)
	}
	out, err = runAgent(t, "-setup", setupFile(t, "setup-gcp"), "-proxy-routes")
	if err == nil || !strings.Contains(out, "this image is nitro") {
		t.Errorf("gcp setup: %v\n%s", err, out)
	}
}
