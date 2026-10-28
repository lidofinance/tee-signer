package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lidofinance/tee-signer/governance/setupwire"
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

func setupFile(t *testing.T, name string, peers ...string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "governance", "setupwire", "testdata", name+".bin"))
	if err != nil {
		t.Fatal(err)
	}
	if peers != nil {
		s, err := setupwire.DecodeSetup(raw)
		if err != nil {
			t.Fatal(err)
		}
		s.Platform.KeygenPeerAttestationHosts = peers
		if raw, err = s.Encode(); err != nil {
			t.Fatal(err)
		}
	}
	p := filepath.Join(t.TempDir(), "setup.bin")
	if err := os.WriteFile(p, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// -proxy-routes prints the fixed routes and, on the peer block, the
// setup's peer endpoints, which parent-run.sh starts a vsock-proxy for
// and puts on the proxies' allowlist. It refuses a setup it could not
// route.
func TestProxyRoutes(t *testing.T) {
	out, err := runAgent(t, "-setup", setupFile(t, "setup-nitro-peers"), "-proxy-routes")
	if err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	want := "8000 kms.eu-west-1.amazonaws.com 443\n8001 sts.eu-west-1.amazonaws.com 443\n8002 www.cloudflare.com 443\n" +
		"8004 signer-marks.s3.eu-west-1.amazonaws.com 443\n8005 time.cloudflare.com 4460\n8006 nts.netnod.se 4460\n" +
		"8007 ptbtime1.ptb.de 4460\n8008 ntppool1.time.nl 4460\n8010 confidentialcomputing.googleapis.com 443\n" +
		"8011 sharedneu.neu.attest.azure.net 443\n8012 www.googleapis.com 443\n"
	if out != want {
		t.Fatalf("routes:\n%s\nwant\n%s", out, want)
	}
	out, err = runAgent(t, "-setup", setupFile(t, "setup-nitro"), "-proxy-routes")
	if err != nil || strings.Count(out, "\n") != 8 || strings.Contains(out, "\n801") {
		t.Fatalf("routes without peers: %v\n%s", err, out)
	}
	for name, c := range map[string]struct {
		file string
		want string
	}{
		"fixed route as a peer": {setupFile(t, "setup-nitro", "kms.eu-west-1.amazonaws.com:443"), "is the fixed route of port 8000"},
		"gcp setup":             {setupFile(t, "setup-gcp"), "this image is nitro"},
	} {
		out, err := runAgent(t, "-setup", c.file, "-proxy-routes")
		if err == nil || !strings.Contains(out, c.want) {
			t.Errorf("%s: %v\n%s", name, err, out)
		}
	}
}
