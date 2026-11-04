package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lidofinance/tee-signer/governance/setuptext"
	"github.com/lidofinance/tee-signer/governance/setupwire"
)

// gcpSample is setupwire's GCP sample setup, a test file of this repo.
const gcpSample = "../../../governance/setuptext/testdata/setup-gcp.conf"

// ownImages are allowed_image_measurements lines, one per platform with an
// image kind.
var ownImages = map[string]string{
	"nitro": "allowed_image_measurements = nitro 0x" + strings.Repeat("11", 48) + " 0x" + strings.Repeat("11", 48) + " 0x" + strings.Repeat("11", 48),
	"azure": "allowed_image_measurements = azure 0x" + strings.Repeat("aa", 32),
	"gcp":   gcpImage,
}

const gcpImage = "allowed_image_measurements = gcp 0x9999999999999999999999999999999999999999999999999999999999999999"

// withoutImage is the sample setup of platform p with no
// allowed_image_measurements line of kind p.
func withoutImage(t *testing.T, sample, p string) string {
	t.Helper()
	text, err := os.ReadFile("../../../governance/setuptext/testdata/" + sample)
	if err != nil {
		t.Fatal(err)
	}
	var keep []string
	for _, l := range strings.Split(string(text), "\n") {
		if !strings.HasPrefix(l, "allowed_image_measurements = "+p+" ") {
			keep = append(keep, l)
		}
	}
	return strings.Join(keep, "\n")
}

// encode and check refuse a setup whose allowed_image_measurements lists
// no image of its own platform, whose runner would refuse every import;
// with that image listed, both pass. A dev setup has no image kind and
// passes either way.
func TestOwnImageListed(t *testing.T) {
	for _, c := range []struct{ p, sample string }{
		{"nitro", "setup-nitro.conf"}, {"azure", "setup-azure.conf"}, {"gcp", "setup-gcp.conf"}, {"dev", "setup-dev-threshold.conf"},
	} {
		t.Run(c.p, func(t *testing.T) {
			dir := t.TempDir()
			bare := withoutImage(t, c.sample, c.p)
			human := filepath.Join(dir, "bare.conf")
			if err := os.WriteFile(human, []byte(bare), 0o600); err != nil {
				t.Fatal(err)
			}
			// The binary setup as an older tool wrote it, without the check.
			s, err := setuptext.ParseSetup(human, []byte(bare))
			if err != nil {
				t.Fatal(err)
			}
			raw, err := s.Encode()
			if err != nil {
				t.Fatal(err)
			}
			old := filepath.Join(dir, "old.setup")
			if err := os.WriteFile(old, raw, 0o600); err != nil {
				t.Fatal(err)
			}
			out := filepath.Join(dir, "bare.setup")
			encErr := encode(human, out)
			checkErr := check([]string{"-platform", c.p, old})
			if c.p == "dev" {
				if encErr != nil || checkErr != nil {
					t.Fatalf("dev setup: encode %v, check %v, want both to pass", encErr, checkErr)
				}
				return
			}
			for name, err := range map[string]error{"encode": encErr, "check": checkErr} {
				if err == nil || !strings.Contains(err.Error(), "allowed_image_measurements lists no "+c.p+" image") {
					t.Fatalf("%s: %v, want the refusal naming the missing %s image", name, err, c.p)
				}
			}
			if _, err := os.Stat(out); !os.IsNotExist(err) {
				t.Fatalf("encode wrote the refused setup (stat: %v)", err)
			}

			listed := filepath.Join(dir, "listed.conf")
			if err := os.WriteFile(listed, []byte(bare+"\n"+ownImages[c.p]+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			out = filepath.Join(dir, "listed.setup")
			if err := encode(listed, out); err != nil {
				t.Fatalf("encode with a %s image: %v", c.p, err)
			}
			if err := check([]string{"-platform", c.p, out}); err != nil {
				t.Fatalf("check with a %s image: %v", c.p, err)
			}
		})
	}
}

// encode refuses a mainnet GCP setup that accepts a key held alone without
// sealing_key_release.no_lock_accepted, as signer-admin setup does, and
// writes nothing; with both acceptances it writes the setup.
func TestEncodeMainnetGCPSingleNeedsNoLockAccepted(t *testing.T) {
	text, err := os.ReadFile(gcpSample)
	if err != nil {
		t.Fatal(err)
	}
	mainnet := strings.Replace(string(text), "genesis_fork_version = 0x00000001\n", "genesis_fork_version = 0x00000000\n", 1)
	if mainnet == string(text) {
		t.Fatal("the sample changed its genesis_fork_version line")
	}
	// A 1-of-1 GCP signer holds a whole key: signing_mode = single.
	singleMode := strings.Replace(mainnet, "\nsigning_mode = threshold\n", "\nsigning_mode = single\n", 1)
	if singleMode == mainnet {
		t.Fatal("the sample changed its signing_mode line")
	}
	// A GCP runner checks itself against a gcp image (setupwire.CheckOwnImageListed).
	mainnet = singleMode + gcpImage + "\n"
	dir := t.TempDir()
	write := func(name, extra string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(mainnet+extra), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	single := write("single.conf", "sealing_key_release.unsafe_single_key_accepted = true\n")
	out := filepath.Join(dir, "single.setup")
	err = encode(single, out)
	if err == nil || !strings.Contains(err.Error(), "on a prod chain") || !strings.Contains(err.Error(), "sealing_key_release.no_lock_accepted = true") {
		t.Fatalf("encode: %v, want the mainnet refusal naming no_lock_accepted", err)
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Fatalf("encode wrote the refused setup (stat: %v)", err)
	}

	both := write("both.conf", "sealing_key_release.unsafe_single_key_accepted = true\nsealing_key_release.no_lock_accepted = true\n")
	out = filepath.Join(dir, "both.setup")
	if err := encode(both, out); err != nil {
		t.Fatalf("encode with both acceptances: %v", err)
	}
	s, err := read(out)
	if err != nil {
		t.Fatal(err)
	}
	if k := s.Platform.SealingKeyRelease; !k.UnsafeSingleKeyAccepted || !k.NoLockAccepted {
		t.Fatalf("the setup carries unsafe_single_key_accepted %v, no_lock_accepted %v, want both", k.UnsafeSingleKeyAccepted, k.NoLockAccepted)
	}
	if !setupwire.ProdChain(s.Chain.GenesisForkVersion) {
		t.Fatal("the setup is not on mainnet")
	}
}
