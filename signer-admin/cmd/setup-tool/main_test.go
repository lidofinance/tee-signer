package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lidofinance/tee-signer/governance/setupwire"
)

// gcpSample is setupwire's GCP sample setup, a test file of this repo.
const gcpSample = "../../../governance/setuptext/testdata/setup-gcp.conf"

// encode refuses a mainnet GCP setup that accepts a key held alone without
// sealing_key_release.no_lock_accepted, as signer-admin setup does, and
// writes nothing; with both acceptances it writes the setup.
func TestEncodeMainnetGCPSingleNeedsNoLockAccepted(t *testing.T) {
	text, err := os.ReadFile(gcpSample)
	if err != nil {
		t.Fatal(err)
	}
	mainnet := strings.Replace(string(text), "genesis_fork_version = 0x00000010\n", "genesis_fork_version = 0x00000000\n", 1)
	if mainnet == string(text) {
		t.Fatal("the sample changed its genesis_fork_version line")
	}
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
	if err == nil || !strings.Contains(err.Error(), "on mainnet") || !strings.Contains(err.Error(), "sealing_key_release.no_lock_accepted = true") {
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
	if !setupwire.IsMainnet(s.Chain.GenesisForkVersion) {
		t.Fatal("the setup is not on mainnet")
	}
}
