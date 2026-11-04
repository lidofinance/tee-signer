package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lidofinance/tee-signer/governance/setupwire"
	"github.com/lidofinance/tee-signer/signer-admin/fakerunner"
	"github.com/lidofinance/tee-signer/signer-protocol/wire"
)

// A member whose cloud.json says verifier dev is refused when its setup
// names a cloud platform: the dev verifier takes an unsigned document from
// whoever answers, and the tool holds the setup, so it can tell. Every
// command that connects to the member refuses before any request, and
// import with -conn does the same when -setup is such a setup. A dev
// platform member with the dev verifier is what every other test uses.
func TestDevVerifierNeedsDevPlatform(t *testing.T) {
	const name = "gsigner-2" // the Nitro signer of cloudSetupText
	shared, section := signerSection(t, cloudSetupText(t, 4, "single", "", ""), name)
	dir := t.TempDir()
	file := writeFile(t, filepath.Join(dir, "setup.conf"), shared+"\n[signer "+name+"]"+section)
	mustTool(t, "setup", "-out", filepath.Join(dir, "setups"), file)
	raw := mustRead(t, filepath.Join(dir, "setups", name+".setup"))
	setup, err := setupwire.DecodeSetup(raw)
	if err != nil {
		t.Fatal(err)
	}
	if setup.Platform.Platform != setupwire.PlatformNitro {
		t.Fatalf("%s is on %s, want nitro", name, setup.Platform.Platform)
	}
	hash, err := setupwire.SetupHash(raw)
	if err != nil {
		t.Fatal(err)
	}
	r := fakerunner.StartSetup(t, raw)
	cert, key := r.ClientFiles(t, t.TempDir())
	conn := writeJSONFile(t, filepath.Join(dir, name, "cloud.json"), map[string]any{
		"address": r.Addr(), "client_cert": cert, "client_key": key,
		"attestation": map[string]any{"verifier": "dev", "setup_sha256": hex.EncodeToString(hash[:])},
	})
	cl := writeJSONFile(t, filepath.Join(dir, "cluster.json"), map[string]any{
		"signers": []any{map[string]string{"name": name, "cloud": name + "/cloud.json", "setup": "setups/" + name + ".setup"}}})
	pk, shares, _ := split(t, dir, 2, 3, []string{name, "y", "z"})
	sharesFile := filepath.Join(dir, "shares.txt")
	if err := os.WriteFile(sharesFile, fmt.Appendf(nil, "%s 7 0x%x\n", pk, shares[0].Secret), 0o600); err != nil {
		t.Fatal(err)
	}
	ic := writeFile(t, filepath.Join(dir, "ic.json"), `{"metadata":{"interchange_format_version":"5","genesis_validators_root":"0x`+
		hex.EncodeToString(setup.Chain.GenesisValidatorsRoot[:])+`"},"data":[{"pubkey":"`+pk.String()+
		`","signed_blocks":[],"signed_attestations":[{"source_epoch":"3","target_epoch":"4"}]}]}`)

	const want = "on the nitro platform"
	wantIn(t, failTool(t, "probe", "-cluster", cl), want)
	wantIn(t, failTool(t, "pin", "-cluster", cl), want)
	wantIn(t, failTool(t, "status", "-cluster", cl), want)
	wantIn(t, failTool(t, "import", "-cluster", cl, "-signer", name, "-shares", sharesFile), want)
	wantIn(t, failTool(t, "import", "-conn", conn, "-setup", filepath.Join(dir, "setups", name+".setup"), "-shares", sharesFile, "-interchange", ic), want)
	if n := r.Seen(wire.TypeIdentity) + r.Seen(wire.TypeHealth); n != 0 {
		t.Fatalf("%d requests reached the refused runner", n)
	}
	out := failTool(t, "probe", "-cluster", cl)
	if strings.Contains(out, "role check passed") {
		t.Fatalf("probe reached the runner:\n%s", out)
	}
}
