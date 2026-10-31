package main

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lidofinance/tee-signer/governance/setupwire"
	"github.com/lidofinance/tee-signer/signer-admin/fakerunner"
)

// cloudSetupText is the runbook's cluster file
// (governance/docs/setup-phase-cloud-test.md, step 0): an Azure signer on
// sharedneu, a Nitro signer with the lines nitroExtra, and a GCP signer.
// format is the shared format line's value, mode the signing_mode line's.
func cloudSetupText(t *testing.T, format int, mode, nitroExtra, azureExtra string) string {
	t.Helper()
	dir := t.TempDir()
	keys := approvers(t, dir, 3)
	var b strings.Builder
	fmt.Fprintf(&b, `setup_format_version = %d
signing_mode = %s
handover_generation = 1
genesis_validators_root = 0x4b36000000000000000000000000000000000000000000000000000000000000
genesis_fork_version = 0x00000010
genesis_time = %d
seconds_per_slot = %d
slots_per_epoch = %d
preset = minimal
voluntary_exit_fork_version = 0x04000010
max_sign_epochs_ahead_of_clock = 2
slashing_mark_prewrite.block_slots = 16
slashing_mark_prewrite.source_epochs = 2
slashing_mark_prewrite.target_epochs = 2
allowed_client_ca = %s
max_keys = 8192
slashing_log_min_lock_days = 1
`, format, mode, genesisTime(), secondsPerSlot, slotsPerEpoch, base64.StdEncoding.EncodeToString(caDER(t)))
	b.WriteString(lockedText(keys, 2, 0, fee1))
	b.WriteString(openText())
	b.WriteString(`
[signer gsigner-1]
platform = azure
slashing_log_store.account = signeraccount
slashing_log_store.container = marks
slashing_log_store.subscription = 0b2c3d4e-5f60-4718-9a2b-3c4d5e6f7a8b
slashing_log_store.resource_group = signer-poc-rg
sealing_key_release.maa_endpoint = sharedneu.neu.attest.azure.net
sealing_key_release.akv_endpoint = signer-vault.vault.azure.net
sealing_key_release.kid = signer-gkek-1
` + azureExtra + `
[signer gsigner-2]
platform = nitro
slashing_log_store.bucket = signer-marks-aws
slashing_log_store.region = eu-central-1
sealing_key_release.region = eu-central-1
sealing_key_release.kms_key_id = arn:aws:kms:eu-central-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab
` + nitroExtra + `
[signer gsigner-3]
platform = gcp
slashing_log_store.bucket = signer-marks-gcp
sealing_key_release.wif_provider = //iam.googleapis.com/projects/123456789/locations/global/workloadIdentityPools/signer-pool/providers/signer-attestation
sealing_key_release.kms_key = projects/signer-project/locations/europe-west4/keyRings/signer/cryptoKeys/sealing
sealing_key_release.attest_audience = signer-runner-identity
`)
	return b.String()
}

// signer-admin setup makes a setup for a cluster of one Azure or Nitro
// signer, and refuses a cluster in which no split passes the signers'
// threshold rule (setupwire.CheckThresholdOn): one GCP signer can only
// hold keys 1 of 1, which a GCP signer refuses unless its setup accepts
// the risk. The refusal comes when the setup is made, not at the first
// order, and names the way to accept. With -allow-gcp-unsafe-single-key,
// or the key sealing_key_release.unsafe_single_key_accepted in the
// section, the setup is made with the acceptance and the run prints the
// warning. One dev signer on a test chain still makes a setup.
func TestSetupSingleSignerOnEveryPlatform(t *testing.T) {
	full := cloudSetupText(t, 2, "single", "", "")
	for _, name := range []string{"gsigner-1", "gsigner-2", "gsigner-3"} {
		shared, section := signerSection(t, full, name)
		dir := t.TempDir()
		file := writeFile(t, filepath.Join(dir, "setup.conf"), shared+"\n[signer "+name+"]"+section)
		if strings.Contains(section, "platform = gcp") {
			wantIn(t, failTool(t, "setup", "-out", filepath.Join(dir, "setups"), file), name, "single-node signer on GCP", "-allow-gcp-unsafe-single-key", "no lock")
			out := mustTool(t, "setup", "-allow-gcp-unsafe-single-key", "-out", filepath.Join(dir, "setups"), file)
			wantIn(t, out, name+" setup_sha256", "WARNING signer "+name, "unsafe_single_key_accepted", "IAM bindings")
			k := keyReleaseOf(t, filepath.Join(dir, "setups", name+".setup"))
			if !k.UnsafeSingleKeyAccepted {
				t.Fatal("the flag did not set unsafe_single_key_accepted in the setup")
			}
			if k.NoLockAccepted {
				t.Fatal("the flag set no_lock_accepted, which is a separate acceptance")
			}
			keyed := writeFile(t, filepath.Join(dir, "keyed.conf"), shared+"\n[signer "+name+"]"+section+"sealing_key_release.unsafe_single_key_accepted = true\n")
			out = mustTool(t, "setup", "-out", filepath.Join(dir, "keyed"), keyed)
			wantIn(t, out, name+" setup_sha256", "WARNING signer "+name)
			if !keyReleaseOf(t, filepath.Join(dir, "keyed", name+".setup")).UnsafeSingleKeyAccepted {
				t.Fatal("the key did not set unsafe_single_key_accepted in the setup")
			}
			continue
		}
		wantIn(t, mustTool(t, "setup", "-out", filepath.Join(dir, "setups"), file), name+" setup_sha256", "signing_mode single")
		// The same signer with signing_mode = threshold could hold no key.
		thr := writeFile(t, filepath.Join(dir, "threshold.conf"), strings.Replace(shared, "signing_mode = single\n", "signing_mode = threshold\n", 1)+"\n[signer "+name+"]"+section)
		wantIn(t, failTool(t, "setup", "-out", filepath.Join(dir, "thr"), thr), "signer "+name, "can hold no key", "signing_mode = threshold", "signing_mode = single")
	}

	dir := t.TempDir()
	one := writeFile(t, filepath.Join(dir, "one.conf"), setupText(dir, caDER(t), genesisTime(), lockedText(approvers(t, dir, 3), 2, 0, fee1), "s1"))
	mustTool(t, "setup", "-out", filepath.Join(dir, "setups"), one)
}

// signing_mode and -allow-gcp-unsafe-single-key, checked before any
// setup is made: a single-mode file has one signer; the flag needs
// signing_mode = single, one signer, and that signer on GCP. Each refusal
// says which rule and how to fix it.
func TestSetupAllowGCPSingleFlagScope(t *testing.T) {
	dir := t.TempDir()
	three := writeFile(t, filepath.Join(dir, "three.conf"), cloudSetupText(t, 2, "threshold", "", ""))
	wantIn(t, failTool(t, "setup", "-allow-gcp-unsafe-single-key", "-out", filepath.Join(dir, "three"), three),
		"-allow-gcp-unsafe-single-key: the file says signing_mode = threshold", "signing_mode = single")
	wantIn(t, mustTool(t, "setup", "-out", filepath.Join(dir, "three"), three), "signing_mode threshold")
	full := cloudSetupText(t, 2, "single", "", "")
	threeSingle := writeFile(t, filepath.Join(dir, "three-single.conf"), full)
	for _, extra := range [][]string{nil, {"-allow-gcp-unsafe-single-key"}} {
		wantIn(t, failTool(t, append(append([]string{"setup"}, extra...), "-out", filepath.Join(dir, "three-single"), threeSingle)...),
			"signing_mode = single: the file has 3 signers", "signing_mode = threshold for a split")
	}
	for _, name := range []string{"gsigner-1", "gsigner-2"} {
		shared, section := signerSection(t, full, name)
		one := writeFile(t, filepath.Join(dir, name+".conf"), shared+"\n[signer "+name+"]"+section)
		wantIn(t, failTool(t, "setup", "-allow-gcp-unsafe-single-key", "-out", filepath.Join(dir, name), one),
			"-allow-gcp-unsafe-single-key: signer "+name+" is on", "not on GCP")
		mustTool(t, "setup", "-out", filepath.Join(dir, name), one)
	}
	// The key in a threshold file is refused too: the acceptance belongs
	// to a single-mode setup.
	shared, section := signerSection(t, cloudSetupText(t, 2, "threshold", "", ""), "gsigner-3")
	keyed := writeFile(t, filepath.Join(dir, "keyed.conf"), shared+"\n[signer gsigner-3]"+section+"sealing_key_release.unsafe_single_key_accepted = true\n")
	wantIn(t, failTool(t, "setup", "-out", filepath.Join(dir, "keyed"), keyed), "unsafe_single_key_accepted needs signing_mode = single")
}

// On mainnet a GCP runner starts only with sealing_key_release.no_lock_accepted
// (platform.Options.CheckNoLock), so a mainnet setup that accepts a key
// held alone (the flag or the key) without it would make a runner that
// never starts: setup refuses it and names no_lock_accepted as the
// separate acceptance. With both, the setup is made with both acceptances
// and both WARNING lines; the flag itself never sets no_lock_accepted.
func TestSetupMainnetGCPSingleNeedsNoLockAccepted(t *testing.T) {
	const name = "gsigner-3"
	shared, section := signerSection(t, cloudSetupText(t, 2, "single", "", ""), name)
	mainnet := strings.Replace(shared, "genesis_fork_version = 0x00000010\n", "genesis_fork_version = 0x00000000\n", 1)
	if mainnet == shared {
		t.Fatal("cloudSetupText changed its genesis_fork_version line")
	}
	dir := t.TempDir()
	file := writeFile(t, filepath.Join(dir, "setup.conf"), mainnet+"\n[signer "+name+"]"+section)
	wantIn(t, failTool(t, "setup", "-allow-gcp-unsafe-single-key", "-out", filepath.Join(dir, "flag"), file),
		"signer "+name, "on mainnet", "sealing_key_release.no_lock_accepted = true", "-allow-gcp-unsafe-single-key does not set it")
	keyed := writeFile(t, filepath.Join(dir, "keyed.conf"), mainnet+"\n[signer "+name+"]"+section+"sealing_key_release.unsafe_single_key_accepted = true\n")
	wantIn(t, failTool(t, "setup", "-out", filepath.Join(dir, "keyed"), keyed), "signer "+name, "on mainnet", "sealing_key_release.no_lock_accepted = true")
	both := writeFile(t, filepath.Join(dir, "both.conf"), mainnet+"\n[signer "+name+"]"+section+"sealing_key_release.no_lock_accepted = true\n")
	out := mustTool(t, "setup", "-allow-gcp-unsafe-single-key", "-out", filepath.Join(dir, "both"), both)
	wantIn(t, out, name+" setup_sha256",
		"WARNING signer "+name+": the setup accepts a key rule without a lock (sealing_key_release.no_lock_accepted)",
		"WARNING signer "+name+": the setup accepts a key held alone on GCP (sealing_key_release.unsafe_single_key_accepted)", "IAM or KMS admin rights")
	if k := keyReleaseOf(t, filepath.Join(dir, "both", name+".setup")); !k.NoLockAccepted || !k.UnsafeSingleKeyAccepted {
		t.Fatalf("the setup carries no_lock_accepted %v, unsafe_single_key_accepted %v, want both", k.NoLockAccepted, k.UnsafeSingleKeyAccepted)
	}
	// A real split (3 of 4) on a mainnet cluster with a GCP signer that
	// accepts neither still makes its setups: the acceptances are only
	// for a key held alone.
	threeFile := writeFile(t, filepath.Join(dir, "three.conf"), strings.Replace(cloudSetupText(t, 2, "threshold", "", ""), "genesis_fork_version = 0x00000010\n", "genesis_fork_version = 0x00000000\n", 1))
	mustTool(t, "setup", "-out", filepath.Join(dir, "three"), threeFile)
}

// import-draft checks the split against the target's own rule
// (setupwire.CheckThresholdOn): a 1 of 1 order to a GCP signer whose setup
// does not accept it is refused as the runner would refuse it, and one to
// a GCP signer that accepts it is drafted only with
// -allow-gcp-unsafe-single-key, with the WARNING line. show of that order
// prints the same WARNING line to each approver when the active values
// name the target, and without them says that it cannot tell the
// platform. A 1 of 1 order to a dev signer needs no flag.
func TestImportDraftSingleGCP(t *testing.T) {
	const name = "gsigner-3"
	shared, section := signerSection(t, cloudSetupText(t, 2, "single", "", ""), name)
	dir := t.TempDir()
	file := writeFile(t, filepath.Join(dir, "setup.conf"), shared+"\n[signer "+name+"]"+section)
	mustTool(t, "setup", "-allow-gcp-unsafe-single-key", "-out", filepath.Join(dir, "setups"), file)
	raw := mustRead(t, filepath.Join(dir, "setups", name+".setup"))
	cl := fakeClusterOf(t, filepath.Join(dir, "accepted"), name, raw)
	_, _, splitPath := split(t, dir, 1, 1, []string{name})
	body := filepath.Join(dir, "import.bin")
	draft := []string{"import-draft", "-cluster", cl, "-signer", name, "-split", splitPath, "-out", body}
	wantIn(t, failTool(t, draft...), name+": a 1 of 1 order to a GCP signer", "IAM bindings", "-allow-gcp-unsafe-single-key confirms it")
	if _, err := os.Stat(body); err == nil {
		t.Fatal("the refused draft wrote the order")
	}
	out := mustTool(t, append(draft, "-allow-gcp-unsafe-single-key")...)
	wantIn(t, out, "WARNING "+name+": 1 of 1 on GCP", "no lock", "slashable", "import order for "+name, "1 of 1, share index 1", "order_sha256 ")
	wantIn(t, mustTool(t, "show", body), "t = 1", "n = 1", "target: "+name, "WARNING "+name+": 1 of 1 on GCP", "IAM bindings")
	alone := writeFile(t, filepath.Join(dir, "alone", "import.bin"), string(mustRead(t, body)))
	out = mustTool(t, "show", alone)
	wantIn(t, out, "1 of 1: the target holds the whole key", "UNSAFE")
	if strings.Contains(out, "WARNING") {
		t.Fatalf("show without the active values claims to know the platform:\n%s", out)
	}

	// A single-mode GCP setup without the acceptance is refused as a
	// setup (setupwire.Setup.Check), so no order to it can be drafted.
	s, err := setupwire.DecodeSetup(raw)
	if err != nil {
		t.Fatal(err)
	}
	s.Platform.SealingKeyRelease.UnsafeSingleKeyAccepted = false
	if _, err := s.Encode(); err == nil || !strings.Contains(err.Error(), "unsafe_single_key_accepted = true") {
		t.Fatalf("single-mode gcp setup without the acceptance: %v, want a refusal", err)
	}

	// A single-mode dev signer holds a key alone without any flag or
	// warning.
	devDir := t.TempDir()
	devConf := writeFile(t, filepath.Join(devDir, "setup.conf"), setupText(devDir, caDER(t), genesisTime(), lockedText(approvers(t, devDir, 3), 2, 0, fee1), "x1"))
	mustTool(t, "setup", "-out", filepath.Join(devDir, "setups"), devConf)
	devCl := fakeClusterOf(t, filepath.Join(devDir, "cl"), "x1", mustRead(t, filepath.Join(devDir, "setups", "x1.setup")))
	_, _, devSplit := split(t, devDir, 1, 1, []string{"x1"})
	devBody := filepath.Join(devDir, "dev.bin")
	out = mustTool(t, "import-draft", "-cluster", devCl, "-signer", "x1", "-split", devSplit, "-out", devBody)
	wantIn(t, out, "signing_mode single")
	if strings.Contains(out, "WARNING") {
		t.Fatalf("a 1 of 1 order to a dev signer warns:\n%s", out)
	}
	if out := mustTool(t, "show", devBody); strings.Contains(out, "WARNING") || strings.Contains(out, "holds the whole key") || !strings.Contains(out, "target signing_mode = single") {
		t.Fatalf("show of a 1 of 1 order to a dev signer, with its active values:\n%s", out)
	}
}

// import-draft refuses a split that does not fit the target's
// signing_mode, as its runner would (setupwire.CheckThresholdOn): 1 of 1
// to a signer of a threshold cluster, a share of a 2-of-3 split to a
// single-mode signer. show names the target's mode.
func TestImportDraftSigningMode(t *testing.T) {
	fc := newFakeCluster(t)
	mustTool(t, "pin", "-cluster", fc.cluster)
	_, _, one := split(t, fc.dir, 1, 1, []string{"s1"})
	wantIn(t, failTool(t, "import-draft", "-cluster", fc.cluster, "-signer", "s1", "-split", one, "-out", fc.path("one.bin")),
		"s1 (signing_mode threshold)", "signing_mode = threshold", "signing_mode = single")
	_, _, three := split(t, fc.dir, 2, 3, []string{"s1", "s2", "s3"})
	body := fc.path("three.bin")
	wantIn(t, mustTool(t, "import-draft", "-cluster", fc.cluster, "-signer", "s1", "-split", three, "-out", body), "signing_mode threshold", "2 of 3")
	wantIn(t, mustTool(t, "show", body), "target signing_mode = threshold")

	dir := t.TempDir()
	conf := writeFile(t, filepath.Join(dir, "setup.conf"), setupText(dir, caDER(t), genesisTime(), lockedText(approvers(t, dir, 3), 2, 0, fee1), "x1"))
	mustTool(t, "setup", "-out", filepath.Join(dir, "setups"), conf)
	raw := mustRead(t, filepath.Join(dir, "setups", "x1.setup"))
	cl := fakeClusterOf(t, filepath.Join(dir, "cl"), "x1", raw)
	_, _, share := split(t, dir, 2, 3, []string{"x1", "y", "z"})
	wantIn(t, failTool(t, "import-draft", "-cluster", cl, "-signer", "x1", "-split", share, "-out", filepath.Join(dir, "share.bin")),
		"x1 (signing_mode single)", "takes whole keys (1 of 1) only")
}

// signerSection cuts one signer's section out of a cluster file and
// returns the shared lines and the section's lines after its header.
func signerSection(t *testing.T, full, name string) (shared, section string) {
	t.Helper()
	shared, rest, ok := strings.Cut(full, "\n[signer gsigner-1]")
	if !ok {
		t.Fatal("cloudSetupText changed its sections")
	}
	_, section, ok = strings.Cut("[signer gsigner-1]"+rest, "[signer "+name+"]")
	if !ok {
		t.Fatalf("no section for %s", name)
	}
	section, _, _ = strings.Cut(section, "\n[signer ")
	return shared, section
}

// fakeClusterOf is the cluster.json of a cluster of one signer: a fake
// runner that serves the binary setup raw, its cloud.json, and the setup
// pinned.
func fakeClusterOf(t *testing.T, dir, name string, raw []byte) string {
	t.Helper()
	r := fakerunner.StartSetup(t, raw)
	cert, key := r.ClientFiles(t, t.TempDir())
	writeFile(t, filepath.Join(dir, name+".setup"), string(raw))
	writeJSONFile(t, filepath.Join(dir, name, "cloud.json"), map[string]any{
		"address": r.Addr(), "client_cert": cert, "client_key": key,
		"attestation": map[string]any{"verifier": "dev"},
	})
	cl := writeJSONFile(t, filepath.Join(dir, "cluster.json"), map[string]any{
		"signers": []any{map[string]string{"name": name, "cloud": name + "/cloud.json", "setup": name + ".setup"}}})
	mustTool(t, "pin", "-cluster", cl)
	return cl
}

// keyReleaseOf reads a binary setup and returns its sealing_key_release.
func keyReleaseOf(t *testing.T, path string) setupwire.KeyRelease {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	s, err := setupwire.DecodeSetup(raw)
	if err != nil {
		t.Fatal(err)
	}
	return s.Platform.SealingKeyRelease
}
