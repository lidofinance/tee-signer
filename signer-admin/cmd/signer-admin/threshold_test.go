package main

import (
	"encoding/base64"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

// cloudSetupText is the runbook's cluster file
// (governance/docs/setup-phase-cloud-test.md, step 0): an Azure signer on
// sharedneu, a Nitro signer with the lines nitroExtra, and a GCP signer.
// format is the shared format line's value.
func cloudSetupText(t *testing.T, format int, nitroExtra, azureExtra string) string {
	t.Helper()
	dir := t.TempDir()
	keys := approvers(t, dir, 3)
	var b strings.Builder
	fmt.Fprintf(&b, `setup_format_version = %d
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
`, format, genesisTime(), secondsPerSlot, slotsPerEpoch, base64.StdEncoding.EncodeToString(caDER(t)))
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
// hold keys 1 of 1, which a GCP signer refuses on every chain. The refusal
// comes when the setup is made, not at the first order. One dev signer on
// a test chain still makes a setup.
func TestSetupSingleSignerOnEveryPlatform(t *testing.T) {
	full := cloudSetupText(t, 1, "", "")
	shared, rest, ok := strings.Cut(full, "\n[signer gsigner-1]")
	if !ok {
		t.Fatal("cloudSetupText changed its sections")
	}
	for _, name := range []string{"gsigner-1", "gsigner-2", "gsigner-3"} {
		_, section, ok := strings.Cut("[signer gsigner-1]"+rest, "[signer "+name+"]")
		if !ok {
			t.Fatalf("no section for %s", name)
		}
		section, _, _ = strings.Cut(section, "\n[signer ")
		dir := t.TempDir()
		file := writeFile(t, filepath.Join(dir, "setup.conf"), shared+"\n[signer "+name+"]"+section)
		if strings.Contains(section, "platform = gcp") {
			wantIn(t, failTool(t, "setup", "-out", filepath.Join(dir, "setups"), file), name, "single-node signer on GCP")
			continue
		}
		wantIn(t, mustTool(t, "setup", "-out", filepath.Join(dir, "setups"), file), name+" setup_sha256")
	}

	dir := t.TempDir()
	one := writeFile(t, filepath.Join(dir, "one.conf"), setupText(dir, caDER(t), genesisTime(), lockedText(approvers(t, dir, 3), 2, 0, fee1), "s1"))
	mustTool(t, "setup", "-out", filepath.Join(dir, "setups"), one)
}
