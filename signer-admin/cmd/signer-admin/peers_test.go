package main

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/lidofinance/tee-signer/governance/dkgorder"
	"github.com/lidofinance/tee-signer/governance/setupwire"
)

// cloudSetupText is the runbook's cluster file
// (governance/docs/setup-phase-cloud-test.md, step 0): an Azure signer on sharedneu, a Nitro signer
// with the lines nitroExtra, and a GCP signer. format is the shared format
// line's value.
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

const peerLines = `keygen_peer_attestation_hosts = sharedneu.neu.attest.azure.net:443
keygen_peer_attestation_hosts = confidentialcomputing.googleapis.com:443
keygen_peer_attestation_hosts = www.googleapis.com:443
`

// signer-admin setup passes keygen_peer_attestation_hosts through to the
// Nitro signer's setup; every setup is format 5. Without the list it warns
// with the lines the Nitro setup needs for its peers.
func TestSetupPeerEndpoints(t *testing.T) {
	file := writeFile(t, filepath.Join(t.TempDir(), "setup.conf"), cloudSetupText(t, 1, "", ""))
	out := mustTool(t, "setup", "-out", filepath.Join(t.TempDir(), "setups"), file)
	wantIn(t, out, "gsigner-2 keygen_peer_attestation_hosts none\n",
		"warning: signer gsigner-2 (nitro) reaches only the hosts of its keygen_peer_attestation_hosts, so its key generation refuses orders with these peers; its setup needs:\n"+
			"  keygen_peer_attestation_hosts = confidentialcomputing.googleapis.com:443   # gsigner-3, gcp-cs\n"+
			"  keygen_peer_attestation_hosts = sharedneu.neu.attest.azure.net:443   # gsigner-1, azure-maa\n"+
			"  keygen_peer_attestation_hosts = www.googleapis.com:443   # gsigner-3, gcp-cs\n")
	if len(setupHashes(out)) != 3 {
		t.Fatalf("setup lines:\n%s", out)
	}

	dir := filepath.Join(t.TempDir(), "setups")
	file = writeFile(t, filepath.Join(t.TempDir(), "setup.conf"), cloudSetupText(t, 1, peerLines, ""))
	out = mustTool(t, "setup", "-out", dir, file)
	wantIn(t, out, "gsigner-2 keygen_peer_attestation_hosts confidentialcomputing.googleapis.com:443 sharedneu.neu.attest.azure.net:443 www.googleapis.com:443\n")
	if strings.Contains(out, "warning") {
		t.Fatalf("warning with every endpoint listed:\n%s", out)
	}
	for name, format := range map[string]byte{"gsigner-1": 1, "gsigner-2": 1, "gsigner-3": 1} {
		raw := mustRead(t, filepath.Join(dir, name+".setup"))
		s, err := setupwire.DecodeSetup(raw)
		if err != nil || raw[1] != format {
			t.Fatalf("%s: format %d, %v", name, raw[1], err)
		}
		if want := name == "gsigner-2"; want != (len(s.Platform.KeygenPeerAttestationHosts) == 3) {
			t.Fatalf("%s: keygen_peer_attestation_hosts %v", name, s.Platform.KeygenPeerAttestationHosts)
		}
	}

	for _, c := range []struct{ name, text, want string }{
		{"format 2", cloudSetupText(t, 2, peerLines, ""), `setup_format_version: "2", want 1`},
		{"on azure", cloudSetupText(t, 1, "", "keygen_peer_attestation_hosts = www.googleapis.com:443\n"), "keygen_peer_attestation_hosts is for nitro and dev"},
		{"not host:port", cloudSetupText(t, 1, "keygen_peer_attestation_hosts = https://sharedneu.neu.attest.azure.net\n", ""), "want host:port"},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := writeFile(t, filepath.Join(t.TempDir(), "setup.conf"), c.text)
			wantIn(t, failTool(t, "setup", "-out", filepath.Join(t.TempDir(), "setups"), f), c.want)
		})
	}
}

// dkg-draft's check: for each signer with limited egress, the lines its
// setup lacks for the order's participants (from their cloud.json
// settings), itself left out.
func TestOrderPeerEndpoints(t *testing.T) {
	setups := func(nitroExtra string) []*setupwire.Setup {
		dir := filepath.Join(t.TempDir(), "setups")
		mustTool(t, "setup", "-out", dir, writeFile(t, filepath.Join(t.TempDir(), "setup.conf"), cloudSetupText(t, 1, nitroExtra, "")))
		var out []*setupwire.Setup
		for _, n := range []string{"gsigner-1", "gsigner-2", "gsigner-3"} {
			b, err := os.ReadFile(filepath.Join(dir, n+".setup"))
			if err != nil {
				t.Fatal(err)
			}
			s, err := setupwire.DecodeSetup(b)
			if err != nil {
				t.Fatal(err)
			}
			out = append(out, s)
		}
		return out
	}
	parts := []dkgorder.Participant{
		{Name: "gsigner-1", Verifier: dkgorder.VerifierAzure, MAAHost: "sharedneu.neu.attest.azure.net"},
		{Name: "gsigner-2", Verifier: dkgorder.VerifierNitro, Image: make([]byte, 144)},
		{Name: "gsigner-3", Verifier: dkgorder.VerifierGCP, GCPIssuer: "https://confidentialcomputing.googleapis.com"},
	}
	peers := make([]peerHosts, len(parts))
	for i := range parts {
		peers[i] = orderPeer(&parts[i])
	}
	bare := setups("")
	if m := missingPeerEndpoints(bare[1], peers, 1); !slices.Equal(m, []string{
		"keygen_peer_attestation_hosts = confidentialcomputing.googleapis.com:443   # gsigner-3, gcp-cs",
		"keygen_peer_attestation_hosts = sharedneu.neu.attest.azure.net:443   # gsigner-1, azure-maa",
		"keygen_peer_attestation_hosts = www.googleapis.com:443   # gsigner-3, gcp-cs",
	}) {
		t.Fatalf("nitro without endpoints: %q", m)
	}
	for _, i := range []int{0, 2} {
		if m := missingPeerEndpoints(bare[i], peers, i); m != nil {
			t.Fatalf("%s: %q", bare[i].SignerName, m)
		}
	}
	if m := missingPeerEndpoints(setups(peerLines)[1], peers, 1); m != nil {
		t.Fatalf("nitro with every endpoint: %q", m)
	}
	// Another MAA host than the setup lists.
	parts[0].MAAHost = "sharedweu.weu.attest.azure.net"
	peers[0] = orderPeer(&parts[0])
	if m := missingPeerEndpoints(setups(peerLines)[1], peers, 1); !slices.Equal(m, []string{
		"keygen_peer_attestation_hosts = sharedweu.weu.attest.azure.net:443   # gsigner-1, azure-maa"}) {
		t.Fatalf("other MAA host: %q", m)
	}
}
