//go:build !peerselect

package runnerclient

import (
	"bytes"
	"reflect"
	"strings"
	"testing"

	"github.com/lidofinance/tee-signer/attestation-verify"
)

// cloud.json settings -> order participant -> settings: the order carries
// what the verifier checks, with the setup pinned and the defaults filled
// in.
func TestOrderParticipantRoundTrip(t *testing.T) {
	setup, op := [32]byte{0x51}, [32]byte{0x52}
	pcr := func(b byte) string { return strings.Repeat(string("0123456789abcdef"[b%16])+"1", 48) }
	for _, a := range []Attestation{
		{Verifier: VerifierAWSNitro, NitroPCRs: map[string]string{"0": pcr(1), "1": pcr(2), "2": pcr(3), "3": pcr(4), "8": pcr(5)}},
		{Verifier: VerifierAWSNitro, NitroPCRs: map[string]string{"0": pcr(1), "1": pcr(2), "2": pcr(3), "3": pcr(4)}, NitroRootSHA256: attest.NitroRootSHA256},
		{Verifier: VerifierAzureMAA, MAAHost: "SharedNEU.neu.attest.azure.net", CCEPolicySHA256: strings.Repeat("ab", 32)},
		{Verifier: VerifierGCPCS, GCPImageDigest: "sha256:" + strings.Repeat("cd", 32), GCPAudience: "signer-runner-identity",
			GCPHWModels: []string{"GCP_INTEL_TDX", "GCP_AMD_SEV"}, GCPServiceAccount: "s@p.iam.gserviceaccount.com", GCPProjectID: "signer-project"},
		{Verifier: VerifierDev},
	} {
		p, err := a.OrderParticipant("x", setup, op)
		if err != nil {
			t.Fatalf("%s: %v", a.Verifier, err)
		}
		back := OrderAttestation(&p)
		if back.Verifier != a.Verifier || back.SetupSHA256 != strings.Repeat("51", 1)+strings.Repeat("00", 31) {
			t.Fatalf("%s: %+v", a.Verifier, back)
		}
		if err := back.Validate(); err != nil {
			t.Fatalf("%s: the settings from the order do not validate: %v", a.Verifier, err)
		}
		again, err := back.OrderParticipant("x", setup, op)
		if err != nil || !reflect.DeepEqual(again, p) {
			t.Fatalf("%s: second trip %+v %v", a.Verifier, again, err)
		}
		switch a.Verifier {
		case VerifierAzureMAA:
			if p.MAAHost != "sharedneu.neu.attest.azure.net" || p.Compliance.String() != attest.ComplianceACI {
				t.Fatalf("azure defaults: %+v", p)
			}
		case VerifierGCPCS:
			if p.GCPIssuer != attest.ConfidentialSpaceIssuer || p.GCPHWModels[0] != "GCP_AMD_SEV" {
				t.Fatalf("gcp defaults: %+v", p)
			}
		case VerifierAWSNitro:
			if !bytes.Equal(p.Image[:2], []byte{0x11, 0x11}) {
				t.Fatalf("nitro image %x", p.Image[:4])
			}
		}
	}
}

func TestOrderParticipantRefusals(t *testing.T) {
	pcrs := map[string]string{"0": strings.Repeat("11", 48), "1": strings.Repeat("22", 48), "2": strings.Repeat("33", 48)}
	for _, c := range []struct {
		a    Attestation
		want string
	}{
		{Attestation{Verifier: VerifierAWSNitro, NitroPCRs: pcrs}, "PCR3"},
		{Attestation{Verifier: VerifierAWSNitro, NitroPCRs: map[string]string{"0": pcrs["0"], "1": pcrs["1"], "2": pcrs["2"], "3": pcrs["0"], "4": pcrs["0"]}}, "PCR4"},
		{Attestation{Verifier: VerifierAWSNitro, NitroPCRs: pcrs, NitroRootSHA256: strings.Repeat("00", 32)}, "AWS's root only"},
		{Attestation{Verifier: VerifierGCPCS, GCPImageDigest: strings.Repeat("cd", 32), GCPAudience: "a", GCPHWModels: []string{"GCP_AMD_SEV"}}, "gcp_project_id"},
		{Attestation{Verifier: VerifierGCPCS, GCPJWKSFile: "keys.json"}, "key set file"},
		{Attestation{Verifier: VerifierDev, AllowUnpinnedSetup: true}, "always pins"},
		{Attestation{Verifier: VerifierDev, MAAHost: "x"}, "belong to the verifier"},
	} {
		if _, err := c.a.OrderParticipant("x", [32]byte{1}, [32]byte{2}); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%+v: got %v, want %q", c.a, err, c.want)
		}
	}
}

// The hosts each verifier fetches its key set from: what a Nitro runner's
// setup must list in keygen_peer_attestation_hosts for that peer.
func TestEndpoints(t *testing.T) {
	cs := []string{"confidentialcomputing.googleapis.com:443", "www.googleapis.com:443"}
	for _, c := range []struct {
		a    Attestation
		want []string
	}{
		{Attestation{Verifier: VerifierAzureMAA, MAAHost: "SharedNEU.neu.attest.azure.net"}, []string{"sharedneu.neu.attest.azure.net:443"}},
		{Attestation{Verifier: VerifierAzureMAA, MAAHost: "127.0.0.1:8443"}, []string{"127.0.0.1:8443"}},
		{Attestation{Verifier: VerifierGCPCS}, cs},
		{Attestation{Verifier: VerifierGCPCS, GCPIssuer: attest.ConfidentialSpaceIssuer}, cs},
		{Attestation{Verifier: VerifierGCPCS, GCPIssuer: "https://issuer.example"}, []string{"issuer.example:443"}},
		{Attestation{Verifier: VerifierGCPCS, GCPIssuer: "https://issuer.example:8443"}, []string{"issuer.example:8443"}},
		{Attestation{Verifier: VerifierGCPCS, GCPJWKSFile: "keys.json"}, nil},
		{Attestation{Verifier: VerifierAWSNitro}, nil},
		{Attestation{Verifier: VerifierDev}, nil},
	} {
		if got := c.a.Endpoints(); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%+v: %v, want %v", c.a, got, c.want)
		}
	}
	// The constants are the hosts of attest's issuer and key set URL.
	for _, u := range []string{attest.ConfidentialSpaceIssuer, attest.ConfidentialSpaceJWKSURL} {
		host := strings.SplitN(strings.TrimPrefix(u, "https://"), "/", 2)[0] + ":443"
		if host != cs[0] && host != cs[1] {
			t.Fatalf("%s: host %s is not in %v", u, host, cs)
		}
	}
	// An order's participant gives the same list as its cloud.json settings.
	a := Attestation{Verifier: VerifierGCPCS, GCPImageDigest: "sha256:" + strings.Repeat("cd", 32), GCPAudience: "signer-runner-identity",
		GCPHWModels: []string{"GCP_AMD_SEV"}, GCPServiceAccount: "s@p.iam.gserviceaccount.com", GCPProjectID: "signer-project"}
	p, err := a.OrderParticipant("g", [32]byte{1}, [32]byte{2})
	if err != nil {
		t.Fatal(err)
	}
	back := OrderAttestation(&p)
	if got := back.Endpoints(); !reflect.DeepEqual(got, cs) {
		t.Fatalf("from the order: %v", got)
	}
}
