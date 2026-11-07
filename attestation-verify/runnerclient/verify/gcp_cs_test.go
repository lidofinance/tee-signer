package verify

import (
	"testing"

	"github.com/lidofinance/tee-signer/attestation-verify"
)

func TestGCPDefaultIssuerIsGoogle(t *testing.T) {
	// Without gcp_issuer the verifier expects Google's issuer. No connection
	// here: that would ask Google for its key set.
	a := gcpGood("")
	s, err := a.gcp()
	if err != nil {
		t.Fatal(err)
	}
	if s.issuer != attest.ConfidentialSpaceIssuer || s.opts.Issuer != attest.ConfidentialSpaceIssuer {
		t.Fatalf("issuer %q, options issuer %q", s.issuer, s.opts.Issuer)
	}
	if s.pinned != nil {
		t.Fatal("a key set is pinned without gcp_jwks_file")
	}
}

// On mainnet a gcp-cs client takes GCP_INTEL_TDX only. AMD SEV and SEV-ES
// share the chip family of Azure's SEV-SNP, and a name Google may add
// later is refused until it is reviewed. Test chains keep any list.
func TestGCPMainnetTDXOnly(t *testing.T) {
	for _, models := range [][]string{
		{"GCP_AMD_SEV"},
		{"GCP_AMD_SEV_ES"},
		{"GCP_INTEL_TDX", "GCP_AMD_SEV"},
		{"GCP_AMD_SEV_SNP"},
		{"gcp_intel_tdx"},
	} {
		a := gcpGood("")
		a.GCPHWModels = models
		if _, err := a.gcp(); err != nil {
			t.Fatalf("%v, not mainnet: %v", models, err)
		}
		a.Mainnet = true
		_, err := a.gcp()
		wantErr(t, err, "a mainnet gcp-cs runner runs on GCP_INTEL_TDX only")
	}
	a := gcpGood("")
	a.Mainnet = true
	a.GCPHWModels = []string{"GCP_INTEL_TDX"}
	s, err := a.gcp()
	if err != nil {
		t.Fatalf("mainnet, GCP_INTEL_TDX: %v", err)
	}
	if len(s.opts.HWModels) != 1 || s.opts.HWModels[0] != "GCP_INTEL_TDX" {
		t.Fatalf("hwmodels %v", s.opts.HWModels)
	}
}
