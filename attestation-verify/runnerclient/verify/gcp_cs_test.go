//go:build !verifierselect

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
