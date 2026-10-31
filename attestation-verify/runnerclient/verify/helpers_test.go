//go:build !verifierselect

package verify

import (
	"encoding/hex"

	"github.com/lidofinance/tee-signer/signer-protocol"
)

// Copies of runnerclient's test settings, for the tests of this package's
// unexported parts.

var testSetupHash = backend.Root{0x5e, 0x70}

func pinOf(r backend.Root) string { return hex.EncodeToString(r[:]) }

const (
	gcpDigest   = "sha256:1f0a6d4b3c2e9a8b7c6d5e4f30211a2b3c4d5e6f708192a3b4c5d6e7f8091a2b"
	gcpAudience = "signer-runner-identity"
)

func gcpGood(issuer string) Attestation {
	return Attestation{
		Verifier: VerifierGCPCS, GCPImageDigest: gcpDigest, GCPAudience: gcpAudience,
		GCPHWModels: []string{"GCP_AMD_SEV", "GCP_INTEL_TDX"}, GCPIssuer: issuer,
	}
}
