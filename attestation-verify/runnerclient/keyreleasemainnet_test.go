//go:build !peerselect

package runnerclient

import (
	"strings"
	"testing"

	"github.com/lidofinance/tee-signer/signer-protocol"
)

// On mainnet an Azure or Nitro signer is
// reached only with key_release_sha256 pinned. On other chains the pin
// stays optional, and GCP, whose key rule has no lock and whose
// key_release_hash is always zero, never needs it.
func TestKeyReleasePinMandatoryOnMainnet(t *testing.T) {
	setup := pinOf(testSetupHash)
	pin := pinOf(backend.Root{7})
	for _, c := range []struct {
		verifier string
		mainnet  bool
		pin      string
		want     string
	}{
		{VerifierAzureMAA, true, "", "mainnet: an azure-maa runner needs key_release_sha256"},
		{VerifierAWSNitro, true, "", "mainnet: an aws-nitro runner needs key_release_sha256"},
		{VerifierAzureMAA, true, pin, ""},
		{VerifierAWSNitro, true, pin, ""},
		{VerifierAzureMAA, false, "", ""},
		{VerifierAWSNitro, false, "", ""},
		{VerifierGCPCS, true, "", ""},
		{VerifierGCPCS, false, "", ""},
	} {
		a := Attestation{Verifier: c.verifier, SetupSHA256: setup, Mainnet: c.mainnet, KeyReleaseSHA256: c.pin}
		_, err := a.setupPins()
		switch {
		case c.want == "" && err != nil:
			t.Errorf("%s mainnet %v pin %q: %v", c.verifier, c.mainnet, c.pin, err)
		case c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)):
			t.Errorf("%s mainnet %v pin %q: %v, want %q", c.verifier, c.mainnet, c.pin, err, c.want)
		}
	}
}
