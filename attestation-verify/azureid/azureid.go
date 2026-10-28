//go:build !peerselect || peer_azure

// Package azureid checks the MAA token in an Azure runner's IDENTITY
// response. It turns the identity and the client's nonce into the runtime
// data that attest.VerifyMAA wants, in one place, so identity.Config and
// runnerclient check an Azure runner the same way.
package azureid

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/lidofinance/tee-signer/attestation-verify"
	"github.com/lidofinance/tee-signer/signer-protocol"
)

// Platform and Format are what an Azure runner puts in its attestation.
const (
	Platform = "azure"
	Format   = "azure-maa-jwt"
)

// Check makes the checks that need no key set: id carries an Azure MAA
// token, and its user data is what backend.IdentityUserData gives for the
// identity fields and nonce. A client calls it before it fetches the
// provider's keys.
func Check(nonce []byte, id *backend.Identity) error {
	if id == nil || id.Attestation == nil {
		return errors.New("azureid: no attestation")
	}
	a := id.Attestation
	if a.Platform != Platform || a.Format != Format {
		return fmt.Errorf("azureid: platform %q format %q is not an Azure MAA token", a.Platform, a.Format)
	}
	if !bytes.Equal(a.UserData, backend.IdentityUserData(nonce, id)) {
		return errors.New("azureid: attestation user data does not match the identity fields and nonce")
	}
	return nil
}

// Verify runs Check and verifies the token with o. It sets o.RuntimeData
// itself: the JSON object backend.MAARuntimeData(user data), which the
// runner sends to MAA and which MAA hashes into the SNP report data. A token for other runtime data, so for another identity or nonce,
// fails with attest.ErrNonce.
func Verify(nonce []byte, id *backend.Identity, o attest.MAAOptions) (*attest.MAAToken, error) {
	if err := Check(nonce, id); err != nil {
		return nil, err
	}
	o.RuntimeData = backend.MAARuntimeData(id.Attestation.UserData)
	return attest.VerifyMAA(string(id.Attestation.Document), o)
}
