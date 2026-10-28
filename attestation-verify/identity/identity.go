//go:build !verifierselect

// Package identity checks a runner's attested identity
// (backend.Identity) with the verifiers in package attest. Config.Verify
// has the signature of remote.VerifyFunc, so a client passes it where it
// passes remote.DevVerifier today.
//
// How each platform binds the identity, from the runner's platform code:
//
//   - nitro: the NSM document carries the client nonce as nonce and
//     backend.IdentityUserData(nonce, id) as user_data.
//   - gcp: the token's eat_nonce carries hex(IdentityUserData).
//   - azure: the runner sends backend.MAARuntimeData(IdentityUserData), a
//     JSON object, to MAA as runtime data with dataType JSON; the SNP
//     report data is sha256 of those exact bytes followed by 32 zero bytes.
package identity

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/lidofinance/tee-signer/attestation-verify"
	"github.com/lidofinance/tee-signer/attestation-verify/azureid"
	"github.com/lidofinance/tee-signer/signer-protocol"
)

// Config holds one verifier config per platform the client accepts. A nil
// entry refuses that platform. Nonce, user data and runtime data fields
// are filled in per call; the rest (roots, keys, measurements, issuer,
// audience) comes from here.
type Config struct {
	Nitro *attest.NitroOptions
	GCP   *attest.ConfidentialSpaceOptions
	Azure *attest.MAAOptions
}

// Verify checks id.Attestation for nonce. It repeats the user data check
// remote.Client does, then verifies the platform document.
func (c Config) Verify(_ context.Context, nonce []byte, id *backend.Identity) error {
	if id == nil || id.Attestation == nil {
		return errors.New("identity: no attestation")
	}
	a := id.Attestation
	ud := backend.IdentityUserData(nonce, id)
	if !bytes.Equal(a.UserData, ud) {
		return errors.New("identity: attestation user data does not match the identity fields and nonce")
	}
	switch {
	case a.Platform == "nitro" && a.Format == "aws-nitro-cose-sign1":
		if c.Nitro == nil {
			return errors.New("identity: nitro not accepted by this config")
		}
		o := *c.Nitro
		o.Nonce, o.UserData = nonce, ud
		_, err := attest.VerifyNitro(a.Document, o)
		return err
	case a.Platform == "gcp" && a.Format == "gcp-confidential-space-jwt":
		if c.GCP == nil {
			return errors.New("identity: gcp not accepted by this config")
		}
		o := *c.GCP
		if o.Audience == attest.STSAudience {
			// A token with this audience can be exchanged at STS for the
			// workload's KMS access, so the runner must not hand one out
			// as its identity.
			return fmt.Errorf("%w: identity tokens must not use the STS audience", attest.ErrConfig)
		}
		o.Nonces = []string{hex.EncodeToString(ud)}
		_, err := attest.VerifyConfidentialSpace(string(a.Document), o)
		return err
	case a.Platform == "azure" && a.Format == "azure-maa-jwt":
		if c.Azure == nil {
			return errors.New("identity: azure not accepted by this config")
		}
		_, err := azureid.Verify(nonce, id, *c.Azure)
		return err
	}
	return fmt.Errorf("identity: platform %q format %q not supported", a.Platform, a.Format)
}
