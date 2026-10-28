//go:build !peerselect || peer_dev

package runnerclient

import (
	"context"

	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/remote"
)

func init() {
	verifierFactories[VerifierDev] = func(*Attestation, *options) (remote.VerifyFunc, error) {
		return remote.DevVerifier, nil
	}
	documentFactories[VerifierDev] = func(*Attestation, *options) (DocumentVerifier, error) {
		return verifyDevDocument, nil
	}
}

// verifyDevDocument checks the dev platform's unsigned document for nonce
// and userData. It proves nothing about the code that made it.
func verifyDevDocument(ctx context.Context, nonce, userData []byte, a *backend.Attestation) error {
	if err := checkUserData(userData, a, "dev", "dev-json", "the dev platform's document"); err != nil {
		return err
	}
	return remote.DevVerifier(ctx, nonce, &backend.Identity{Attestation: a})
}
