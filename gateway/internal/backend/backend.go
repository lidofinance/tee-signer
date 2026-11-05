// Package backend is the signing side of the gateway. It sends each request
// to the TEE signers over mutual TLS, checks every partial signature and
// combines a threshold of them into the validator signature.
package backend

import (
	"context"
	"errors"

	"github.com/attestantio/go-eth2-client/spec/phase0"

	"github.com/lidofinance/tee-signer/web3signer-api/signing"
)

// ErrUnknownKey means no signer holds the requested public key (HTTP 404).
var ErrUnknownKey = errors.New("unknown public key")

// DeniedError means the signers refused, normally on slashing protection
// or policy (HTTP 412).
type DeniedError struct{ Detail string }

func (e *DeniedError) Error() string { return "signing denied: " + e.Detail }

// Signer signs on behalf of validator public keys.
type Signer interface {
	// PublicKeys lists the validator public keys.
	PublicKeys(ctx context.Context) []phase0.BLSPubKey
	// HasKey reports whether pubkey can be signed for.
	HasKey(ctx context.Context, pubkey phase0.BLSPubKey) bool
	// Sign returns the validator signature over job.SigningRoot.
	Sign(ctx context.Context, pubkey phase0.BLSPubKey, job *signing.Job) (phase0.BLSSignature, error)
}
