// Package attest verifies the attestation documents the cloud runner
// returns: AWS Nitro NSM documents (COSE_Sign1), Google Confidential Space
// tokens and Microsoft Azure Attestation tokens (both JWT).
//
// Every verifier fails closed: it needs the trust anchors (root
// certificate or key set), the expected measurements and a freshness
// input (nonce or maximum age) from the caller, and returns an error that
// wraps one of the sentinel errors below. See README.md for what was
// tested against real documents and what only against synthetic ones.
package attest

import (
	"errors"
	"time"
)

var (
	// ErrFormat: the document does not parse or misses a required field.
	ErrFormat = errors.New("attest: malformed document")
	// ErrConfig: the options leave a required check unset.
	ErrConfig = errors.New("attest: incomplete verifier config")
	// ErrSignature: the signature does not verify.
	ErrSignature = errors.New("attest: bad signature")
	// ErrChain: the signing certificate does not chain to a pinned root.
	ErrChain = errors.New("attest: certificate chain not trusted")
	// ErrUnknownKey: the token names a key that is not in the key set.
	ErrUnknownKey = errors.New("attest: signing key not in the key set")
	// ErrIssuer: the token comes from another issuer.
	ErrIssuer = errors.New("attest: wrong issuer")
	// ErrAudience: the token is meant for another audience.
	ErrAudience = errors.New("attest: wrong audience")
	// ErrExpired: the token is expired or not yet valid.
	ErrExpired = errors.New("attest: token outside its validity window")
	// ErrStale: the document is older than the allowed age or dated in
	// the future.
	ErrStale = errors.New("attest: document not fresh")
	// ErrNonce: the document does not carry the expected nonce.
	ErrNonce = errors.New("attest: nonce mismatch")
	// ErrUserData: the document does not carry the expected user data.
	ErrUserData = errors.New("attest: user data mismatch")
	// ErrMeasurement: a PCR, image digest, host data or launch measurement
	// differs from the expected value.
	ErrMeasurement = errors.New("attest: measurement mismatch")
	// ErrDebug: the TEE runs in debug mode.
	ErrDebug = errors.New("attest: debug mode")
	// ErrClaim: another required claim is missing or wrong.
	ErrClaim = errors.New("attest: claim check failed")
)

// DefaultSkew is the clock difference allowed between the verifier and
// the issuer when the options leave Skew at zero. It is a config choice,
// not a measured value.
const DefaultSkew = time.Minute

func nowOr(t time.Time) time.Time {
	if t.IsZero() {
		return time.Now()
	}
	return t
}

func skewOr(d time.Duration) time.Duration {
	if d == 0 {
		return DefaultSkew
	}
	return d
}
