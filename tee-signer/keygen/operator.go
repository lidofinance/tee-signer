package keygen

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"

	"github.com/lidofinance/tee-signer/platform"
	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/dkgmsg"
)

// The operator key binds a DKG position to an operator, where attestation
// binds it only to an image. The runner makes it once and keeps it sealed
// in its store, so only a runner that unseals that operator's storage has
// it: on the clouds the sealing key comes from the operator's own KMS key or
// Key Vault, released only to the attested image (runner/platform). The
// operator reads the public key over an attested connection
// (DKG_OPERATOR, dkg-coordinator operator-keys) and puts it in the policy at
// its position; every runner then checks each hello's key against it.
//
// What it does not stop: the operator's own cloud account. Whoever can make
// that account's KMS release the sealing key to a runner of the approved
// image controls this key, which is the operator by definition. A host that
// deletes the sealed key makes the runner draw a new one, which no longer
// matches the policy: the runner then takes no part in key generation.

const operatorKeyName = "operator/key"

var operatorKeyAAD = []byte("signer-operator-key-v1")

// OperatorKeys holds the runner's operator key.
type OperatorKeys struct {
	pub      [32]byte
	attester platform.Attester
}

// LoadOperatorKeys unseals the operator key, or makes and seals one on the
// first start.
func LoadOperatorKeys(sealer platform.Sealer, store platform.Store, att platform.Attester) (*OperatorKeys, error) {
	blob, err := store.Get(operatorKeyName)
	switch {
	case errors.Is(err, platform.ErrNotFound):
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		defer clear(priv)
		blob, err = sealer.Seal(priv.Seed(), operatorKeyAAD)
		if err != nil {
			return nil, err
		}
		if err := store.Put(operatorKeyName, blob); err != nil {
			return nil, err
		}
	case err != nil:
		return nil, err
	}
	seed, err := sealer.Unseal(blob, operatorKeyAAD)
	if err != nil {
		return nil, errors.New("operator key: unseal failed (stored by another runner, or changed)")
	}
	defer clear(seed)
	if len(seed) != ed25519.SeedSize {
		return nil, errors.New("operator key: bad record")
	}
	priv := ed25519.NewKeyFromSeed(seed)
	defer clear(priv)
	k := &OperatorKeys{attester: att}
	copy(k.pub[:], priv.Public().(ed25519.PublicKey))
	return k, nil
}

// Public is the operator key.
func (k *OperatorKeys) Public() [32]byte { return k.pub }

// PublicHex is the operator key as the policy writes it.
func (k *OperatorKeys) PublicHex() string { return hex.EncodeToString(k.pub[:]) }

// Answer is the DKG_OPERATOR response: the key and an attested identity
// whose nonce covers the relay's nonce and the key, under the operator
// context (backend.DKGOperatorUserData), not IDENTITY's.
func (k *OperatorKeys) Answer(ctx context.Context, q *dkgmsg.OperatorRequest, state backend.SetupState, tlsKeyHash []byte) ([]byte, error) {
	info := &dkgmsg.OperatorInfo{Nonce: q.Nonce, Key: k.pub,
		Identity: &backend.Identity{State: state, TLSKeyHash: tlsKeyHash}}
	nonce := info.AttestNonce()
	a, err := k.attester.Attest(ctx, nonce, backend.DKGOperatorUserData(nonce, info.Identity))
	if err != nil {
		return nil, backend.Refused(backend.StatusPlatform, "attest: %v", err)
	}
	info.Identity.Attestation = a
	return info.Encode()
}
