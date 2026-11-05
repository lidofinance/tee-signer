package backend

import (
	"errors"
	"fmt"

	"github.com/attestantio/go-eth2-client/spec/phase0"

	"github.com/lidofinance/tee-signer/signer-core/core"
	"github.com/lidofinance/tee-signer/signer-core/threshold"
	proto "github.com/lidofinance/tee-signer/signer-protocol"
)

// VerifyBLS checks sig over root for pubkey with the signer core's blst
// check (Ethereum proof-of-possession ciphersuite). It refuses a public
// key at infinity and a key or signature outside its subgroup.
func VerifyBLS(pubkey phase0.BLSPubKey, root phase0.Root, sig phase0.BLSSignature) error {
	if !core.Verify(proto.Pubkey(pubkey), proto.Root(root), proto.Signature(sig)) {
		return errors.New("signature does not verify")
	}

	return nil
}

// checkIndices refuses share index 0: share i is the split polynomial's
// value at x = i, and the value at 0 is the secret itself.
func checkIndices(indices []uint64) error {
	for _, i := range indices {
		if i == 0 {
			return errors.New("share index 0")
		}
	}

	return nil
}

// combine interpolates partial signatures at zero (Lagrange): t partials
// of a t-of-n split, with their share indices, give the validator
// signature.
func combine(indices []uint64, sigs []phase0.BLSSignature) (phase0.BLSSignature, error) {
	if err := checkIndices(indices); err != nil {
		return phase0.BLSSignature{}, err
	}
	parts := make([]proto.Signature, len(sigs))
	for i := range sigs {
		parts[i] = proto.Signature(sigs[i])
	}
	s, err := threshold.RecoverSignature(indices, parts)
	if err != nil {
		return phase0.BLSSignature{}, fmt.Errorf("combine: %w", err)
	}

	return phase0.BLSSignature(s), nil
}

// recoverPubkey is combine for public keys: t share keys with their
// indices give the validator key.
func recoverPubkey(indices []uint64, keys []phase0.BLSPubKey) (phase0.BLSPubKey, error) {
	if err := checkIndices(indices); err != nil {
		return phase0.BLSPubKey{}, err
	}
	parts := make([]proto.Pubkey, len(keys))
	for i := range keys {
		parts[i] = proto.Pubkey(keys[i])
	}
	pk, err := threshold.RecoverPubkey(indices, parts)
	if err != nil {
		return phase0.BLSPubKey{}, fmt.Errorf("recover public key: %w", err)
	}

	return phase0.BLSPubKey(pk), nil
}
