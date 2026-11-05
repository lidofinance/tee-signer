package backend

import (
	"errors"
	"fmt"
	"strconv"
	"sync"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/herumi/bls-eth-go-binary/bls"
)

var (
	blsOnce sync.Once
	blsErr  error
)

// initBLS sets herumi BLS up for Ethereum: BLS12-381 with the hash to curve
// and serialization of the consensus specs.
func initBLS() error {
	blsOnce.Do(func() {
		if blsErr = bls.Init(bls.BLS12_381); blsErr == nil {
			blsErr = bls.SetETHmode(bls.EthModeDraft07)
		}
	})

	return blsErr
}

// VerifyBLS checks sig over root for pubkey.
func VerifyBLS(pubkey phase0.BLSPubKey, root phase0.Root, sig phase0.BLSSignature) error {
	if err := initBLS(); err != nil {
		return fmt.Errorf("init BLS: %w", err)
	}
	var pk bls.PublicKey
	if err := pk.Deserialize(pubkey[:]); err != nil {
		return fmt.Errorf("public key: %w", err)
	}
	var s bls.Sign
	if err := s.Deserialize(sig[:]); err != nil {
		return fmt.Errorf("signature: %w", err)
	}
	if !s.VerifyByte(&pk, root[:]) {
		return errors.New("signature does not verify")
	}

	return nil
}

// shareID is the x coordinate of share index i, the point at which the
// split polynomial gives that share.
func shareID(i uint64) (bls.ID, error) {
	var id bls.ID
	if i == 0 {
		return id, errors.New("share index 0")
	}

	return id, id.SetDecString(strconv.FormatUint(i, 10))
}

func shareIDs(indices []uint64) ([]bls.ID, error) {
	ids := make([]bls.ID, len(indices))
	for i, x := range indices {
		var err error
		if ids[i], err = shareID(x); err != nil {
			return nil, err
		}
	}

	return ids, nil
}

// combine interpolates partial signatures at zero (Lagrange): t partials
// of a t-of-n split, with their share indices, give the validator
// signature.
func combine(indices []uint64, sigs []phase0.BLSSignature) (phase0.BLSSignature, error) {
	var out phase0.BLSSignature
	if err := initBLS(); err != nil {
		return out, err
	}
	ids, err := shareIDs(indices)
	if err != nil {
		return out, err
	}
	parts := make([]bls.Sign, len(sigs))
	for i := range sigs {
		if err := parts[i].Deserialize(sigs[i][:]); err != nil {
			return out, fmt.Errorf("partial signature %d: %w", i, err)
		}
	}
	var s bls.Sign
	if err := s.Recover(parts, ids); err != nil {
		return out, err
	}
	copy(out[:], s.Serialize())

	return out, nil
}

// recoverPubkey is combine for public keys: t share keys with their
// indices give the validator key.
func recoverPubkey(indices []uint64, keys []phase0.BLSPubKey) (phase0.BLSPubKey, error) {
	var out phase0.BLSPubKey
	if err := initBLS(); err != nil {
		return out, err
	}
	ids, err := shareIDs(indices)
	if err != nil {
		return out, err
	}
	parts := make([]bls.PublicKey, len(keys))
	for i := range keys {
		if err := parts[i].Deserialize(keys[i][:]); err != nil {
			return out, fmt.Errorf("share key %d: %w", i, err)
		}
	}
	var pk bls.PublicKey
	if err := pk.Recover(parts, ids); err != nil {
		return out, err
	}
	copy(out[:], pk.Serialize())

	return out, nil
}
