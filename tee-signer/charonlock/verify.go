package charonlock

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"

	"github.com/lidofinance/tee-signer/signer-core/core"
	"github.com/lidofinance/tee-signer/signer-core/dkgmath"
	"github.com/lidofinance/tee-signer/signer-core/threshold"
	"github.com/lidofinance/tee-signer/signer-protocol"
)

// The BLS checks `charon run` makes on a lock (research/charon-tee-dkg.md,
// items 4 to 6), plus the deposit signatures, which Charon only hashes. The
// node signatures (secp256k1) are checked by the lock tool, which has the
// curve.

func pubkey(b Hex) (backend.Pubkey, error) {
	var pk backend.Pubkey
	if len(b) != len(pk) {
		return pk, errors.New("not 48 bytes")
	}
	copy(pk[:], b)
	return pk, nil
}

func signature(b Hex) (backend.Signature, error) {
	var s backend.Signature
	if len(b) != len(s) {
		return s, errors.New("not 96 bytes")
	}
	copy(s[:], b)
	return s, nil
}

// ForkVersion returns the definition's fork version.
func (d *Definition) Fork() (backend.Version, error) {
	var v backend.Version
	if len(d.ForkVersion) != len(v) {
		return v, errors.New("charonlock: fork_version is not 4 bytes")
	}
	copy(v[:], d.ForkVersion)
	return v, nil
}

// Shares returns validator i's group key and public shares.
func (l *Lock) Shares(i int) (backend.Pubkey, []backend.Pubkey, error) {
	v := &l.Validators[i]
	gk, err := pubkey(v.PubKey)
	if err != nil {
		return gk, nil, fmt.Errorf("validator %d key: %w", i, err)
	}
	var shares []backend.Pubkey
	for j, s := range v.PubShares {
		p, err := pubkey(s)
		if err != nil {
			return gk, nil, fmt.Errorf("validator %d share %d: %w", i, j, err)
		}
		shares = append(shares, p)
	}
	return gk, shares, nil
}

// VerifyShares checks one public share per operator, no repeated key or
// share, and that the shares are those of one polynomial of degree t-1 at
// x = 1..n with the validator key at 0.
func (l *Lock) VerifyShares() error {
	d := &l.Definition
	t, n := d.Threshold, len(d.Operators)
	if t < 1 || t > n {
		return fmt.Errorf("charonlock: threshold %d of %d", t, n)
	}
	seen := map[backend.Pubkey]bool{}
	for i := range l.Validators {
		gk, shares, err := l.Shares(i)
		if err != nil {
			return err
		}
		if seen[gk] {
			return fmt.Errorf("charonlock: validator %d key repeats", i)
		}
		seen[gk] = true
		if len(shares) != n {
			return fmt.Errorf("charonlock: validator %d has %d public shares for %d operators", i, len(shares), n)
		}
		dup := map[backend.Pubkey]bool{}
		for _, s := range shares {
			if dup[s] {
				return fmt.Errorf("charonlock: validator %d: a public share repeats", i)
			}
			dup[s] = true
		}
		ids := make([]uint64, t)
		for k := range ids {
			ids[k] = uint64(k + 1)
		}
		check := func(ids []uint64) error {
			pks := make([]backend.Pubkey, len(ids))
			for k, x := range ids {
				pks[k] = shares[x-1]
			}
			got, err := threshold.RecoverPubkey(ids, pks)
			if err != nil || got != gk {
				return fmt.Errorf("charonlock: validator %d: shares %v do not give the validator key", i, ids)
			}
			return nil
		}
		if err := check(ids); err != nil {
			return err
		}
		for x := t + 1; x <= n; x++ {
			if err := check(append(append([]uint64(nil), ids[:t-1]...), uint64(x))); err != nil {
				return err
			}
		}
	}
	return nil
}

// RegistrationMessage is the registration Charon checks: the definition's
// fee recipient, the lock's gas limit and timestamp, the validator key.
func (l *Lock) RegistrationMessage(i int) (*backend.ValidatorRegistration, error) {
	if i >= len(l.Definition.Validators) {
		return nil, fmt.Errorf("charonlock: no addresses for validator %d", i)
	}
	fee, err := Address(l.Definition.Validators[i].FeeRecipientAddress)
	if err != nil {
		return nil, err
	}
	gk, err := pubkey(l.Validators[i].PubKey)
	if err != nil {
		return nil, err
	}
	r := &l.Validators[i].BuilderRegistration.Message
	if r.GasLimit == 0 || r.Timestamp == 0 || len(r.FeeRecipient) != 20 || len(r.PubKey) != 48 {
		return nil, fmt.Errorf("charonlock: validator %d: registration incomplete", i)
	}
	return &backend.ValidatorRegistration{FeeRecipient: fee, GasLimit: r.GasLimit, Timestamp: r.Timestamp, Pubkey: gk}, nil
}

// VerifyRegistrations checks each validator's registration signature under
// its key, over the message Charon rebuilds.
func (l *Lock) VerifyRegistrations() error {
	fork, err := l.Definition.Fork()
	if err != nil {
		return err
	}
	for i := range l.Validators {
		m, err := l.RegistrationMessage(i)
		if err != nil {
			return err
		}
		root, err := RegistrationSigningRoot(m, fork)
		if err != nil {
			return err
		}
		sig, err := signature(l.Validators[i].BuilderRegistration.Signature)
		if err != nil || !core.Verify(m.Pubkey, root, sig) {
			return fmt.Errorf("charonlock: validator %d: builder registration signature does not verify", i)
		}
	}
	return nil
}

// VerifyDeposits checks each deposit: the validator's key, and a signature
// under it over the deposit message with the genesis fork version.
func (l *Lock) VerifyDeposits() error {
	fork, err := l.Definition.Fork()
	if err != nil {
		return err
	}
	for i := range l.Validators {
		gk, _ := pubkey(l.Validators[i].PubKey)
		for j, d := range l.Validators[i].PartialDepositData {
			if !bytes.Equal(d.PubKey, gk[:]) || len(d.WithdrawalCredentials) != 32 {
				return fmt.Errorf("charonlock: validator %d deposit %d: other key or bad credentials", i, j)
			}
			var wc backend.Root
			copy(wc[:], d.WithdrawalCredentials)
			sig, err := signature(d.Signature)
			if err != nil || !core.Verify(gk, DepositSigningRoot(gk, wc, d.Amount, fork), sig) {
				return fmt.Errorf("charonlock: validator %d deposit %d: signature does not verify", i, j)
			}
		}
	}
	return nil
}

// AggregateShares is the sum of every public share of every validator, the
// key signature_aggregate verifies under.
func (l *Lock) AggregateShares() (backend.Pubkey, error) {
	var pts []backend.Pubkey
	var ones []*big.Int
	for i := range l.Validators {
		_, shares, err := l.Shares(i)
		if err != nil {
			return backend.Pubkey{}, err
		}
		for _, s := range shares {
			pts = append(pts, s)
			ones = append(ones, big.NewInt(1))
		}
	}
	return dkgmath.G1LinComb(pts, ones)
}

// VerifyAggregate checks signature_aggregate: every share signed the raw
// lock hash.
func (l *Lock) VerifyAggregate() error {
	agg, err := l.AggregateShares()
	if err != nil {
		return err
	}
	var lh backend.Root
	if len(l.LockHash) != 32 {
		return errors.New("charonlock: lock_hash is not 32 bytes")
	}
	copy(lh[:], l.LockHash)
	sig, err := signature(l.SignatureAggregate)
	if err != nil || !core.Verify(agg, lh, sig) {
		return errors.New("charonlock: signature_aggregate does not verify")
	}
	return nil
}

// VerifyBLS runs every BLS check above.
func (l *Lock) VerifyBLS() error {
	return errors.Join(l.VerifyShares(), l.VerifyRegistrations(), l.VerifyDeposits(), l.VerifyAggregate())
}
