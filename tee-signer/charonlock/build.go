package charonlock

import (
	"errors"
	"fmt"

	"github.com/lidofinance/tee-signer/signer-protocol"
)

// Cluster is what a lock needs besides the keys: the settings the
// operators agree on, and each operator's ENR in share ID order.
type Cluster struct {
	Name      string
	UUID      string
	Timestamp string // RFC 3339, as Charon writes it
	// ENRs[i] is the ENR of the node whose runner holds the shares at
	// x = i+1 (dkg-result.json participant i+1).
	ENRs              []string
	Threshold         int
	ForkVersion       backend.Version // the chain's genesis fork version
	FeeRecipient      string          // 0x address, every validator
	WithdrawalAddress string          // 0x address, every validator
	Compounding       bool
	DepositAmounts    []uint64 // gwei; empty: Charon's default for the lock
	GasLimit          uint64
	// RegistrationTimestamp is the builder registration's timestamp; Charon
	// uses the chain's genesis time.
	RegistrationTimestamp uint64
}

// DKGAlgorithm names the key generation in the lock. Charon only hashes it.
const DKGAlgorithm = "tee-runners"

// NewLock builds a lock for the generated keys: definition with its hashes,
// and per validator the key and the public shares in share ID order. The
// deposits, the registrations, the lock hash and the signatures come after
// (SetDeposits, SetRegistration, then Seal).
func NewLock(c *Cluster, groupKeys []backend.Pubkey, publicShares [][]backend.Pubkey) (*Lock, error) {
	n := len(c.ENRs)
	if len(groupKeys) == 0 || len(groupKeys) != len(publicShares) {
		return nil, errors.New("charonlock: keys and shares differ in number")
	}
	if c.Threshold < 1 || c.Threshold > n {
		return nil, fmt.Errorf("charonlock: threshold %d of %d", c.Threshold, n)
	}
	for _, a := range []string{c.FeeRecipient, c.WithdrawalAddress} {
		if _, err := Address(a); err != nil {
			return nil, err
		}
	}
	d := Definition{
		Name: c.Name, UUID: c.UUID, Version: Version, Timestamp: c.Timestamp,
		NumValidators: len(groupKeys), Threshold: c.Threshold, DKGAlgorithm: DKGAlgorithm,
		ForkVersion: append(Hex(nil), c.ForkVersion[:]...), DepositAmounts: c.DepositAmounts,
		TargetGasLimit: c.GasLimit, Compounding: c.Compounding,
	}
	for _, e := range c.ENRs {
		d.Operators = append(d.Operators, Operator{ENR: e})
	}
	l := &Lock{}
	for v, gk := range groupKeys {
		if len(publicShares[v]) != n {
			return nil, fmt.Errorf("charonlock: validator %d has %d shares for %d operators", v, len(publicShares[v]), n)
		}
		d.Validators = append(d.Validators, ValidatorAddresses{FeeRecipientAddress: c.FeeRecipient, WithdrawalAddress: c.WithdrawalAddress})
		dv := DistValidator{PubKey: append(Hex(nil), gk[:]...)}
		for _, s := range publicShares[v] {
			dv.PubShares = append(dv.PubShares, append(Hex(nil), s[:]...))
		}
		l.Validators = append(l.Validators, dv)
	}
	if err := d.SetHashes(); err != nil {
		return nil, err
	}
	l.Definition = d
	return l, nil
}

// RegistrationFor is the builder registration of validator i as Charon
// checks it.
func (l *Lock) RegistrationFor(i int, c *Cluster) (*backend.ValidatorRegistration, error) {
	fee, err := Address(c.FeeRecipient)
	if err != nil {
		return nil, err
	}
	var gk backend.Pubkey
	copy(gk[:], l.Validators[i].PubKey)
	return &backend.ValidatorRegistration{FeeRecipient: fee, GasLimit: c.GasLimit, Timestamp: c.RegistrationTimestamp, Pubkey: gk}, nil
}

// SetRegistration stores validator i's signed registration.
func (l *Lock) SetRegistration(i int, m *backend.ValidatorRegistration, sig backend.Signature) {
	l.Validators[i].BuilderRegistration = Registration{
		Message: RegistrationMessage{FeeRecipient: append(Hex(nil), m.FeeRecipient[:]...), GasLimit: m.GasLimit,
			Timestamp: m.Timestamp, PubKey: append(Hex(nil), m.Pubkey[:]...)},
		Signature: append(Hex(nil), sig[:]...),
	}
}

// AddDeposit appends one signed deposit to validator i.
func (l *Lock) AddDeposit(i int, wc backend.Root, amount uint64, sig backend.Signature) {
	l.Validators[i].PartialDepositData = append(l.Validators[i].PartialDepositData, DepositData{
		PubKey: append(Hex(nil), l.Validators[i].PubKey...), WithdrawalCredentials: append(Hex(nil), wc[:]...),
		Amount: amount, Signature: append(Hex(nil), sig[:]...),
	})
}

// SetLockHash computes and stores the lock hash.
func (l *Lock) SetLockHash() (backend.Root, error) {
	h, err := l.ComputeLockHash()
	if err != nil {
		return h, err
	}
	l.LockHash = append(Hex(nil), h[:]...)
	return h, nil
}
