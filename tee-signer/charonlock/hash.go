package charonlock

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/lidofinance/tee-signer/signer-protocol"
)

// Field limits of the v1.11 hashes.
const (
	limitUUID          = 64
	limitName          = 256
	limitVersion       = 16
	limitTimestamp     = 32
	limitDKGAlgorithm  = 32
	limitENR           = 1024
	limitOperators     = 256
	limitValidators    = 65536
	limitDepositAmount = 256
	limitK1Sigs        = 32
	k1SigLen           = 65
)

func k1SigList(sig []byte) (root, error) {
	if len(sig)%k1SigLen != 0 || len(sig)/k1SigLen > limitK1Sigs {
		return root{}, errors.New("charonlock: signature list is not up to 32 signatures of 65 bytes")
	}
	var elems []root
	for i := 0; i < len(sig); i += k1SigLen {
		elems = append(elems, fixedBytes(sig[i:i+k1SigLen]))
	}
	return list(elems, limitK1Sigs), nil
}

func checkedByteList(name string, s []byte, limit int) (root, error) {
	if len(s) > limit {
		return root{}, fmt.Errorf("charonlock: %s longer than %d bytes", name, limit)
	}
	return byteList(s, uint64(limit)), nil
}

// definitionRoot is the hash tree root of the v1.11 definition; with
// configOnly the config hash, else the definition hash.
func (d *Definition) definitionRoot(configOnly bool) (root, error) {
	var f []root
	add := func(r root, err error) error {
		if err == nil {
			f = append(f, r)
		}
		return err
	}
	if err := errors.Join(
		add(checkedByteList("uuid", []byte(d.UUID), limitUUID)),
		add(checkedByteList("name", []byte(d.Name), limitName)),
		add(checkedByteList("version", []byte(d.Version), limitVersion)),
		add(checkedByteList("timestamp", []byte(d.Timestamp), limitTimestamp)),
	); err != nil {
		return root{}, err
	}
	f = append(f, u64(uint64(d.NumValidators)), u64(uint64(d.Threshold)))
	if err := add(checkedByteList("dkg_algorithm", []byte(d.DKGAlgorithm), limitDKGAlgorithm)); err != nil {
		return root{}, err
	}
	if len(d.ForkVersion) != 4 {
		return root{}, errors.New("charonlock: fork_version is not 4 bytes")
	}
	f = append(f, fixedBytes(d.ForkVersion))

	if len(d.Operators) > limitOperators {
		return root{}, errors.New("charonlock: too many operators")
	}
	var ops []root
	for i, o := range d.Operators {
		addr, err := addressOrZero(o.Address)
		if err != nil {
			return root{}, fmt.Errorf("operator %d: %w", i, err)
		}
		fields := []root{fixedBytes(addr[:])}
		if !configOnly {
			enr, err := checkedByteList("enr", []byte(o.ENR), limitENR)
			if err != nil {
				return root{}, err
			}
			cs, err := k1SigList(o.ConfigSignature)
			if err != nil {
				return root{}, err
			}
			es, err := k1SigList(o.ENRSignature)
			if err != nil {
				return root{}, err
			}
			fields = append(fields, enr, cs, es)
		}
		ops = append(ops, container(fields...))
	}
	f = append(f, list(ops, limitOperators))

	caddr, err := addressOrZero(d.Creator.Address)
	if err != nil {
		return root{}, fmt.Errorf("creator: %w", err)
	}
	creator := []root{fixedBytes(caddr[:])}
	if !configOnly {
		cs, err := k1SigList(d.Creator.ConfigSignature)
		if err != nil {
			return root{}, err
		}
		creator = append(creator, cs)
	}
	f = append(f, container(creator...))

	var vals []root
	for i, v := range d.Validators {
		fee, err := addressOrZero(v.FeeRecipientAddress)
		if err != nil {
			return root{}, fmt.Errorf("validator %d fee recipient: %w", i, err)
		}
		wd, err := addressOrZero(v.WithdrawalAddress)
		if err != nil {
			return root{}, fmt.Errorf("validator %d withdrawal address: %w", i, err)
		}
		vals = append(vals, container(fixedBytes(fee[:]), fixedBytes(wd[:])))
	}
	f = append(f, list(vals, limitValidators))
	if len(d.DepositAmounts) > limitDepositAmount {
		return root{}, errors.New("charonlock: too many deposit amounts")
	}
	f = append(f, u64List(d.DepositAmounts, limitDepositAmount))
	if err := add(checkedByteList("consensus_protocol", []byte(d.ConsensusProtocol), limitName)); err != nil {
		return root{}, err
	}
	f = append(f, u64(d.TargetGasLimit), boolean(d.Compounding))
	if !configOnly {
		if len(d.ConfigHash) != 32 {
			return root{}, errors.New("charonlock: config_hash is not 32 bytes")
		}
		f = append(f, fixedBytes(d.ConfigHash))
	}
	return container(f...), nil
}

// ConfigHash computes the definition's config hash.
func (d *Definition) ComputeConfigHash() (backend.Root, error) { return d.definitionRoot(true) }

// ComputeDefinitionHash computes the definition hash; ConfigHash must be set.
func (d *Definition) ComputeDefinitionHash() (backend.Root, error) { return d.definitionRoot(false) }

// SetHashes sets ConfigHash and DefinitionHash from the content.
func (d *Definition) SetHashes() error {
	c, err := d.ComputeConfigHash()
	if err != nil {
		return err
	}
	d.ConfigHash = c[:]
	h, err := d.ComputeDefinitionHash()
	if err != nil {
		return err
	}
	d.DefinitionHash = h[:]
	return nil
}

func exactly(name string, b []byte, n int) (root, error) {
	if len(b) != n {
		return root{}, fmt.Errorf("charonlock: %s is %d bytes, want %d", name, len(b), n)
	}
	return fixedBytes(b), nil
}

func (v *DistValidator) hashRoot() (root, error) {
	pk, err := exactly("distributed_public_key", v.PubKey, 48)
	if err != nil {
		return root{}, err
	}
	if len(v.PubShares) > limitOperators {
		return root{}, errors.New("charonlock: too many public shares")
	}
	var shares []root
	for _, s := range v.PubShares {
		r, err := exactly("public share", s, 48)
		if err != nil {
			return root{}, err
		}
		shares = append(shares, r)
	}
	if len(v.PartialDepositData) > limitDepositAmount {
		return root{}, errors.New("charonlock: too many deposits")
	}
	var deps []root
	for _, d := range v.PartialDepositData {
		r, err := d.hashRoot()
		if err != nil {
			return root{}, err
		}
		deps = append(deps, r)
	}
	reg, err := v.BuilderRegistration.hashRoot()
	if err != nil {
		return root{}, err
	}
	return container(pk, list(shares, limitOperators), list(deps, limitDepositAmount), reg), nil
}

func (d *DepositData) hashRoot() (root, error) {
	pk, err := exactly("deposit pubkey", d.PubKey, 48)
	if err != nil {
		return root{}, err
	}
	wc, err := exactly("withdrawal_credentials", d.WithdrawalCredentials, 32)
	if err != nil {
		return root{}, err
	}
	sig, err := exactly("deposit signature", d.Signature, 96)
	if err != nil {
		return root{}, err
	}
	return container(pk, wc, u64(d.Amount), sig), nil
}

func (r *Registration) hashRoot() (root, error) {
	m := &r.Message
	if len(m.FeeRecipient) > 32 {
		return root{}, errors.New("charonlock: registration fee_recipient too long")
	}
	pk, err := exactly("registration pubkey", m.PubKey, 48)
	if err != nil {
		return root{}, err
	}
	msg := container(fixedBytes(m.FeeRecipient), u64(m.GasLimit), u64(m.Timestamp), pk)
	sig, err := exactly("registration signature", r.Signature, 96)
	if err != nil {
		return root{}, err
	}
	return container(msg, sig), nil
}

// ComputeLockHash computes the lock hash: the definition (with its config
// hash) and every validator. Signatures are not part of it.
func (l *Lock) ComputeLockHash() (backend.Root, error) {
	def, err := l.Definition.definitionRoot(false)
	if err != nil {
		return root{}, err
	}
	if len(l.Validators) > limitValidators {
		return root{}, errors.New("charonlock: too many validators")
	}
	var vals []root
	for i := range l.Validators {
		r, err := l.Validators[i].hashRoot()
		if err != nil {
			return root{}, fmt.Errorf("validator %d: %w", i, err)
		}
		vals = append(vals, r)
	}
	return container(def, list(vals, limitValidators)), nil
}

// VerifyHashes recomputes the config, definition and lock hashes and
// compares them with the ones the lock carries.
func (l *Lock) VerifyHashes() error {
	d := &l.Definition
	c, err := d.ComputeConfigHash()
	if err != nil {
		return err
	}
	if !bytes.Equal(c[:], d.ConfigHash) {
		return errors.New("charonlock: config_hash does not recompute")
	}
	h, err := d.ComputeDefinitionHash()
	if err != nil {
		return err
	}
	if !bytes.Equal(h[:], d.DefinitionHash) {
		return errors.New("charonlock: definition_hash does not recompute")
	}
	if len(l.Validators) != d.NumValidators {
		return errors.New("charonlock: number of validators differs from num_validators")
	}
	lh, err := l.ComputeLockHash()
	if err != nil {
		return err
	}
	if !bytes.Equal(lh[:], l.LockHash) {
		return errors.New("charonlock: lock_hash does not recompute")
	}
	return nil
}
