package keygen

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/lidofinance/tee-signer/platform"
	"github.com/lidofinance/tee-signer/signer-core/dkgmath"
	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/dkgmsg"
	"github.com/lidofinance/tee-signer/tee-signer/charonlock"
)

// DKG_SETUP_SIGN: the signatures a new key needs before it can work, made
// only for keys this runner generated, only while their setup is open, and
// only after the runner checked the full message against the policy's setup
// section and its chain config. It computes every signing root itself
// (invariant 2).
//
//	deposit       the policy's withdrawal credentials and an amount it lists;
//	              DOMAIN_DEPOSIT with the chain's genesis fork version
//	registration  Charon path: through the signer core, whose policy checks
//	              the fee recipient allowlist, gas limit and timestamp
//	charon lock   Charon path: the whole lock, checked (below); the runner
//	              signs the lock hash it computes, once per key it holds
//
// Setup closes for a key after the lock signature (Charon path) or once every
// deposit amount of the policy is signed (Dirk path). The first deposit or
// lock signature fixes the key's withdrawal credentials (KeyRecord.
// Credentials): while setup is open, a locked update that changes the
// credentials in force stops setup signing for the key instead of giving it
// deposits for two sets of credentials (TKGSETUP-01). The record of that is
// sealed in the host's store, so a host that rolls the store back reopens
// it; the signatures it can then get again are the same ones.

// SetupSign serves one DKG_SETUP_SIGN request.
func (m *Manager) SetupSign(_ context.Context, payload []byte) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, err := m.policy.rules()
	if err != nil {
		return nil, backend.Refused(backend.StatusPolicyPubkey, "setup: %v", err)
	}
	if r == nil {
		return nil, backend.Refused(backend.StatusUnsupported, "setup: the policy has no setup section")
	}
	q, err := dkgmsg.DecodeSetupRequest(payload)
	if err != nil {
		return nil, backend.Refused(backend.StatusBadRequest, "setup: %v", err)
	}
	switch q.Kind {
	case dkgmsg.SetupDeposit:
		return m.signDeposit(r, q.Deposit)
	case dkgmsg.SetupRegistration:
		if r.path != "charon" {
			return nil, backend.Refused(backend.StatusUnsupported, "setup: builder registrations are part of the Charon path only")
		}
		return m.signRegistration(r, q.Registration)
	case dkgmsg.SetupCharonLock:
		if r.path != "charon" {
			return nil, backend.Refused(backend.StatusUnsupported, "setup: the policy's path is %s, not charon", r.path)
		}
		return m.signLock(r, q.Lock)
	}
	return nil, backend.Refused(backend.StatusBadRequest, "setup: unknown kind")
}

// openRecord loads the key record of a key this runner generated under this
// policy and still holds, with setup open.
func (m *Manager) openRecord(pk backend.Pubkey) (*KeyRecord, error) {
	rec, err := LoadKeyRecord(m.env.Sealer, m.env.Store, pk)
	if errors.Is(err, platform.ErrNotFound) {
		return nil, backend.Refused(backend.StatusUnknownValidator, "setup: %s is not a key this runner generated", pk.String()[:18])
	}
	if err != nil {
		return nil, backend.Refused(backend.StatusPlatform, "setup: key record: %v", err)
	}
	if !bytes.Equal(rec.PolicyHash, m.policyHash[:]) {
		return nil, backend.Refused(backend.StatusPolicyPubkey, "setup: %s was generated under another policy", pk.String()[:18])
	}
	if rec.SetupClosed {
		return nil, backend.Refused(backend.StatusPolicyPubkey, "setup: closed for %s", pk.String()[:18])
	}
	held := false
	for _, k := range m.env.Keys() {
		held = held || k.Pubkey == pk
	}
	if !held {
		return nil, backend.Refused(backend.StatusUnknownValidator, "setup: %s is not loaded", pk.String()[:18])
	}
	return rec, nil
}

// keyCredentials refuses setup signing for rec when the key already has a
// signature for other withdrawal credentials than the rules in force name.
func keyCredentials(rec *KeyRecord, r *setupRules) error {
	if len(rec.Credentials) != 0 && !bytes.Equal(rec.Credentials, r.credentials[:]) {
		return backend.Refused(backend.StatusPolicyPubkey, "setup: %s has withdrawal credentials %x since its first deposit signature; the rules in force name %x",
			rec.Pubkey.String()[:18], rec.Credentials, r.credentials[:])
	}
	return nil
}

// signRoot signs msg with the share of pk.
func (m *Manager) signRoot(pk backend.Pubkey, msg []byte) (backend.Signature, error) {
	var sig backend.Signature
	err := m.env.WithShare(pk, func(secret *[32]byte) error {
		var err error
		sig, err = dkgmath.Sign(secret, msg)
		return err
	})
	if err != nil {
		return sig, backend.Refused(backend.StatusPlatform, "setup: sign: %v", err)
	}
	return sig, nil
}

func (m *Manager) signDeposit(r *setupRules, d *dkgmsg.Deposit) ([]byte, error) {
	rec, err := m.openRecord(d.Pubkey)
	if err != nil {
		return nil, err
	}
	if d.WithdrawalCredentials != r.credentials {
		return nil, backend.Refused(backend.StatusPolicyPubkey, "setup: withdrawal credentials are not the policy's %x", r.credentials[:])
	}
	if !r.amounts[d.Amount] {
		return nil, backend.Refused(backend.StatusPolicyPubkey, "setup: deposit amount %d gwei is not in the policy", d.Amount)
	}
	if err := keyCredentials(rec, r); err != nil {
		return nil, err
	}
	// Stored before the signature leaves: a store failure signs nothing.
	if len(rec.Credentials) == 0 {
		rec.Credentials = slices.Clone(r.credentials[:])
		if err := m.storeKeyRecord(rec); err != nil {
			return nil, backend.Refused(backend.StatusPlatform, "setup: key record: %v", err)
		}
	}
	root := charonlock.DepositSigningRoot(d.Pubkey, d.WithdrawalCredentials, d.Amount, m.chain().GenesisForkVersion)
	sig, err := m.signRoot(d.Pubkey, root[:])
	if err != nil {
		return nil, err
	}
	if !slices.Contains(rec.DepositsSigned, d.Amount) {
		rec.DepositsSigned = append(rec.DepositsSigned, d.Amount)
	}
	if r.path == "dirk" && len(rec.DepositsSigned) == len(r.amounts) {
		rec.SetupClosed = true
	}
	if err := m.storeKeyRecord(rec); err != nil {
		return nil, backend.Refused(backend.StatusPlatform, "setup: key record: %v", err)
	}
	m.env.Log.Info("setup: deposit signed", "pubkey", d.Pubkey.String()[:18], "amount_gwei", d.Amount, "setup_closed", rec.SetupClosed)
	return sig[:], nil
}

func (m *Manager) signRegistration(r *setupRules, reg *backend.ValidatorRegistration) ([]byte, error) {
	rec, err := m.openRecord(reg.Pubkey)
	if err != nil {
		return nil, err
	}
	if err := keyCredentials(rec, r); err != nil {
		return nil, err
	}
	// The core checks the allowlist, gas limit and timestamp and computes
	// the root under DOMAIN_APPLICATION_BUILDER itself. The request names
	// that domain, which does not depend on the fork schedule.
	chain := m.chain()
	domain := chain.Domain(backend.DomainApplicationBuilder, 0)
	sig, err := m.env.Sign(backend.SignRequest{Pubkey: reg.Pubkey, Message: reg, Domain: domain})
	if err != nil {
		return nil, err
	}
	rec.RegistrationSigned = true
	if err := m.storeKeyRecord(rec); err != nil {
		return nil, backend.Refused(backend.StatusPlatform, "setup: key record: %v", err)
	}
	m.env.Log.Info("setup: builder registration signed", "pubkey", reg.Pubkey.String()[:18], "gas_limit", reg.GasLimit)
	return sig[:], nil
}

// signLock checks the whole lock and signs the lock hash it computes with
// each share it holds.
func (m *Manager) signLock(r *setupRules, raw []byte) ([]byte, error) {
	l, err := charonlock.Parse(raw)
	if err != nil {
		return nil, backend.Refused(backend.StatusBadRequest, "setup: lock: %v", err)
	}
	refuse := func(format string, args ...any) ([]byte, error) {
		return nil, backend.Refused(backend.StatusPolicyPubkey, "setup: lock: "+format, args...)
	}
	recs, err := m.checkLock(r, l)
	if err != nil {
		return refuse("%v", err)
	}
	lh, err := l.ComputeLockHash()
	if err != nil {
		return refuse("%v", err)
	}
	out := &dkgmsg.LockSigned{LockHash: lh}
	for _, rec := range recs {
		sig, err := m.signRoot(rec.Pubkey, lh[:])
		if err != nil {
			return nil, err
		}
		out.Signatures = append(out.Signatures, dkgmsg.LockSignature{Pubkey: rec.Pubkey, Signature: sig})
	}
	// Every record closes in one store change (platform.Apply).
	ch := &platform.Change{}
	for _, rec := range recs {
		rec.LockSigned, rec.SetupClosed = true, true
		rec.Credentials = slices.Clone(r.credentials[:])
		blob, err := m.sealKeyRecord(rec)
		if err != nil {
			return nil, backend.Refused(backend.StatusPlatform, "setup: key record: %v", err)
		}
		ch.Put(keyRecordKey(rec.Pubkey), blob)
	}
	if err := platform.Apply(m.env.Store, ch); err != nil {
		return nil, backend.Refused(backend.StatusPlatform, "setup: key records: %v", err)
	}
	m.env.Log.Info("setup: lock hash signed, setup closed", "lock_hash", fmt.Sprintf("%x", lh[:6]), "validators", len(recs))
	return out.Encode(), nil
}

// checkLock checks a lock before the runner signs its hash, and returns the
// key records of its validators. Every validator must be one this runner
// generated under this policy, with setup open.
func (m *Manager) checkLock(r *setupRules, l *charonlock.Lock) ([]*KeyRecord, error) {
	d := &l.Definition
	n := len(m.policy.Participants)
	if d.Threshold != m.policy.Threshold || len(d.Operators) != n {
		return nil, fmt.Errorf("threshold %d of %d operators, the policy says %d of %d", d.Threshold, len(d.Operators), m.policy.Threshold, n)
	}
	if d.Creator.Address != "" || len(d.Creator.ConfigSignature) != 0 {
		return nil, errors.New("creator is set; locks made here carry no EIP-712 signatures")
	}
	for i, o := range d.Operators {
		if o.Address != "" || len(o.ConfigSignature) != 0 || len(o.ENRSignature) != 0 {
			return nil, fmt.Errorf("operator %d has an address or EIP-712 signatures", i)
		}
		if o.ENR != r.enrs[i] {
			return nil, fmt.Errorf("operator %d is not the Charon node the policy names for participant %d", i, i+1)
		}
	}
	if d.NumValidators != len(l.Validators) || len(d.Validators) != len(l.Validators) || len(l.Validators) == 0 {
		return nil, errors.New("validator counts differ")
	}
	fork, err := d.Fork()
	if err != nil {
		return nil, err
	}
	chain := m.chain()
	if fork != chain.GenesisForkVersion {
		return nil, fmt.Errorf("fork_version %x is not the chain's genesis fork version %x", fork[:], chain.GenesisForkVersion[:])
	}
	if d.Compounding != r.compounding {
		return nil, fmt.Errorf("compounding %v, the policy says %v", d.Compounding, r.compounding)
	}
	for _, a := range d.DepositAmounts {
		if !r.amounts[a] {
			return nil, fmt.Errorf("deposit amount %d gwei is not in the policy", a)
		}
	}
	allow := func(addr string) bool {
		a, err := charonlock.Address(addr)
		return err == nil && slices.Contains(chain.FeeRecipients, backend.Address(a))
	}
	for i, v := range d.Validators {
		w, err := charonlock.Address(v.WithdrawalAddress)
		if err != nil || w != r.address {
			return nil, fmt.Errorf("validator %d withdrawal address %q is not the policy's", i, v.WithdrawalAddress)
		}
		if !allow(v.FeeRecipientAddress) {
			return nil, fmt.Errorf("validator %d fee recipient %q is not in the allowlist", i, v.FeeRecipientAddress)
		}
	}
	// The hashes it carries must recompute; it is the computed lock hash
	// that gets signed.
	if err := l.VerifyHashes(); err != nil {
		return nil, err
	}
	if err := l.VerifyShares(); err != nil {
		return nil, err
	}
	var recs []*KeyRecord
	for i := range l.Validators {
		gk, shares, err := l.Shares(i)
		if err != nil {
			return nil, err
		}
		rec, err := m.openRecord(gk)
		if err != nil {
			return nil, fmt.Errorf("validator %d: %v", i, err)
		}
		if err := keyCredentials(rec, r); err != nil {
			return nil, fmt.Errorf("validator %d: %v", i, err)
		}
		if int(rec.Threshold) != d.Threshold || !slices.Equal(rec.PublicShares, shares) {
			return nil, fmt.Errorf("validator %d: public shares are not the ones key generation made (this runner's share must be at position %d)", i, rec.Self)
		}
		for j, dep := range l.Validators[i].PartialDepositData {
			if !bytes.Equal(dep.WithdrawalCredentials, r.credentials[:]) || !r.amounts[dep.Amount] {
				return nil, fmt.Errorf("validator %d deposit %d: credentials or amount not in the policy", i, j)
			}
		}
		reg, err := l.RegistrationMessage(i)
		if err != nil {
			return nil, err
		}
		c := &chain
		if reg.GasLimit < c.GasLimitMin || reg.GasLimit > c.GasLimitMax {
			return nil, fmt.Errorf("validator %d: registration gas limit %d outside %d to %d", i, reg.GasLimit, c.GasLimitMin, c.GasLimitMax)
		}
		if !bytes.Equal(l.Validators[i].BuilderRegistration.Message.FeeRecipient, reg.FeeRecipient[:]) ||
			!bytes.Equal(l.Validators[i].BuilderRegistration.Message.PubKey, gk[:]) {
			return nil, fmt.Errorf("validator %d: registration message differs from the definition", i)
		}
		recs = append(recs, rec)
	}
	if err := errors.Join(l.VerifyDeposits(), l.VerifyRegistrations()); err != nil {
		return nil, err
	}
	// The lock holds every key of each key generation session it holds a
	// key of, no more and no less: signing a lock closes setup for its keys,
	// so a lock with part of a session would leave the rest without a lock
	// this runner can sign. A lock may hold several whole sessions, since a
	// session makes at most dkgmsg.MaxValidators keys.
	inLock := map[string]int{}
	var order []string
	for _, rec := range recs {
		s := string(rec.Session)
		if inLock[s] == 0 {
			order = append(order, s)
		}
		inLock[s]++
	}
	all, err := m.sessionKeyCounts()
	if err != nil {
		return nil, err
	}
	for _, s := range order {
		if all[s] != inLock[s] {
			return nil, fmt.Errorf("the lock holds %d of the %d keys of key generation session %x; it must hold every key of each session",
				inLock[s], all[s], []byte(s)[:min(6, len(s))])
		}
	}
	return recs, nil
}

// sessionKeyCounts counts the key records of each session, in one pass.
func (m *Manager) sessionKeyCounts() (map[string]int, error) {
	names, err := m.env.Store.List("dkg/keys/")
	if err != nil {
		return nil, err
	}
	n := map[string]int{}
	for _, name := range names {
		var pk backend.Pubkey
		b, err := hex.DecodeString(strings.TrimPrefix(name, "dkg/keys/"))
		if err != nil || len(b) != len(pk) {
			continue
		}
		copy(pk[:], b)
		rec, err := LoadKeyRecord(m.env.Sealer, m.env.Store, pk)
		if err != nil {
			return nil, fmt.Errorf("key record %s: %v", name, err)
		}
		n[string(rec.Session)]++
	}
	return n, nil
}
