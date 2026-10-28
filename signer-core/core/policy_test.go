package core

import (
	"errors"
	"reflect"
	"testing"

	"github.com/lidofinance/tee-signer/signer-protocol"
)

// SetPolicy replaces the policy of a running signer: each value takes
// effect with the next request, the fork schedule and the loaded validators
// stay. A policy the checks refuse changes nothing; CheckPolicy changes
// nothing either.
func TestSetPolicy(t *testing.T) {
	s, pk, cfg := newTestSigner(t, NewMemHooks())
	sign := func(m backend.Message) error {
		_, err := s.Sign(signReq(s, pk, m))
		return err
	}
	newFee := backend.Address{0x22}
	reg := func(fee backend.Address, gas uint64) *backend.ValidatorRegistration {
		return &backend.ValidatorRegistration{FeeRecipient: fee, GasLimit: gas, Timestamp: genesis, Pubkey: pk}
	}
	aggregate := &backend.RootMessage{Type: backend.RootAggregateAndProof, Epoch: 20, ObjectRoot: backend.Root{9},
		Domain: cfg.Domain(backend.DomainAggregateAndProof, 20)}
	wantStatus(t, sign(reg(newFee, 36_000_000)), backend.StatusPolicyFeeRecipient)
	wantStatus(t, sign(reg(cfg.FeeRecipients[0], 70_000_000)), backend.StatusPolicyGasLimit)
	wantStatus(t, sign(aggregate), backend.StatusPolicyDomain)
	if err := sign(&backend.VoluntaryExit{Epoch: 5, ValidatorIndex: 7}); err != nil {
		t.Fatal(err)
	}

	p := cfg.Policy()
	p.FeeRecipients = append(p.FeeRecipients, newFee)
	p.GasLimitMax = 80_000_000
	p.ExitAllowlist = nil
	p.AllowUnverifiedNonslashable = true
	if err := s.CheckPolicy(p); err != nil {
		t.Fatal(err)
	}
	if got := s.Config(); !reflect.DeepEqual(got.Policy(), cfg.Policy()) {
		t.Fatal("CheckPolicy changed the policy")
	}
	if err := s.SetPolicy(p); err != nil {
		t.Fatal(err)
	}
	for name, m := range map[string]backend.Message{"new fee recipient": reg(newFee, 36_000_000),
		"wider gas range": reg(cfg.FeeRecipients[0], 70_000_000), "unverified root": aggregate} {
		if err := sign(m); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	wantStatus(t, sign(&backend.VoluntaryExit{Epoch: 5, ValidatorIndex: 7}), backend.StatusPolicyExit)
	got := s.Config()
	if !reflect.DeepEqual(got.Policy(), p) || !reflect.DeepEqual(got.Schedule(), cfg.Schedule()) ||
		got.GenesisValidatorsRoot != cfg.GenesisValidatorsRoot || got.MaxEpochsAhead != cfg.MaxEpochsAhead {
		t.Fatalf("config after SetPolicy: %+v", got)
	}
	if len(s.Keys()) != 1 {
		t.Fatal("the validator did not stay loaded")
	}

	bad := p
	bad.GasLimitMin = bad.GasLimitMax + 1
	wantStatus(t, s.CheckPolicy(bad), backend.StatusArg)
	wantStatus(t, s.SetPolicy(bad), backend.StatusArg)
	tooMany := p
	tooMany.FeeRecipients = make([]backend.Address, maxFeeRecipients+1)
	wantStatus(t, s.SetPolicy(tooMany), backend.StatusArg)
	if after := s.Config(); !reflect.DeepEqual(after.Policy(), p) {
		t.Fatal("a refused policy changed the signer")
	}
	s.Close()
	if err := s.SetPolicy(p); !errors.Is(err, ErrClosed) {
		t.Fatalf("closed signer: %v", err)
	}
	if err := s.CheckPolicy(p); !errors.Is(err, ErrClosed) {
		t.Fatalf("closed signer: %v", err)
	}
}
