package core

import (
	"errors"
	"math"
	"testing"

	"github.com/lidofinance/tee-signer/signer-protocol"
)

// SignGuarded signs only under the config its caller checked: the same
// generation, and before the time the next config comes into force.
func TestSignGuarded(t *testing.T) {
	h := NewMemHooks()
	now := uint64(genesis + 1000)
	h.Clock = func() (uint64, error) { return now, nil }
	s, pk, cfg := newTestSigner(t, h)
	reg := &backend.ValidatorRegistration{FeeRecipient: cfg.FeeRecipients[0], GasLimit: 36_000_000, Timestamp: genesis, Pubkey: pk}
	g := Guard{Generation: s.Generation(), Until: math.MaxUint64}
	if _, _, err := s.SignGuarded(signReq(s, pk, reg), g); err != nil {
		t.Fatal(err)
	}
	// Due at now: the pending config is in force, so the guard no longer holds.
	if _, _, err := s.SignGuarded(signReq(s, pk, reg), Guard{Generation: g.Generation, Until: now}); !errors.Is(err, ErrConfigMoved) {
		t.Fatalf("at the next config's time: %v", err)
	}
	if _, _, err := s.SignGuarded(signReq(s, pk, reg), Guard{Generation: g.Generation, Until: now + 1}); err != nil {
		t.Fatalf("one second before: %v", err)
	}
	if err := s.SetPolicy(cfg.Policy()); err != nil {
		t.Fatal(err)
	}
	if s.Generation() != g.Generation+1 {
		t.Fatalf("generation %d after SetPolicy, want %d", s.Generation(), g.Generation+1)
	}
	if _, _, err := s.SignGuarded(signReq(s, pk, reg), g); !errors.Is(err, ErrConfigMoved) {
		t.Fatalf("after a policy change: %v", err)
	}
	if _, _, err := s.SignGuarded(signReq(s, pk, reg), Guard{Generation: s.Generation(), Until: math.MaxUint64}); err != nil {
		t.Fatal(err)
	}
}
