package core_test

import (
	"testing"

	"github.com/lidofinance/tee-signer/signer-core/core"
	"github.com/lidofinance/tee-signer/signer-core/software"
	"github.com/lidofinance/tee-signer/signer-protocol"
)

// A distributed validator share loads under its own key with the group key
// for selection proofs: an aggregate or contribution that carries the
// group's proof signs with the share. Loaded without it, or with another
// group key, the group's proof is refused.
func TestDVShareSelectionProof(t *testing.T) {
	group, groupPk, cfg := newTestSigner(t, software.NewMemHooks())
	slot := uint64(20*32 + 3)
	proof, err := group.Sign(signReq(group, groupPk, &backend.SelectionProof{Slot: slot}))
	if err != nil {
		t.Fatal(err)
	}
	syncProof, err := group.Sign(signReq(group, groupPk, &backend.SyncSelectionProof{Slot: slot, SubcommitteeIndex: 2}))
	if err != nil {
		t.Fatal(err)
	}
	sk, err := software.NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	pk, _ := core.PubkeyOf(sk)
	other, _ := software.NewSecret()
	otherPk, _ := core.PubkeyOf(other)

	load := func(g *backend.Pubkey) *core.Signer {
		t.Helper()
		m := software.NewMemHooks()
		m.Clock = clockAtEpoch(20)
		s, err := core.NewSigner(cfg, 4, 4, m)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(s.Close)
		saved := m.Clock
		m.Clock = func() (uint64, error) { return genesis, nil }
		var k backend.ValidatorKey
		if g == nil {
			k, err = s.AddValidator(pk, sk, 7, nil)
		} else {
			k, err = s.AddValidatorGroup(pk, sk, 7, nil, *g)
		}
		m.Clock = saved
		if err != nil || k.Pubkey != pk || k.SharePubkey != pk {
			t.Fatalf("load: %v, key %+v", err, k)
		}
		return s
	}
	agg := &backend.AggregateAndProof{Form: backend.AggregateElectra, SSZ: electraAggregate(7, slot, proof)}
	con := &backend.ContributionAndProof{SSZ: contribution(7, slot, 2, syncProof)}

	dv := load(&groupPk)
	for _, m := range []backend.Message{agg, con} {
		sig, err := dv.Sign(signReq(dv, pk, m))
		if err != nil {
			t.Fatalf("%v with the group key: %v", m.Kind(), err)
		}
		root, _ := cfg.SigningRoot(m)
		if !core.Verify(pk, root, sig) {
			t.Fatalf("%v: not the share's signature", m.Kind())
		}
	}
	// The partial selection proof is the share's own signature.
	sel := &backend.SelectionProof{Slot: slot}
	sig, err := dv.Sign(signReq(dv, pk, sel))
	if root, _ := cfg.SigningRoot(sel); err != nil || !core.Verify(pk, root, sig) {
		t.Fatalf("partial selection proof: %v", err)
	}
	for name, s := range map[string]*core.Signer{"no group key": load(nil), "another group key": load(&otherPk)} {
		for _, m := range []backend.Message{agg, con} {
			_, err := s.Sign(signReq(s, pk, m))
			if backend.StatusOf(err) != backend.StatusSelectionProof {
				t.Fatalf("%s, %v: %v, want SELECTION_PROOF", name, m.Kind(), err)
			}
		}
	}

	// A group key that is not a G1 point loads nothing.
	m := software.NewMemHooks()
	m.Clock = clockAtEpoch(20)
	s, err := core.NewSigner(cfg, 4, 4, m)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.AddValidatorGroup(pk, sk, 7, nil, backend.Pubkey{0xc0}); backend.StatusOf(err) != backend.StatusBadKey {
		t.Fatalf("infinity as the group key: %v", err)
	}
	if len(s.Keys()) != 0 {
		t.Fatal("a key loaded with a bad group key")
	}
}
