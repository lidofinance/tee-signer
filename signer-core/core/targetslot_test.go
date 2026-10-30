package core_test

import (
	"testing"

	"github.com/lidofinance/tee-signer/signer-core/software"
	"github.com/lidofinance/tee-signer/signer-protocol"
)

// withSlot is a with its slot moved.
func withSlot(a *backend.AttestationData, slot uint64) *backend.AttestationData {
	a.Slot = slot
	return a
}

// An attestation whose target epoch is not the epoch of its slot can never
// be included: process_attestation asserts target.epoch ==
// compute_epoch_at_slot(slot). The core refuses it before the repeat
// shortcut and before any mark moves. This is a data check only; the slot
// rule (TestAttestationFutureSlot) keeps the slot from running ahead.
func TestAttestationTargetSlot(t *testing.T) {
	h := software.NewMemHooks()
	s, pk, _ := newTestSigner(t, h) // clock epoch 20, targets up to 21
	sign := func(m backend.Message) error {
		_, err := s.Sign(signReq(s, pk, m))
		return err
	}
	if err := sign(att(18, 19)); err != nil {
		t.Fatal(err)
	}
	writes := h.Writes
	for name, m := range map[string]*backend.AttestationData{
		"target above the slot's epoch": withSlot(att(19, 21), 20*32+5),
		"target below the slot's epoch": withSlot(att(19, 20), 21*32),
		// Refused for its slot before the slashing check sees the target.
		"a double vote by target, wrong slot": withSlot(att(18, 19), 20*32),
	} {
		if err := sign(m); backend.StatusOf(err) != backend.StatusPolicyTargetSlot {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if !backend.StatusPolicyTargetSlot.IsPolicy() || backend.StatusPolicyTargetSlot.IsSlashing() {
		t.Fatal("SC_ERR_POLICY_TARGET_SLOT is a policy refusal")
	}
	st, err := s.State(pk)
	if err != nil {
		t.Fatal(err)
	}
	if st.RAM.TargetEpoch != 19 || st.RAM.SourceEpoch != 18 || h.Writes != writes {
		t.Fatalf("the refusals moved state: %+v, writes %d -> %d", st.RAM, writes, h.Writes)
	}
	if _, rep, err := s.SignDetailed(signReq(s, pk, att(18, 19))); err != nil || !rep {
		t.Fatalf("the repeat root changed: rep=%v err=%v", rep, err)
	}
	// The honest votes sign once their slots start: the clock is in the
	// last slot of epoch 20, then of epoch 21.
	if err := sign(withSlot(att(19, 20), 20*32)); err != nil {
		t.Fatal(err)
	}
	h.Clock = clockAtEpoch(21)
	if err := sign(withSlot(att(20, 21), 22*32-1)); err != nil {
		t.Fatal(err)
	}
}

// madlabman's case on #45: with the clock in epoch 20, a vote for slot 672
// (epoch 21) passes the target/slot check and the epoch horizon (21 <= 20 +
// 1). Signed, it would raise the target mark to 21 and refuse the
// validator's real vote for epoch 21. The slot rule refuses it with no mark
// moved; in epoch 21 the honest vote for slot 672 signs.
func TestAttestationFutureSlot(t *testing.T) {
	h := software.NewMemHooks()
	s, pk, _ := newTestSigner(t, h) // clock in slot 671, the last of epoch 20
	sign := func(m backend.Message) error {
		_, err := s.Sign(signReq(s, pk, m))
		return err
	}
	if err := sign(att(19, 20)); err != nil {
		t.Fatal(err)
	}
	writes := h.Writes
	future := withSlot(att(20, 21), 672)
	wantStatus(t, sign(future), backend.StatusPolicyFuture)
	st, err := s.State(pk)
	if err != nil {
		t.Fatal(err)
	}
	if st.RAM.TargetEpoch != 20 || h.Writes != writes {
		t.Fatalf("the refusal moved state: %+v, writes %d -> %d", st.RAM, writes, h.Writes)
	}
	// Within SC_SLOT_MARGIN_SECONDS of slot 672's start it signs.
	start672 := uint64(genesis + 672*12)
	h.Clock = func() (uint64, error) { return start672 - 3, nil }
	wantStatus(t, sign(future), backend.StatusPolicyFuture)
	h.Clock = func() (uint64, error) { return start672 - 2, nil }
	if err := sign(future); err != nil {
		t.Fatalf("the honest vote for slot 672: %v", err)
	}
	// A block for a later slot is refused the same way; the current slot's signs.
	wantStatus(t, sign(&backend.BeaconBlockHeader{Slot: 673, ProposerIndex: 7}), backend.StatusPolicyFuture)
	if err := sign(&backend.BeaconBlockHeader{Slot: 672, ProposerIndex: 7}); err != nil {
		t.Fatal(err)
	}
}
