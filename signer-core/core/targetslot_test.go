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
// compute_epoch_at_slot(slot). Signed, it would only raise the target mark,
// and the honest vote of the slot's epoch would then be refused. The core
// refuses it before the repeat shortcut and before any mark moves.
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
	} {
		if err := sign(m); err == nil {
			t.Fatalf("%s: signed", name)
		}
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
	for _, m := range []*backend.AttestationData{withSlot(att(19, 20), 20*32), withSlot(att(20, 21), 22*32-1)} {
		if err := sign(m); err != nil {
			t.Fatalf("honest vote (%d, %d) at slot %d: %v", m.Source.Epoch, m.Target.Epoch, m.Slot, err)
		}
	}
}
