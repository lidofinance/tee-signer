//go:build !debugimport

package server

import (
	"testing"

	"github.com/lidofinance/tee-signer/signer-protocol"
)

// lateImport is a runner that idled 20 epochs after A, then took B without
// history: the device mark's block bound stays at the start floor f0, and
// B's import floor is late.
func lateImport(t *testing.T, e *tgtEnv) (pka, pkb backend.Pubkey, f0, late uint64) {
	t.Helper()
	f0 = e.floorOf()
	ska, pka := newKey(t)
	if err := e.importSealed(pka, ska, 5, nil); err != nil {
		t.Fatal(err)
	}
	e.clock.add(20 * testEpoch)
	late = e.floorOf()
	skb, pkb := newKey(t)
	if err := e.importSealed(pkb, skb, 6, nil); err != nil {
		t.Fatal(err)
	}
	return pka, pkb, f0, late
}

func wantSlashing(t *testing.T, err error, what string) {
	t.Helper()
	if err == nil || !backend.StatusOf(err).IsSlashing() {
		t.Errorf("%s: %v, want a slashing refusal", what, err)
	}
}

// A key imported without history while the runner runs may have proposed
// elsewhere up to its import floor: with the device mark the core started
// it from the device's block bound, which holds only what keys here
// signed. Its own mark now refuses blocks up to the last slot of its floor
// epoch; a key loaded at start keeps the start floor; a restart floors
// both.
func TestLateImportGetsABlockFloor(t *testing.T) {
	e := newTgtEnv(t, "dev", nil)
	pka, pkb, f0, late := lateImport(t, e)
	x := (f0+5)*8 + 3 // above the start floor, below B's import floor
	wantSlashing(t, e.signMsg(pkb, &backend.BeaconBlockHeader{Slot: x, ProposerIndex: 6, BodyRoot: backend.Root{0xb0, 1}}),
		"B: a block below its import floor")
	e.clock.add((late + 1 - e.signer.EpochAt(e.now())) * testEpoch)
	if err := e.signMsg(pkb, &backend.BeaconBlockHeader{Slot: (late+1)*8 + 1, ProposerIndex: 6, BodyRoot: backend.Root{0xb0, 2}}); err != nil {
		t.Errorf("B: a block above its import floor: %v", err)
	}
	if f, ok := e.hooks.Floor(pkb); !ok || f != late {
		t.Errorf("B's floor for refusal details: %d %v, want %d", f, ok, late)
	}
	if err := e.signMsg(pka, &backend.BeaconBlockHeader{Slot: x, ProposerIndex: 5, BodyRoot: backend.Root{0xb0, 3}}); err != nil {
		t.Errorf("A: a block above the start floor: %v", err)
	}
	if f, ok := e.hooks.Floor(pka); !ok || f != f0 {
		t.Errorf("A's floor for refusal details: %d %v, want %d", f, ok, f0)
	}
	e.restart()
	f2 := e.floorOf()
	for i, pk := range []backend.Pubkey{pka, pkb} {
		wantSlashing(t, e.signMsg(pk, &backend.BeaconBlockHeader{Slot: (f2-1)*8 + 4, ProposerIndex: uint64(5 + i), BodyRoot: backend.Root{0xb1}}),
			"after a restart: a block below the restart floor")
	}
}

// The same holds for the slot of PTC votes, which the core raises with
// the block bound. An envelope needs the block this key signed at its
// slot, which the block bound refuses below the floor.
func TestLateImportGetsAPTCFloor(t *testing.T) {
	e := newTgtEnv(t, "dev", nil)
	if e.signer.Config().GloasForkEpoch == nil {
		t.Skip("the dev setup schedules no Gloas fork")
	}
	pka, pkb, f0, late := lateImport(t, e)
	x := (f0+5)*8 + 3
	ptc := func(slot uint64) *backend.PayloadAttestationData {
		return &backend.PayloadAttestationData{BeaconBlockRoot: backend.Root{0xc1}, Slot: slot, PayloadPresent: true}
	}
	env := func(slot uint64) *backend.PayloadEnvelope {
		m := &backend.PayloadEnvelope{BuilderIndex: backend.BuilderIndexSelfBuild, BeaconBlockRoot: backend.Root{0xc2}}
		m.Payload.SlotNumber = slot
		m.Payload.FeeRecipient = e.setup.Locked.AllowedFeeRecipients[0]
		return m
	}
	wantSlashing(t, e.signMsg(pkb, ptc(x)), "B: a PTC vote below its import floor")
	wantSlashing(t, e.signMsg(pkb, &backend.BeaconBlockHeader{Slot: x, ProposerIndex: 6, BodyRoot: backend.Root{0xc2}}),
		"B: the block an envelope below its import floor needs")
	if err := e.signMsg(pkb, env(x)); err == nil {
		t.Error("B: an envelope below its import floor signed")
	}
	e.clock.add((late + 1 - e.signer.EpochAt(e.now())) * testEpoch)
	if err := e.signMsg(pkb, ptc((late+1)*8+1)); err != nil {
		t.Errorf("B: a PTC vote above its import floor: %v", err)
	}
	if err := e.signMsg(pka, ptc(x)); err != nil {
		t.Errorf("A: a PTC vote above the start floor: %v", err)
	}
}

// A handover target refuses a block below a handed-over key's floor too:
// the source's import raised its device mark, which the page carries, and
// the target adds its own floor.
func TestHandoverTargetGetsABlockFloor(t *testing.T) {
	src := newSrcEnv(t, nil)
	tgt := newTargetOf(t, src, nil, nil, nil)
	start := tgt.floorOf() // the target's device mark starts from this floor
	src.clock.add(20 * testEpoch)
	sk, pk := newKey(t)
	if err := src.importSealed(pk, sk, 6, nil); err != nil {
		t.Fatal(err)
	}
	order, _ := srcOrder(t, src, tgt, []byte{1, 2}, nil)
	if _, err := src.push(order); err != nil {
		t.Fatal(err)
	}
	src.clock.add(srcDelay)
	if _, imp := handOverAll(t, src, tgt, order); !imp.Done {
		t.Fatalf("import %+v", imp)
	}
	f, ok := tgt.hooks.Floor(pk)
	if !ok || f <= start+5 {
		t.Fatalf("the handed-over key's floor %d (%v), want above the target's start floor %d", f, ok, start)
	}
	wantSlashing(t, tgt.signMsg(pk, &backend.BeaconBlockHeader{Slot: (start+3)*8 + 3, ProposerIndex: 6, BodyRoot: backend.Root{0xb4}}),
		"the target: a block above its start floor, below the import floor")
}
