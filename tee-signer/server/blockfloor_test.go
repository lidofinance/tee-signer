//go:build !debugimport

package server

import (
	"errors"
	"strings"
	"sync"
	"sync/atomic"
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

// A handover target gives each key it takes the floor of its own import:
// the target takes the first share, the clock moves on 20 epochs, then it
// takes the second. The target's device mark loaded with the first share
// and the page's mark hold only bounds from then; the second key's own
// mark holds its later floor.
func TestHandoverTargetGetsABlockFloor(t *testing.T) {
	src := newSrcEnv(t, nil)
	tgt := newTargetOf(t, src, nil, nil, nil)
	var pks []backend.Pubkey
	for i := range 2 {
		sk, pk := newKey(t)
		if err := src.importSealed(pk, sk, uint64(6+i), nil); err != nil {
			t.Fatal(err)
		}
		pks = append(pks, pk)
	}
	order, _ := srcOrder(t, src, tgt, []byte{1, 2}, nil)
	if _, err := src.push(order); err != nil {
		t.Fatal(err)
	}
	src.clock.add(srcDelay)
	page, err := handOver(t, src, tgt, order, 0)
	if err != nil {
		t.Fatal(err)
	}
	first, second := *page, *page
	first.Shares, second.Shares = page.Shares[:1], page.Shares[1:]
	tgt.mustImp(order, &first, 0)
	start := tgt.floorOf()
	src.clock.add(20 * testEpoch)
	if imp := tgt.mustImp(order, &second, 0); !imp.Done {
		t.Fatalf("import %+v", imp)
	}
	late := second.Shares[0].Pubkey
	if f, ok := tgt.hooks.Floor(late); !ok || f <= start+10 {
		t.Fatalf("the second key's floor %d (%v), want above %d", f, ok, start+10)
	}
	wantSlashing(t, tgt.signMsg(late, &backend.BeaconBlockHeader{Slot: (start+5)*8 + 3, ProposerIndex: second.Shares[0].Index, BodyRoot: backend.Root{0xb4}}),
		"the target: a block above its earlier bounds, below the second key's import floor")
}

// A key imported with vote history while the runner runs gets the floor's
// block bound too: it may have proposed elsewhere after its interchange
// was exported.
func TestLateImportWithHistoryGetsABlockFloor(t *testing.T) {
	e := newTgtEnv(t, "dev", nil)
	f0 := e.floorOf()
	ska, pka := newKey(t)
	if err := e.importSealed(pka, ska, 5, nil); err != nil {
		t.Fatal(err)
	}
	e.clock.add(20 * testEpoch)
	start := f0 - e.setup.Safety.MaxSignEpochsAheadOfClock - 1
	hist := &backend.Watermark{HasAttestation: true, SourceEpoch: start - 3, TargetEpoch: start - 2, HasBlock: true, BlockSlot: (start - 2) * 8}
	skb, pkb := newKey(t)
	if err := e.importSealed(pkb, skb, 6, hist); err != nil {
		t.Fatal(err)
	}
	wantSlashing(t, e.signMsg(pkb, &backend.BeaconBlockHeader{Slot: (f0+5)*8 + 3, ProposerIndex: 6, BodyRoot: backend.Root{0xb5}}),
		"B (with history): a block below its import floor")
	if _, on := e.hooks.SourceFloor(pkb); on {
		t.Error("a key with history got a source floor")
	}
	err := e.signMsg(pkb, &backend.BeaconBlockHeader{Slot: (f0+5)*8 + 3, ProposerIndex: 6, BodyRoot: backend.Root{0xb6}})
	var r *backend.RefusedError
	if !errors.As(err, &r) || !strings.Contains(r.Detail, "import floor epoch") {
		t.Errorf("refusal detail %v, want the import floor named", err)
	}
}

// The floor is in the key's mark from the moment the key can sign: SIGN
// requests for a block below the import floor, sent while the key is
// being imported, are all refused (the core takes the floor with the key,
// under one lock hold). A fresh runner each round: an import raises the
// device mark, so only the first late import starts below the floor.
func TestLateImportBlockFloorHasNoWindow(t *testing.T) {
	for round := range 25 {
		e := newTgtEnv(t, "dev", nil)
		f0 := e.floorOf()
		ska, pka := newKey(t)
		if err := e.importSealed(pka, ska, 5, nil); err != nil {
			t.Fatal(err)
		}
		e.clock.add(20 * testEpoch)
		x := (f0+5)*8 + 3 // above the start floor, below the import floor
		sk, pk := newKey(t)
		var signed atomic.Int32
		stop := make(chan struct{})
		var wg sync.WaitGroup
		for g := range 4 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for n := 0; ; n++ {
					select {
					case <-stop:
						return
					default:
					}
					m := &backend.BeaconBlockHeader{Slot: x, ProposerIndex: 6, BodyRoot: backend.Root{byte(g), byte(n), byte(n >> 8)}}
					if e.signMsg(pk, m) == nil {
						signed.Add(1)
					}
				}
			}()
		}
		if err := e.importSealed(pk, sk, 6, nil); err != nil {
			t.Fatal(err)
		}
		close(stop)
		wg.Wait()
		if n := signed.Load(); n > 0 {
			t.Fatalf("round %d: %d blocks below the import floor signed while the key was being imported", round, n)
		}
	}
}
