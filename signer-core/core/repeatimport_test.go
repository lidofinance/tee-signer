package core_test

import (
	"bytes"
	"testing"

	"github.com/lidofinance/tee-signer/signer-core/core"
	"github.com/lidofinance/tee-signer/signer-core/software"
	"github.com/lidofinance/tee-signer/signer-protocol"
)

// An import brings history signed elsewhere. A repeat root from before it
// must not sign: the signature for it may never have left (a crash before
// release), and the history may hold a vote inside it.

func TestRepeatRefusedAfterImportInRun(t *testing.T) {
	for _, in := range [][2]uint64{{16, 17}, {17, 17}} {
		s, pk, _ := newTestSigner(t, software.NewMemHooks())
		if _, err := s.Sign(signReq(s, pk, att(15, 18))); err != nil {
			t.Fatal(err)
		}
		if err := s.Import(pk, backend.Watermark{HasAttestation: true, SourceEpoch: in[0], TargetEpoch: in[1]}); err != nil {
			t.Fatal(err)
		}
		_, rep, err := s.SignDetailed(signReq(s, pk, att(15, 18)))
		if rep || !backend.StatusOf(err).IsSlashing() {
			t.Errorf("(15, 18) again after an import of (%d, %d): repeat=%v err=%v, want a slashing refusal", in[0], in[1], rep, err)
		}
	}
}

func TestRepeatRefusedAfterImportRestart(t *testing.T) {
	h := software.NewMemHooks()
	h.Clock = clockAtEpoch(20)
	cfg := software.DevConfig(genesis, 12, 32)
	cfg.PersistRepeatRoot = true
	sk, _ := software.NewSecret()
	pk, _ := core.PubkeyOf(sk)
	start := func(wm *backend.Watermark) *core.Signer {
		t.Helper()
		s, err := core.NewSigner(cfg, 4, 4, h)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.AddValidator(pk, sk, 7, wm); err != nil {
			t.Fatal(err)
		}
		return s
	}
	s := start(nil)
	blk := &backend.BeaconBlockHeader{Slot: 19*32 + 1, ProposerIndex: 7, BodyRoot: backend.Root{4}}
	if _, err := s.Sign(signReq(s, pk, att(15, 18))); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Sign(signReq(s, pk, blk)); err != nil {
		t.Fatal(err)
	}
	s.Close() // stops before the signatures are released

	wm := backend.Watermark{HasAttestation: true, SourceEpoch: 16, TargetEpoch: 17, HasBlock: true, BlockSlot: blk.Slot}
	s = start(&wm)
	check := func(when string) {
		t.Helper()
		if _, rep, err := s.SignDetailed(signReq(s, pk, att(15, 18))); rep || !backend.StatusOf(err).IsSlashing() {
			t.Errorf("%s: (15, 18) again: repeat=%v err=%v, want a slashing refusal", when, rep, err)
		}
		if _, rep, err := s.SignDetailed(signReq(s, pk, blk)); rep || !backend.StatusOf(err).IsSlashing() {
			t.Errorf("%s: block at slot %d again: repeat=%v err=%v, want a slashing refusal", when, blk.Slot, rep, err)
		}
	}
	check("after the import")
	if rec, _, _ := h.LoadRepeatRoots(pk); !bytes.Equal(rec, core.NoRepeatRoots()) {
		t.Errorf("stored roots after the import: %x, want the empty record", rec)
	}
	s.Close()
	s = start(nil) // a later restart must not bring the old roots back
	defer s.Close()
	check("after the next restart")
}

// The root store fails: the import is refused before it raises the marks,
// and the key stays unready.
func TestImportRefusedWhenRootsNotDropped(t *testing.T) {
	h := software.NewMemHooks()
	h.Clock = clockAtEpoch(20)
	cfg := software.DevConfig(genesis, 12, 32)
	cfg.PersistRepeatRoot = true
	sk, _ := software.NewSecret()
	pk, _ := core.PubkeyOf(sk)
	s, err := core.NewSigner(cfg, 4, 4, h)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.AddValidator(pk, sk, 7, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Sign(signReq(s, pk, att(15, 18))); err != nil {
		t.Fatal(err)
	}
	h.FailRoots = true
	err = s.Import(pk, backend.Watermark{HasAttestation: true, SourceEpoch: 16, TargetEpoch: 17})
	wantStatus(t, err, backend.StatusStorage)
	if st, _ := s.State(pk); st.RAM.SourceEpoch != 15 || st.RAM.TargetEpoch != 18 {
		t.Errorf("marks raised by an import that was refused: %+v", st)
	}
	if _, rep, err := s.SignDetailed(signReq(s, pk, att(15, 18))); rep || err == nil {
		t.Errorf("(15, 18) again after a refused import: repeat=%v err=%v", rep, err)
	}
}

func TestBlockRepeatRefusedAfterImport(t *testing.T) {
	s, pk, _ := newTestSigner(t, software.NewMemHooks())
	b := &backend.BeaconBlockHeader{Slot: 20*32 + 3, ProposerIndex: 7, BodyRoot: backend.Root{0xa}}
	if _, err := s.Sign(signReq(s, pk, b)); err != nil {
		t.Fatal(err)
	}
	if err := s.Import(pk, backend.Watermark{HasBlock: true, BlockSlot: b.Slot}); err != nil {
		t.Fatal(err)
	}
	if _, rep, err := s.SignDetailed(signReq(s, pk, b)); rep || !backend.StatusOf(err).IsSlashing() {
		t.Errorf("block at slot %d again after an import of that slot: repeat=%v err=%v", b.Slot, rep, err)
	}
}

func TestGloasRepeatRefusedAfterImport(t *testing.T) {
	s, pk, cfg, _ := gloasSigner(t, software.NewMemHooks())
	ptc := &backend.PayloadAttestationData{BeaconBlockRoot: backend.Root{1}, Slot: 20*32 + 5, PayloadPresent: true}
	block := &backend.BeaconBlockHeader{Slot: 20*32 + 6, ProposerIndex: 7, ParentRoot: backend.Root{4}, BodyRoot: backend.Root{5}}
	env := &backend.PayloadEnvelope{BuilderIndex: backend.BuilderIndexSelfBuild, ParentBeaconBlockRoot: block.ParentRoot}
	env.Payload.SlotNumber = block.Slot
	env.Payload.FeeRecipient = cfg.FeeRecipients[0]
	env.BeaconBlockRoot, _ = backend.HashTreeRoot(block)
	for _, m := range []backend.Message{ptc, block, env} {
		if _, err := s.Sign(signReq(s, pk, m)); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Import(pk, backend.Watermark{HasBlock: true, BlockSlot: block.Slot}); err != nil {
		t.Fatal(err)
	}
	for _, m := range []backend.Message{ptc, env} {
		if _, rep, err := s.SignDetailed(signReq(s, pk, m)); rep || !backend.StatusOf(err).IsSlashing() {
			t.Errorf("%T again after an import: repeat=%v err=%v, want a slashing refusal", m, rep, err)
		}
	}
}
