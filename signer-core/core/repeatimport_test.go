package core_test

import (
	"testing"

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
