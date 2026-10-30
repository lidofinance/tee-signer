package core_test

import (
	"testing"

	"github.com/lidofinance/tee-signer/signer-core/core"
	"github.com/lidofinance/tee-signer/signer-core/software"
	"github.com/lidofinance/tee-signer/signer-protocol"
)

// VSGLOAS-01: an import raises the block bound but not the Gloas slot
// bounds, so a PTC vote for a slot the imported history covers signs.
func TestVSGLOAS01ImportRaisesGloasSlotBounds(t *testing.T) {
	t.Run("per validator", func(t *testing.T) {
		s, pk, _, _ := gloasSigner(t, software.NewMemHooks())
		if err := s.Import(pk, backend.Watermark{HasBlock: true, BlockSlot: 20*32 + 10}); err != nil {
			t.Fatal(err)
		}
		_, err := s.Sign(signReq(s, pk, &backend.PayloadAttestationData{BeaconBlockRoot: backend.Root{1}, Slot: 20*32 + 5}))
		if backend.StatusOf(err) != backend.StatusEquivocation {
			t.Errorf("PTC vote at slot %d under an imported block bound %d: %v, want %v", 20*32+5, 20*32+10, err, backend.StatusEquivocation)
		}
	})
	t.Run("per device", func(t *testing.T) {
		h := &deviceHooks{MemHooks: software.NewMemHooks()}
		h.Clock = clockAtEpoch(20)
		cfg := software.DevConfig(genesis, 12, 32)
		cfg.Forks = append(cfg.Forks, core.Fork{Epoch: gloasEpoch, Version: backend.Version{0x07, 0x00, 0x00, 0x01}})
		e := uint64(gloasEpoch)
		cfg.GloasForkEpoch = &e
		cfg.DeviceMark = true
		s, err := core.NewSigner(cfg, 4, 0, h)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(s.Close)
		sk, _ := software.NewSecret()
		pk, _ := core.PubkeyOf(sk)
		wm := backend.Watermark{HasBlock: true, BlockSlot: 20*32 + 10}
		if _, err := s.AddValidator(pk, sk, 7, &wm); err != nil {
			t.Fatal(err)
		}
		_, err = s.Sign(signReq(s, pk, &backend.PayloadAttestationData{BeaconBlockRoot: backend.Root{1}, Slot: 20*32 + 5}))
		if backend.StatusOf(err) != backend.StatusEquivocation {
			t.Errorf("PTC vote at slot %d under an imported block bound %d: %v, want %v", 20*32+5, 20*32+10, err, backend.StatusEquivocation)
		}
	})
}
