package core_test

import (
	"errors"
	"testing"

	"github.com/lidofinance/tee-signer/signer-core/core"
	"github.com/lidofinance/tee-signer/signer-core/software"
	"github.com/lidofinance/tee-signer/signer-protocol"
)

// failingDeviceHooks are deviceHooks whose next failStores device mark
// writes fail, as a mark log store that is down.
type failingDeviceHooks struct {
	deviceHooks
	failStores int
}

func (h *failingDeviceHooks) StoreDeviceMark(wm backend.Watermark) error {
	h.mu.Lock()
	if h.failStores > 0 {
		h.failStores--
		h.mu.Unlock()
		return errors.New("mark log store down")
	}
	h.mu.Unlock()
	return h.deviceHooks.StoreDeviceMark(wm)
}

// SSI-HISTORY-02: AddValidator loads the key, then imports its maxima. When
// the import's device mark write fails, the key stays loaded with the RAM
// bounds from before the import, and a request that waited for the lock
// signs under them. A key whose history did not reach the core must sign
// nothing.
func TestSSIHISTORY02FailedImportLeavesNoSignableKey(t *testing.T) {
	h := &failingDeviceHooks{deviceHooks: deviceHooks{MemHooks: software.NewMemHooks()}}
	h.Clock = clockAtEpoch(20)
	cfg := software.DevConfig(genesis, 12, 32)
	cfg.DeviceMark = true
	s, err := core.NewSigner(cfg, 4, 0, h)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	sk, _ := software.NewSecret()
	pk, _ := core.PubkeyOf(sk)
	history := backend.Watermark{HasAttestation: true, SourceEpoch: 15, TargetEpoch: 18}
	h.failStores = 1
	if _, err := s.AddValidator(pk, sk, 7, &history); err == nil {
		t.Fatal("the import's failed mark write did not reach AddValidator")
	}
	// Source 10 is below the imported history's source 15: a surround of
	// the vote (15, 18) the history stands for.
	if _, err := s.Sign(signReq(s, pk, att(10, 21))); err == nil {
		t.Error("vote (source 10, target 21) signed by a key whose history (source 15, target 18) did not reach the core")
	}
}
