//go:build !debugimport

package server

import (
	"testing"

	"github.com/lidofinance/tee-signer/governance/exitapproval"
	"github.com/lidofinance/tee-signer/signer-protocol"
)

// SHH-01: an exit is recorded only for a key this runner has loaded.
func TestSHH01ExitOfAKeyNotLoadedRefused(t *testing.T) {
	e := newTgtEnv(t, "dev", nil)
	_, pk := newKey(t)
	epoch := e.signer.EpochAt(e.now())
	a := exitapproval.Approval{GenesisValidatorsRoot: e.setup.Chain.GenesisValidatorsRoot, Pubkey: pk, ValidatorIndex: 5, ExitEpoch: epoch,
		EffectiveBalance: 32 * eth, NotAfter: e.now() + 3600, Nonce: [32]byte{1}}
	if err := e.approve(e.approval([]byte{1, 2}, a)); err != nil {
		t.Fatal(err)
	}
	if err := e.srv.exitAllowed(pk, &backend.VoluntaryExit{Epoch: epoch, ValidatorIndex: 5}); err == nil {
		t.Error("an exit of a key this runner does not hold was recorded")
	}
	if d, _ := e.hooks.Exits(); d != nil {
		t.Errorf("ledger %+v, want none", d)
	}
}
