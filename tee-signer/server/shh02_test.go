//go:build !debugimport

package server

import (
	"testing"

	"github.com/lidofinance/tee-signer/governance/exitapproval"
	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/slashing-log"
)

// SHH-02: a ledger of a later day (a handover from a source whose clock is
// past midnight) is not dropped as if a new day had begun: exitAllowed
// refuses while the stored day is ahead of the clock, and the ledger keeps
// its day.
func TestSHH02LedgerDayAheadRefused(t *testing.T) {
	e := newTgtEnv(t, "dev", nil)
	sk, pk := newKey(t)
	if err := e.importSealed(pk, sk, 5, nil); err != nil {
		t.Fatal(err)
	}
	today := e.now() / daySeconds
	ahead := &markstore.ExitDay{Day: today + 1, Stake: 2048 * eth, Exits: []markstore.ExitEntry{{ValidatorIndex: 9, ExitEpoch: 1, Stake: 2048 * eth, Nonce: [32]byte{9}}}}
	if err := e.hooks.RecordExits(ctx, ahead); err != nil {
		t.Fatal(err)
	}
	epoch := e.signer.EpochAt(e.now())
	a := exitapproval.Approval{GenesisValidatorsRoot: e.setup.Chain.GenesisValidatorsRoot, Pubkey: pk, ValidatorIndex: 5, ExitEpoch: epoch,
		EffectiveBalance: 32 * eth, NotAfter: e.now() + 3600, Nonce: [32]byte{1}}
	// The approval is refused too while the ledger is ahead; either way no
	// exit may be recorded.
	_ = e.approve(e.approval([]byte{1, 2}, a))
	if err := e.srv.exitAllowed(pk, &backend.VoluntaryExit{Epoch: epoch, ValidatorIndex: 5}); err == nil {
		t.Error("an exit was recorded under a ledger of a later day")
	}
	if d, _ := e.hooks.Exits(); d == nil || d.Day != today+1 {
		t.Errorf("ledger day %+v, want %d", d, today+1)
	}
}
