//go:build !debugimport

package server

import (
	"testing"

	"github.com/lidofinance/tee-signer/governance/exitapproval"
	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/slashing-log"
	"github.com/lidofinance/tee-signer/tee-signer/handover"
)

// SHH-01: a target with a same-day ledger kept its own and dropped the
// carried one, so the source's exits of the day did not count. The
// ledgers merge: every exit of either counts, each nonce once.
func TestSHH01CarriedExitsMergeIntoTheDay(t *testing.T) {
	e := newTgtEnv(t, "dev", nil)
	today := e.now() / daySeconds
	own := &markstore.ExitDay{Day: today, Stake: 2048 * eth, Exits: []markstore.ExitEntry{{ValidatorIndex: 1, ExitEpoch: 1, Stake: 2048 * eth, Nonce: [32]byte{1}}}}
	if err := e.hooks.RecordExits(ctx, own); err != nil {
		t.Fatal(err)
	}
	carry := &handover.Carry{Exits: &handover.Exits{Day: today, Stake: 4096 * eth, Entries: []handover.Exit{
		{ValidatorIndex: 2, ExitEpoch: 1, Stake: 2048 * eth, Nonce: [32]byte{2}},
		{ValidatorIndex: 3, ExitEpoch: 1, Stake: 2048 * eth, Nonce: [32]byte{3}}}}}
	im := &importer{s: e.srv}
	if err := im.takeExits(ctx, carry); err != nil {
		t.Fatal(err)
	}
	d, _ := e.hooks.Exits()
	if d == nil || d.Day != today || len(d.Exits) != 3 || d.Stake != 3*2048*eth {
		t.Fatalf("ledger after the carry: %+v, want 3 exits and %d Gwei", d, 3*2048*eth)
	}
	// The same carry again changes nothing.
	if err := im.takeExits(ctx, carry); err != nil {
		t.Fatal(err)
	}
	if d2, _ := e.hooks.Exits(); len(d2.Exits) != 3 || d2.Stake != d.Stake {
		t.Fatalf("the carry counted twice: %+v", d2)
	}
}

// SHH-01, second part: an exit is recorded only for a key this runner has
// loaded, so an empty target holds no ledger entry before its import.
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
