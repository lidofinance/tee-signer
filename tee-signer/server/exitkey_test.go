//go:build (peer_azure || peer_aws || peer_gcp || peer_dev) && !debugimport

package server

import (
	"testing"

	"github.com/lidofinance/tee-signer/governance/exitapproval"
	"github.com/lidofinance/tee-signer/governance/setupwire"
	"github.com/lidofinance/tee-signer/signer-protocol"
)

// OPTEE-EXIT-01, cloud form: the day's exit ledger matched a repeat on
// (index, epoch) only. An exit quorum that pairs a second key with the
// first key's index and epoch got the second exit signed without its stake
// counted. A repeat must match the key too, so the second key's exit hits
// the cap, also after a restart.
func TestOPTEEEXIT01RepeatMatchesTheKey(t *testing.T) {
	e := newTgtEnv(t, "dev", func(s *setupwire.Setup) { s.Locked.ExitStakeCapPerDay = 2048 * eth })
	gvr := e.setup.Chain.GenesisValidatorsRoot
	ska, pka := newKey(t)
	skb, pkb := newKey(t)
	if err := e.importSealed(pka, ska, 5, nil); err != nil {
		t.Fatal(err)
	}
	if err := e.importSealed(pkb, skb, 6, nil); err != nil {
		t.Fatal(err)
	}
	epoch := e.signer.EpochAt(e.now())
	approve := func(pk backend.Pubkey, nonce byte) {
		t.Helper()
		a := exitapproval.Approval{GenesisValidatorsRoot: gvr, Pubkey: pk, ValidatorIndex: 5, ExitEpoch: epoch,
			EffectiveBalance: 2048 * eth, NotAfter: e.now() + 3600, Nonce: [32]byte{nonce}}
		if err := e.approve(e.approval([]byte{1, 2}, a)); err != nil {
			t.Fatal(err)
		}
	}
	exit := &backend.VoluntaryExit{Epoch: epoch, ValidatorIndex: 5}
	approve(pka, 1)
	approve(pkb, 2) // B paired with A's index and epoch
	if err := e.srv.exitAllowed(pka, exit); err != nil {
		t.Fatalf("A's exit: %v", err)
	}
	if err := e.srv.exitAllowed(pka, exit); err != nil {
		t.Fatalf("A's exit again (a repeat counts nothing): %v", err)
	}
	wantExitRefusal(t, e.srv.exitAllowed(pkb, exit), "the cap is")

	e.restart()
	approve(pkb, 2)
	wantExitRefusal(t, e.srv.exitAllowed(pkb, exit), "the cap is")
}
