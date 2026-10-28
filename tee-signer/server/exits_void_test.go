//go:build !debugimport

package server

import (
	"testing"

	"github.com/lidofinance/tee-signer/governance/exitapproval"
	"github.com/lidofinance/tee-signer/governance/setupwire"
	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/wire"
	wireadmin "github.com/lidofinance/tee-signer/signer-protocol/wire/admin"
)

// VSEXIT-01: a held exit approval counts only under the approver set and
// exit_approvals_needed it was checked against, as in the TA, which clears
// its held approvals on every locked activation. A locked update that
// raises exit_approvals_needed comes into force; the approval held before
// it no longer lets the exit sign.
func TestHeldExitApprovalVoidAfterLockedChange(t *testing.T) {
	e := newTgtEnv(t, "dev", func(s *setupwire.Setup) {
		s.Locked.ExitStakeCapPerDay = 3000 * eth
		s.Locked.ChangeDelaySeconds = u64(3600)
	})
	sk5, pk5 := newKey(t)
	if err := e.importSealed(pk5, sk5, 5, nil); err != nil {
		t.Fatal(err)
	}
	epoch := e.signer.EpochAt(e.now())
	a5 := exitapproval.Approval{GenesisValidatorsRoot: e.setup.Chain.GenesisValidatorsRoot, Pubkey: pk5, ValidatorIndex: 5, ExitEpoch: epoch,
		EffectiveBalance: 2048 * eth, NotAfter: e.now() + 3*3600, Nonce: [32]byte{5}}
	if err := e.approve(e.approval([]byte{1, 2}, a5)); err != nil {
		t.Fatal(err)
	}

	fresh, err := setupwire.DecodeSetup(e.raw)
	if err != nil {
		t.Fatal(err)
	}
	prev, err := e.setup.GroupHash(setupwire.GroupLocked)
	if err != nil {
		t.Fatal(err)
	}
	b := &setupwire.UpdateBody{ClusterID: e.setup.ClusterID, ChainHash: e.setup.Chain.Hash(), Group: setupwire.GroupLocked,
		Version: 1, PrevHash: prev, ActivateAt: e.now(), Locked: &fresh.Locked}
	b.Locked.ExitApprovalsNeeded = 3
	b.Salts = testSalts(b)
	p, err := wireadmin.EncodeConfigUpdate(signed(t, b, first2, nil))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.srv.dispatch(ctx, wire.Frame{Type: wireadmin.TypeConfigUpdate, Payload: p}); err != nil {
		t.Fatal(err)
	}
	e.clock.add(3601)
	if l, err := e.upd.LockedInForce(); err != nil || l.ExitApprovalsNeeded != 3 {
		t.Fatalf("the locked update is not in force: %v", err)
	}
	wantExitRefusal(t, e.signMsg(pk5, &backend.VoluntaryExit{Epoch: epoch, ValidatorIndex: 5}), "no exit approval")
	// Approved again under the values in force, it signs.
	if err := e.approve(e.approval([]byte{1, 2, 3}, a5)); err != nil {
		t.Fatal(err)
	}
	if err := e.signMsg(pk5, &backend.VoluntaryExit{Epoch: epoch, ValidatorIndex: 5}); err != nil {
		t.Fatalf("exit approved under the values in force: %v", err)
	}
}
