//go:build !debugimport

package server

import (
	"strings"
	"testing"

	"github.com/lidofinance/tee-signer/governance/exitapproval"
	"github.com/lidofinance/tee-signer/governance/setupwire"
	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/wire"
	wireadmin "github.com/lidofinance/tee-signer/signer-protocol/wire/admin"
)

const eth = uint64(1e9)

// approval is a signed exit approval by the approvers ids.
func (e *tgtEnv) approval(ids []byte, a exitapproval.Approval) []byte {
	e.t.Helper()
	s := exitapproval.Signed{Approval: a}
	for _, id := range ids {
		s.Approvals = append(s.Approvals, setupwire.Approval{Position: id - 1, Signature: exitapproval.Sign(approver(id), &a)})
	}
	raw, err := s.Encode()
	if err != nil {
		e.t.Fatal(err)
	}
	return raw
}

func (e *tgtEnv) approve(raw []byte) error {
	_, err := e.srv.dispatch(ctx, wire.Frame{Type: wireadmin.TypeApproveExit, Payload: raw})
	return err
}

func wantExitRefusal(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("%v, want a refusal with %q", err, want)
	}
}

// Issue #4 F4, the TA's exit rules on the runner: an approval of
// exit_approvals_needed approvers bound to key, index, epoch and a nonce,
// and the day's stake cap, which a restart keeps.
func TestExitApprovals(t *testing.T) {
	e := newTgtEnv(t, "dev", func(s *setupwire.Setup) { s.Locked.ExitStakeCapPerDay = 3000 * eth })
	gvr := e.setup.Chain.GenesisValidatorsRoot
	sk5, pk5 := newKey(t)
	sk126, pk126 := newKey(t)
	if err := e.importSealed(pk5, sk5, 5, nil); err != nil {
		t.Fatal(err)
	}
	if err := e.importSealed(pk126, sk126, 126, nil); err != nil {
		t.Fatal(err)
	}
	epoch := e.signer.EpochAt(e.now())
	a5 := exitapproval.Approval{GenesisValidatorsRoot: gvr, Pubkey: pk5, ValidatorIndex: 5, ExitEpoch: epoch,
		EffectiveBalance: 2048 * eth, NotAfter: e.now() + 3600, Nonce: [32]byte{5}}

	wantExitRefusal(t, e.approve(e.approval([]byte{1}, a5)), "exit_approvals_needed is 2")
	wantExitRefusal(t, e.signMsg(pk5, &backend.VoluntaryExit{Epoch: epoch, ValidatorIndex: 5}), "no exit approval")
	bad := a5
	bad.EffectiveBalance = 2049 * eth
	wantExitRefusal(t, e.approve(e.approval([]byte{1, 2}, bad)), "allowed 1 to")
	bad = a5
	bad.NotAfter = e.now() + 8*86400
	wantExitRefusal(t, e.approve(e.approval([]byte{1, 2}, bad)), "valid too long")
	bad = a5
	bad.GenesisValidatorsRoot[0] ^= 1
	wantExitRefusal(t, e.approve(e.approval([]byte{1, 2}, bad)), "another chain")

	if err := e.approve(e.approval([]byte{1, 2}, a5)); err != nil {
		t.Fatal(err)
	}
	wantExitRefusal(t, e.signMsg(pk5, &backend.VoluntaryExit{Epoch: epoch + 1, ValidatorIndex: 5}), "no exit approval")
	wantExitRefusal(t, e.signMsg(pk126, &backend.VoluntaryExit{Epoch: epoch, ValidatorIndex: 126}), "no exit approval")
	if err := e.signMsg(pk5, &backend.VoluntaryExit{Epoch: epoch, ValidatorIndex: 5}); err != nil {
		t.Fatalf("approved exit: %v", err)
	}
	if err := e.signMsg(pk5, &backend.VoluntaryExit{Epoch: epoch, ValidatorIndex: 5}); err != nil {
		t.Fatalf("the same exit again: %v", err)
	}

	// The nonce is used for the day.
	again := a5
	again.ExitEpoch++
	wantExitRefusal(t, e.approve(e.approval([]byte{2, 3}, again)), "nonce was used today")

	// 2048 ETH counted, the cap is 3000 ETH: another 2048 ETH exit does not
	// fit, also after a restart.
	a126 := exitapproval.Approval{GenesisValidatorsRoot: gvr, Pubkey: pk126, ValidatorIndex: 126, ExitEpoch: epoch,
		EffectiveBalance: 2048 * eth, NotAfter: e.now() + 3600, Nonce: [32]byte{126}}
	if err := e.approve(e.approval([]byte{1, 3}, a126)); err != nil {
		t.Fatal(err)
	}
	wantExitRefusal(t, e.signMsg(pk126, &backend.VoluntaryExit{Epoch: epoch, ValidatorIndex: 126}), "the cap is")
	e.restart()
	if err := e.approve(e.approval([]byte{1, 3}, a126)); err != nil {
		t.Fatal(err)
	}
	wantExitRefusal(t, e.signMsg(pk126, &backend.VoluntaryExit{Epoch: epoch, ValidatorIndex: 126}), "the cap is")
	// A smaller stated balance counts max_effective_balance all the same
	// (VSEXIT-02): it does not fit either.
	small := a126
	small.EffectiveBalance, small.ExitEpoch, small.Nonce = 900*eth, epoch+1, [32]byte{128}
	if err := e.approve(e.approval([]byte{1, 3}, small)); err != nil {
		t.Fatal(err)
	}
	wantExitRefusal(t, e.signMsg(pk126, &backend.VoluntaryExit{Epoch: epoch + 1, ValidatorIndex: 126}), "the cap is")
}
