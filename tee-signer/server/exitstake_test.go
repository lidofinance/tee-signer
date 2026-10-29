//go:build !debugimport

package server

import (
	"testing"

	"github.com/lidofinance/tee-signer/governance/exitapproval"
	"github.com/lidofinance/tee-signer/governance/setupwire"
	"github.com/lidofinance/tee-signer/signer-protocol"
)

// VSEXIT-02 and OPTEE-DEPOSIT-02: every exit
// counts max_effective_balance against the day's cap, whatever balance the
// approval states and whatever the setup's withdrawal credentials prefix.
// The runner cannot check a stated balance, and a 0x01 validator may have
// switched to compounding since.
func TestExitChargesMaxEffectiveBalance(t *testing.T) {
	for name, change := range map[string]func(s *setupwire.Setup){
		"setup credentials": func(s *setupwire.Setup) {},
		"0x01 credentials":  func(s *setupwire.Setup) { s.Locked.WithdrawalCredentials[0] = 0x01 },
	} {
		t.Run(name, func(t *testing.T) {
			e := newTgtEnv(t, "dev", func(s *setupwire.Setup) {
				change(s)
				s.Locked.ExitStakeCapPerDay = 3000 * eth
			})
			gvr := e.setup.Chain.GenesisValidatorsRoot
			epoch := e.signer.EpochAt(e.now())
			for i, idx := range []uint64{5, 6} {
				sk, pk := newKey(t)
				if err := e.importSealed(pk, sk, idx, nil); err != nil {
					t.Fatal(err)
				}
				a := exitapproval.Approval{GenesisValidatorsRoot: gvr, Pubkey: pk, ValidatorIndex: idx, ExitEpoch: epoch,
					EffectiveBalance: 32 * eth, NotAfter: e.now() + 3600, Nonce: [32]byte{byte(i + 1)}}
				if err := e.approve(e.approval([]byte{1, 2}, a)); err != nil {
					t.Fatal(err)
				}
				err := e.srv.exitAllowed(pk, &backend.VoluntaryExit{Epoch: epoch, ValidatorIndex: idx})
				if i == 0 && err != nil {
					t.Fatalf("first exit: %v", err)
				}
				if i == 1 {
					// 2048 ETH counted for the first, the cap is 3000 ETH.
					wantExitRefusal(t, err, "the cap is")
				}
			}
			d, err := e.hooks.Exits()
			if err != nil || d == nil || d.Stake != e.setup.Locked.MaxEffectiveBalance {
				t.Fatalf("the day's stake %+v (%v), want max_effective_balance %d", d, err, e.setup.Locked.MaxEffectiveBalance)
			}
		})
	}
}
