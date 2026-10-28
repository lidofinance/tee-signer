package server

import (
	"strings"
	"testing"

	"github.com/lidofinance/tee-signer/signer-core/core"
	"github.com/lidofinance/tee-signer/signer-protocol"
)

// A runner without a setup has no exit approvals and no daily cap, so off
// the dev platform it refuses every VOLUNTARY_EXIT; on dev the core
// decides as before.
func TestNoExitWithoutSetup(t *testing.T) {
	for _, platform := range []string{"gcp", "azure", "nitro", "dev"} {
		s := roleServer(t)
		s.Platform.Name = platform
		sk, err := core.NewSecret()
		if err != nil {
			t.Fatal(err)
		}
		pk, err := core.PubkeyOf(sk)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.addShare(pk, &sk, 1, nil, "test"); err != nil {
			t.Fatal(err)
		}
		_, err = s.sign(backend.SignRequest{Pubkey: pk, Message: &backend.VoluntaryExit{Epoch: 1, ValidatorIndex: 5}})
		refused := err != nil && strings.Contains(err.Error(), "no setup")
		if refused != (platform != "dev") {
			t.Errorf("platform %s: %v", platform, err)
		}
		if refused && refusedWith(err) != backend.StatusPolicyExit {
			t.Errorf("platform %s: code %v, want POLICY_EXIT", platform, refusedWith(err))
		}
	}
}
