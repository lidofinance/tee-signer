package server

import (
	"testing"

	"github.com/lidofinance/tee-signer/signer-core/core"
	"github.com/lidofinance/tee-signer/signer-core/software"
	"github.com/lidofinance/tee-signer/signer-protocol"
)

// A runner without a setup signs a voluntary exit like any other message,
// on every platform: the core checks the key's bound index only.
func TestExitWithoutSetup(t *testing.T) {
	for _, platform := range []string{"gcp", "azure", "nitro", "dev"} {
		s := roleServer(t)
		s.Platform.Name = platform
		sk, err := software.NewSecret()
		if err != nil {
			t.Fatal(err)
		}
		pk, err := core.PubkeyOf(sk)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.addShare(pk, &sk, 5, nil, "test"); err != nil {
			t.Fatal(err)
		}
		exit := func(index uint64) error {
			m := &backend.VoluntaryExit{Epoch: 1, ValidatorIndex: index}
			cfg := s.Signer.Config()
			d, err := cfg.MessageDomain(m)
			if err != nil {
				t.Fatal(err)
			}
			_, err = s.sign(backend.SignRequest{Pubkey: pk, Message: m, Domain: d})
			return err
		}
		if err := exit(5); err != nil {
			t.Errorf("platform %s: %v", platform, err)
		}
		if err := exit(6); refusedWith(err) != backend.StatusPolicyIndex {
			t.Errorf("platform %s: an exit for another index: %v, want POLICY_INDEX", platform, err)
		}
	}
}
