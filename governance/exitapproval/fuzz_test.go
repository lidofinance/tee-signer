package exitapproval

import (
	"bytes"
	"testing"

	"github.com/lidofinance/tee-signer/devkit/fuzzcheck"
	"github.com/lidofinance/tee-signer/governance/setupwire"
	"github.com/lidofinance/tee-signer/signer-protocol"
)

// The signed exit approval comes in APPROVE_EXIT from an admin client.
// Oracles: no panic, bounded allocation, and what decodes encodes back.

func FuzzDecode(f *testing.F) {
	a := Approval{GenesisValidatorsRoot: backend.Root{1}, Pubkey: backend.Pubkey{2}, ValidatorIndex: 3, ExitEpoch: 4,
		EffectiveBalance: 5, NotAfter: 6, Nonce: [32]byte{7}}
	s := Signed{Approval: a}
	for _, id := range []byte{1, 3} {
		s.Approvals = append(s.Approvals, setupwire.Approval{Position: id - 1, Signature: Sign(approver(id), &a)})
	}
	raw, err := s.Encode()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(raw)
	f.Fuzz(func(t *testing.T, b []byte) {
		fuzzcheck.Watch(t)
		var s *Signed
		var err error
		fuzzcheck.Bounded(t, len(b), func() { s, err = Decode(b) })
		if err != nil {
			return
		}
		if again, err := s.Encode(); err != nil || !bytes.Equal(again, b) {
			t.Fatalf("approval does not encode back (%v):\n%x\n%x", err, again, b)
		}
	})
}
