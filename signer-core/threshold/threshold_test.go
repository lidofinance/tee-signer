package threshold_test

import (
	"testing"

	"github.com/lidofinance/tee-signer/signer-core/core"
	"github.com/lidofinance/tee-signer/signer-core/software"
	"github.com/lidofinance/tee-signer/signer-core/threshold"
	"github.com/lidofinance/tee-signer/signer-protocol"
)

const genesis = 1_000_000

func clockAtEpoch(e uint64) func() (uint64, error) {
	return func() (uint64, error) { return genesis + e*12*32 + 5, nil }
}

func signReq(s *core.Signer, pk backend.Pubkey, m backend.Message) backend.SignRequest {
	cfg := s.Config()
	d, _ := cfg.MessageDomain(m)
	return backend.SignRequest{Pubkey: pk, Message: m, Domain: d}
}

func TestThresholdRecover(t *testing.T) {
	cfg := software.DevConfig(genesis, 12, 32)
	sk, _ := software.NewSecret()
	pk, _ := core.PubkeyOf(sk)
	shares, err := software.Split(sk, 3, 5)
	if err != nil {
		t.Fatal(err)
	}
	a := &backend.AttestationData{Slot: 20 * 32, BeaconBlockRoot: backend.Root{0xbb}, Source: backend.Checkpoint{Epoch: 19, Root: backend.Root{5}}, Target: backend.Checkpoint{Epoch: 20, Root: backend.Root{7}}}
	root, _ := cfg.SigningRoot(a)
	sigs := map[uint64]backend.Signature{}
	sharePks := map[uint64]backend.Pubkey{}
	for _, sh := range shares {
		h := software.NewMemHooks()
		h.Clock = clockAtEpoch(20)
		s, err := core.NewSigner(cfg, 1, 0, h)
		if err != nil {
			t.Fatal(err)
		}
		k, err := s.AddValidator(pk, sh.Secret, 7, nil)
		if err != nil {
			t.Fatal(err)
		}
		sig, err := s.Sign(signReq(s, pk, a))
		s.Close()
		if err != nil {
			t.Fatal(err)
		}
		if !core.Verify(k.SharePubkey, root, sig) {
			t.Fatalf("share %d: partial signature does not verify under the share key", sh.ID)
		}
		if core.Verify(pk, root, sig) {
			t.Fatalf("share %d: partial signature verifies under the full key", sh.ID)
		}
		sigs[sh.ID], sharePks[sh.ID] = sig, k.SharePubkey
	}
	subsets := 0
	for i := uint64(1); i <= 5; i++ {
		for j := i + 1; j <= 5; j++ {
			for k := j + 1; k <= 5; k++ {
				ids := []uint64{i, j, k}
				full, err := threshold.RecoverSignature(ids, []backend.Signature{sigs[i], sigs[j], sigs[k]})
				if err != nil {
					t.Fatal(err)
				}
				if !core.Verify(pk, root, full) {
					t.Fatalf("subset %v: recovered signature does not verify", ids)
				}
				rpk, err := threshold.RecoverPubkey(ids, []backend.Pubkey{sharePks[i], sharePks[j], sharePks[k]})
				if err != nil || rpk != pk {
					t.Fatalf("subset %v: recovered pubkey differs", ids)
				}
				subsets++
			}
		}
	}
	two, _ := threshold.RecoverSignature([]uint64{1, 2}, []backend.Signature{sigs[1], sigs[2]})
	if core.Verify(pk, root, two) {
		t.Fatal("2 shares must not be enough")
	}
	t.Logf("3-of-5: %d subsets recovered and verified", subsets)
}

func TestFeldmanCommitments(t *testing.T) {
	secret, err := software.NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	shares, commitments, err := software.SplitWithCommitments(secret, 3, 5)
	if err != nil {
		t.Fatal(err)
	}
	full, err := core.PubkeyOf(secret)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := threshold.FeldmanEval(commitments, 0); err != nil || got != full {
		t.Fatalf("constant coefficient: %x, %v", got, err)
	}
	for _, share := range shares {
		want, err := core.PubkeyOf(share.Secret)
		if err != nil {
			t.Fatal(err)
		}
		if got, err := threshold.FeldmanEval(commitments, share.ID); err != nil || got != want {
			t.Fatalf("share %d: %x, %v; want %x", share.ID, got, err, want)
		}
	}
	if _, err := threshold.FeldmanEval(nil, 1); err == nil {
		t.Fatal("accepted no commitments")
	}
	commitments[1] = backend.Pubkey{}
	if _, err := threshold.FeldmanEval(commitments, 1); err == nil {
		t.Fatal("accepted malformed commitment")
	}
}

func TestRecoveryRejectsMalformedShares(t *testing.T) {
	if _, err := threshold.RecoverSignature(nil, nil); err == nil {
		t.Fatal("accepted no signatures")
	}
	if _, err := threshold.RecoverPubkey(nil, nil); err == nil {
		t.Fatal("accepted no public keys")
	}
	if _, err := threshold.RecoverSignature([]uint64{1}, nil); err == nil {
		t.Fatal("accepted mismatched signatures")
	}
	if _, err := threshold.RecoverPubkey([]uint64{1}, nil); err == nil {
		t.Fatal("accepted mismatched public keys")
	}
	if _, err := threshold.RecoverSignature([]uint64{1, 1}, make([]backend.Signature, 2)); err == nil {
		t.Fatal("accepted duplicate signature IDs")
	}
	if _, err := threshold.RecoverPubkey([]uint64{1, 1}, make([]backend.Pubkey, 2)); err == nil {
		t.Fatal("accepted duplicate public key IDs")
	}
	if _, err := threshold.RecoverSignature([]uint64{1}, []backend.Signature{{}}); err == nil {
		t.Fatal("accepted malformed signature")
	}
	if _, err := threshold.RecoverPubkey([]uint64{1}, []backend.Pubkey{{}}); err == nil {
		t.Fatal("accepted malformed public key")
	}
}
