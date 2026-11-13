package threshold_test

import (
	"encoding/hex"
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
		// The share loads at epoch 0, so the restart floor (epoch 2) stays
		// below the vote at epoch 20.
		h.Clock = clockAtEpoch(0)
		s, err := core.NewSigner(cfg, 1, 0, h)
		if err != nil {
			t.Fatal(err)
		}
		k, err := s.AddValidator(pk, sh.Secret, 7, nil)
		if err != nil {
			t.Fatal(err)
		}
		h.Clock = clockAtEpoch(20)
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

// Commitments from t share public keys are the split's own Feldman
// commitments, whichever t shares they come from (a Charon cluster lock
// gives the share public keys and no commitments).
func TestCommitmentsFromShares(t *testing.T) {
	secret, _ := software.NewSecret()
	shares, want, err := software.SplitWithCommitments(secret, 3, 5)
	if err != nil {
		t.Fatal(err)
	}
	pub := map[uint64]backend.Pubkey{}
	for _, s := range shares {
		pub[s.ID], _ = core.PubkeyOf(s.Secret)
	}
	for _, ids := range [][]uint64{{1, 2, 3}, {5, 1, 4}, {2, 4, 5}} {
		got, err := threshold.Commitments(ids, []backend.Pubkey{pub[ids[0]], pub[ids[1]], pub[ids[2]]})
		if err != nil || len(got) != 3 {
			t.Fatalf("%v: %v", ids, err)
		}
		for k := range want {
			if got[k] != want[k] {
				t.Fatalf("%v: commitment %d differs", ids, k)
			}
		}
	}
	if _, err := threshold.Commitments([]uint64{1, 1}, []backend.Pubkey{pub[1], pub[1]}); err == nil {
		t.Fatal("accepted a repeated id")
	}
	if _, err := threshold.Commitments([]uint64{0, 1}, []backend.Pubkey{pub[1], pub[2]}); err == nil {
		t.Fatal("accepted id 0")
	}
	if _, err := threshold.Commitments([]uint64{1, 2}, []backend.Pubkey{pub[1], {}}); err == nil {
		t.Fatal("accepted a malformed key")
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

// Compressed generators of G1 and G2, and the compressed point at infinity.
var (
	g1   = mustHex48("97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb")
	g2   = mustHex96("93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8")
	inf1 = backend.Pubkey{0xc0}
	inf2 = backend.Signature{0xc0}
)

func mustHex48(s string) (p backend.Pubkey) {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != len(p) {
		panic(s)
	}
	copy(p[:], b)
	return p
}

func mustHex96(s string) (p backend.Signature) {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != len(p) {
		panic(s)
	}
	copy(p[:], b)
	return p
}

func TestRecoveryRejectsIDZeroAndInfinity(t *testing.T) {
	// A single share with ID 1 has Lagrange coefficient 1, so a valid point
	// comes back unchanged.
	if got, err := threshold.RecoverSignature([]uint64{1}, []backend.Signature{g2}); err != nil || got != g2 {
		t.Fatalf("valid partial: %x, %v", got, err)
	}
	if got, err := threshold.RecoverPubkey([]uint64{1}, []backend.Pubkey{g1}); err != nil || got != g1 {
		t.Fatalf("valid share key: %x, %v", got, err)
	}
	if _, err := threshold.RecoverSignature([]uint64{0}, []backend.Signature{g2}); err == nil {
		t.Error("accepted signature share ID 0")
	}
	if _, err := threshold.RecoverSignature([]uint64{0, 2}, []backend.Signature{g2, g2}); err == nil {
		t.Error("accepted signature share ID 0 among others")
	}
	if _, err := threshold.RecoverPubkey([]uint64{0}, []backend.Pubkey{g1}); err == nil {
		t.Error("accepted public key share ID 0")
	}
	if _, err := threshold.RecoverPubkey([]uint64{2, 0}, []backend.Pubkey{g1, g1}); err == nil {
		t.Error("accepted public key share ID 0 among others")
	}
	if _, err := threshold.RecoverSignature([]uint64{1}, []backend.Signature{inf2}); err == nil {
		t.Error("accepted a partial signature at infinity")
	}
	if _, err := threshold.RecoverSignature([]uint64{1, 2}, []backend.Signature{g2, inf2}); err == nil {
		t.Error("accepted a partial signature at infinity among others")
	}
	if _, err := threshold.RecoverPubkey([]uint64{1}, []backend.Pubkey{inf1}); err == nil {
		t.Error("accepted a share key at infinity")
	}
	if _, err := threshold.RecoverPubkey([]uint64{1, 2}, []backend.Pubkey{g1, inf1}); err == nil {
		t.Error("accepted a share key at infinity among others")
	}
}
