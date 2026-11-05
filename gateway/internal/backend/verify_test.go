package backend

import (
	"testing"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	blst "github.com/supranational/blst/bindings/go"
)

// A signature made with blst, the library of the signers' core, verifies
// here (herumi) under the same ciphersuite.
func TestVerifyBLS(t *testing.T) {
	ikm := make([]byte, 32)
	ikm[0] = 7
	sk := blst.KeyGen(ikm)
	var pk phase0.BLSPubKey
	copy(pk[:], new(blst.P1Affine).From(sk).Compress())
	root := phase0.Root{1, 2, 3}
	var sig phase0.BLSSignature
	copy(sig[:], new(blst.P2Affine).Sign(sk, root[:], []byte("BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_")).Compress())

	if err := VerifyBLS(pk, root, sig); err != nil {
		t.Fatalf("valid signature rejected: %v", err)
	}
	if err := VerifyBLS(pk, phase0.Root{9}, sig); err == nil {
		t.Fatal("signature verified for another root")
	}
}
