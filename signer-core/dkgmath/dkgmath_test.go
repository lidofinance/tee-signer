package dkgmath

import (
	"math/big"
	"testing"

	"github.com/lidofinance/tee-signer/signer-core/core"
	"github.com/lidofinance/tee-signer/signer-core/threshold"
	"github.com/lidofinance/tee-signer/signer-protocol"
)

func scalarBytes(k *big.Int) [32]byte {
	var b [32]byte
	k.FillBytes(b[:])
	return b
}

func bigPoly(coeffs [][32]byte, x uint64) [32]byte {
	y := new(big.Int)
	xb := new(big.Int).SetUint64(x)
	for k := len(coeffs) - 1; k >= 0; k-- {
		y.Mul(y, xb).Add(y, new(big.Int).SetBytes(coeffs[k][:])).Mod(y, curveOrder)
	}
	return scalarBytes(y)
}

func TestPolyEvalMatchesBigInt(t *testing.T) {
	for _, deg := range []int{1, 2, 3, 7} {
		coeffs := make([][32]byte, deg)
		for i := range coeffs {
			var err error
			if coeffs[i], err = RandomScalar(); err != nil {
				t.Fatal(err)
			}
		}
		for _, x := range []uint64{1, 2, 3, 10, 1 << 40} {
			got, err := PolyEval(coeffs, x)
			if err != nil {
				t.Fatal(err)
			}
			if got != bigPoly(coeffs, x) {
				t.Fatalf("t=%d x=%d: blst and math/big differ", deg, x)
			}
		}
	}
}

func TestPolyEvalRefusesBadInput(t *testing.T) {
	a, _ := RandomScalar()
	if _, err := PolyEval(nil, 1); err == nil {
		t.Fatal("no coefficients accepted")
	}
	if _, err := PolyEval([][32]byte{a}, 0); err == nil {
		t.Fatal("x = 0 accepted")
	}
	var zero [32]byte
	if _, err := PolyEval([][32]byte{a, zero}, 2); err == nil {
		t.Fatal("zero coefficient accepted")
	}
	over := scalarBytes(curveOrder)
	if _, err := PolyEval([][32]byte{over, a}, 2); err == nil {
		t.Fatal("coefficient r accepted")
	}
}

func TestScalarAdd(t *testing.T) {
	a, _ := RandomScalar()
	b, _ := RandomScalar()
	got, err := ScalarAdd(a, b)
	if err != nil {
		t.Fatal(err)
	}
	want := new(big.Int).Add(new(big.Int).SetBytes(a[:]), new(big.Int).SetBytes(b[:]))
	if got != scalarBytes(want.Mod(want, curveOrder)) {
		t.Fatal("sum differs")
	}
	neg := scalarBytes(new(big.Int).Sub(curveOrder, new(big.Int).SetBytes(a[:])))
	if _, err := ScalarAdd(a, neg); err == nil {
		t.Fatal("zero sum accepted")
	}
}

// The Feldman commitments of a polynomial give the public key of every
// share, and Lagrange over the share keys gives the key of f(0).
func TestFeldmanAndRecovery(t *testing.T) {
	const thr, n = 2, 3
	coeffs := make([][32]byte, thr)
	commits := make([]backend.Pubkey, thr)
	for k := range coeffs {
		coeffs[k], _ = RandomScalar()
		commits[k], _ = core.PubkeyOf(coeffs[k])
		if !G1Valid(commits[k]) {
			t.Fatal("commitment not valid")
		}
	}
	var ids []uint64
	var pks []backend.Pubkey
	for x := uint64(1); x <= n; x++ {
		s, err := PolyEval(coeffs, x)
		if err != nil {
			t.Fatal(err)
		}
		pk, _ := core.PubkeyOf(s)
		fe, err := FeldmanEval(commits, x)
		if err != nil {
			t.Fatal(err)
		}
		if fe != pk {
			t.Fatalf("x=%d: Feldman value differs from the share's key", x)
		}
		ids, pks = append(ids, x), append(pks, pk)
	}
	for _, pick := range [][]int{{0, 1}, {0, 2}, {1, 2}} {
		got, err := threshold.RecoverPubkey([]uint64{ids[pick[0]], ids[pick[1]]}, []backend.Pubkey{pks[pick[0]], pks[pick[1]]})
		if err != nil {
			t.Fatal(err)
		}
		if got != commits[0] {
			t.Fatalf("shares %v do not recover the key", pick)
		}
	}
}

func TestG1ValidRefuses(t *testing.T) {
	var inf backend.Pubkey
	inf[0] = 0xc0
	if G1Valid(inf) {
		t.Fatal("identity accepted")
	}
	var junk backend.Pubkey
	junk[0] = 0x80
	junk[47] = 1
	if G1Valid(junk) {
		t.Fatal("junk accepted")
	}
}

// Sign over a 32-byte message verifies as a signature over that root.
func TestSign(t *testing.T) {
	sk, _ := RandomScalar()
	pk, _ := core.PubkeyOf(sk)
	var msg backend.Root
	msg[0], msg[31] = 7, 9
	sig, err := Sign(&sk, msg[:])
	if err != nil {
		t.Fatal(err)
	}
	if !core.Verify(pk, msg, sig) {
		t.Fatal("signature does not verify")
	}
	msg[5] = 1
	if core.Verify(pk, msg, sig) {
		t.Fatal("signature verifies for another message")
	}
	var zero [32]byte
	if _, err := Sign(&zero, msg[:]); err == nil {
		t.Fatal("zero secret signed")
	}
}

// Signatures of one message by several keys add up to a signature under
// the sum of the keys.
func TestAggregateSignatures(t *testing.T) {
	msg := backend.Root{1, 2, 3}
	var sigs []backend.Signature
	var pks []backend.Pubkey
	var ones []*big.Int
	for range 3 {
		sk, _ := RandomScalar()
		pk, _ := core.PubkeyOf(sk)
		sig, err := Sign(&sk, msg[:])
		if err != nil {
			t.Fatal(err)
		}
		sigs, pks, ones = append(sigs, sig), append(pks, pk), append(ones, big.NewInt(1))
	}
	agg, err := AggregateSignatures(sigs)
	if err != nil {
		t.Fatal(err)
	}
	apk, err := G1LinComb(pks, ones)
	if err != nil {
		t.Fatal(err)
	}
	if !core.Verify(apk, msg, agg) {
		t.Fatal("aggregate does not verify under the summed key")
	}
	if core.Verify(apk, msg, sigs[0]) {
		t.Fatal("one signature verifies under the summed key")
	}
	var junk backend.Signature
	junk[0] = 0x80
	junk[95] = 1
	if _, err := AggregateSignatures([]backend.Signature{sigs[0], junk}); err == nil {
		t.Fatal("junk point accepted")
	}
}
