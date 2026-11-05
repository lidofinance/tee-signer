package software

import (
	"math/big"
	"testing"

	"github.com/lidofinance/tee-signer/signer-core/core"
)

// r, the order of the BLS12-381 subgroups, for the check of the split.
var testOrder, _ = new(big.Int).SetString("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 16)

func TestWipeClearsScalar(t *testing.T) {
	var s scalar
	b := [32]byte{1, 2, 3}
	b[31] = 9
	if !scalarFromBytes(&s, &b) {
		t.Fatal("a small scalar is out of range")
	}
	if *bytesOf(&s) == [32]byte{} {
		t.Fatal("the scalar is empty after the load")
	}
	wipe(&s)
	if *bytesOf(&s) != [32]byte{} {
		t.Fatalf("the scalar is %x after wipe", *bytesOf(&s))
	}
}

// The scalar range check: 0 and r are refused, 1 and r-1 taken, and the
// bytes come back as they went in.
func TestScalarRange(t *testing.T) {
	var s scalar
	var zero, one, rm1, rb [32]byte
	one[31] = 1
	testOrder.FillBytes(rb[:])
	new(big.Int).Sub(testOrder, big.NewInt(1)).FillBytes(rm1[:])
	for _, c := range []struct {
		name string
		b    [32]byte
		ok   bool
	}{{"zero", zero, false}, {"one", one, true}, {"r-1", rm1, true}, {"r", rb, false}} {
		if got := scalarFromBytes(&s, &c.b); got != c.ok {
			t.Errorf("%s: in range %t, want %t", c.name, got, c.ok)
		}
		if c.ok {
			var back [32]byte
			scalarToBytes(&back, &s)
			if back != c.b {
				t.Errorf("%s: %x comes back as %x", c.name, c.b, back)
			}
		}
	}
	if _, _, err := SplitWithCommitments(zero, 1, 1); err == nil {
		t.Error("split of 0 passed")
	}
	if _, _, err := SplitWithCommitments(rb, 1, 1); err == nil {
		t.Error("split of r passed")
	}
	for range 32 {
		sk, err := NewSecret()
		if err != nil {
			t.Fatal(err)
		}
		if k := new(big.Int).SetBytes(sk[:]); k.Sign() == 0 || k.Cmp(testOrder) >= 0 {
			t.Fatalf("NewSecret %x is out of range", sk)
		}
	}
}

// A 3 of 5 split: any 3 shares recover the secret by Lagrange
// interpolation at 0 (checked here with math/big, on a test secret), the
// share IDs are 1..5, commitment 0 is the key's public key, and a 1 of 1
// split is the secret itself.
func TestSplitRecoversSecret(t *testing.T) {
	sk, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	pk, _ := core.PubkeyOf(sk)
	shares, comm, err := SplitWithCommitments(sk, 3, 5)
	if err != nil {
		t.Fatal(err)
	}
	if len(shares) != 5 || len(comm) != 3 || comm[0] != pk {
		t.Fatalf("%d shares, %d commitments, commitment 0 is the key: %t", len(shares), len(comm), comm[0] == pk)
	}
	want := new(big.Int).SetBytes(sk[:])
	for _, ids := range [][]int{{0, 1, 2}, {2, 3, 4}, {0, 2, 4}, {1, 3, 4}} {
		got := new(big.Int)
		for _, i := range ids {
			if shares[i].ID != uint64(i+1) {
				t.Fatalf("share %d has ID %d", i, shares[i].ID)
			}
			num, den := big.NewInt(1), big.NewInt(1)
			for _, j := range ids {
				if i == j {
					continue
				}
				num.Mul(num, big.NewInt(int64(shares[j].ID))).Mod(num, testOrder)
				den.Mul(den, big.NewInt(int64(shares[j].ID)-int64(shares[i].ID))).Mod(den, testOrder)
			}
			l := num.Mul(num, new(big.Int).ModInverse(den, testOrder)).Mod(num, testOrder)
			y := new(big.Int).SetBytes(shares[i].Secret[:])
			got.Add(got, l.Mul(l, y)).Mod(got, testOrder)
		}
		if got.Cmp(want) != 0 {
			t.Fatalf("shares %v do not recover the secret", ids)
		}
	}
	if y := new(big.Int).SetBytes(shares[0].Secret[:]); y.Cmp(want) == 0 {
		t.Fatal("share 1 is the secret")
	}
	one, _, err := SplitWithCommitments(sk, 1, 1)
	if err != nil || len(one) != 1 || one[0].Secret != sk {
		t.Fatalf("1 of 1: %v, %v", one, err)
	}
}
