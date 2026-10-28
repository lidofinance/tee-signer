package setupwire

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"testing"
)

func key32(t *testing.T, s string) [32]byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		t.Fatalf("bad test key %s", s)
	}
	return [32]byte(b)
}

// The eight points of small order in their canonical encodings (the list
// libsodium keeps for the same check).
var smallOrder = []string{
	"0100000000000000000000000000000000000000000000000000000000000000", // identity
	"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", // order 2
	"0000000000000000000000000000000000000000000000000000000000000000", // order 4
	"0000000000000000000000000000000000000000000000000000000000000080", // order 4
	"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a", // order 8
	"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa", // order 8
	"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05", // order 8
	"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85", // order 8
}

// Encodings that are not canonical: y >= p, or x = 0 with the sign bit.
var nonCanonical = []string{
	"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", // y = p
	"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", // y = p + 1, the identity
	"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", // y = 2^255 - 1
	"0100000000000000000000000000000000000000000000000000000000000080", // identity with the sign bit
	"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", // order 2 point with the sign bit
}

func TestCheckKey(t *testing.T) {
	for _, s := range smallOrder {
		if err := CheckKey(key32(t, s)); !errors.Is(err, errKeySmallOrder) {
			t.Errorf("%s: got %v, want small order", s, err)
		}
	}
	for _, s := range nonCanonical {
		if err := CheckKey(key32(t, s)); !errors.Is(err, errKeyNonCanonical) {
			t.Errorf("%s: got %v, want not canonical", s, err)
		}
	}
	// About half of all y values have no x on the curve.
	off := 0
	for y := byte(2); y < 40; y++ {
		if err := CheckKey([32]byte{y}); errors.Is(err, errKeyNotOnCurve) {
			off++
		}
	}
	if off == 0 {
		t.Fatal("no y between 2 and 40 was refused as off the curve")
	}
	// Real keys pass, and their signatures verify through verifyKey.
	for range 50 {
		pub, priv, _ := ed25519.GenerateKey(rand.Reader)
		k := [32]byte(pub)
		if err := CheckKey(k); err != nil {
			t.Fatalf("%x: %v", k, err)
		}
		var sig [64]byte
		copy(sig[:], ed25519.Sign(priv, []byte("m")))
		if !verifyKey(k, []byte("m"), sig) || verifyKey(k, []byte("n"), sig) {
			t.Fatal("verifyKey")
		}
	}
	// A key decodes to the same point Go's ed25519 uses: the base point's
	// encoding gives x with the sign RFC 8032 names.
	base := key32(t, "5866666666666666666666666666666666666666666666666666666666666666")
	x, _, err := decodePoint(base)
	if err != nil || x.Text(16) != "216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51a" {
		t.Fatalf("base point x = %v, %v", x, err)
	}
}

func TestApproverSet(t *testing.T) {
	keys := func(n int) [][32]byte {
		var out [][32]byte
		for i := range n {
			out = append(out, approverPub(byte(i+1)))
		}
		return out
	}
	cases := []struct {
		n, k int
		ok   bool
	}{
		{1, 1, false}, {2, 1, false}, {2, 2, true}, {3, 1, false}, {3, 2, true}, {3, 3, true}, {3, 4, false},
		{4, 2, false}, {4, 3, true}, {5, 3, true}, {6, 3, false}, {6, 4, true}, {7, 4, true},
		{8, 4, false}, {8, 5, true}, {8, 8, true}, {9, 5, false}, {0, 0, false},
	}
	for _, c := range cases {
		a := ApproverSet{Keys: keys(c.n), ApprovalsNeeded: uint8(c.k)}
		if err := a.Check(); (err == nil) != c.ok {
			t.Errorf("n=%d k=%d: got %v, want ok=%v", c.n, c.k, err, c.ok)
		}
	}
	a := ApproverSet{Keys: keys(3), ApprovalsNeeded: 2}
	b := a.clone()
	if !a.Equal(&b) || a.Hash() != b.Hash() {
		t.Fatal("clone differs")
	}
	b.Keys[0], b.Keys[1] = b.Keys[1], b.Keys[0]
	if a.Equal(&b) || a.Hash() == b.Hash() {
		t.Fatal("order does not count")
	}
	b = a.clone()
	b.ApprovalsNeeded = 3
	if a.Equal(&b) || a.Hash() == b.Hash() {
		t.Fatal("k does not count")
	}
}
