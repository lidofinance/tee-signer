package setupwire

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"math/big"
)

// Approver key rules (setup-phase.md, section 8), for the setup's first set
// and every rotation: 2 to 8 keys, no duplicates, no small-order keys, no
// non-canonical encodings, approvals_needed (k) at least 2 and above n/2.
const (
	MinApprovers = 2
	MaxApprovers = 8
	MinThreshold = 2
)

// ApproverSet is the approver list and approvals_needed (k). Signatures name an approver by
// position in Keys, so the order is part of the set.
type ApproverSet struct {
	Keys            [][32]byte // Ed25519 public keys
	ApprovalsNeeded uint8
}

// Check applies the key rules and the rules of approvals_needed.
func (a *ApproverSet) Check() error {
	n := len(a.Keys)
	if n < MinApprovers || n > MaxApprovers {
		return fmt.Errorf("approvers: %d keys, want %d to %d", n, MinApprovers, MaxApprovers)
	}
	seen := map[[32]byte]bool{}
	for i, k := range a.Keys {
		if err := CheckKey(k); err != nil {
			return fmt.Errorf("approvers: key %d: %w", i, err)
		}
		// Every point has one canonical encoding, so equal points are
		// equal bytes here.
		if seen[k] {
			return fmt.Errorf("approvers: key %d is listed twice", i)
		}
		seen[k] = true
	}
	switch {
	case a.ApprovalsNeeded < MinThreshold:
		return fmt.Errorf("approvals_needed is %d, want at least %d: one approver alone must not change the config", a.ApprovalsNeeded, MinThreshold)
	case int(a.ApprovalsNeeded) > n:
		return fmt.Errorf("approvals_needed is %d, above the %d approvers", a.ApprovalsNeeded, n)
	case 2*int(a.ApprovalsNeeded) <= n:
		return fmt.Errorf("approvals_needed is %d, want more than half of the %d approvers", a.ApprovalsNeeded, n)
	}
	return nil
}

// Hash is the approver set hash IDENTITY carries: approvals_needed, n and
// the keys in order.
func (a *ApproverSet) Hash() [32]byte {
	b := []byte{a.ApprovalsNeeded, uint8(len(a.Keys))}
	for _, k := range a.Keys {
		b = append(b, k[:]...)
	}
	return CtxApproverSet.Hash(b)
}

// Equal reports whether a and b are the same set: same approvals_needed,
// same keys in the same order.
func (a *ApproverSet) Equal(b *ApproverSet) bool {
	if a.ApprovalsNeeded != b.ApprovalsNeeded || len(a.Keys) != len(b.Keys) {
		return false
	}
	for i := range a.Keys {
		if a.Keys[i] != b.Keys[i] {
			return false
		}
	}
	return true
}

func (a *ApproverSet) clone() ApproverSet {
	return ApproverSet{Keys: append([][32]byte(nil), a.Keys...), ApprovalsNeeded: a.ApprovalsNeeded}
}

var (
	errKeyNonCanonical = errors.New("not the canonical encoding of a point")
	errKeyNotOnCurve   = errors.New("not a point on the curve")
	errKeySmallOrder   = errors.New("a small-order point")
)

// Curve constants of edwards25519 (RFC 8032, section 5.1).
var (
	edP      = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))
	edD      = edDValue()
	edSqrtM1 = new(big.Int).Exp(big.NewInt(2), new(big.Int).Rsh(new(big.Int).Sub(edP, big.NewInt(1)), 2), edP)
)

// edDValue is d = -121665 / 121666 mod p.
func edDValue() *big.Int {
	num := new(big.Int).Sub(edP, big.NewInt(121665))
	den := new(big.Int).ModInverse(big.NewInt(121666), edP)
	return num.Mul(num, den).Mod(num, edP)
}

// CheckKey refuses an Ed25519 public key that is not the canonical
// encoding of a curve point, or that is a point of small order. Go's
// crypto/ed25519 accepts both kinds, so the check is explicit. It works on
// public data only, so plain big.Int arithmetic is fine.
func CheckKey(k [32]byte) error {
	x, y, err := decodePoint(k)
	if err != nil {
		return err
	}
	// The small-order points are the ones that [8]P sends to the identity.
	for range 3 {
		x, y = edAdd(x, y, x, y)
	}
	if x.Sign() == 0 && y.Cmp(big.NewInt(1)) == 0 {
		return errKeySmallOrder
	}
	return nil
}

// decodePoint is RFC 8032 section 5.1.3, refusing y >= p and the encoding
// of x = 0 with the sign bit set.
func decodePoint(k [32]byte) (x, y *big.Int, err error) {
	sign := uint(k[31] >> 7)
	le := k
	le[31] &= 0x7f
	be := make([]byte, 32)
	for i := range 32 {
		be[i] = le[31-i]
	}
	y = new(big.Int).SetBytes(be)
	if y.Cmp(edP) >= 0 {
		return nil, nil, errKeyNonCanonical
	}
	y2 := new(big.Int).Mul(y, y)
	y2.Mod(y2, edP)
	u := new(big.Int).Sub(y2, big.NewInt(1))
	u.Mod(u, edP)
	v := new(big.Int).Mul(edD, y2)
	v.Add(v, big.NewInt(1)).Mod(v, edP)
	// x^2 = u/v; v is never 0 because d is not a square.
	x2 := new(big.Int).ModInverse(v, edP)
	x2.Mul(x2, u).Mod(x2, edP)
	x = new(big.Int)
	if x2.Sign() != 0 {
		// p = 5 mod 8: a candidate root is x2^((p+3)/8); if its square is
		// -x2, multiply by sqrt(-1).
		e := new(big.Int).Add(edP, big.NewInt(3))
		e.Rsh(e, 3)
		x.Exp(x2, e, edP)
		sq := new(big.Int).Mul(x, x)
		sq.Mod(sq, edP)
		if sq.Cmp(x2) != 0 {
			x.Mul(x, edSqrtM1).Mod(x, edP)
			sq.Mul(x, x).Mod(sq, edP)
			if sq.Cmp(x2) != 0 {
				return nil, nil, errKeyNotOnCurve
			}
		}
	}
	if x.Sign() == 0 && sign == 1 {
		return nil, nil, errKeyNonCanonical
	}
	if x.Bit(0) != sign {
		x.Sub(edP, x)
	}
	return x, y, nil
}

// edAdd adds two points in affine coordinates on -x^2 + y^2 = 1 + d x^2 y^2.
// The formula is complete on this curve, so doubling needs no special case.
func edAdd(x1, y1, x2, y2 *big.Int) (*big.Int, *big.Int) {
	t := new(big.Int).Mul(x1, x2)
	t.Mul(t, y1).Mul(t, y2).Mul(t, edD).Mod(t, edP)
	nx := new(big.Int).Mul(x1, y2)
	nx.Add(nx, new(big.Int).Mul(y1, x2))
	ny := new(big.Int).Mul(y1, y2)
	ny.Add(ny, new(big.Int).Mul(x1, x2))
	dx := new(big.Int).Add(big.NewInt(1), t)
	dy := new(big.Int).Sub(big.NewInt(1), t)
	dx.Mod(dx, edP).ModInverse(dx, edP)
	dy.Mod(dy, edP).ModInverse(dy, edP)
	nx.Mul(nx, dx).Mod(nx, edP)
	ny.Mul(ny, dy).Mod(ny, edP)
	return nx, ny
}

// verifyKey checks sig over msg with an approver key that passed CheckKey.
func verifyKey(k [32]byte, msg []byte, sig [64]byte) bool {
	return ed25519.Verify(ed25519.PublicKey(k[:]), msg, sig[:])
}
