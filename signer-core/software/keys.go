package software

import (
	"crypto/rand"
	"errors"
	"io"
	"math/big"

	"github.com/lidofinance/tee-signer/signer-core/core"
	"github.com/lidofinance/tee-signer/signer-protocol"
)

// curveOrder is r, the order of the BLS12-381 G1 and G2 subgroups.
var curveOrder, _ = new(big.Int).SetString("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 16)

// Share is one point of a Shamir split. ID is the x coordinate (Dirk uses 1..n).
type Share struct {
	ID     uint64
	Secret [32]byte
}

func randScalar(r io.Reader) (*big.Int, error) {
	for {
		k, err := rand.Int(r, curveOrder)
		if err != nil {
			return nil, err
		}
		if k.Sign() != 0 {
			return k, nil
		}
	}
}

func scalarBytes(k *big.Int) [32]byte {
	var b [32]byte
	k.FillBytes(b[:])
	return b
}

// NewSecret returns a random valid secret key. Dev and test use only.
func NewSecret() ([32]byte, error) {
	k, err := randScalar(rand.Reader)
	if err != nil {
		return [32]byte{}, err
	}
	return scalarBytes(k), nil
}

// Split makes an t-of-n Shamir split of secret with IDs 1..n. Dev and test
// use only: in production Dirk's distributed key generation makes shares.
func Split(secret [32]byte, t, n int) ([]Share, error) {
	shares, _, err := SplitWithCommitments(secret, t, n)
	return shares, err
}

// SplitWithCommitments is Split, and also returns the public commitments of
// the polynomial (Feldman): the public key of each coefficient, the first
// being the public key of secret. Dev and test use only.
func SplitWithCommitments(secret [32]byte, t, n int) ([]Share, []backend.Pubkey, error) {
	if t < 1 || n < t {
		return nil, nil, errors.New("core: need 1 <= t <= n")
	}
	coef := []*big.Int{new(big.Int).SetBytes(secret[:])}
	if coef[0].Sign() == 0 || coef[0].Cmp(curveOrder) >= 0 {
		return nil, nil, errors.New("core: secret out of range")
	}
	for i := 1; i < t; i++ {
		c, err := randScalar(rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		coef = append(coef, c)
	}
	commitments := make([]backend.Pubkey, len(coef))
	for i, c := range coef {
		p, err := core.PubkeyOf(scalarBytes(c))
		if err != nil {
			return nil, nil, err
		}
		commitments[i] = p
	}
	shares := make([]Share, n)
	for i := range shares {
		x := big.NewInt(int64(i + 1))
		y := new(big.Int)
		for j := len(coef) - 1; j >= 0; j-- { // Horner
			y.Mul(y, x).Add(y, coef[j]).Mod(y, curveOrder)
		}
		shares[i] = Share{ID: uint64(i + 1), Secret: scalarBytes(y)}
	}
	return shares, commitments, nil
}
