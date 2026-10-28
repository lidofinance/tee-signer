package core

/*
#include <stdint.h>
#include <stddef.h>
#include "signer_core.h"

int scgo_p2_lincomb(const uint8_t *points, const uint8_t *scalars, size_t n, uint8_t out[96]);
int scgo_p1_lincomb(const uint8_t *points, const uint8_t *scalars, size_t n, uint8_t out[48]);
*/
import "C"

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math/big"

	"github.com/lidofinance/tee-signer/signer-protocol"
)

// Verify checks a BLS signature with blst (sc_bls_verify, Ethereum POP
// ciphersuite) over a 32-byte signing root.
func Verify(pubkey backend.Pubkey, signingRoot backend.Root, sig backend.Signature) bool {
	return C.sc_bls_verify(u8(pubkey[:]), u8(signingRoot[:]), 32, u8(sig[:])) == C.SC_OK
}

// PubkeyOf returns the public key of a secret scalar (big endian).
func PubkeyOf(secret [32]byte) (backend.Pubkey, error) {
	var pk backend.Pubkey
	if rc := C.sc_bls_pubkey(u8(secret[:]), u8(pk[:])); rc != C.SC_OK {
		return pk, fmt.Errorf("core: %v", backend.Status(rc))
	}
	return pk, nil
}

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
		p, err := PubkeyOf(scalarBytes(c))
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

// lagrangeAtZero returns little-endian scalars l_i = prod_{j!=i} x_j/(x_j-x_i) mod r.
func lagrangeAtZero(ids []uint64) ([]byte, error) {
	out := make([]byte, 0, 32*len(ids))
	for i, xi := range ids {
		num, den := big.NewInt(1), big.NewInt(1)
		for j, xj := range ids {
			if i == j {
				continue
			}
			if xi == xj {
				return nil, errors.New("core: duplicate share id")
			}
			num.Mul(num, new(big.Int).SetUint64(xj)).Mod(num, curveOrder)
			d := new(big.Int).Sub(new(big.Int).SetUint64(xj), new(big.Int).SetUint64(xi))
			den.Mul(den, d.Mod(d, curveOrder)).Mod(den, curveOrder)
		}
		l := num.Mul(num, new(big.Int).ModInverse(den, curveOrder)).Mod(num, curveOrder)
		be := scalarBytes(l)
		for k := 31; k >= 0; k-- {
			out = append(out, be[k])
		}
	}
	return out, nil
}

// RecoverSignature combines t partial signatures (share IDs ids) into the
// signature of the full key, by Lagrange interpolation in G2.
func RecoverSignature(ids []uint64, sigs []backend.Signature) (backend.Signature, error) {
	var out backend.Signature
	if len(ids) == 0 || len(ids) != len(sigs) {
		return out, errors.New("core: ids and signatures differ in length")
	}
	scalars, err := lagrangeAtZero(ids)
	if err != nil {
		return out, err
	}
	pts := make([]byte, 0, 96*len(sigs))
	for _, s := range sigs {
		pts = append(pts, s[:]...)
	}
	if C.scgo_p2_lincomb(u8(pts), u8(scalars), C.size_t(len(ids)), u8(out[:])) != 0 {
		return out, errors.New("core: bad partial signature")
	}
	return out, nil
}

// RecoverPubkey combines share public keys into the full public key.
func RecoverPubkey(ids []uint64, pks []backend.Pubkey) (backend.Pubkey, error) {
	var out backend.Pubkey
	if len(ids) == 0 || len(ids) != len(pks) {
		return out, errors.New("core: ids and keys differ in length")
	}
	scalars, err := lagrangeAtZero(ids)
	if err != nil {
		return out, err
	}
	pts := make([]byte, 0, 48*len(pks))
	for _, p := range pks {
		pts = append(pts, p[:]...)
	}
	if C.scgo_p1_lincomb(u8(pts), u8(scalars), C.size_t(len(ids)), u8(out[:])) != 0 {
		return out, errors.New("core: bad share public key")
	}
	return out, nil
}

// FeldmanEval returns sum commitments[k] * x^k, the public key of the
// split polynomial's value at x when commitments[k] is the public key of
// coefficient k (Feldman). It refuses a commitment that is not a G1 point
// of the subgroup.
func FeldmanEval(commitments []backend.Pubkey, x uint64) (backend.Pubkey, error) {
	var out backend.Pubkey
	if len(commitments) == 0 {
		return out, errors.New("core: no commitments")
	}
	scalars := make([]byte, 0, 32*len(commitments))
	pts := make([]byte, 0, 48*len(commitments))
	acc, xb := big.NewInt(1), new(big.Int).SetUint64(x)
	for _, c := range commitments {
		be := scalarBytes(acc)
		for k := 31; k >= 0; k-- {
			scalars = append(scalars, be[k])
		}
		pts = append(pts, c[:]...)
		acc.Mul(acc, xb).Mod(acc, curveOrder)
	}
	if C.scgo_p1_lincomb(u8(pts), u8(scalars), C.size_t(len(commitments)), u8(out[:])) != 0 {
		return out, errors.New("core: a commitment is not a G1 point")
	}
	return out, nil
}
