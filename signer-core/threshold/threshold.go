// Package threshold checks polynomial commitments and recovers BLS signatures
// and public keys from shares. It has no dependency on the signing bindings.
package threshold

/*
#cgo CFLAGS: -I${SRCDIR}/../third_party/blst/bindings
#cgo linux,amd64 LDFLAGS: -L${SRCDIR}/../../build/x86_64/lib -lblst
#cgo linux,arm64 LDFLAGS: -L${SRCDIR}/../../build/aarch64/lib -lblst
#include <stdint.h>
#include <stddef.h>

int threshold_p2_lincomb(const uint8_t *points, const uint8_t *scalars, size_t n, uint8_t out[96]);
int threshold_p1_lincomb(const uint8_t *points, const uint8_t *scalars, size_t n, uint8_t out[48]);
*/
import "C"

import (
	"errors"
	"math/big"
	"unsafe"

	"github.com/lidofinance/tee-signer/signer-protocol"
)

func u8(p []byte) *C.uint8_t { return (*C.uint8_t)(unsafe.Pointer(&p[0])) }

// curveOrder is r, the order of the BLS12-381 G1 and G2 subgroups.
var curveOrder, _ = new(big.Int).SetString("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 16)

func scalarBytes(k *big.Int) [32]byte {
	var b [32]byte
	k.FillBytes(b[:])
	return b
}

// compressedInfinity is the flag bit of a compressed point (byte 0) that
// marks the point at infinity. An encoding with it set is either infinity or
// does not decode.
const compressedInfinity = 0x40

// lagrangeAtZero returns little-endian scalars l_i = prod_{j!=i} x_j/(x_j-x_i) mod r.
// It refuses share ID 0: share i is the polynomial's value at x = i, and the
// value at 0 is the secret itself.
func lagrangeAtZero(ids []uint64) ([]byte, error) {
	for _, x := range ids {
		if x == 0 {
			return nil, errors.New("threshold: share id 0")
		}
	}
	out := make([]byte, 0, 32*len(ids))
	for i, xi := range ids {
		num, den := big.NewInt(1), big.NewInt(1)
		for j, xj := range ids {
			if i == j {
				continue
			}
			if xi == xj {
				return nil, errors.New("threshold: duplicate share id")
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
// signature of the full key, by Lagrange interpolation in G2. It refuses
// share ID 0 and a partial signature at infinity.
func RecoverSignature(ids []uint64, sigs []backend.Signature) (backend.Signature, error) {
	var out backend.Signature
	if len(ids) == 0 || len(ids) != len(sigs) {
		return out, errors.New("threshold: ids and signatures differ in length")
	}
	scalars, err := lagrangeAtZero(ids)
	if err != nil {
		return out, err
	}
	pts := make([]byte, 0, 96*len(sigs))
	for _, s := range sigs {
		if s[0]&compressedInfinity != 0 {
			return out, errors.New("threshold: partial signature at infinity")
		}
		pts = append(pts, s[:]...)
	}
	if C.threshold_p2_lincomb(u8(pts), u8(scalars), C.size_t(len(ids)), u8(out[:])) != 0 {
		return out, errors.New("threshold: bad partial signature")
	}
	return out, nil
}

// RecoverPubkey combines share public keys into the full public key. It
// refuses share ID 0 and a share key at infinity.
func RecoverPubkey(ids []uint64, pks []backend.Pubkey) (backend.Pubkey, error) {
	var out backend.Pubkey
	if len(ids) == 0 || len(ids) != len(pks) {
		return out, errors.New("threshold: ids and keys differ in length")
	}
	scalars, err := lagrangeAtZero(ids)
	if err != nil {
		return out, err
	}
	pts := make([]byte, 0, 48*len(pks))
	for _, p := range pks {
		if p[0]&compressedInfinity != 0 {
			return out, errors.New("threshold: share public key at infinity")
		}
		pts = append(pts, p[:]...)
	}
	if C.threshold_p1_lincomb(u8(pts), u8(scalars), C.size_t(len(ids)), u8(out[:])) != 0 {
		return out, errors.New("threshold: bad share public key")
	}
	return out, nil
}

// Commitments returns the Feldman commitments of the degree t-1 split
// polynomial through t share public keys pks at share IDs ids (t =
// len(ids)): commitment k is sum_i c_ik * pks[i], where c_ik is
// coefficient k of the Lagrange basis polynomial of ids[i]. Commitment 0
// is the full public key. IDs must be distinct and not 0.
func Commitments(ids []uint64, pks []backend.Pubkey) ([]backend.Pubkey, error) {
	t := len(ids)
	if t == 0 || t != len(pks) {
		return nil, errors.New("threshold: ids and keys differ in length")
	}
	// basis[i][k]: coefficient k of prod_{j!=i} (x - x_j) / (x_i - x_j).
	basis := make([][]*big.Int, t)
	for i, xi := range ids {
		if xi == 0 {
			return nil, errors.New("threshold: share id 0")
		}
		poly := []*big.Int{big.NewInt(1)}
		den := big.NewInt(1)
		for j, xj := range ids {
			if i == j {
				continue
			}
			if xi == xj {
				return nil, errors.New("threshold: duplicate share id")
			}
			// poly *= (x - x_j)
			next := make([]*big.Int, len(poly)+1)
			for k := range next {
				next[k] = new(big.Int)
			}
			neg := new(big.Int).Neg(new(big.Int).SetUint64(xj))
			for k, c := range poly {
				next[k+1].Add(next[k+1], c)
				next[k].Add(next[k], new(big.Int).Mul(c, neg))
			}
			for _, c := range next {
				c.Mod(c, curveOrder)
			}
			poly = next
			d := new(big.Int).Sub(new(big.Int).SetUint64(xi), new(big.Int).SetUint64(xj))
			den.Mul(den, d.Mod(d, curveOrder)).Mod(den, curveOrder)
		}
		inv := new(big.Int).ModInverse(den, curveOrder)
		for _, c := range poly {
			c.Mul(c, inv).Mod(c, curveOrder)
		}
		basis[i] = poly
	}
	pts := make([]byte, 0, 48*t)
	for _, p := range pks {
		pts = append(pts, p[:]...)
	}
	out := make([]backend.Pubkey, t)
	for k := range t {
		scalars := make([]byte, 0, 32*t)
		for i := range t {
			be := scalarBytes(basis[i][k])
			for b := 31; b >= 0; b-- {
				scalars = append(scalars, be[b])
			}
		}
		if C.threshold_p1_lincomb(u8(pts), u8(scalars), C.size_t(t), u8(out[k][:])) != 0 {
			return nil, errors.New("threshold: bad share public key")
		}
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
		return out, errors.New("threshold: no commitments")
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
	if C.threshold_p1_lincomb(u8(pts), u8(scalars), C.size_t(len(commitments)), u8(out[:])) != 0 {
		return out, errors.New("threshold: a commitment is not a G1 point")
	}
	return out, nil
}
