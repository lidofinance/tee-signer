package main

/*
#cgo CFLAGS: -I${SRCDIR}/../../../signer-core/third_party/blst/bindings
#cgo linux,amd64 LDFLAGS: -L${SRCDIR}/../../../build/x86_64/lib -lblst
#cgo linux,arm64 LDFLAGS: -L${SRCDIR}/../../../build/aarch64/lib -lblst
#cgo darwin,amd64 LDFLAGS: -L${SRCDIR}/../../../build/x86_64/lib -lblst
#cgo darwin,arm64 LDFLAGS: -L${SRCDIR}/../../../build/aarch64/lib -lblst
#include <stdint.h>
#include <stddef.h>

int admin_p1_lincomb(const uint8_t *points, const uint8_t *scalars, size_t n, uint8_t out[48]);
*/
import "C"

import (
	"errors"
	"math/big"
	"unsafe"

	cloud "github.com/lidofinance/tee-signer/signer-protocol"
)

// curveOrder is r, the order of the BLS12-381 G1 subgroup.
var curveOrder, _ = new(big.Int).SetString("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 16)

// commitmentsFromShares returns the Feldman commitments of the degree t-1
// split polynomial through t share public keys pks at share IDs ids (t =
// len(ids)): commitment k is sum_i c_ik * pks[i], where c_ik is
// coefficient k of the Lagrange basis polynomial of ids[i]. Commitment 0
// is the full public key. IDs must be distinct and not 0. dv-split is its
// only user: a Charon cluster lock gives share public keys and no
// commitments.
func commitmentsFromShares(ids []uint64, pks []cloud.Pubkey) ([]cloud.Pubkey, error) {
	t := len(ids)
	if t == 0 || t != len(pks) {
		return nil, errors.New("commitments: ids and keys differ in length")
	}
	// basis[i][k]: coefficient k of prod_{j!=i} (x - x_j) / (x_i - x_j).
	basis := make([][]*big.Int, t)
	for i, xi := range ids {
		if xi == 0 {
			return nil, errors.New("commitments: share id 0")
		}
		poly := []*big.Int{big.NewInt(1)}
		den := big.NewInt(1)
		for j, xj := range ids {
			if i == j {
				continue
			}
			if xi == xj {
				return nil, errors.New("commitments: duplicate share id")
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
	out := make([]cloud.Pubkey, t)
	for k := range t {
		scalars := make([]byte, 0, 32*t)
		for i := range t {
			var be [32]byte
			basis[i][k].FillBytes(be[:])
			for b := 31; b >= 0; b-- {
				scalars = append(scalars, be[b])
			}
		}
		if C.admin_p1_lincomb(u8(pts), u8(scalars), C.size_t(t), u8(out[k][:])) != 0 {
			return nil, errors.New("commitments: bad share public key")
		}
	}
	return out, nil
}

func u8(p []byte) *C.uint8_t { return (*C.uint8_t)(unsafe.Pointer(&p[0])) }
