// Package dkgmath holds the scalar and G1 helpers of distributed key
// generation, on blst. Secret scalars are 32-byte big endian values in
// [1, r) and the arithmetic on them runs in blst's constant-time scalar
// code. Public scalars (share IDs and their powers) go through math/big.
//
// It is its own cgo package so that a runner built without key generation
// links none of it (scripts/build-runner.sh checks those builds stay
// byte-identical).
package dkgmath

/*
#cgo CFLAGS: -I${SRCDIR}/../third_party/blst/bindings
#cgo linux,amd64 LDFLAGS: -L${SRCDIR}/../../build/x86_64/lib -lblst
#cgo linux,arm64 LDFLAGS: -L${SRCDIR}/../../build/aarch64/lib -lblst
#include <stdint.h>
#include <stddef.h>

int dkg_keygen(const uint8_t *ikm, size_t ikm_len, uint8_t out_be[32]);
int dkg_poly_eval(const uint8_t *coeffs_be, size_t t, uint64_t x, uint8_t out_be[32]);
int dkg_scalar_add(const uint8_t a_be[32], const uint8_t b_be[32], uint8_t out_be[32]);
int dkg_g1_check(const uint8_t p[48]);
int dkg_sign(const uint8_t sk_be[32], const uint8_t *msg, size_t len, uint8_t sig[96]);
int dkg_p2_sum(const uint8_t *points, size_t n, uint8_t out[96]);
int dkg_p1_lincomb(const uint8_t *points, const uint8_t *scalars, size_t n, uint8_t out[48]);
*/
import "C"

import (
	"crypto/rand"
	"errors"
	"math/big"
	"unsafe"

	"github.com/lidofinance/tee-signer/signer-protocol"
)

// curveOrder is r, the order of the BLS12-381 G1 and G2 subgroups.
var curveOrder, _ = new(big.Int).SetString("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 16)

func u8(p []byte) *C.uint8_t { return (*C.uint8_t)(unsafe.Pointer(&p[0])) }

var errScalar = errors.New("core: scalar out of range")

// RandomScalar returns a fresh secret scalar: IETF KeyGen over 32 bytes
// from crypto/rand.
func RandomScalar() ([32]byte, error) {
	var ikm, out [32]byte
	defer clear(ikm[:])
	if _, err := rand.Read(ikm[:]); err != nil {
		return out, err
	}
	if C.dkg_keygen(u8(ikm[:]), 32, u8(out[:])) != 0 {
		return out, errScalar
	}
	return out, nil
}

// PolyEval returns f(x) = sum coeffs[k] x^k mod r. x must be at least 1.
func PolyEval(coeffs [][32]byte, x uint64) ([32]byte, error) {
	var out [32]byte
	if len(coeffs) == 0 || x == 0 {
		return out, errScalar
	}
	flat := make([]byte, 0, 32*len(coeffs))
	defer clear(flat)
	for i := range coeffs {
		flat = append(flat, coeffs[i][:]...)
	}
	if C.dkg_poly_eval(u8(flat), C.size_t(len(coeffs)), C.uint64_t(x), u8(out[:])) != 0 {
		return out, errScalar
	}
	return out, nil
}

// ScalarAdd returns a + b mod r.
func ScalarAdd(a, b [32]byte) ([32]byte, error) {
	var out [32]byte
	if C.dkg_scalar_add(u8(a[:]), u8(b[:]), u8(out[:])) != 0 {
		return out, errScalar
	}
	return out, nil
}

// G1Valid reports whether p is a compressed point of the G1 subgroup other
// than the identity.
func G1Valid(p backend.Pubkey) bool { return C.dkg_g1_check(u8(p[:])) == 1 }

// G1LinComb returns sum scalars[i] * points[i]. The scalars are public.
func G1LinComb(points []backend.Pubkey, scalars []*big.Int) (backend.Pubkey, error) {
	var out backend.Pubkey
	if len(points) == 0 || len(points) != len(scalars) {
		return out, errors.New("core: points and scalars differ in length")
	}
	pts := make([]byte, 0, 48*len(points))
	sc := make([]byte, 0, 32*len(points))
	for i, p := range points {
		pts = append(pts, p[:]...)
		var be [32]byte
		new(big.Int).Mod(scalars[i], curveOrder).FillBytes(be[:])
		for k := 31; k >= 0; k-- {
			sc = append(sc, be[k])
		}
	}
	if C.dkg_p1_lincomb(u8(pts), u8(sc), C.size_t(len(points)), u8(out[:])) != 0 {
		return out, errors.New("core: bad G1 point")
	}
	return out, nil
}

// FeldmanEval returns sum commitments[k] * x^k: the public key of the
// polynomial's value at x when commitments[k] = a_k * G1.
func FeldmanEval(commitments []backend.Pubkey, x uint64) (backend.Pubkey, error) {
	powers := make([]*big.Int, len(commitments))
	xb := new(big.Int).SetUint64(x)
	acc := big.NewInt(1)
	for k := range commitments {
		powers[k] = new(big.Int).Set(acc)
		acc.Mul(acc, xb).Mod(acc, curveOrder)
	}
	return G1LinComb(commitments, powers)
}

// Sign returns the BLS signature of msg with the secret scalar: the same
// ciphersuite as every Ethereum signature, here over any message. Setup
// signing (runner/keygen) uses it with a signing root it computed itself,
// or with a Charon lock hash it computed itself.
func Sign(secret *[32]byte, msg []byte) (backend.Signature, error) {
	var sig backend.Signature
	var p *C.uint8_t
	if len(msg) > 0 {
		p = u8(msg)
	}
	if C.dkg_sign(u8(secret[:]), p, C.size_t(len(msg)), u8(sig[:])) != 0 {
		return sig, errScalar
	}
	return sig, nil
}

// AggregateSignatures adds BLS signatures: the signature Charon's
// signature_aggregate is, which verifies under the sum of the keys when
// every key signed the same message.
func AggregateSignatures(sigs []backend.Signature) (backend.Signature, error) {
	var out backend.Signature
	if len(sigs) == 0 {
		return out, errors.New("dkgmath: no signatures")
	}
	flat := make([]byte, 0, 96*len(sigs))
	for _, s := range sigs {
		flat = append(flat, s[:]...)
	}
	if C.dkg_p2_sum(u8(flat), C.size_t(len(sigs)), u8(out[:])) != 0 {
		return out, errors.New("dkgmath: bad signature")
	}
	return out, nil
}
