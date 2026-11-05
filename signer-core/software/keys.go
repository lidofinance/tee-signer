package software

/*
#cgo CFLAGS: -I${SRCDIR}/../third_party/blst/bindings
#cgo linux,amd64 LDFLAGS: -L${SRCDIR}/../../build/x86_64/lib -lblst
#cgo linux,arm64 LDFLAGS: -L${SRCDIR}/../../build/aarch64/lib -lblst
#include "blst.h"
*/
import "C"

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"unsafe"

	"github.com/lidofinance/tee-signer/signer-core/core"
	"github.com/lidofinance/tee-signer/signer-protocol"
)

// Share is one point of a Shamir split. ID is the x coordinate (1..n).
type Share struct {
	ID     uint64
	Secret [32]byte
}

// scalar is a blst scalar: an element of the field of r, the order of the
// BLS12-381 subgroups, in blst's own 32-byte layout. The split works on
// scalars in fixed buffers, which wipe clears, rather than on math/big
// ints, whose words live on the heap and cannot be cleared.
//
// Copies this code does not control remain: the secret a caller passes by
// value, the 32-byte buffer core.PubkeyOf takes by value, the C stack of
// blst, and any spill the Go compiler makes. So the shares and the key
// can stay in the process's memory after the split; the caller keeps that
// memory out of core dumps and swap.
type scalar = C.blst_scalar

func bytesOf(s *scalar) *[32]byte { return (*[32]byte)(unsafe.Pointer(s)) }

// wipe clears a scalar.
func wipe(s *scalar) { clear(bytesOf(s)[:]) }

// scalarFromBytes loads the big-endian scalar b into s. It reports whether
// b is in 1..r-1.
func scalarFromBytes(s *scalar, b *[32]byte) bool {
	C.blst_scalar_from_bendian(s, (*C.byte)(&b[0]))
	return bool(C.blst_sk_check(s)) && *bytesOf(s) != [32]byte{}
}

// scalarToBytes writes s to b, big-endian.
func scalarToBytes(b *[32]byte, s *scalar) { C.blst_bendian_from_scalar((*C.byte)(&b[0]), s) }

// randScalar fills s with a uniform scalar in 1..r-1: 32 random bytes,
// kept when they are in range (about half the draws are).
func randScalar(r io.Reader, s *scalar) error {
	var b [32]byte
	defer clear(b[:])
	for {
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return err
		}
		if scalarFromBytes(s, &b) {
			return nil
		}
	}
}

// NewSecret returns a random valid secret key. Dev and test use only.
func NewSecret() ([32]byte, error) {
	var s scalar
	defer wipe(&s)
	if err := randScalar(rand.Reader, &s); err != nil {
		return [32]byte{}, err
	}
	var b [32]byte
	scalarToBytes(&b, &s)
	return b, nil
}

// Split makes a t-of-n Shamir split of secret with IDs 1..n. Dev and test
// use only.
func Split(secret [32]byte, t, n int) ([]Share, error) {
	shares, _, err := SplitWithCommitments(secret, t, n)
	return shares, err
}

// SplitWithCommitments is Split, and also returns the public commitments of
// the polynomial (Feldman): the public key of each coefficient, the first
// being the public key of secret. The offline dealer (signer-admin split)
// uses it on real keys, so the coefficients and the shares are computed in
// buffers this function clears; see scalar for what it cannot clear. It
// clears its own copy of secret; the caller clears the one it passed.
func SplitWithCommitments(secret [32]byte, t, n int) ([]Share, []backend.Pubkey, error) {
	defer clear(secret[:])
	if t < 1 || n < t {
		return nil, nil, errors.New("core: need 1 <= t <= n")
	}
	coef := make([]scalar, t)
	defer func() {
		for i := range coef {
			wipe(&coef[i])
		}
	}()
	if !scalarFromBytes(&coef[0], &secret) {
		return nil, nil, errors.New("core: secret out of range")
	}
	for i := 1; i < t; i++ {
		if err := randScalar(rand.Reader, &coef[i]); err != nil {
			return nil, nil, err
		}
	}
	var b [32]byte
	defer clear(b[:])
	commitments := make([]backend.Pubkey, t)
	for i := range coef {
		scalarToBytes(&b, &coef[i])
		p, err := core.PubkeyOf(b)
		if err != nil {
			return nil, nil, err
		}
		commitments[i] = p
	}
	shares := make([]Share, n)
	var x, y scalar
	defer wipe(&y)
	for i := range shares {
		clear(b[:])
		binary.BigEndian.PutUint64(b[24:], uint64(i+1))
		scalarFromBytes(&x, &b)
		// Horner from the top coefficient: y = y*x + coef[j], mod r.
		y = coef[t-1]
		for j := t - 2; j >= 0; j-- {
			if !C.blst_sk_mul_n_check(&y, &y, &x) || !C.blst_sk_add_n_check(&y, &y, &coef[j]) {
				return nil, nil, errors.New("core: degenerate split")
			}
		}
		shares[i].ID = uint64(i + 1)
		scalarToBytes(&shares[i].Secret, &y)
	}
	return shares, commitments, nil
}
