//go:build nts

package nts

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
	"fmt"
)

// AES-SIV-CMAC-256 (RFC 5297) on Go's crypto/aes, the AEAD of the NTS
// extension fields (RFC 8915 section 5.6, AEAD_AES_SIV_CMAC_256). S2V takes
// the associated data strings (the packet so far, then the nonce) and the
// plaintext last. The AES block function is Go's, hardware AES on amd64 and
// arm64; dbl is branch-free; the tag compare is constant time.

// sivKeyLen is the AES-SIV-CMAC-256 key: 16 octets for S2V, 16 for CTR.
const sivKeyLen = 32

// dbl is multiplication by x in GF(2^128) (RFC 5297 section 2.3), without
// a branch on the carried bit.
func dbl(b [16]byte) [16]byte {
	var out [16]byte
	mask := -(b[0] >> 7) & 0x87
	for i := 0; i < 15; i++ {
		out[i] = b[i]<<1 | b[i+1]>>7
	}
	out[15] = b[15]<<1 ^ mask
	return out
}

// cmac is AES-CMAC (RFC 4493).
func cmac(c cipher.Block, msg []byte) [16]byte {
	var l [16]byte
	c.Encrypt(l[:], l[:])
	k1 := dbl(l)
	k2 := dbl(k1)
	n := (len(msg) + 15) / 16
	complete := n > 0 && len(msg)%16 == 0
	if n == 0 {
		n = 1
	}
	var last [16]byte
	tail := msg[(n-1)*16:]
	if complete {
		for i := range last {
			last[i] = tail[i] ^ k1[i]
		}
	} else {
		copy(last[:], tail)
		last[len(tail)] = 0x80
		for i := range last {
			last[i] ^= k2[i]
		}
	}
	var x [16]byte
	for i := 0; i < n-1; i++ {
		for j := 0; j < 16; j++ {
			x[j] ^= msg[i*16+j]
		}
		c.Encrypt(x[:], x[:])
	}
	for j := range x {
		x[j] ^= last[j]
	}
	c.Encrypt(x[:], x[:])
	return x
}

// s2v is RFC 5297 section 2.4 over the strings, the last one being the
// plaintext.
func s2v(c cipher.Block, strs ...[]byte) [16]byte {
	var zero [16]byte
	d := cmac(c, zero[:])
	for _, s := range strs[:len(strs)-1] {
		m := cmac(c, s)
		d = dbl(d)
		for i := range d {
			d[i] ^= m[i]
		}
	}
	sn := strs[len(strs)-1]
	var t []byte
	if len(sn) >= 16 {
		t = append([]byte(nil), sn...)
		for i := 0; i < 16; i++ {
			t[len(t)-16+i] ^= d[i]
		}
	} else {
		d = dbl(d)
		var p [16]byte
		copy(p[:], sn)
		p[len(sn)] = 0x80
		for i := range p {
			p[i] ^= d[i]
		}
		t = p[:]
	}
	return cmac(c, t)
}

// sivCTR is AES-CTR under the second half of the key with the IV of
// RFC 5297 section 2.6: V with bits 31 and 63 (from the right) cleared.
func sivCTR(c cipher.Block, v [16]byte, in []byte) []byte {
	q := v
	q[8] &= 0x7f
	q[12] &= 0x7f
	out := make([]byte, len(in))
	cipher.NewCTR(c, q[:]).XORKeyStream(out, in)
	return out
}

// sivKey is one AES-SIV-CMAC-256 key, expanded once.
type sivKey struct {
	mac, ctr cipher.Block
}

// newSIVKey expands a key of exactly sivKeyLen octets (RFC 5297 section
// 6.1: K_LEN is 32 for AEAD_AES_SIV_CMAC_256).
func newSIVKey(key []byte) (*sivKey, error) {
	if len(key) != sivKeyLen {
		return nil, fmt.Errorf("AES-SIV-CMAC-256 key of %d octets, want %d", len(key), sivKeyLen)
	}
	mac, err := aes.NewCipher(key[:16])
	if err != nil {
		return nil, err
	}
	ctr, err := aes.NewCipher(key[16:])
	if err != nil {
		return nil, err
	}
	return &sivKey{mac: mac, ctr: ctr}, nil
}

// Seal returns V || C over the associated data strings ad and plaintext
// (RFC 5297 sections 2.6, 6.1).
func (k *sivKey) Seal(ad [][]byte, plaintext []byte) []byte {
	v := s2v(k.mac, append(append([][]byte(nil), ad...), plaintext)...)
	return append(v[:], sivCTR(k.ctr, v, plaintext)...)
}

// Open checks and decrypts V || C (RFC 5297 section 2.7).
func (k *sivKey) Open(ad [][]byte, ct []byte) ([]byte, bool) {
	if len(ct) < 16 {
		return nil, false
	}
	var v [16]byte
	copy(v[:], ct[:16])
	p := sivCTR(k.ctr, v, ct[16:])
	t := s2v(k.mac, append(append([][]byte(nil), ad...), p)...)
	if subtle.ConstantTimeCompare(t[:], v[:]) != 1 {
		return nil, false
	}
	return p, true
}
