//go:build nts

package ntstest

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
)

// AES-SIV-CMAC-256 (RFC 5297), written here from the RFC with Go's AES. It
// shares no code with the client's nts/siv.go, and must not: the
// cross-check of the two (TestSIVMatchesTestServer) depends on it. NTS gives S2V
// the vector (associated data, nonce) and then the plaintext (RFC 8915
// section 5.6, RFC 5297 section 3).

// dbl is multiplication by x in GF(2^128) (RFC 5297 section 2.3).
func dbl(b [16]byte) [16]byte {
	var out [16]byte
	carry := b[0] >> 7
	for i := 0; i < 15; i++ {
		out[i] = b[i]<<1 | b[i+1]>>7
	}
	out[15] = b[15] << 1
	if carry == 1 {
		out[15] ^= 0x87
	}
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

// s2v is RFC 5297 section 2.4 over the strings, the last one being the plaintext.
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

func ctr(key []byte, v [16]byte, in []byte) []byte {
	// RFC 5297 section 2.6: clear bits 31 and 63 (from the right) of V.
	q := v
	q[8] &= 0x7f
	q[12] &= 0x7f
	c, _ := aes.NewCipher(key)
	out := make([]byte, len(in))
	cipher.NewCTR(c, q[:]).XORKeyStream(out, in)
	return out
}

// Seal returns V || C for a 32-octet key (RFC 5297 sections 2.6, 6.1).
func Seal(key, ad, nonce, plaintext []byte) []byte {
	return SealVector(key, [][]byte{ad, nonce}, plaintext)
}

// SealVector is Seal with any list of associated data strings (the RFC 5297
// appendix A.1 vector has one and no nonce).
func SealVector(key []byte, ad [][]byte, plaintext []byte) []byte {
	mac, _ := aes.NewCipher(key[:16])
	v := s2v(mac, append(append([][]byte(nil), ad...), plaintext)...)
	return append(v[:], ctr(key[16:], v, plaintext)...)
}

// Open checks and decrypts V || C (RFC 5297 section 2.7).
func Open(key, ad, nonce, ct []byte) ([]byte, bool) {
	if len(ct) < 16 {
		return nil, false
	}
	var v [16]byte
	copy(v[:], ct[:16])
	p := ctr(key[16:], v, ct[16:])
	mac, _ := aes.NewCipher(key[:16])
	t := s2v(mac, ad, nonce, p)
	if subtle.ConstantTimeCompare(t[:], v[:]) != 1 {
		return nil, false
	}
	return p, true
}
