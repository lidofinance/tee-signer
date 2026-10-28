package azure

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"
)

// aesWrapWithPadding is the wrap side of RFC 5649, for the fake Key Vault.
func aesWrapWithPadding(block cipher.Block, p []byte) []byte {
	return aesWrapWithAIV(block, p, kwpAIV)
}

// aesWrapWithAIV wraps with the given high half of the initial value, so a
// test can make a blob that is well formed except for that value.
func aesWrapWithAIV(block cipher.Block, p []byte, aiv [4]byte) []byte {
	padded := append([]byte(nil), p...)
	for len(padded)%8 != 0 {
		padded = append(padded, 0)
	}
	var a [8]byte
	copy(a[:4], aiv[:])
	binary.BigEndian.PutUint32(a[4:], uint32(len(p)))
	n := len(padded) / 8
	var buf [16]byte
	if n == 1 {
		copy(buf[:8], a[:])
		copy(buf[8:], padded)
		block.Encrypt(buf[:], buf[:])
		return append([]byte(nil), buf[:]...)
	}
	r := padded
	for j := 0; j <= 5; j++ {
		for i := 1; i <= n; i++ {
			copy(buf[:8], a[:])
			copy(buf[8:], r[(i-1)*8:i*8])
			block.Encrypt(buf[:], buf[:])
			t := uint64(n*j + i)
			binary.BigEndian.PutUint64(a[:], binary.BigEndian.Uint64(buf[:8])^t)
			copy(r[(i-1)*8:i*8], buf[8:])
		}
	}
	return append(a[:], r...)
}

// Vectors: the first two are the examples of RFC 5649 section 6, the others
// come from the Python cryptography package (aes_key_wrap_with_padding), an
// independent implementation.
var kwpVectors = []struct{ kek, plain, wrapped string }{
	{"5840df6e29b02af1ab493b705bf16ea1ae8338f4dcc176a8", "c37b7e6492584340bed12207808941155068f738",
		"138bdeaa9b8fa7fc61f97742e72248ee5ae6ae5360d1ae6a5f54f373fa543b6a"},
	{"5840df6e29b02af1ab493b705bf16ea1ae8338f4dcc176a8", "466f7250617369", "afbeb0f07dfbf5419200f2ccb50bb24f"},
	{"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "6465666768696a6b6c6d6e6f707172737475767778797a",
		"a5b5a5241e658a125861fb881e565491f8349af18ee80eae879ee8fe9248e20f"},
	{"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "0102030405060708", "35808873fe6b6a455d47109fc67558f4"},
}

func TestAESUnwrapWithPaddingVectors(t *testing.T) {
	for i, v := range kwpVectors {
		kek, _ := hex.DecodeString(v.kek)
		want, _ := hex.DecodeString(v.plain)
		wrapped, _ := hex.DecodeString(v.wrapped)
		got, err := aesUnwrapWithPadding(kek, wrapped)
		if err != nil || !bytes.Equal(got, want) {
			t.Errorf("vector %d: got %x, %v; want %x", i, got, err, want)
		}
		block, _ := aes.NewCipher(kek)
		if w := aesWrapWithPadding(block, want); !bytes.Equal(w, wrapped) {
			t.Errorf("vector %d: the test wrap gives %x, want %x", i, w, wrapped)
		}
	}
}

func TestAESUnwrapWithPaddingRoundTripAndTampering(t *testing.T) {
	kek := make([]byte, 32)
	rand.Read(kek)
	block, _ := aes.NewCipher(kek)
	for n := 1; n <= 70; n++ {
		p := make([]byte, n)
		rand.Read(p)
		w := aesWrapWithPadding(block, p)
		got, err := aesUnwrapWithPadding(kek, w)
		if err != nil || !bytes.Equal(got, p) {
			t.Fatalf("%d bytes: got %x, %v", n, got, err)
		}
		// Any flipped bit, the wrong KEK, a cut or an extended blob fails the integrity check.
		bad := append([]byte(nil), w...)
		bad[n%len(bad)] ^= 0x01
		if _, err := aesUnwrapWithPadding(kek, bad); err == nil {
			t.Fatalf("%d bytes: a flipped bit was accepted", n)
		}
		other := make([]byte, 32)
		rand.Read(other)
		if _, err := aesUnwrapWithPadding(other, w); err == nil {
			t.Fatalf("%d bytes: the wrong KEK was accepted", n)
		}
		if _, err := aesUnwrapWithPadding(kek, w[:len(w)-8]); n > 8 && err == nil {
			t.Fatalf("%d bytes: a cut blob was accepted", n)
		}
	}
	for _, bad := range [][]byte{nil, make([]byte, 8), make([]byte, 17), make([]byte, 15)} {
		if _, err := aesUnwrapWithPadding(kek, bad); err == nil {
			t.Errorf("a blob of %d bytes was accepted", len(bad))
		}
	}
	if _, err := aesUnwrapWithPadding(make([]byte, 5), make([]byte, 16)); err == nil {
		t.Error("a 5-byte KEK was accepted")
	}
}

// A blob that is well formed but carries another initial value (the one of
// plain RFC 3394 key wrap) is refused: the integrity check is the AIV.
func TestAESUnwrapRefusesAnotherInitialValue(t *testing.T) {
	kek := make([]byte, 32)
	rand.Read(kek)
	block, _ := aes.NewCipher(kek)
	for _, n := range []int{8, 16, 33} {
		p := make([]byte, n)
		rand.Read(p)
		good := aesWrapWithAIV(block, p, kwpAIV)
		if got, err := aesUnwrapWithPadding(kek, good); err != nil || !bytes.Equal(got, p) {
			t.Fatalf("%d bytes: %v", n, err)
		}
		bad := aesWrapWithAIV(block, p, [4]byte{0xA6, 0xA6, 0xA6, 0xA6})
		if _, err := aesUnwrapWithPadding(kek, bad); err == nil || !strings.Contains(err.Error(), "integrity") {
			t.Fatalf("%d bytes: got %v", n, err)
		}
	}
}
