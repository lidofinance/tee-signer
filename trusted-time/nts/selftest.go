//go:build nts

package nts

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
)

// AESSIVSelfTest runs the AES-SIV-CMAC-256 test vectors of RFC 5297
// appendix A: A.1 (the deterministic form, one associated data string) and
// A.2 (the nonce-based form NTS uses, two associated data strings and a
// nonce). It returns nil if both match.
func AESSIVSelfTest() error {
	h := func(s string) []byte { b, _ := hex.DecodeString(s); return b }
	cases := []struct {
		name  string
		key   []byte
		ad    [][]byte
		plain []byte
		want  []byte
	}{
		{"A.1", h("fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"),
			[][]byte{h("101112131415161718191a1b1c1d1e1f2021222324252627")},
			h("112233445566778899aabbccddee"),
			h("85632d07c6e8f37f950acd320a2ecc9340c02b9690c4dc04daef7f6afe5c")},
		{"A.2", h("7f7e7d7c7b7a79787776757473727170404142434445464748494a4b4c4d4e4f"),
			[][]byte{h("00112233445566778899aabbccddeeffdeaddadadeaddadaffeeddccbbaa99887766554433221100"),
				h("102030405060708090a0"), h("09f911029d74e35bd84156c5635688c0")},
			h("7468697320697320736f6d6520706c61696e7465787420746f20656e6372797074207573696e67205349562d414553"),
			h("7bdb6e3b432667eb06f4d14bff2fbd0fcb900f2fddbe404326601965c889bf17dba77ceb094fa663b7a3f748ba8af829ea64ad544a272e9c485b62a3fd5c0d")},
	}
	for _, c := range cases {
		k, err := newSIVKey(c.key)
		if err != nil {
			return err
		}
		if got := k.Seal(c.ad, c.plain); !bytes.Equal(got, c.want) {
			return fmt.Errorf("AES-SIV-CMAC-256 self-test failed: RFC 5297 %s seal does not match", c.name)
		}
		back, ok := k.Open(c.ad, c.want)
		if !ok || !bytes.Equal(back, c.plain) {
			return fmt.Errorf("AES-SIV-CMAC-256 self-test failed: RFC 5297 %s open does not match", c.name)
		}
		tampered := append([]byte(nil), c.want...)
		tampered[len(tampered)-1] ^= 1
		if _, ok := k.Open(c.ad, tampered); ok {
			return errors.New("AES-SIV-CMAC-256 self-test failed: a tampered ciphertext opened")
		}
	}
	return nil
}
