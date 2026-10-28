//go:build nts

package nts

import (
	"bytes"
	"encoding/hex"
	"errors"

	"github.com/secure-io/siv-go"
)

// AESSIVSelfTest runs a known-answer test through the AES-SIV-CMAC-256 of
// the NTS library, in the nonce-based form NTS uses (RFC 5297 section 3,
// the nonce as the last S2V input before the plaintext). The key, the
// associated data, the nonce and the plaintext are those of RFC 5297
// appendix A.2 with its single associated-data component; the answer is
// what ntstest's own AES-SIV, checked against appendix A.1
// (TestTestServerSIVMatchesRFC5297), computes for them, and the library
// agreed with it when this value was recorded. It returns nil if the
// output still matches.
func AESSIVSelfTest() error {
	h := func(s string) []byte { b, _ := hex.DecodeString(s); return b }
	key := h("7f7e7d7c7b7a79787776757473727170404142434445464748494a4b4c4d4e4f")
	ad := h("00112233445566778899aabbccddeeffdeaddadadeaddadaffeeddccbbaa99887766554433221100")
	nonce := h("09f911029d74e35bd84156c5635688c0")
	plain := h("7468697320697320736f6d6520706c61696e7465787420746f20656e6372797074207573696e67205349562d414553")
	want := h("85825e22e90cf2ddda2c548dc7c1b6310dcdaca0cebf9dc6cb90583f5bf1506e02cd48832b00e4e598b2b22a53e6199d4df0c1666a35a0433b250dc134d776")
	aead, err := siv.NewCMAC(key)
	if err != nil {
		return err
	}
	if got := aead.Seal(nil, nonce, plain, ad); !bytes.Equal(got, want) {
		return errors.New("AES-SIV-CMAC-256 self-test failed: the known answer does not match")
	}
	back, err := aead.Open(nil, nonce, want, ad)
	if err != nil || !bytes.Equal(back, plain) {
		return errors.New("AES-SIV-CMAC-256 self-test failed: open of the known answer does not match")
	}
	return nil
}
