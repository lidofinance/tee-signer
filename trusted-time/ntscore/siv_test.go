//go:build nts

package ntscore

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/lidofinance/tee-signer/trusted-time/nts/ntstest"
)

// Our AES-SIV-CMAC-256 (siv.go) against Wycheproof's fixed vectors and,
// under the fuzzer, against the separate copy in ntstest. The two copies
// share no code, so a bug in one shows as a difference.

// wycheproofSIV is testdata/wycheproof_aes_siv_cmac_256.json: the keySize
// 256 group of Wycheproof's aes_siv_cmac_test.json, the deterministic form
// of RFC 5297 with one associated data string.
type wycheproofSIV struct {
	Source string `json:"source"`
	Tests  []struct {
		ID      int    `json:"tcId"`
		Comment string `json:"comment"`
		Key     string `json:"key"`
		AAD     string `json:"aad"`
		Msg     string `json:"msg"`
		CT      string `json:"ct"`
		Result  string `json:"result"`
	} `json:"tests"`
}

func loadWycheproof(t testing.TB) wycheproofSIV {
	t.Helper()
	raw, err := os.ReadFile("testdata/wycheproof_aes_siv_cmac_256.json")
	if err != nil {
		t.Fatal(err)
	}
	var v wycheproofSIV
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	if len(v.Tests) < 100 {
		t.Fatalf("%d vectors", len(v.Tests))
	}
	return v
}

func unhex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Every Wycheproof vector of the 32-octet key: a valid one seals to its
// ciphertext and opens to its message, in our copy and in ntstest's; an
// invalid one opens in neither.
func TestWycheproofAESSIV(t *testing.T) {
	v := loadWycheproof(t)
	valid, invalid := 0, 0
	for _, c := range v.Tests {
		key, aad, msg, ct := unhex(t, c.Key), unhex(t, c.AAD), unhex(t, c.Msg), unhex(t, c.CT)
		k, err := NewSIVKey(key)
		if err != nil {
			t.Fatalf("tcId %d: %v", c.ID, err)
		}
		ad := [][]byte{aad}
		switch c.Result {
		case "valid":
			valid++
			if got := k.Seal(ad, msg); !bytes.Equal(got, ct) {
				t.Fatalf("tcId %d (%s): seal %x, want %x", c.ID, c.Comment, got, ct)
			}
			if got := ntstest.SealVector(key, ad, msg); !bytes.Equal(got, ct) {
				t.Fatalf("tcId %d (%s): ntstest seal %x, want %x", c.ID, c.Comment, got, ct)
			}
			if p, ok := k.Open(ad, ct); !ok || !bytes.Equal(p, msg) {
				t.Fatalf("tcId %d (%s): open failed", c.ID, c.Comment)
			}
		case "invalid":
			invalid++
			// ntstest.Open takes the nonce-based form, a second associated
			// data string, so the deterministic vectors apply to our Open
			// only; FuzzSIV compares the two copies on the nonce-based form.
			if _, ok := k.Open(ad, ct); ok {
				t.Fatalf("tcId %d (%s): an invalid ciphertext opened", c.ID, c.Comment)
			}
		default:
			t.Fatalf("tcId %d: result %q", c.ID, c.Result)
		}
	}
	t.Logf("%s: %d valid, %d invalid", v.Source, valid, invalid)
}

// FuzzSIV feeds random keys, associated data, nonces and messages to our
// AES-SIV and to ntstest's separate copy: both give the same ciphertext,
// a sealed message always opens in both, and a ciphertext with one changed
// bit opens in neither. The key is derived from the input so every input
// exercises a full 32-octet key.
func FuzzSIV(f *testing.F) {
	for _, c := range loadWycheproof(f).Tests[:8] {
		f.Add(unhex(f, c.Key), unhex(f, c.AAD), []byte{}, unhex(f, c.Msg), uint16(0))
	}
	f.Add([]byte("key"), []byte("ad"), []byte("nonce"), []byte("the plaintext, more than one block long!"), uint16(3))
	f.Add([]byte{}, []byte{}, []byte{}, []byte{}, uint16(0))
	f.Fuzz(func(t *testing.T, keySeed, ad, nonce, pt []byte, flip uint16) {
		sum := sha256.Sum256(keySeed)
		key := sum[:]
		k, err := NewSIVKey(key)
		if err != nil {
			t.Fatal(err)
		}
		ours := k.Seal([][]byte{ad, nonce}, pt)
		theirs := ntstest.Seal(key, ad, nonce, pt)
		if !bytes.Equal(ours, theirs) {
			t.Fatalf("seal differs: ours %x, ntstest %x", ours, theirs)
		}
		if len(ours) != 16+len(pt) {
			t.Fatalf("ciphertext of %d octets for %d of plaintext", len(ours), len(pt))
		}
		if p, ok := k.Open([][]byte{ad, nonce}, theirs); !ok || !bytes.Equal(p, pt) {
			t.Fatal("ours does not open ntstest's ciphertext")
		}
		if p, ok := ntstest.Open(key, ad, nonce, ours); !ok || !bytes.Equal(p, pt) {
			t.Fatal("ntstest does not open our ciphertext")
		}
		// One changed bit anywhere in V || C: refused by both.
		bad := append([]byte(nil), ours...)
		bit := int(flip) % (len(bad) * 8)
		bad[bit/8] ^= 1 << (bit % 8)
		if _, ok := k.Open([][]byte{ad, nonce}, bad); ok {
			t.Fatalf("ours opened a ciphertext with bit %d changed", bit)
		}
		if _, ok := ntstest.Open(key, ad, nonce, bad); ok {
			t.Fatalf("ntstest opened a ciphertext with bit %d changed", bit)
		}
		// A changed associated data string or nonce: refused as well.
		if _, ok := k.Open([][]byte{append(append([]byte(nil), ad...), 0), nonce}, ours); ok {
			t.Fatal("opened under a longer associated data string")
		}
		if _, ok := k.Open([][]byte{ad, append(append([]byte(nil), nonce...), 0)}, ours); ok {
			t.Fatal("opened under a longer nonce")
		}
	})
}
