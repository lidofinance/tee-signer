//go:build nts

package ntscore

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/lidofinance/tee-signer/devkit/fuzzcheck"
	"github.com/lidofinance/tee-signer/trusted-time/nts/ntstest"
)

// Our AES-SIV-CMAC-256 (siv.c) against Wycheproof's fixed vectors and,
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
	onBothAESPaths(t, func(t *testing.T) { runWycheproof(t, loadWycheproof(t)) })
}

// onBothAESPaths runs f on the CPU's AES instructions where the CPU has
// them, and on the constant-time software (the fallback everywhere else).
func onBothAESPaths(t *testing.T, f func(t *testing.T)) {
	t.Helper()
	was := SIVHardware()
	defer SIVUseHardware(was)
	for _, hw := range []bool{true, false} {
		if SIVUseHardware(hw) != hw {
			t.Logf("no AES instructions on this CPU: the software path only")
			continue
		}
		name := "software"
		if hw {
			name = "hardware"
		}
		t.Run(name, f)
	}
}

func runWycheproof(t *testing.T, v wycheproofSIV) {
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
			if got, err := k.Seal(ad, msg); err != nil || !bytes.Equal(got, ct) {
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
		fuzzcheck.Watch(t)
		sum := sha256.Sum256(keySeed)
		key := sum[:]
		k, err := NewSIVKey(key)
		if err != nil {
			t.Fatal(err)
		}
		ours, err := k.Seal([][]byte{ad, nonce}, pt)
		if err != nil {
			t.Fatal(err)
		}
		theirs := ntstest.Seal(key, ad, nonce, pt)
		if !bytes.Equal(ours, theirs) {
			t.Fatalf("seal differs: ours %x, ntstest %x", ours, theirs)
		}
		// The constant-time software path gives the same bytes as the
		// CPU's instructions (where the CPU has them; else it ran above).
		if SIVHardware() {
			SIVUseHardware(false)
			sw, err := k.Seal([][]byte{ad, nonce}, pt)
			SIVUseHardware(true)
			if err != nil || !bytes.Equal(sw, ours) {
				t.Fatalf("the software AES differs: %x, hardware %x (%v)", sw, ours, err)
			}
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

// The refusals of RFC 5297 that the vectors do not show (the Rust core's
// selftest.rs): A.2 with its associated data strings in another order
// (S2V is not symmetric in them), with the nonce moved, under another key,
// and ciphertexts shorter than the tag, the empty one among them, which
// the core refuses itself.
func TestSIVRefusals(t *testing.T) {
	h := func(s string) []byte { b, _ := hex.DecodeString(s); return b }
	key := h("7f7e7d7c7b7a79787776757473727170404142434445464748494a4b4c4d4e4f")
	ad1, ad2, nonce := h("00112233445566778899aabbccddeeffdeaddadadeaddadaffeeddccbbaa99887766554433221100"),
		h("102030405060708090a0"), h("09f911029d74e35bd84156c5635688c0")
	ct := h("7bdb6e3b432667eb06f4d14bff2fbd0fcb900f2fddbe404326601965c889bf17dba77ceb094fa663b7a3f748ba8af829ea64ad544a272e9c485b62a3fd5c0d")
	k, err := NewSIVKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := k.Open([][]byte{ad1, ad2, nonce}, ct); !ok {
		t.Fatal("RFC 5297 A.2 does not open")
	}
	for name, ad := range map[string][][]byte{
		"AD swapped":     {ad2, ad1, nonce},
		"nonce first":    {nonce, ad1, ad2},
		"nonce dropped":  {ad1, ad2},
		"AD joined":      {append(append([]byte(nil), ad1...), ad2...), nonce},
		"empty AD added": {ad1, ad2, nonce, {}},
		"no AD":          nil,
	} {
		if _, ok := k.Open(ad, ct); ok {
			t.Errorf("%s: opened", name)
		}
	}
	other := append([]byte(nil), key...)
	other[31] ^= 1
	ko, err := NewSIVKey(other)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := ko.Open([][]byte{ad1, ad2, nonce}, ct); ok {
		t.Error("opened under another key")
	}
	for _, n := range []int{0, 1, 15} {
		if _, ok := k.Open([][]byte{ad1, ad2, nonce}, ct[:n]); ok {
			t.Errorf("a ciphertext of %d octets opened", n)
		}
	}
	// The tag alone is the empty plaintext's ciphertext: it opens.
	empty, err := k.Seal([][]byte{nonce}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if pt, ok := k.Open([][]byte{nonce}, empty); !ok || len(pt) != 0 || len(empty) != SIVTagLen {
		t.Fatalf("empty plaintext: %x, %v", pt, ok)
	}
	// S2V takes eight strings with the plaintext: an eighth associated
	// data string is refused, not sealed as an empty ciphertext.
	if ct, err := k.Seal(make([][]byte, MaxSIVAD+1), nil); err == nil || ct != nil {
		t.Fatalf("%d associated data strings: %x, %v", MaxSIVAD+1, ct, err)
	}
	if ct, err := k.Seal(make([][]byte, MaxSIVAD), nil); err != nil || len(ct) != SIVTagLen {
		t.Fatalf("%d associated data strings: %x, %v", MaxSIVAD, ct, err)
	}
}

// The two AES paths agree on random inputs, and the RFC 5297 self-test
// passes on both (nts.AESSIVSelfTest runs it on both at start as well).
func TestAESSoftwareMatchesHardware(t *testing.T) {
	if !SIVHardware() {
		t.Skip("no AES instructions on this CPU: the software path is the only one, and the vectors ran on it")
	}
	defer SIVUseHardware(true)
	rng := testRng(0x4145_5300)
	for i := 0; i < 500; i++ {
		key, ad, nonce, pt := rng.bytes(32), rng.bytes(rng.below(80)), rng.bytes(1+rng.below(24)), rng.bytes(rng.below(300))
		k, err := NewSIVKey(key)
		if err != nil {
			t.Fatal(err)
		}
		SIVUseHardware(true)
		hw, err1 := k.Seal([][]byte{ad, nonce}, pt)
		SIVUseHardware(false)
		sw, err2 := k.Seal([][]byte{ad, nonce}, pt)
		p, ok := k.Open([][]byte{ad, nonce}, hw)
		if err1 != nil || err2 != nil || !bytes.Equal(hw, sw) || !ok || !bytes.Equal(p, pt) {
			t.Fatalf("%d: hardware %x, software %x, open %v (%v, %v)", i, hw, sw, ok, err1, err2)
		}
	}
}
