package approver

import (
	"encoding/hex"
	"strings"
	"testing"
)

// A key is named by its full 40-digit v4 fingerprint only: a 16-digit key
// ID or any other suffix is refused, since a 64-bit ID can be matched by a
// second key made for it.
func TestSelectOpenPGPKeyFullFingerprint(t *testing.T) {
	var a, b OpenPGPKey
	for i := range a.Fingerprint {
		a.Fingerprint[i], b.Fingerprint[i] = byte(i), byte(0x80+i)
	}
	a.CanSign, b.CanSign, b.Subkey = true, true, true
	keys := []OpenPGPKey{a, b}
	full := strings.ToUpper(hex.EncodeToString(b.Fingerprint[:]))

	for _, want := range []string{full, strings.ToLower(full), "0x" + full, full[:20] + " " + full[20:]} {
		if k, err := SelectOpenPGPKey(keys, want); err != nil || k.Fingerprint != b.Fingerprint {
			t.Fatalf("SelectOpenPGPKey(%q): %X %v", want, k.Fingerprint, err)
		}
	}
	for _, want := range []string{b.KeyID(), full[1:], full[:39], full + "00"} {
		if k, err := SelectOpenPGPKey(keys, want); err == nil {
			t.Fatalf("SelectOpenPGPKey(%q) picked %X, want a refusal", want, k.Fingerprint)
		}
	}
}
