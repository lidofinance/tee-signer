package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lidofinance/tee-signer/signer-core/core"
	"github.com/lidofinance/tee-signer/signer-core/software"
)

// assertNoSecret fails when msg holds the secret's hex, or any run of 16
// of its hex digits, in either case.
func assertNoSecret(t *testing.T, msg string, secret []byte) {
	t.Helper()
	h, m := hex.EncodeToString(secret), strings.ToLower(msg)
	for i := 0; i+16 <= len(h); i++ {
		if strings.Contains(m, h[i:i+16]) {
			t.Fatalf("error shows the secret: %s", msg)
		}
	}
}

// A damaged line of a shares file names the line and the field, and its
// error does not show the secret, whichever field the secret ends up in.
func TestReadSharesErrorsHideSecret(t *testing.T) {
	sk, _ := software.NewSecret()
	pk, _ := core.PubkeyOf(sk)
	for _, c := range []struct{ name, line, want string }{
		{"seed line without share pubkey", fmt.Sprintf("0x%x %s 9", sk, pk), ":2: pubkey"},
		{"secret in the pubkey field", fmt.Sprintf("0x%x - 0x%x", sk, sk), ":2: pubkey"},
		{"secret in the index field", fmt.Sprintf("%s 0x%x 0x%x", pk, sk, sk), ":2: index"},
		{"secret in the index field, no 0x", fmt.Sprintf("%s %x 0x%x", pk, sk, sk), ":2: index"},
		{"secret in the share pubkey field", fmt.Sprintf("0x%x %s 9 0x%x", sk, pk, sk), ":2: share pubkey"},
		{"pubkey and secret swapped", fmt.Sprintf("%s 0x%x 9 %s", pk, sk, pk), ":2: "},
		{"secret too short", fmt.Sprintf("%s - 0x%x", pk, sk[:31]), ":2: secret"},
	} {
		t.Run(c.name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "s.txt")
			if err := os.WriteFile(p, []byte("# shares\n"+c.line+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := readShares(p)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("want an error with %q, got %v", c.want, err)
			}
			assertNoSecret(t, err.Error(), sk[:])
		})
	}
}

// A shares file given where a pubkey list goes: the error names the line
// and does not show the secret on it.
func TestReadExpectErrorHidesSecret(t *testing.T) {
	sk, _ := software.NewSecret()
	pk, _ := core.PubkeyOf(sk)
	p := filepath.Join(t.TempDir(), "expect.txt")
	if err := os.WriteFile(p, fmt.Appendf(nil, "%s\n%s - 0x%x\n", pk, pk, sk), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := readExpect(p)
	if err == nil || !strings.Contains(err.Error(), ":2: pubkey") {
		t.Fatalf("want an error for line 2, got %v", err)
	}
	assertNoSecret(t, err.Error(), sk[:])
}
