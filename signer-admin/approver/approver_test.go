package approver

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lidofinance/tee-signer/governance/setupwire"
)

func writeKey(t *testing.T, mode os.FileMode, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "approver.key")
	if err := os.WriteFile(p, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
	return p
}

var seedHex = strings.Repeat("11", 32)

// A key file opens by path and as file:PATH; a wider mode, a directory,
// another scheme and a bad seed are refused.
func TestOpen(t *testing.T) {
	p := writeKey(t, 0o600, "0x"+seedHex+"\n")
	want := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x11}, 32)).Public().(ed25519.PublicKey)
	for _, uri := range []string{p, "file:" + p} {
		s, err := Open(uri)
		if err != nil {
			t.Fatalf("%s: %v", uri, err)
		}
		if !s.Public().Equal(want) {
			t.Fatalf("%s: wrong key", uri)
		}
	}
	for name, uri := range map[string]string{
		"mode 0644":  writeKey(t, 0o644, seedHex),
		"directory":  t.TempDir(),
		"pkcs11":     "pkcs11:token=x",
		"short seed": writeKey(t, 0o600, "1122"),
		"empty":      "file:",
	} {
		if _, err := Open(uri); err == nil {
			t.Errorf("%s: opened", name)
		}
	}
}

// Sign makes the direct and the hashed form, Verify tells them apart, and
// a signature of one kind does not verify as another kind.
func TestSignForms(t *testing.T) {
	s, err := Open(writeKey(t, 0o400, seedHex))
	if err != nil {
		t.Fatal(err)
	}
	body := []byte("an import order body")
	direct, err := Sign(s, setupwire.CtxImportOrder, false, body)
	if err != nil {
		t.Fatal(err)
	}
	hashed, err := Sign(s, setupwire.CtxImportOrder, true, body)
	if err != nil {
		t.Fatal(err)
	}
	k := Key(s)
	if ok, h := Verify(k, setupwire.CtxImportOrder, direct, body); !ok || h {
		t.Fatalf("direct: %v %v", ok, h)
	}
	if ok, h := Verify(k, setupwire.CtxImportOrder, hashed, body); !ok || !h {
		t.Fatalf("hashed: %v %v", ok, h)
	}
	if ok, _ := Verify(k, setupwire.CtxDKGOrder, hashed, body); ok {
		t.Fatal("an import order signature verified as a DKG order")
	}
	d := sha256.Sum256(setupwire.CtxImportOrder.Message(body))
	m := setupwire.CtxImportOrderHash.Hash(d[:])
	if !ed25519.Verify(s.Public(), m[:], hashed[:]) {
		t.Fatal("hashed form is not SHA-256 of the hash context and SHA-256 of the direct message")
	}
	if !setupwire.VerifyApproval(k, setupwire.CtxImportOrder, hashed, body) {
		t.Fatal("the runner's verifier refuses the hashed signature")
	}
	if _, err := Sign(s, setupwire.CtxSetup, false, body); err == nil {
		t.Fatal("signed under a context that is not an approver's")
	}
}
