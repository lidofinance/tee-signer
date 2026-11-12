package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A share file that others can read is refused, as signer-admin refuses a
// key file of that mode.
func TestReadSecretRefusesOpenFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "share.hex")
	if err := os.WriteFile(p, []byte("0x10"+strings.Repeat("22", 31)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readSecret(p); err == nil || !strings.Contains(err.Error(), "chmod 600") {
		t.Fatalf("readSecret of a 0644 share file: %v, want a refusal", err)
	}
}

func TestReadSecret(t *testing.T) {
	sk, err := readSecret(shareFile(t))
	if err != nil {
		t.Fatal(err)
	}
	if sk[0] != 0x10 || sk[31] != 0x22 {
		t.Fatalf("readSecret: %x", sk)
	}
}
