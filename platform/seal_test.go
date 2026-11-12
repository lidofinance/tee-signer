package platform

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"testing"
)

// The schedule seed is a fixed function of the key, differs per key, and
// is not the key.
func TestScheduleSeed(t *testing.T) {
	k1, k2 := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)
	s1 := ScheduleSeed(k1)
	m := hmac.New(sha256.New, k1)
	m.Write([]byte("tee-signer nts-schedule v1"))
	if !bytes.Equal(s1, m.Sum(nil)) || !bytes.Equal(s1, ScheduleSeed(k1)) {
		t.Fatalf("seed %x", s1)
	}
	if bytes.Equal(s1, ScheduleSeed(k2)) || bytes.Equal(s1, k1) {
		t.Fatal("seed does not depend on the key, or is the key")
	}
}
