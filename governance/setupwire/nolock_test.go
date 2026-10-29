package setupwire

import (
	"bytes"
	"strings"
	"testing"
)

// sealing_key_release.no_lock_accepted (T-124): a GCP setup may say that it
// accepts a key rule without a lock. It is a flag byte at the end of the
// GCP sealing_key_release, before unsafe_single_key_accepted and the peer
// hosts.
func TestNoLockAccepted(t *testing.T) {
	plain := samples(t)["setup-gcp"]
	before, err := plain.Encode()
	if err != nil {
		t.Fatal(err)
	}
	accepted := samples(t)["setup-gcp"]
	accepted.Platform.SealingKeyRelease.NoLockAccepted = true
	b, err := accepted.Encode()
	if err != nil {
		t.Fatal(err)
	}
	at := len(before) - 3 // the flag, then unsafe_single_key_accepted 0 and host_count 0
	if len(b) != len(before) || before[at] != 0 || b[at] != 1 || !bytes.Equal(b[:at], before[:at]) || !bytes.Equal(b[at+1:], before[at+1:]) {
		t.Fatalf("encoding: want the setup without it with the flag byte 1")
	}
	got, err := DecodeSetup(b)
	if err != nil || !got.Platform.SealingKeyRelease.NoLockAccepted {
		t.Fatalf("decode: %v", err)
	}
	h1, _ := plain.Hash()
	h2, _ := accepted.Hash()
	if h1 == h2 {
		t.Fatal("setup_hash does not cover no_lock_accepted")
	}
	// Any other trailing byte is refused.
	for _, last := range []byte{0, 2} {
		bad := append(bytes.Clone(before), last)
		if _, err := DecodeSetup(bad); err == nil {
			t.Errorf("trailing byte %d accepted", last)
		}
	}
	// The human form carries it, and only for GCP.
	text, err := accepted.Format()
	if err != nil || !strings.Contains(string(text), "sealing_key_release.no_lock_accepted = true") {
		t.Fatalf("format: %v\n%s", err, text)
	}
	back, err := ParseSetup("gcp.conf", text)
	if err != nil || !back.Platform.SealingKeyRelease.NoLockAccepted {
		t.Fatalf("parse: %v", err)
	}
	if text, _ := plain.Format(); strings.Contains(string(text), "no_lock_accepted") {
		t.Fatal("format writes no_lock_accepted for a setup without it")
	}
	for _, name := range []string{"setup-nitro", "setup-azure", "setup-dev"} {
		s := samples(t)[name]
		s.Platform.SealingKeyRelease.NoLockAccepted = true
		if _, err := s.Encode(); err == nil || !strings.Contains(err.Error(), "no_lock_accepted") {
			t.Errorf("%s: %v, want a refusal", name, err)
		}
	}
}
