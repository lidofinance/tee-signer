package setupwire

import (
	"bytes"
	"strings"
	"testing"
)

// sealing_key_release.unsafe_single_key_accepted: a GCP setup may say that
// it accepts a key held alone (an import order with t = n = 1), which
// CheckThresholdOn refuses otherwise. It is a flag byte after
// no_lock_accepted, before the peer hosts; setup_hash covers it. The human
// form is checked in governance/setuptext.
func TestUnsafeSingleKeyAccepted(t *testing.T) {
	plain := samples(t)["setup-gcp"]
	before, err := plain.Encode()
	if err != nil {
		t.Fatal(err)
	}
	accepted := samples(t)["setup-gcp"]
	accepted.Platform.SealingKeyRelease.UnsafeSingleKeyAccepted = true
	b, err := accepted.Encode()
	if err != nil {
		t.Fatal(err)
	}
	at := len(before) - 2 // the flag, then host_count 0
	if len(b) != len(before) || before[at] != 0 || b[at] != 1 || !bytes.Equal(b[:at], before[:at]) || !bytes.Equal(b[at+1:], before[at+1:]) {
		t.Fatalf("encoding: want the setup without it with the flag byte 1")
	}
	got, err := DecodeSetup(b)
	if err != nil || !got.Platform.SealingKeyRelease.UnsafeSingleKeyAccepted {
		t.Fatalf("decode: %v", err)
	}
	h1, _ := plain.Hash()
	h2, _ := accepted.Hash()
	if h1 == h2 {
		t.Fatal("setup_hash does not cover unsafe_single_key_accepted")
	}
	if err := CheckThresholdOn(&plain.Platform, plain.Chain.GenesisForkVersion, 1, 1); err == nil {
		t.Fatal("1 of 1 passes on gcp without the acceptance")
	}
	if err := CheckThresholdOn(&accepted.Platform, accepted.Chain.GenesisForkVersion, 1, 1); err != nil {
		t.Fatalf("1 of 1 on gcp with the acceptance: %v", err)
	}
	for _, name := range []string{"setup-nitro", "setup-azure", "setup-dev"} {
		s := samples(t)[name]
		s.Platform.SealingKeyRelease.UnsafeSingleKeyAccepted = true
		if _, err := s.Encode(); err == nil || !strings.Contains(err.Error(), "unsafe_single_key_accepted") {
			t.Errorf("%s: %v, want a refusal", name, err)
		}
	}
}
