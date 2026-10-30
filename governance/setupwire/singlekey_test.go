package setupwire

import (
	"bytes"
	"strings"
	"testing"
)

// sealing_key_release.unsafe_single_key_accepted: a GCP setup with
// signing_mode = single must say that it accepts a key held alone (an
// import order with t = n = 1); Check and CheckThresholdOn refuse it
// otherwise. It is a flag byte after
// no_lock_accepted, before the peer hosts; setup_hash covers it. The human
// form is checked in governance/setuptext.
func TestUnsafeSingleKeyAccepted(t *testing.T) {
	plain := samples(t)["setup-gcp"]
	plain.SigningMode = SigningModeSingle
	before := rawSetup(plain)
	accepted := samples(t)["setup-gcp"]
	accepted.SigningMode = SigningModeSingle
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
	w := &writer{}
	plain.writePrivate(w)
	if pc, _ := accepted.PlatformCommitment(); CtxPlatformCommitment.Hash(plain.PlatformSalt[:], w.b) == pc {
		t.Fatal("setup_hash does not cover unsafe_single_key_accepted")
	}
	if _, err := plain.Encode(); err == nil || !strings.Contains(err.Error(), "signing_mode = single on gcp needs sealing_key_release.unsafe_single_key_accepted = true") {
		t.Fatalf("a single-mode gcp setup without the acceptance: %v, want a refusal", err)
	}
	if err := CheckThresholdOn(plain, 1, 1); err == nil {
		t.Fatal("1 of 1 passes on gcp without the acceptance")
	}
	if err := CheckThresholdOn(accepted, 1, 1); err != nil {
		t.Fatalf("1 of 1 on gcp with the acceptance: %v", err)
	}
	for _, name := range []string{"setup-nitro", "setup-azure", "setup-dev"} {
		s := samples(t)[name]
		s.SigningMode = SigningModeSingle
		s.Platform.SealingKeyRelease.UnsafeSingleKeyAccepted = true
		if _, err := s.Encode(); err == nil || !strings.Contains(err.Error(), "unsafe_single_key_accepted") {
			t.Errorf("%s: %v, want a refusal", name, err)
		}
	}
}
