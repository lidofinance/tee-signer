package setupwire

import (
	"bytes"
	"strings"
	"testing"
)

// signing_mode is the last leaf of the public part: one byte after
// slashing_log_min_lock_days, 1 threshold or 2 single. It moves
// policy_root and setup_hash, not platform_commitment, and survives the
// published form that a handover source reads.
func TestSigningMode(t *testing.T) {
	th := samples(t)["setup-nitro"]
	si := samples(t)["setup-nitro"]
	si.SigningMode = SigningModeSingle
	a, b := must(th.Encode()), must(si.Encode())
	ok := func(h [32]byte, err error) [32]byte {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return h
	}
	at := 1 + publicLen - 1
	if a[at] != 1 || b[at] != 2 || !bytes.Equal(a[:at], b[:at]) {
		t.Fatalf("signing_mode byte at %d: %d and %d, want 1 and 2 after the same bytes", at, a[at], b[at])
	}
	if got, err := DecodeSetup(b); err != nil || got.SigningMode != SigningModeSingle {
		t.Fatalf("decode: %v", err)
	}
	pub, _, _ := LeafNames()
	if len(pub) != NumPublicLeaves || pub[NumPublicLeaves-1] != "signing_mode" {
		t.Fatalf("public leaves %v, want signing_mode last", pub)
	}
	if ok(th.PolicyRoot()) == ok(si.PolicyRoot()) || ok(th.Hash()) == ok(si.Hash()) {
		t.Fatal("policy_root or setup_hash does not cover signing_mode")
	}
	if ok(th.PlatformCommitment()) != ok(si.PlatformCommitment()) {
		t.Fatal("signing_mode moved platform_commitment")
	}
	pb, err := PublishedOf(si)
	if err != nil {
		t.Fatal(err)
	}
	back, err := DecodePublished(must(pb.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	if back.Policy.SigningMode != SigningModeSingle || ok(back.SetupHash()) != ok(si.Hash()) {
		t.Fatalf("published round trip: %v", err)
	}
	// A bad byte in the setup and in a published leaf.
	for _, v := range []byte{0, 3} {
		raw := bytes.Clone(b)
		raw[at] = v
		if _, err := DecodeSetup(raw); err == nil || !strings.Contains(err.Error(), "signing_mode") {
			t.Errorf("signing_mode byte %d: %v, want a refusal", v, err)
		}
	}
	pubL, lk, op, _ := si.Policy().Leaves()
	pubL[NumPublicLeaves-1].Value = []byte{0}
	if _, err := PolicyFromLeaves(pubL, lk, op); err == nil || !strings.Contains(err.Error(), "signing_mode") {
		t.Errorf("published signing_mode 0: %v, want a refusal", err)
	}
	for _, c := range []struct {
		s    string
		want SigningMode
	}{{"threshold", SigningModeThreshold}, {"single", SigningModeSingle}, {"", 0}, {"Single", 0}, {"1", 0}} {
		m, err := ParseSigningMode(c.s)
		if m != c.want || (err == nil) != (c.want != 0) {
			t.Errorf("ParseSigningMode(%q) = %v, %v", c.s, m, err)
		}
	}
}

// The acceptance of a key held alone on GCP and the mode go together: a
// threshold setup with it is refused on every platform, a single GCP
// setup without it is refused when it is salted (Check), not before
// (CheckValues), so signer-admin setup can still add it.
func TestSigningModeAcceptance(t *testing.T) {
	g := samples(t)["setup-gcp"]
	g.Platform.SealingKeyRelease.UnsafeSingleKeyAccepted = true
	if _, err := g.Encode(); err == nil || !strings.Contains(err.Error(), "unsafe_single_key_accepted needs signing_mode = single") {
		t.Errorf("threshold gcp setup with the acceptance: %v, want a refusal", err)
	}
	g = samples(t)["setup-gcp"]
	g.SigningMode = SigningModeSingle
	if err := g.CheckValues(); err != nil {
		t.Errorf("CheckValues of a single gcp setup without the acceptance: %v, want nil", err)
	}
	if err := g.Check(); err == nil || !strings.Contains(err.Error(), "signing_mode = single on gcp") {
		t.Errorf("Check of a single gcp setup without the acceptance: %v, want a refusal", err)
	}
	g.Platform.SealingKeyRelease.UnsafeSingleKeyAccepted = true
	if err := g.Check(); err != nil {
		t.Errorf("single gcp setup with the acceptance: %v", err)
	}
}

// The samples cover both modes: setup-dev-single and setup-gcp-single
// take whole keys only, setup-gcp-single with the acceptance on GCP; the
// others take shares of splits only.
func TestSampleSigningModes(t *testing.T) {
	for name, s := range samples(t) {
		single := name == "setup-dev-single" || name == "setup-gcp-single"
		want := SigningModeThreshold
		if single {
			want = SigningModeSingle
		}
		if s.SigningMode != want {
			t.Errorf("%s: signing_mode %s, want %s", name, s.SigningMode, want)
		}
		if err := s.Check(); err != nil {
			t.Errorf("%s: %v", name, err)
		}
		whole, split := CheckThresholdOn(s, 1, 1), CheckThresholdOn(s, 2, 3)
		if single != (whole == nil) || single == (split == nil) {
			t.Errorf("%s: 1 of 1 %v, 2 of 3 %v", name, whole, split)
		}
	}
	if !samples(t)["setup-gcp-single"].Platform.SealingKeyRelease.UnsafeSingleKeyAccepted {
		t.Error("setup-gcp-single lacks unsafe_single_key_accepted")
	}
}
