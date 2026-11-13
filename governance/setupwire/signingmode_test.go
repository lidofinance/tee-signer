package setupwire

import (
	"bytes"
	"strings"
	"testing"
)

// signing_mode is the last leaf of the public part: one byte after
// slashing_log_min_lock_days, 1 threshold or 2 single. It moves
// policy_root and setup_hash, not platform_commitment.
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
	// A bad byte in the setup. A runner built before dv_share refused 3 the
	// same way, so it never starts from a dv_share setup.
	for _, v := range []byte{0, 4, 0xff} {
		raw := bytes.Clone(b)
		raw[at] = v
		if _, err := DecodeSetup(raw); err == nil || !strings.Contains(err.Error(), "signing_mode") {
			t.Errorf("signing_mode byte %d: %v, want a refusal", v, err)
		}
	}
	for _, c := range []struct {
		s    string
		want SigningMode
	}{{"threshold", SigningModeThreshold}, {"single", SigningModeSingle}, {"dv_share", SigningModeDVShare},
		{"", 0}, {"Single", 0}, {"1", 0}, {"dv-share", 0}} {
		m, err := ParseSigningMode(c.s)
		if m != c.want || (err == nil) != (c.want != 0) {
			t.Errorf("ParseSigningMode(%q) = %v, %v", c.s, m, err)
		}
	}
}

// signing_mode = dv_share is byte 3. It adds a value and changes no byte or
// hash of a threshold or single setup (TestSigningMode pins those). It
// takes splits as threshold does (n >= 2, the chain's threshold rule), needs
// no GCP acceptance, refuses one, and allows clusters of many signers.
func TestSigningModeDVShare(t *testing.T) {
	s := samples(t)["setup-gcp"]
	s.SigningMode = SigningModeDVShare
	raw := must(s.Encode())
	if raw[1+publicLen-1] != 3 {
		t.Fatalf("dv_share byte %d, want 3", raw[1+publicLen-1])
	}
	got, err := DecodeSetup(raw)
	if err != nil || got.SigningMode != SigningModeDVShare || got.SigningMode.String() != "dv_share" {
		t.Fatalf("decode: %v, %v", got, err)
	}
	if err := s.Check(); err != nil {
		t.Errorf("dv_share gcp setup without the acceptance: %v", err)
	}
	for _, c := range []struct {
		t, n int
		ok   bool
	}{{1, 1, false}, {3, 4, true}, {5, 7, true}, {2, 4, false}} {
		if err := CheckThresholdOn(s, c.t, c.n); (err == nil) != c.ok {
			t.Errorf("dv_share %d of %d: %v", c.t, c.n, err)
		}
	}
	if err := CheckMembers(SigningModeDVShare, 4); err != nil {
		t.Errorf("dv_share cluster of 4: %v", err)
	}
	s.Platform.SealingKeyRelease.UnsafeSingleKeyAccepted = true
	if _, err := s.Encode(); err == nil || !strings.Contains(err.Error(), "unsafe_single_key_accepted needs signing_mode = single") {
		t.Errorf("dv_share setup with the acceptance: %v, want a refusal", err)
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
