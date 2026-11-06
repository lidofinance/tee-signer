package setuptext

import (
	"bytes"
	"reflect"
	"strings"
	"testing"

	"github.com/lidofinance/tee-signer/governance/setupwire"
)

// Every sample setup survives human -> struct -> human, and the human form
// gives the same struct as the binary form.
func TestSetupRoundTrip(t *testing.T) {
	for name, s := range setups(t) {
		text, err := FormatSetup(s)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := ParseSetup(name, text)
		if err != nil {
			t.Fatalf("%s: parse: %v\n%s", name, err, text)
		}
		if !reflect.DeepEqual(parsed, s) {
			t.Fatalf("%s: parsed\n%+v\nwant\n%+v", name, parsed, s)
		}
		again, _ := FormatSetup(parsed)
		if !bytes.Equal(again, text) {
			t.Fatalf("%s: human form changed:\n%s\n---\n%s", name, text, again)
		}
	}
}

// Every sample update, and its body alone, survives the human form.
func TestUpdateRoundTrip(t *testing.T) {
	for name, u := range updates(t) {
		text, err := FormatUpdate(u)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := ParseUpdate(name, text)
		if err != nil {
			t.Fatalf("%s: parse: %v\n%s", name, err, text)
		}
		if !reflect.DeepEqual(parsed, u) {
			t.Fatalf("%s: parsed %+v, want %+v", name, parsed, u)
		}
		btext := must(FormatUpdateBody(&u.Body))
		pb, err := ParseUpdateBody(name, btext)
		if err != nil || !reflect.DeepEqual(*pb, u.Body) {
			t.Fatalf("%s: body text: %v", name, err)
		}
	}
}

// The format functions check their value first and write nothing for one
// that Encode refuses.
func TestFormatRefuses(t *testing.T) {
	s := setups(t)["setup-nitro"]
	s.Locked.Approvers.ApprovalsNeeded = 1
	if _, err := s.Encode(); err == nil {
		t.Fatal("the changed sample encodes")
	}
	if _, err := FormatSetup(s); err == nil || !strings.Contains(err.Error(), "approvals_needed is 1") {
		t.Errorf("setup: %v", err)
	}
	if _, err := FormatLocked(&s.Locked); err == nil {
		t.Error("locked group: format accepted it")
	}
	u := updates(t)["update-open"]
	u.Approvals = nil
	if _, err := FormatUpdate(u); err == nil || !strings.Contains(err.Error(), "0 approver signatures") {
		t.Errorf("update: %v", err)
	}
}

// sealing_key_release.no_lock_accepted (T-124): the human form carries it,
// and only for a setup that has it.
func TestNoLockAccepted(t *testing.T) {
	plain := setups(t)["setup-gcp"]
	accepted := setups(t)["setup-gcp"]
	accepted.Platform.SealingKeyRelease.NoLockAccepted = true
	text, err := FormatSetup(accepted)
	if err != nil || !strings.Contains(string(text), "sealing_key_release.no_lock_accepted = true") {
		t.Fatalf("format: %v\n%s", err, text)
	}
	back, err := ParseSetup("gcp.conf", text)
	if err != nil || !back.Platform.SealingKeyRelease.NoLockAccepted {
		t.Fatalf("parse: %v", err)
	}
	if text, _ := FormatSetup(plain); strings.Contains(string(text), "no_lock_accepted") {
		t.Fatal("format writes no_lock_accepted for a setup without it")
	}
}

// The human form carries unsafe_single_key_accepted under the warning, and
// only for a setup that sets it.
func TestUnsafeSingleKeyAccepted(t *testing.T) {
	plain := setups(t)["setup-gcp"]
	accepted := setups(t)["setup-gcp-single"]
	text, err := FormatSetup(accepted)
	want := "# UNSAFE: " + setupwire.UnsafeSingleKeyWarning + "\nsealing_key_release.unsafe_single_key_accepted = true\n"
	if err != nil || !strings.Contains(string(text), want) {
		t.Fatalf("format: %v\n%s", err, text)
	}
	back, err := ParseSetup("gcp.conf", text)
	if err != nil || !back.Platform.SealingKeyRelease.UnsafeSingleKeyAccepted {
		t.Fatalf("parse: %v", err)
	}
	if text, _ := FormatSetup(plain); strings.Contains(string(text), "unsafe_single_key") {
		t.Fatal("format writes unsafe_single_key_accepted for a setup without it")
	}
}

// sealing_key_release.kms_key_creation_date: the human form carries it as
// an RFC 3339 time, and only for a setup that has it.
func TestKMSKeyCreationDate(t *testing.T) {
	plain := setups(t)["setup-nitro"]
	plain.Platform.SealingKeyRelease.KMSKeyCreationDate = 0
	pinned := setups(t)["setup-nitro"]
	pinned.Platform.SealingKeyRelease.KMSKeyCreationDate = 1793895285
	text, err := FormatSetup(pinned)
	if err != nil || !strings.Contains(string(text), "sealing_key_release.kms_key_creation_date = 2026-11-05T16:14:45Z\n") {
		t.Fatalf("format: %v\n%s", err, text)
	}
	back, err := ParseSetup("nitro.conf", text)
	if err != nil || back.Platform.SealingKeyRelease.KMSKeyCreationDate != 1793895285 {
		t.Fatalf("parse: %v", err)
	}
	// The aws CLI form (a fraction and +00:00), another offset: the same
	// second, the fraction dropped.
	for _, form := range []string{"2026-11-05T16:14:45.048000+00:00", "2026-11-05T17:14:45.678+01:00"} {
		other := strings.Replace(string(text), "= 2026-11-05T16:14:45Z", "= "+form, 1)
		if back, err := ParseSetup("nitro.conf", []byte(other)); err != nil || back.Platform.SealingKeyRelease.KMSKeyCreationDate != 1793895285 {
			t.Fatalf("parse %s: %v", form, err)
		}
	}
	if text, _ := FormatSetup(plain); strings.Contains(string(text), "kms_key_creation_date") {
		t.Fatal("format writes kms_key_creation_date for a setup without it")
	}
}

// The CloudTrail note on kms_key_creation_date shows on a prod chain only:
// off prod the key may be unlocked on purpose.
func TestKMSKeyCreationDateNote(t *testing.T) {
	const cloudTrail = "check in CloudTrail that its CreateKey had the final locked policy"
	s := setups(t)["setup-nitro"]
	text, err := FormatSetup(s)
	if err != nil || strings.Contains(string(text), cloudTrail) || !strings.Contains(string(text), "the runner starts only on the key with this date") {
		t.Fatalf("off prod: %v\n%s", err, text)
	}
	s.Chain.GenesisForkVersion = setupwire.MainnetForkVersion
	if !s.Chain.Prod() {
		t.Fatal("the mainnet chain is not prod")
	}
	if text, err := FormatSetup(s); err != nil || !strings.Contains(string(text), cloudTrail) {
		t.Fatalf("prod: %v\n%s", err, text)
	}
}
