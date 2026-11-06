package setupwire

import (
	"bytes"
	"encoding/binary"
	"slices"
	"strings"
	"testing"
)

const testCreationDate = 1793895285 // 2026-11-05T16:14:45Z

// sealing_key_release.kms_key_creation_date is a presence byte after
// kms_key_id, then the date when the byte is 1. The Nitro key release is
// the end of the setup.
func TestKMSKeyCreationDateRoundTrip(t *testing.T) {
	s := samples(t)["setup-nitro"]
	b, err := s.Encode()
	if err != nil {
		t.Fatal(err)
	}
	plain := samples(t)["setup-nitro"]
	plain.Platform.SealingKeyRelease.KMSKeyCreationDate = 0
	pb, err := plain.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if pb[len(pb)-1] != 0 {
		t.Fatalf("absent date: last byte %d, want the presence byte 0", pb[len(pb)-1])
	}
	if want := binary.BigEndian.AppendUint64(append(slices.Clone(pb[:len(pb)-1]), 1), testCreationDate); !bytes.Equal(b, want) {
		t.Fatalf("encoding: %x, want presence byte 1 and the date", b[len(pb)-1:])
	}
	for _, c := range []struct {
		b    []byte
		want uint64
	}{{b, testCreationDate}, {pb, 0}} {
		got, err := DecodeSetup(c.b)
		if err != nil || got.Platform.SealingKeyRelease.KMSKeyCreationDate != c.want {
			t.Fatalf("decode, want %d: %v", c.want, err)
		}
	}
	h1, _ := plain.Hash()
	h2, _ := s.Hash()
	if h1 == h2 {
		t.Fatal("the date does not change setup_hash")
	}
}

// The decoder refuses a zero date, a presence byte other than 0 or 1 and a
// cut date; Check refuses a date the text form cannot write and the field
// on another platform.
func TestKMSKeyCreationDateStrict(t *testing.T) {
	s := samples(t)["setup-nitro"]
	b, _ := s.Encode()
	at := len(b) - 9 // the presence byte
	zero := slices.Clone(b)
	clear(zero[at+1:])
	two := slices.Clone(b)
	two[at] = 2
	for name, c := range map[string]struct {
		b    []byte
		want string
	}{
		"zero date":       {zero, "encode back"},
		"presence byte 2": {two, "kms_key_creation_date presence byte is 2"},
		"cut date":        {b[:len(b)-1], "too short"},
	} {
		if _, err := DecodeSetup(c.b); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", name, err, c.want)
		}
	}
	s.Platform.SealingKeyRelease.KMSKeyCreationDate = MaxKMSKeyCreationDate + 1
	if _, err := s.Encode(); err == nil || !strings.Contains(err.Error(), "after year 9999") {
		t.Errorf("date after 9999: %v", err)
	}
	az := samples(t)["setup-azure"]
	az.Platform.SealingKeyRelease.KMSKeyCreationDate = testCreationDate
	if _, err := az.Encode(); err == nil || !strings.Contains(err.Error(), "kms_key_creation_date does not apply to azure") {
		t.Errorf("azure: %v", err)
	}
}

// A Nitro setup of a prod chain needs the date; off prod it may leave it
// out.
func TestKMSKeyCreationDateProd(t *testing.T) {
	s := samples(t)["setup-nitro"]
	if s.Chain.Prod() {
		t.Fatal("the sample chain is prod")
	}
	s.Platform.SealingKeyRelease.KMSKeyCreationDate = 0
	if _, err := s.Encode(); err != nil {
		t.Fatalf("off prod without the date: %v", err)
	}
	s.Chain.GenesisForkVersion = MainnetForkVersion
	if _, err := s.Encode(); err == nil || !strings.Contains(err.Error(), "needs sealing_key_release.kms_key_creation_date") {
		t.Fatalf("prod without the date: %v", err)
	}
	if _, err := DecodeSetup(rawSetup(s)); err == nil {
		t.Fatal("decode: a prod setup without the date is accepted")
	}
	s.Platform.SealingKeyRelease.KMSKeyCreationDate = testCreationDate
	b, err := s.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeSetup(b); err != nil {
		t.Fatal(err)
	}
}
