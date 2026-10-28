package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	cloud "github.com/lidofinance/tee-signer/signer-protocol"
)

// An EIP-3076 file reduces to each validator's maxima, entries of one
// validator merged; a validator without history carries none, one the file
// does not list is an error, and so is a source above its target.
func TestInterchange(t *testing.T) {
	pk1, pk2 := "0x"+strings.Repeat("a1", 48), "0x"+strings.Repeat("b2", 48)
	file := func(body string) string {
		p := filepath.Join(t.TempDir(), "ic.json")
		if err := os.WriteFile(p, []byte(`{"metadata":{"interchange_format_version":"5","genesis_validators_root":"0x`+
			strings.Repeat("11", 32)+`"},"data":[`+body+`]}`), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	ic, err := loadInterchange(file(`{"pubkey":"` + pk1 + `","signed_blocks":[{"slot":"100"},{"slot":"90"}],"signed_attestations":[{"source_epoch":"3","target_epoch":"4"}]},` +
		`{"pubkey":"` + pk1 + `","signed_blocks":[],"signed_attestations":[{"source_epoch":"4","target_epoch":"5"}]},` +
		`{"pubkey":"` + pk2 + `","signed_blocks":[],"signed_attestations":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	var p1, p2, p3 cloud.Pubkey
	_ = p1.UnmarshalText([]byte(pk1))
	_ = p2.UnmarshalText([]byte(pk2))
	p3[0] = 1
	w, err := ic.markOf(p1)
	if err != nil || w == nil || *w != (cloud.Watermark{HasBlock: true, BlockSlot: 100, HasAttestation: true, SourceEpoch: 4, TargetEpoch: 5}) {
		t.Fatalf("validator 1: %+v %v", w, err)
	}
	if w, err := ic.markOf(p2); err != nil || w != nil {
		t.Fatalf("validator 2: %+v %v", w, err)
	}
	if _, err := ic.markOf(p3); err == nil {
		t.Fatal("a validator the file does not list")
	}
	if _, err := loadInterchange(file(`{"pubkey":"` + pk1 + `","signed_blocks":[],"signed_attestations":[{"source_epoch":"6","target_epoch":"5"}]}`)); err == nil {
		t.Fatal("a source above its target")
	}
}
