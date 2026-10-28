package markstore

import (
	"bytes"
	"testing"

	"github.com/lidofinance/tee-signer/signer-protocol"
)

// A record round-trips with its exits and source gate, and Parse refuses
// trailing bytes, a presence byte of 2 and any magic but SMARK1.
func TestRecordFormatRoundTrip(t *testing.T) {
	gate := uint64(1002)
	r := Record{Setup: [32]byte{0x5e, 1}, Signer: "signer-1", Version: 3, PrevVersion: 2, PrevHash: [32]byte{2}, LogID: [32]byte{1},
		Mark: mark(20), Time: 1_800_000_000, State: testSetup("signer-1").First.Clone(), SourceGate: &gate,
		Exits: &ExitDay{Day: 20833, Stake: 64e9, Exits: []ExitEntry{
			{Pubkey: backend.Pubkey{0xa1}, ValidatorIndex: 7, ExitEpoch: 100, Stake: 32e9, Nonce: [32]byte{1}},
			{Pubkey: backend.Pubkey{0xa2}, ValidatorIndex: 7, ExitEpoch: 100, Stake: 32e9, Nonce: [32]byte{2}}}}}
	enc := signed(t, testKey(1), r)
	if string(enc[:6]) != "SMARK1" {
		t.Fatalf("magic %q", enc[:6])
	}
	got, err := decode(enc, testKey(1), r.Setup, r.Signer, 3)
	if err != nil {
		t.Fatal(err)
	}
	if got.SourceGate == nil || *got.SourceGate != gate || !exitsEqual(got.Exits, r.Exits) {
		t.Fatalf("read back: gate %v, exits %+v", got.SourceGate, got.Exits)
	}
	// Without exits and gate: both presence bytes 0.
	r.Exits, r.SourceGate = nil, nil
	got, err = decode(signed(t, testKey(1), r), testKey(1), r.Setup, r.Signer, 3)
	if err != nil || got.Exits != nil || got.SourceGate != nil {
		t.Fatalf("no exits, no gate: %+v, %v", got, err)
	}

	enc = signed(t, testKey(1), r)
	body := enc[:len(enc)-64]
	cases := map[string][]byte{
		"trailing byte":   append(bytes.Clone(body), 0),
		"gate presence 2": append(bytes.Clone(body[:len(body)-1]), 2),
	}
	for _, d := range []byte{'0', '2'} {
		b := bytes.Clone(body)
		b[5] = d
		cases["magic SMARK"+string(d)] = b
	}
	for name, b := range cases {
		if _, err := Parse(append(b, make([]byte, 64)...)); err == nil {
			t.Errorf("%s: parsed", name)
		}
	}
	// The header of a newer version still reads, so the fail-closed rule
	// can tell it from an object that is no record; version 0 does not.
	for d, want := range map[byte]bool{'0': false, '1': true, '2': true} {
		b := bytes.Clone(enc)
		b[5] = d
		if _, ok := RecordHeader(b); ok != want {
			t.Errorf("header of SMARK%c: %v, want %v", d, ok, want)
		}
	}
}
