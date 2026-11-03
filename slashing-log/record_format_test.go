package markstore

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"testing"

	"github.com/lidofinance/tee-signer/platform"
	"github.com/lidofinance/tee-signer/signer-protocol"
)

// A record round-trips with its exits, source gate and share set, and
// Parse refuses trailing bytes, a presence byte of 2 and any magic but
// SMARK1 and SMARK2.
func TestRecordFormatRoundTrip(t *testing.T) {
	gate := uint64(1002)
	r := Record{Setup: [32]byte{0x5e, 1}, Signer: "signer-1", Version: 3, PrevVersion: 2, PrevHash: [32]byte{2}, LogID: [32]byte{1},
		Mark: mark(20), Time: 1_800_000_000, State: testSetup("signer-1").First.Clone(), SourceGate: &gate,
		Shares: &ShareSet{Current: [32]byte{0xc1}, Pending: &[32]byte{0xc2}},
		Exits: &ExitDay{Day: 20833, Stake: 64e9, Exits: []ExitEntry{
			{Pubkey: backend.Pubkey{0xa1}, ValidatorIndex: 7, ExitEpoch: 100, Stake: 32e9, Nonce: [32]byte{1}},
			{Pubkey: backend.Pubkey{0xa2}, ValidatorIndex: 7, ExitEpoch: 100, Stake: 32e9, Nonce: [32]byte{2}}}}}
	enc := signed(t, testKey(1), r)
	if string(enc[:6]) != "SMARK2" {
		t.Fatalf("magic %q", enc[:6])
	}
	got, err := decode(enc, testKey(1), r.Setup, r.Signer, 3)
	if err != nil {
		t.Fatal(err)
	}
	if got.SourceGate == nil || *got.SourceGate != gate || !exitsEqual(got.Exits, r.Exits) || !sameShares(got.Shares, r.Shares) {
		t.Fatalf("read back: gate %v, exits %+v, shares %+v", got.SourceGate, got.Exits, got.Shares)
	}
	r.Shares.Pending = nil
	got, err = decode(signed(t, testKey(1), r), testKey(1), r.Setup, r.Signer, 3)
	if err != nil || !sameShares(got.Shares, r.Shares) {
		t.Fatalf("share set without a pending root: %+v, %v", got.Shares, err)
	}
	// Without exits, gate and share set: the presence bytes 0.
	r.Exits, r.SourceGate, r.Shares = nil, nil, nil
	got, err = decode(signed(t, testKey(1), r), testKey(1), r.Setup, r.Signer, 3)
	if err != nil || got.Exits != nil || got.SourceGate != nil || got.Shares != nil {
		t.Fatalf("no exits, no gate, no share set: %+v, %v", got, err)
	}
	// An SMARK1 record (no share set field) reads, with no share set.
	got, err = decode(signedV1(t, testKey(1), r), testKey(1), r.Setup, r.Signer, 3)
	if err != nil || got.Shares != nil {
		t.Fatalf("SMARK1: %+v, %v", got, err)
	}

	enc = signed(t, testKey(1), r)
	body := enc[:len(enc)-64]
	cases := map[string][]byte{
		"trailing byte":     append(bytes.Clone(body), 0),
		"shares presence 2": append(bytes.Clone(body[:len(body)-1]), 2),
		// An SMARK1 body with the share set's presence byte.
		"SMARK1 with a share set": append([]byte("SMARK1"), body[6:]...),
	}
	for _, d := range []byte{'0', '3'} {
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
	for d, want := range map[byte]bool{'0': false, '1': true, '2': true, '3': true} {
		b := bytes.Clone(enc)
		b[5] = d
		if _, ok := RecordHeader(b); ok != want {
			t.Errorf("header of SMARK%c: %v, want %v", d, ok, want)
		}
	}
}

// signedV1 makes r (without a share set) as an SMARK1 record: the SMARK2
// body without the share set's presence byte.
func signedV1(t *testing.T, keys platform.Keys, r Record) []byte {
	t.Helper()
	if r.Shares != nil {
		t.Fatal("an SMARK1 record has no share set")
	}
	seed, blob, err := keys.NewKey(context.Background(), KeyAAD(r.Setup, r.Signer))
	if err != nil {
		t.Fatal(err)
	}
	r.KeyBlob = blob
	b := r.encodeBody()
	body := append([]byte(recordMagicV1), b[len(recordMagic):len(b)-1]...)
	return append(body, ed25519.Sign(ed25519.NewKeyFromSeed(seed), signedMessage(body))...)
}

// A nil share set vouches for the empty set only (a log written before
// share sets, or one with no share yet); a set vouches for its current
// and its pending root.
func TestShareSetVouches(t *testing.T) {
	empty := ShareSetRoot(nil)
	one := ShareSetRoot(map[backend.Pubkey][32]byte{{1}: {2}})
	two := ShareSetRoot(map[backend.Pubkey][32]byte{{1}: {2}, {3}: {4}})
	var none *ShareSet
	if !none.Vouches(empty) || none.Vouches(one) {
		t.Fatal("nil share set")
	}
	s := &ShareSet{Current: one, Pending: &two}
	if !s.Vouches(one) || !s.Vouches(two) || s.Vouches(empty) {
		t.Fatal("current and pending")
	}
	if one == ShareSetRoot(map[backend.Pubkey][32]byte{{1}: {3}}) {
		t.Fatal("the root does not bind the record hash")
	}
}

// The root takes the keys in byte order, whatever order the map holds
// them in.
func TestShareSetRootKeyOrder(t *testing.T) {
	recs := map[backend.Pubkey][32]byte{{3}: {0x33}, {1}: {0x11}, {2}: {0x22}, {9}: {0x99}, {5}: {0x55}}
	h := sha256.New()
	h.Write([]byte("signer-share-set-v1"))
	for _, b := range []byte{1, 2, 3, 5, 9} {
		pk, r := backend.Pubkey{b}, recs[backend.Pubkey{b}]
		h.Write(pk[:])
		h.Write(r[:])
	}
	want := [32]byte(h.Sum(nil))
	for range 20 {
		if ShareSetRoot(recs) != want {
			t.Fatal("the root is not over the keys in byte order")
		}
	}
}
