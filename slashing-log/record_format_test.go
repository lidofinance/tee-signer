package markstore

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"testing"

	"github.com/lidofinance/tee-signer/governance/setupwire"
	"github.com/lidofinance/tee-signer/platform"
	"github.com/lidofinance/tee-signer/signer-protocol"
)

// A record round-trips with its source gate, share set and config
// history, and Parse refuses trailing bytes, a presence byte of 2 and any
// magic but SMARK1 to SMARK3.
func TestRecordFormatRoundTrip(t *testing.T) {
	gate := uint64(1002)
	r := Record{Setup: [32]byte{0x5e, 1}, Signer: "signer-1", Version: 3, PrevVersion: 2, PrevHash: [32]byte{2}, LogID: [32]byte{1},
		Mark: mark(20), Time: 1_800_000_000, State: testSetup("signer-1").First.Clone(), SourceGate: &gate,
		Shares: &ShareSet{Current: [32]byte{0xc1}, Pending: &[32]byte{0xc2}}}
	enc := signed(t, testKey(1), r)
	if string(enc[:6]) != "SMARK3" {
		t.Fatalf("magic %q", enc[:6])
	}
	got, err := decode(enc, testKey(1), r.Setup, r.Signer, 3)
	if err != nil {
		t.Fatal(err)
	}
	if got.SourceGate == nil || *got.SourceGate != gate || !sameShares(got.Shares, r.Shares) {
		t.Fatalf("read back: gate %v, shares %+v", got.SourceGate, got.Shares)
	}
	r.Shares.Pending = nil
	got, err = decode(signed(t, testKey(1), r), testKey(1), r.Setup, r.Signer, 3)
	if err != nil || !sameShares(got.Shares, r.Shares) {
		t.Fatalf("share set without a pending root: %+v, %v", got.Shares, err)
	}
	// Without gate and share set: the presence bytes 0.
	r.SourceGate, r.Shares = nil, nil
	got, err = decode(signed(t, testKey(1), r), testKey(1), r.Setup, r.Signer, 3)
	if err != nil || got.SourceGate != nil || got.Shares != nil {
		t.Fatalf("no gate, no share set: %+v, %v", got, err)
	}
	// An SMARK1 record (no share set field) reads, with no share set.
	got, err = decode(signedOld(t, testKey(1), r, 1), testKey(1), r.Setup, r.Signer, 3)
	if err != nil || got.Shares != nil {
		t.Fatalf("SMARK1: %+v, %v", got, err)
	}
	// An SMARK2 record (no config history) reads, with none.
	got, err = decode(signedOld(t, testKey(1), r, 2), testKey(1), r.Setup, r.Signer, 3)
	if err != nil || got.State.RemovedAt != 0 || got.State.Carried != nil || got.State.Paths != ([4]setupwire.Path{}) {
		t.Fatalf("SMARK2: %+v, %v", got, err)
	}
	// The config history round-trips.
	h := r
	h.State = r.State.Clone()
	h.State.RemovedAt, h.State.Carried = 1_800_000_100, [][32]byte{{0x11}, {0x12}}
	h.State.Locked.Version, h.State.Locked.Hash = 4, [32]byte{0x44}
	h.Copies[0] = BodyCopy{N: 1, At: 1_800_000_000}
	h.State.SetPath(setupwire.GroupLocked, false, setupwire.PathEmergencyRemoval)
	got, err = decode(signed(t, testKey(1), h), testKey(1), r.Setup, r.Signer, 3)
	if err != nil || !got.State.Equal(h.State) {
		t.Fatalf("config history: %+v, %v", got, err)
	}
	for name, c := range map[string][][32]byte{"unsorted": {{2}, {1}}, "repeated": {{1}, {1}}, "zero": {{}}} {
		h.State.Carried = c
		if _, err := decode(signed(t, testKey(1), h), testKey(1), r.Setup, r.Signer, 3); err == nil {
			t.Errorf("carried revocations %s: parsed", name)
		}
	}

	enc = signed(t, testKey(1), r)
	body := enc[:len(enc)-64]
	cases := map[string][]byte{
		"trailing byte":       append(bytes.Clone(body), 0),
		"shares presence 2":   append(bytes.Clone(body[:len(body)-7]), 2, 0, 0, 0, 0, 0, 0),
		"removal presence 2":  append(bytes.Clone(body[:len(body)-6]), 2, 0, 0, 0, 0, 0),
		"removal at 0":        append(bytes.Clone(body[:len(body)-6]), append([]byte{1}, make([]byte, 13)...)...),
		"carried count short": append(bytes.Clone(body[:len(body)-5]), 1, 0, 0, 0, 0),
		"path 4":              append(bytes.Clone(body[:len(body)-4]), 0, 0, 0, 4),
		"path of no update":   append(bytes.Clone(body[:len(body)-4]), 1, 0, 0, 0),
		// An SMARK1 body with the share set's presence byte, an SMARK2 one
		// with the history.
		"SMARK1 with a share set": append([]byte("SMARK1"), body[6:]...),
		"SMARK2 with a history":   append([]byte("SMARK2"), body[6:]...),
	}
	for _, d := range []byte{'0', '4'} {
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
	for d, want := range map[byte]bool{'0': false, '1': true, '2': true, '3': true, '4': true} {
		b := bytes.Clone(enc)
		b[5] = d
		if _, ok := RecordHeader(b); ok != want {
			t.Errorf("header of SMARK%c: %v, want %v", d, ok, want)
		}
	}
}

// signedOld makes r (without a share set or config history) as an SMARK1
// (ver 1: the SMARK3 body without the share set's presence byte and the
// history) or SMARK2 record (ver 2: without the history).
func signedOld(t *testing.T, keys platform.Keys, r Record, ver int) []byte {
	t.Helper()
	if r.Shares != nil || r.State.RemovedAt != 0 || r.State.Carried != nil {
		t.Fatal("an old record has no share set or history here")
	}
	seed, blob, err := keys.NewKey(context.Background(), KeyAAD(r.Setup, r.Signer))
	if err != nil {
		t.Fatal(err)
	}
	r.KeyBlob = blob
	b := r.encodeBody()
	body := append([]byte(recordMagicV1), b[len(recordMagic):len(b)-7]...)
	if ver == 2 {
		body = append([]byte(recordMagicV2), b[len(recordMagic):len(b)-6]...)
	}
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
