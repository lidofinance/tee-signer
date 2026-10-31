package markstore

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"
	"time"
)

// The fail-closed reader rule (the in-place swap dry run): a runner whose
// newest record of its signer is one it cannot parse refuses to start. It
// does not skip the record and fall back to the mark below it, which a
// newer image may have raised past. Objects that are no record of this
// signer under this key release are still skipped.
func TestUnreadableNewestRecordRefused(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_800_000_000, 0)
	opt := Options{Setup: testSetup("signer-1"), Clock: clockAt(&now), Log: quiet}
	setup := opt.Setup.Hash

	// written is a log of records 1 to 4 and the encoding of the newest.
	written := func() (*memLog, *MarkLog, []byte) {
		l := &memLog{objs: map[string][][]byte{}}
		m, _ := New(l, "signer-1", testKey(1), opt)
		if _, _, err := m.Claim(ctx, false); err != nil {
			t.Fatal(err)
		}
		for e := uint64(5); e < 8; e++ {
			if err := m.Append(ctx, mark(e)); err != nil {
				t.Fatal(err)
			}
		}
		objs := l.objs[Name(setup, "signer-1", 4)]
		if len(objs) != 1 {
			t.Fatalf("%d objects at version 4", len(objs))
		}
		return l, m, objs[0]
	}
	// next is record 5 as a newer image would write it under the same key
	// release, its encoding changed by change and signed again.
	next := func(m *MarkLog, prev []byte, change func(body []byte) []byte) []byte {
		r, err := Parse(prev)
		if err != nil {
			t.Fatal(err)
		}
		r.Version, r.PrevVersion, r.PrevHash, r.Mark, r.KeyBlob = 5, 4, Hash(prev), mark(20), m.blob
		enc := r.Sign(m.key)
		body := change(bytes.Clone(enc[:len(enc)-64]))
		return append(body, ed25519.Sign(m.key, signedMessage(body))...)
	}

	cases := []struct {
		name   string
		change func(body []byte) []byte
	}{
		{"an unknown trailing field", func(b []byte) []byte { return append(b, 2, 0xab, 0xcd) }},
		{"a higher record version", func(b []byte) []byte { b[5] = '5'; return b }},
	}
	for _, c := range cases {
		l, m, prev := written()
		enc := next(m, prev, c.change)
		if _, err := Parse(enc); err == nil {
			t.Fatalf("%s: this reader parses the newer record", c.name)
		}
		if h, ok := RecordHeader(enc); !ok || h.Version != 5 || h.Signer != "signer-1" || h.Setup != setup {
			t.Fatalf("%s: header %+v %v", c.name, h, ok)
		}
		l.objs[Name(setup, "signer-1", 5)] = [][]byte{enc}
		m2, _ := New(l, "signer-1", testKey(1), opt)
		_, _, err := m2.Claim(ctx, true)
		if !errors.Is(err, ErrUnreadable) || !strings.Contains(err.Error(), "version 5") {
			t.Fatalf("%s: claim %v, want ErrUnreadable", c.name, err)
		}
		// Nothing was written: the log still ends at version 5.
		if len(l.objs[Name(setup, "signer-1", 6)]) != 0 {
			t.Fatalf("%s: the refused claim wrote a record", c.name)
		}
	}

	// Skipped as before: junk, a record start whose key blob another key
	// release made, and a record of another signer under this name.
	l, _, prev := written()
	other, _ := New(&memLog{objs: map[string][][]byte{}}, "signer-1", testKey(9), opt)
	if _, _, err := other.Claim(ctx, false); err != nil {
		t.Fatal(err)
	}
	foreign := next(other, prev, func(b []byte) []byte { return append(b, 1) })
	r, _ := Parse(prev)
	r.Signer = "signer-2"
	_, m1, _ := written()
	wrongSigner := append(r.Sign(m1.key), 9)
	l.objs[Name(setup, "signer-1", 5)] = [][]byte{[]byte("junk"), foreign, wrongSigner}
	m3, _ := New(l, "signer-1", testKey(1), opt)
	if got, _, err := m3.Claim(ctx, true); err != nil || got != mark(7) {
		t.Fatalf("claim past objects that are not records of this signer: %+v %v", got, err)
	}
}

// A record start with a key blob copied from a real record is no proof
// that a runner wrote the object: the blob is a public field. An object
// that names this signer and carries a copied blob, but no signature under
// the blob's key over the bytes before its last 64, is skipped like any
// other junk, at a future version and next to the newest record. Without
// that check one such object under a compliance lock stops every start of
// the signer for the retention period.
func TestForgedHeaderSkipped(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_800_000_000, 0)
	setup := testSetup("signer-1").Hash

	// forge builds an object that names version v of signer-1 and carries
	// the key blob of the record enc, then 200 bytes of 0xee, and ends in
	// a signature that sign makes (nil: no signature, just the padding).
	forge := func(enc []byte, v uint64, sign func(body []byte) []byte) []byte {
		r, err := Parse(enc)
		if err != nil {
			t.Fatal(err)
		}
		r.Version = v
		body := r.encodeBody()
		end := bytes.Index(body, r.KeyBlob) + len(r.KeyBlob)
		body = append(body[:end:end], bytes.Repeat([]byte{0xee}, 200)...)
		if sign == nil {
			return body
		}
		return append(body, sign(body)...)
	}
	_, attacker, _ := ed25519.GenerateKey(nil)
	signers := []struct {
		name string
		sign func(body []byte) []byte
	}{
		{"no signature", nil},
		{"a signature under a key of its own", func(b []byte) []byte { return ed25519.Sign(attacker, signedMessage(b)) }},
		{"a copied signature", nil}, // set below: the tail of the real record
	}

	for _, allowCreate := range []bool{false, true} {
		opt := Options{Setup: testSetup("signer-1"), Clock: clockAt(&now), Log: quiet, AllowCreate: allowCreate}
		for i, sg := range signers {
			for _, at := range []uint64{5, 4} {
				l := &memLog{objs: map[string][][]byte{}}
				m, _ := New(l, "signer-1", testKey(1), opt)
				if _, _, err := m.Claim(ctx, false); err != nil {
					t.Fatal(err)
				}
				for e := uint64(5); e < 8; e++ {
					if err := m.Append(ctx, mark(e)); err != nil {
						t.Fatal(err)
					}
				}
				prev := l.objs[Name(setup, "signer-1", 4)][0]
				sign := sg.sign
				if i == 2 {
					sign = func([]byte) []byte { return bytes.Clone(prev[len(prev)-64:]) }
				}
				forged := forge(prev, at, sign)
				if _, err := Parse(forged); err == nil {
					t.Fatalf("%s: the forgery parses", sg.name)
				}
				if h, ok := RecordHeader(forged); sign != nil && (!ok || h.Version != at) {
					t.Fatalf("%s: the forgery has no record header: %+v %v", sg.name, h, ok)
				}
				n := Name(setup, "signer-1", at)
				l.objs[n] = append(l.objs[n], forged)

				m2, _ := New(l, "signer-1", testKey(1), opt)
				got, _, err := m2.Claim(ctx, true)
				if err != nil || got != mark(7) {
					t.Fatalf("%s at version %d, allow create %v: claim %+v %v, want mark 7", sg.name, at, allowCreate, got, err)
				}
				// The writer skips the name the forgery holds.
				if err := m2.Append(ctx, mark(9)); err != nil {
					t.Fatalf("%s at version %d: append %v", sg.name, at, err)
				}
				m3, _ := New(l, "signer-1", testKey(1), opt)
				if got, _, err := m3.Claim(ctx, true); err != nil || got != mark(9) {
					t.Fatalf("%s at version %d: claim after append %+v %v", sg.name, at, got, err)
				}
			}
		}
	}
}
