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

// The fail-closed reader rule on the write path and in the chain walk
// (review M1). Two instances run under one key release and one signer, the
// image-swap window where both measurements are admitted. The newer image
// writes a record this one cannot parse (a higher magic digit, signed under
// a key this key release opens). Skipping it as junk would let this
// instance write past it and keep signing next to the other: it must latch
// ErrLost and write nothing, and a start over the forked state must
// refuse. Objects that are no record of this signer under this key release
// still take the skip path, and a readable record of another owner still
// gives ErrLost.
func TestUnreadableRecordOnWriteLatchesLost(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_800_000_000, 0)
	opt := Options{Setup: testSetup("signer-1"), Clock: clockAt(&now), Log: quiet}
	setup := opt.Setup.Hash

	// written is a live instance with records 1 to 4 and the encoding of
	// record 4.
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
		return l, m, l.objs[Name(setup, "signer-1", 4)][0]
	}
	// other is a second instance under the same key release, with a log of
	// its own so its claim writes nothing here.
	other, _ := New(&memLog{objs: map[string][][]byte{}}, "signer-1", testKey(1), opt)
	if _, _, err := other.Claim(ctx, false); err != nil {
		t.Fatal(err)
	}
	// recordBy is version v as the instance w writes it on top of prev
	// (record 4), with mark 20; magic sets the format digit.
	recordBy := func(w *MarkLog, prev []byte, v uint64, magic byte) []byte {
		r, err := Parse(prev)
		if err != nil {
			t.Fatal(err)
		}
		r.Version, r.PrevVersion, r.PrevHash, r.Mark = v, 4, Hash(prev), mark(20)
		r.Owner, r.KeyBlob = w.owner, w.blob
		enc := r.Sign(w.key)
		if magic == enc[5] {
			return enc
		}
		body := bytes.Clone(enc[:len(enc)-64])
		body[5] = magic
		return append(body, ed25519.Sign(w.key, signedMessage(body))...)
	}

	// (a) The newer image's record at version 5: this instance's next
	// write must latch ErrLost and write nothing.
	l, a, prev := written()
	newer := recordBy(other, prev, 5, '3')
	if _, err := Parse(newer); err == nil {
		t.Fatal("this reader parses the newer record")
	}
	if h, ok := RecordHeader(newer); !ok || h.Version != 5 || !h.Verify(other.key.Public().(ed25519.PublicKey)) {
		t.Fatalf("header %+v %v", h, ok)
	}
	l.objs[Name(setup, "signer-1", 5)] = [][]byte{newer}
	err := a.Append(ctx, mark(9))
	if !errors.Is(err, ErrLost) || !errors.Is(a.Lost(), ErrLost) {
		t.Errorf("append over a newer image's record at version 5: err %v, Lost %v; want ErrLost", err, a.Lost())
	}
	if n := len(l.objs[Name(setup, "signer-1", 6)]); n != 0 {
		t.Errorf("append over a newer image's record wrote version 6 (%d objects): this instance signs on next to the other", n)
	}

	// (b) The forked state (a) leaves behind on the old code: this
	// instance's readable record 6 above the newer image's record 5. A
	// start must refuse with ErrUnreadable, not take record 6.
	l, a, prev = written()
	l.objs[Name(setup, "signer-1", 5)] = [][]byte{recordBy(other, prev, 5, '3')}
	l.objs[Name(setup, "signer-1", 6)] = [][]byte{recordBy(a, prev, 6, '2')}
	m2, _ := New(l, "signer-1", testKey(1), opt)
	if _, _, err := m2.Claim(ctx, true); !errors.Is(err, ErrUnreadable) || !strings.Contains(err.Error(), "version 5") {
		t.Errorf("claim over a newer image's record below the newest: %v, want ErrUnreadable at version 5", err)
	}

	// (c) Control: junk and a copied key blob without a signature under it
	// still cost a skip, nothing more.
	l, a, prev = written()
	r, _ := Parse(prev)
	r.Version = 5
	blobOnly := r.encodeBody()
	blobOnly = append(blobOnly[:bytes.Index(blobOnly, r.KeyBlob)+len(r.KeyBlob)], bytes.Repeat([]byte{0xee}, 100)...)
	l.objs[Name(setup, "signer-1", 5)] = [][]byte{[]byte("junk"), blobOnly}
	if err := a.Append(ctx, mark(9)); err != nil {
		t.Fatalf("append past objects that are not records: %v", err)
	}
	if _, v := a.Mark(); v != 6 || len(l.objs[Name(setup, "signer-1", 6)]) != 1 {
		t.Fatalf("append past junk at 5: version %d", v)
	}

	// (d) Control: a readable record of another owner at version 5 gives
	// ErrLost, as before.
	l, a, prev = written()
	l.objs[Name(setup, "signer-1", 5)] = [][]byte{recordBy(other, prev, 5, '2')}
	if err := a.Append(ctx, mark(9)); !errors.Is(err, ErrLost) {
		t.Fatalf("append over another owner's readable record: %v, want ErrLost", err)
	}
}
