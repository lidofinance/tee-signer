package markstore

import (
	"bytes"
	"context"
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
		return append(body, r.Sign(m.key)[len(enc)-64:]...)
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
