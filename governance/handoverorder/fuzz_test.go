package handoverorder

import (
	"bytes"
	"testing"

	"github.com/lidofinance/tee-signer/devkit/fuzzcheck"
)

// The handover order comes in HANDOVER_ORDER, HANDOVER and
// IMPORT_HANDOVER; the state is the source's answer the tools read.
// Oracles: no panic, bounded allocation, and what decodes encodes back.

func FuzzDecode(f *testing.F) {
	o := signed(f, sampleBody(sampleSetup(f)), 0, 1)
	raw, err := o.Encode()
	if err != nil {
		f.Fatal(err)
	}
	body, err := o.Body.Encode()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(raw)
	f.Add(body)
	f.Fuzz(func(t *testing.T, b []byte) {
		var o *Order
		var err error
		fuzzcheck.Bounded(t, len(b), func() { o, err = Decode(b) })
		if err == nil {
			if again, err := o.Encode(); err != nil || !bytes.Equal(again, b) {
				t.Fatalf("order does not encode back (%v):\n%x\n%x", err, again, b)
			}
		}
		var body *Body
		fuzzcheck.Bounded(t, len(b), func() { body, err = DecodeBody(b) })
		if err == nil {
			if again, err := body.Encode(); err != nil || !bytes.Equal(again, b) {
				t.Fatalf("body does not encode back (%v):\n%x\n%x", err, again, b)
			}
		}
	})
}

func FuzzDecodeState(f *testing.F) {
	f.Add((&State{Outcome: Known, Status: Done, Hash: [32]byte{7}, Arrived: 10, ActAt: 430, NotAfter: 43_210, Why: "why"}).Encode())
	f.Fuzz(func(t *testing.T, b []byte) {
		var s *State
		var err error
		fuzzcheck.Bounded(t, len(b), func() { s, err = DecodeState(b) })
		if err == nil && !bytes.Equal(s.Encode(), b) {
			t.Fatalf("state does not encode back:\n%x\n%x", s.Encode(), b)
		}
	})
}
