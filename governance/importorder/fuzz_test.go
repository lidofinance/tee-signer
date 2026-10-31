package importorder

import (
	"bytes"
	"testing"

	"github.com/lidofinance/tee-signer/devkit/fuzzcheck"
)

// The import order comes with IMPORT_SHARE_SEALED from an admin client.
// Oracles: no panic, bounded allocation, and what decodes encodes back.

func FuzzDecode(f *testing.F) {
	o, body := sample(&testing.T{})
	raw, err := o.Encode()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(raw)
	f.Add(body)
	f.Fuzz(func(t *testing.T, b []byte) {
		fuzzcheck.Watch(t)
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
