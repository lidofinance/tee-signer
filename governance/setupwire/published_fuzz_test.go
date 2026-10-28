package setupwire

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/lidofinance/tee-signer/devkit/fuzzcheck"
)

// A target's published setup comes in HANDOVER requests. Oracles: no
// panic, bounded allocation, and what decodes encodes back.
func FuzzDecodePublished(f *testing.F) {
	for name := range publishedGolden {
		raw, err := os.ReadFile(filepath.Join("testdata", name))
		if err != nil {
			f.Fatal(err)
		}
		s, err := DecodeSetup(raw)
		if err != nil {
			f.Fatal(err)
		}
		p, err := PublishedOf(s)
		if err != nil {
			f.Fatal(err)
		}
		enc, err := p.Encode()
		if err != nil {
			f.Fatal(err)
		}
		f.Add(enc)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		var p *Published
		var err error
		fuzzcheck.Bounded(t, len(b), func() { p, err = DecodePublished(b) })
		if err != nil {
			return
		}
		if again, err := p.Encode(); err != nil || !bytes.Equal(again, b) {
			t.Fatalf("published setup does not encode back (%v):\n%x\n%x", err, again, b)
		}
	})
}
