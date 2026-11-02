package setupwire

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

// publishedGolden is sha256 of the Published encoding of each sample
// setup, so a change to the encoding fails here.
var publishedGolden = map[string]string{
	"setup-dev-single.bin":    "152fc8c1c61d51d0ace457372dccf93962d952a399d2b965892480664f13a9d5",
	"setup-dev-threshold.bin": "3208907e3458eefe82e4e59daba0537e8c36b468d38d84b107e8afbbce25787f",
	"setup-nitro.bin":         "03ee482563430f62a9b60c0c23690f4a386efda2fb2ee2e91db3c645b43c9da1",
}

func TestPublished(t *testing.T) {
	for name, want := range publishedGolden {
		raw, err := os.ReadFile(filepath.Join("testdata", name))
		if err != nil {
			t.Fatal(err)
		}
		s, err := DecodeSetup(raw)
		if err != nil {
			t.Fatal(err)
		}
		p, err := PublishedOf(s)
		if err != nil {
			t.Fatal(err)
		}
		enc, err := p.Encode()
		if err != nil {
			t.Fatal(err)
		}
		if got := sha256.Sum256(enc); hex.EncodeToString(got[:]) != want {
			t.Errorf("%s: published encoding sha256 %x, want %s", name, got, want)
		}
		back, err := DecodePublished(enc)
		if err != nil {
			t.Fatal(err)
		}
		h, err := back.SetupHash()
		if err != nil {
			t.Fatal(err)
		}
		if sh, _ := s.Hash(); h != sh {
			t.Fatalf("%s: the published part hashes to %x, the setup to %x", name, h[:8], sh[:8])
		}
		again, _ := back.Encode()
		if !bytes.Equal(again, enc) {
			t.Fatalf("%s: does not encode back", name)
		}
		for what, b := range map[string][]byte{
			"version 2": append([]byte{2}, enc[1:]...),
			"trailing":  append(bytes.Clone(enc), 0),
			"short":     enc[:len(enc)-1],
			"count":     append(bytes.Clone(enc[:33]), enc[33]+1),
		} {
			if _, err := DecodePublished(b); err == nil {
				t.Errorf("%s: %s decoded", name, what)
			}
		}
	}
}
