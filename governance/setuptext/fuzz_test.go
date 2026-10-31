package setuptext

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/lidofinance/tee-signer/devkit/fuzzcheck"
	"github.com/lidofinance/tee-signer/governance/setupwire"
)

// Seeds come from the golden vectors. Every target checks that a value
// survives the human form and that nothing panics.

func addSeeds(f *testing.F, dir, pattern string) {
	paths, _ := filepath.Glob(filepath.Join(dir, pattern))
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}
}

func FuzzFormatSetup(f *testing.F) {
	addSeeds(f, wireTestdata, "setup-*.bin")
	f.Fuzz(func(t *testing.T, b []byte) {
		fuzzcheck.Watch(t)
		s, err := setupwire.DecodeSetup(b)
		if err != nil {
			return
		}
		text, err := FormatSetup(s)
		if err != nil {
			t.Fatal(err)
		}
		p, err := ParseSetup("fuzz", text)
		if err != nil || !reflect.DeepEqual(p, s) {
			t.Fatalf("human form does not read back: %v\n%s", err, text)
		}
	})
}

func FuzzFormatUpdateBody(f *testing.F) {
	paths, _ := filepath.Glob(filepath.Join(wireTestdata, "update-*.bin"))
	for _, p := range paths {
		b, _ := os.ReadFile(p)
		if u, err := setupwire.DecodeUpdate(b); err == nil {
			f.Add(must(u.Body.Encode()))
		}
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		fuzzcheck.Watch(t)
		u, err := setupwire.DecodeUpdateBody(b)
		if err != nil {
			return
		}
		p, err := ParseUpdateBody("fuzz", must(FormatUpdateBody(u)))
		if err != nil || !reflect.DeepEqual(p, u) {
			t.Fatalf("human form does not read back: %v", err)
		}
	})
}

func FuzzFormatUpdate(f *testing.F) {
	addSeeds(f, wireTestdata, "update-*.bin")
	f.Fuzz(func(t *testing.T, b []byte) {
		fuzzcheck.Watch(t)
		u, err := setupwire.DecodeUpdate(b)
		if err != nil {
			return
		}
		p, err := ParseUpdate("fuzz", must(FormatUpdate(u)))
		if err != nil || !reflect.DeepEqual(p, u) {
			t.Fatalf("human form does not read back: %v", err)
		}
	})
}

func FuzzParseSetup(f *testing.F) {
	addSeeds(f, "testdata", "setup-*.conf")
	f.Fuzz(func(t *testing.T, text []byte) {
		fuzzcheck.Watch(t)
		s, err := ParseSetup("fuzz", text)
		if err != nil || !s.Salted() {
			return
		}
		b, err := s.Encode()
		if err != nil {
			t.Fatalf("parsed setup does not encode: %v", err)
		}
		d, err := setupwire.DecodeSetup(b)
		if err != nil || !reflect.DeepEqual(d, s) {
			t.Fatalf("parsed setup does not decode back: %v", err)
		}
		again, err := ParseSetup("fuzz", must(FormatSetup(s)))
		if err != nil || !reflect.DeepEqual(again, s) {
			t.Fatalf("canonical form does not read back: %v", err)
		}
	})
}

func FuzzParseUpdate(f *testing.F) {
	addSeeds(f, "testdata", "update-*.conf")
	f.Fuzz(func(t *testing.T, text []byte) {
		fuzzcheck.Watch(t)
		u, err := ParseUpdate("fuzz", text)
		if err != nil {
			return
		}
		b, err := u.Encode()
		if err != nil {
			t.Fatalf("parsed update does not encode: %v", err)
		}
		d, err := setupwire.DecodeUpdate(b)
		if err != nil || !reflect.DeepEqual(d, u) {
			t.Fatalf("parsed update does not decode back: %v", err)
		}
	})
}
