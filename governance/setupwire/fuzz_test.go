package setupwire

import (
	"bytes"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// Seeds come from the golden vectors in testdata. Every target checks that
// what decodes also encodes back to the same bytes and survives the human
// form, and that nothing panics.

func addSeeds(f *testing.F, pattern string) {
	paths, _ := filepath.Glob(filepath.Join("testdata", pattern))
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}
}

func FuzzDecodeSetup(f *testing.F) {
	addSeeds(f, "setup-*.bin")
	f.Fuzz(func(t *testing.T, b []byte) {
		s, err := DecodeSetup(b)
		if err != nil {
			return
		}
		if again, err := s.Encode(); err != nil || !bytes.Equal(again, b) {
			t.Fatalf("decoded setup does not encode back: %v", err)
		}
		text, err := s.Format()
		if err != nil {
			t.Fatal(err)
		}
		p, err := ParseSetup("fuzz", text)
		if err != nil || !reflect.DeepEqual(p, s) {
			t.Fatalf("human form does not read back: %v\n%s", err, text)
		}
	})
}

func FuzzDecodeUpdateBody(f *testing.F) {
	paths, _ := filepath.Glob(filepath.Join("testdata", "update-*.bin"))
	for _, p := range paths {
		b, _ := os.ReadFile(p)
		if u, err := DecodeUpdate(b); err == nil {
			f.Add(must(u.Body.Encode()))
		}
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		u, err := DecodeUpdateBody(b)
		if err != nil {
			return
		}
		if again, err := u.Encode(); err != nil || !bytes.Equal(again, b) {
			t.Fatalf("decoded body does not encode back: %v", err)
		}
		p, err := ParseUpdateBody("fuzz", must(u.Format()))
		if err != nil || !reflect.DeepEqual(p, u) {
			t.Fatalf("human form does not read back: %v", err)
		}
	})
}

func FuzzDecodeUpdate(f *testing.F) {
	addSeeds(f, "update-*.bin")
	setup, err := os.ReadFile(filepath.Join("testdata", "setup-nitro.bin"))
	if err != nil {
		f.Fatal(err)
	}
	s, err := DecodeSetup(setup)
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		u, err := DecodeUpdate(b)
		if err != nil {
			return
		}
		if again, err := u.Encode(); err != nil || !bytes.Equal(again, b) {
			t.Fatalf("decoded update does not encode back: %v", err)
		}
		_ = u.Verify(&s.Locked.Approvers)
		p, err := ParseUpdate("fuzz", must(u.Format()))
		if err != nil || !reflect.DeepEqual(p, u) {
			t.Fatalf("human form does not read back: %v", err)
		}
	})
}

func FuzzParseSetup(f *testing.F) {
	addSeeds(f, "setup-*.conf")
	f.Fuzz(func(t *testing.T, text []byte) {
		s, err := ParseSetup("fuzz", text)
		if err != nil || s.unsalted() {
			return
		}
		b, err := s.Encode()
		if err != nil {
			t.Fatalf("parsed setup does not encode: %v", err)
		}
		d, err := DecodeSetup(b)
		if err != nil || !reflect.DeepEqual(d, s) {
			t.Fatalf("parsed setup does not decode back: %v", err)
		}
		again, err := ParseSetup("fuzz", must(s.Format()))
		if err != nil || !reflect.DeepEqual(again, s) {
			t.Fatalf("canonical form does not read back: %v", err)
		}
	})
}

func FuzzParseUpdate(f *testing.F) {
	addSeeds(f, "update-*.conf")
	f.Fuzz(func(t *testing.T, text []byte) {
		u, err := ParseUpdate("fuzz", text)
		if err != nil {
			return
		}
		b, err := u.Encode()
		if err != nil {
			t.Fatalf("parsed update does not encode: %v", err)
		}
		d, err := DecodeUpdate(b)
		if err != nil || !reflect.DeepEqual(d, u) {
			t.Fatalf("parsed update does not decode back: %v", err)
		}
	})
}

// A key that passes CheckKey decodes to a point whose canonical encoding
// is the key itself.
func FuzzCheckKey(f *testing.F) {
	for _, s := range append(append([]string{}, smallOrder...), nonCanonical...) {
		b := make([]byte, 32)
		for i := range 32 {
			b[i] = hexByte(s[2*i])<<4 | hexByte(s[2*i+1])
		}
		f.Add(b)
	}
	f.Add(must32(approverPub(1)))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) != 32 {
			return
		}
		k := [32]byte(b)
		if CheckKey(k) != nil {
			return
		}
		x, y, err := decodePoint(k)
		if err != nil {
			t.Fatal(err)
		}
		if encodePoint(x, y) != k {
			t.Fatalf("%x is not canonical", k)
		}
	})
}

func hexByte(c byte) byte {
	if c >= 'a' {
		return c - 'a' + 10
	}
	return c - '0'
}

func encodePoint(x, y *big.Int) [32]byte {
	var out [32]byte
	be := y.FillBytes(make([]byte, 32))
	for i := range 32 {
		out[i] = be[31-i]
	}
	out[31] |= byte(x.Bit(0)) << 7
	return out
}
