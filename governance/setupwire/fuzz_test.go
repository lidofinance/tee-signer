package setupwire

import (
	"bytes"
	"math/big"
	"os"
	"path/filepath"
	"testing"
)

// Seeds come from the golden vectors in testdata. Every target checks that
// what decodes also encodes back to the same bytes, and that nothing
// panics. The human form targets are in governance/setuptext.

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
