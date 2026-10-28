package platform

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/lidofinance/tee-signer/governance/setupwire"
)

func TestImageSeen(t *testing.T) {
	ctx := context.Background()
	a := setupwire.Image{Kind: setupwire.ImageGCP, Measurement: bytes.Repeat([]byte{1}, 32)}
	b := setupwire.Image{Kind: setupwire.ImageAzure, Measurement: bytes.Repeat([]byte{1}, 32)}

	var s ImageSeen
	if _, err := s.Get(ctx); err == nil || !strings.Contains(err.Error(), "no key release evidence") {
		t.Fatalf("empty: %v", err)
	}
	s.Record(a, nil)
	a.Measurement[0] = 9 // the caller's slice is not kept
	got, err := s.Get(ctx)
	if err != nil || got.Kind != setupwire.ImageGCP || got.Measurement[0] != 1 {
		t.Fatalf("%v %x, %v", got.Kind, got.Measurement, err)
	}
	got.Measurement[1] = 9 // nor is the returned one shared
	s.Record(setupwire.Image{Kind: setupwire.ImageGCP, Measurement: bytes.Repeat([]byte{1}, 32)}, nil)
	if _, err := s.Get(ctx); err != nil {
		t.Fatalf("the same image again: %v", err)
	}
	// The same bytes under another kind are another image.
	s.Record(b, nil)
	if _, err := s.Get(ctx); err == nil || !strings.Contains(err.Error(), "two images") {
		t.Fatalf("two kinds: %v", err)
	}

	var bad ImageSeen
	bad.Record(setupwire.Image{}, errors.New("no image_digest"))
	bad.Record(a, nil) // a later good one does not clear it
	if _, err := bad.Get(ctx); err == nil || !strings.Contains(err.Error(), "no image_digest") {
		t.Fatalf("after a bad record: %v", err)
	}

	var none *ImageSeen
	none.Record(a, nil) // a platform without a record keeps nothing, and does not panic
}

func TestNitroImage(t *testing.T) {
	pcr := func(b byte) []byte { return bytes.Repeat([]byte{b}, 48) }
	im, err := NitroImage(map[int][]byte{2: pcr(2), 0: pcr(0), 1: pcr(1), 4: pcr(4)})
	if err != nil || im.Kind != setupwire.ImageNitro || len(im.Measurement) != setupwire.ImageNitro.Size() ||
		im.Measurement[0] != 0 || im.Measurement[48] != 1 || im.Measurement[96] != 2 {
		t.Fatalf("%x, %v", im.Measurement, err)
	}
	if _, err := NitroImage(map[int][]byte{0: pcr(0), 2: pcr(2)}); err == nil || !strings.Contains(err.Error(), "no PCR1") {
		t.Fatal(err)
	}
	if _, err := NitroImage(map[int][]byte{0: pcr(0), 1: pcr(1), 2: make([]byte, 47)}); err == nil || !strings.Contains(err.Error(), "PCR2 is 47 bytes") {
		t.Fatal(err)
	}
}
