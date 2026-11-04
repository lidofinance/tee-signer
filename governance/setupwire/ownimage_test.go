package setupwire

import (
	"bytes"
	"strings"
	"testing"
)

// CheckOwnImageListed refuses a setup of a cloud platform whose
// allowed_image_measurements lists no image of that platform, and passes
// it once the list has one. The dev platform has no image kind and passes
// with any list.
func TestCheckOwnImageListed(t *testing.T) {
	images := map[ImageKind]Image{
		ImageNitro: {Kind: ImageNitro, Measurement: bytes.Repeat([]byte{0x11}, ImageNitro.Size())},
		ImageAzure: {Kind: ImageAzure, Measurement: bytes.Repeat([]byte{0xaa}, ImageAzure.Size())},
		ImageGCP:   {Kind: ImageGCP, Measurement: bytes.Repeat([]byte{0x99}, ImageGCP.Size())},
		ImageTA:    {Kind: ImageTA, Measurement: bytes.Repeat([]byte{0x77}, ImageTA.Size())},
	}
	// others is every image but those of kind k, sorted as a setup keeps them.
	others := func(k ImageKind) []Image {
		var out []Image
		for _, kind := range []ImageKind{ImageNitro, ImageAzure, ImageGCP, ImageTA} {
			if kind != k {
				out = append(out, images[kind])
			}
		}
		return out
	}
	for _, c := range []struct {
		p Platform
		k ImageKind
	}{{PlatformNitro, ImageNitro}, {PlatformAzure, ImageAzure}, {PlatformGCP, ImageGCP}} {
		t.Run(c.p.String(), func(t *testing.T) {
			s := &Setup{Platform: PlatformConfig{Platform: c.p}}
			for _, list := range [][]Image{nil, others(c.k)} {
				s.Locked.AllowedImageMeasurements = list
				err := s.CheckOwnImageListed()
				if err == nil || !strings.Contains(err.Error(), "lists no "+c.k.String()+" image") {
					t.Fatalf("%d images, none of kind %s: %v, want the refusal", len(list), c.k, err)
				}
			}
			s.Locked.AllowedImageMeasurements = []Image{images[c.k]}
			if err := s.CheckOwnImageListed(); err != nil {
				t.Fatalf("its own image alone: %v", err)
			}
			s.Locked.AllowedImageMeasurements = append(others(c.k), images[c.k])
			if err := s.CheckOwnImageListed(); err != nil {
				t.Fatalf("every kind: %v", err)
			}
		})
	}
	t.Run("dev", func(t *testing.T) {
		s := &Setup{Platform: PlatformConfig{Platform: PlatformDev}}
		for _, list := range [][]Image{nil, others(0)} {
			s.Locked.AllowedImageMeasurements = list
			if err := s.CheckOwnImageListed(); err != nil {
				t.Fatalf("dev with %d images: %v", len(list), err)
			}
		}
	})
}
