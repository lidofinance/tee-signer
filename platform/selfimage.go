package platform

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/lidofinance/tee-signer/governance/setupwire"
)

// ImageSeen holds this runner's own image measurement as the evidence of
// its key release showed it: the attestation that went to the key service
// (GCP: the launcher token sent to STS; Azure: the MAA token sent to Key
// Vault; Nitro: the NSM document sent to KMS). The platform records the
// value each time it builds such evidence, and Platform.SelfImage reads it.
// The value never comes from a flag, the setup or the host.
//
// Two different values, or evidence that does not parse, make Get fail for
// good: the runner cannot say which image it is, so it serves nothing that
// needs the image check (server.ImageGate).
type ImageSeen struct {
	mu  sync.Mutex
	im  *setupwire.Image
	err error
}

// Record keeps im, the image of one piece of key release evidence, or err
// when that evidence did not give one. A nil ImageSeen records nothing.
func (s *ImageSeen) Record(im setupwire.Image, err error) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case s.err != nil:
	case err != nil:
		s.err = fmt.Errorf("the key release evidence names no image: %w", err)
	case s.im == nil:
		c := setupwire.Image{Kind: im.Kind, Measurement: bytes.Clone(im.Measurement)}
		s.im = &c
	case s.im.Kind != im.Kind || !bytes.Equal(s.im.Measurement, im.Measurement):
		s.err = fmt.Errorf("the key release evidence named two images, %s %x and %s %x", s.im.Kind, s.im.Measurement, im.Kind, im.Measurement)
	}
}

// Get is the recorded image. It fails when no key release evidence was
// built yet, or when Record saw an error or two values.
func (s *ImageSeen) Get(context.Context) (setupwire.Image, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return setupwire.Image{}, s.err
	}
	if s.im == nil {
		return setupwire.Image{}, errors.New("no key release evidence was built, so the image is unknown")
	}
	return setupwire.Image{Kind: s.im.Kind, Measurement: bytes.Clone(s.im.Measurement)}, nil
}

// NitroImage is the allowed_image_measurements entry of a Nitro enclave:
// PCR0, PCR1 and PCR2 of its attestation document, 48 bytes each, in that
// order (setupwire.ImageNitro).
func NitroImage(pcrs map[int][]byte) (setupwire.Image, error) {
	m := make([]byte, 0, setupwire.ImageNitro.Size())
	for i := range 3 {
		p, ok := pcrs[i]
		if !ok {
			return setupwire.Image{}, fmt.Errorf("the attestation document has no PCR%d", i)
		}
		if len(p) != 48 {
			return setupwire.Image{}, fmt.Errorf("PCR%d is %d bytes, want 48", i, len(p))
		}
		m = append(m, p...)
	}
	return setupwire.Image{Kind: setupwire.ImageNitro, Measurement: m}, nil
}
