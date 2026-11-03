package verify

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/lidofinance/tee-signer/attestation-verify/runnerclient/internal/optset"
	"github.com/lidofinance/tee-signer/signer-protocol"
)

// DocumentVerifier checks a runner's attestation document against user
// data the caller computed itself, with the checks of the verifier the
// settings name. A handover source checks its target's IDENTITY with it
// (tee-signer/server handover_source.go computes the user data), and a
// target checks the source's origin proof the same way (package handover).
//
// The setup pins (setup_sha256, the minimum versions) do not apply: the
// caller decodes the setup state of that other form and checks it.
type DocumentVerifier func(ctx context.Context, nonce, userData []byte, a *backend.Attestation) error

// documentFactories holds the document verifiers built into this program,
// next to verifierFactories; each verifier's file adds its own.
var documentFactories = map[string]func(a *Attestation, o *optset.Options) (DocumentVerifier, error){}

// NewDocumentVerifier returns the document verifier the settings name. It
// validates the settings as NewVerifier does.
func (a *Attestation) NewDocumentVerifier(opts ...Option) (DocumentVerifier, error) {
	o := optset.New(opts)
	if _, err := a.verifier(o); err != nil {
		return nil, err
	}
	f, ok := documentFactories[a.Verifier]
	if !ok {
		return nil, fmt.Errorf("attestation.verifier: %q has no document verifier in this program (build tag %s)", a.Verifier, peerTags[a.Verifier])
	}
	return f(a, o)
}

// checkUserData makes the checks a document verifier makes before any
// key: a document of this platform and format, binding the user data the
// caller expects.
func checkUserData(userData []byte, a *backend.Attestation, platform, format, what string) error {
	if a == nil {
		return errors.New("runnerclient: no attestation")
	}
	if a.Platform != platform || a.Format != format {
		return fmt.Errorf("runnerclient: platform %q format %q is not %s", a.Platform, a.Format, what)
	}
	if len(userData) == 0 || !bytes.Equal(a.UserData, userData) {
		return errors.New("runnerclient: attestation user data is not the one expected")
	}
	return nil
}
