package runnerclient

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/remote"
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
var documentFactories = map[string]func(a *Attestation, o *options) (DocumentVerifier, error){}

// NewDocumentVerifier returns the document verifier the settings name. It
// validates the settings as NewVerifier does.
func (a *Attestation) NewDocumentVerifier(opts ...Option) (DocumentVerifier, error) {
	o := newOptions(opts)
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

// NewDKGHelloVerifier returns the verifier of a DKG hello's identity
// (TKGPEER-01): the document must bind backend.DKGHelloUserData(nonce, id),
// checked with the document verifier the settings name, and the identity's
// setup state must pass the setup pins. A document over
// backend.IdentityUserData, which IDENTITY answers for any nonce a client
// sends, is refused.
func (a *Attestation) NewDKGHelloVerifier(opts ...Option) (remote.VerifyFunc, error) {
	return a.contextVerifier(backend.DKGHelloUserData, "a DKG hello's", opts)
}

// NewDKGOperatorVerifier returns the verifier of a DKG_OPERATOR answer's
// identity, as NewDKGHelloVerifier does for a hello: the document must bind
// backend.DKGOperatorUserData(nonce, id). IDENTITY evidence for the same
// nonce is refused.
func (a *Attestation) NewDKGOperatorVerifier(opts ...Option) (remote.VerifyFunc, error) {
	return a.contextVerifier(backend.DKGOperatorUserData, "a DKG_OPERATOR answer's", opts)
}

// contextVerifier checks a document over userData(nonce, id) with the
// settings' document verifier, then the setup pins.
func (a *Attestation) contextVerifier(userData func([]byte, *backend.Identity) []byte, what string, opts []Option) (remote.VerifyFunc, error) {
	o := newOptions(opts)
	dv, err := a.NewDocumentVerifier(opts...)
	if err != nil {
		return nil, err
	}
	pins, err := a.setupPins()
	if err != nil {
		return nil, err
	}
	return func(ctx context.Context, nonce []byte, id *backend.Identity) error {
		if id == nil || id.Attestation == nil {
			return errors.New("runnerclient: no attestation")
		}
		ud := userData(nonce, id)
		if !bytes.Equal(id.Attestation.UserData, ud) {
			return fmt.Errorf("runnerclient: attestation user data is not %s for these identity fields and nonce", what)
		}
		if err := dv(ctx, nonce, ud, id.Attestation); err != nil {
			return err
		}
		return pins.check(&id.State, o.now())
	}, nil
}
