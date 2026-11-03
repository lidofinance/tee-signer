// Package admin is the client side of the admin messages: share import,
// config updates. A runner
// answers them only to a client of the admin role (docs/protocol.md,
// "Client roles"). Client wraps a remote.Client, so it has the signing and
// attestation calls too; the signing client builds remote without this package.
package admin

import (
	"context"
	"crypto/rand"
	"errors"

	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/remote"
	"github.com/lidofinance/tee-signer/signer-protocol/sealedimport"
	"github.com/lidofinance/tee-signer/signer-protocol/wire"
	wireadmin "github.com/lidofinance/tee-signer/signer-protocol/wire/admin"
)

// Client is a remote.Client with the admin calls.
type Client struct{ *remote.Client }

// New dials nothing yet; it is remote.New with the admin calls.
func New(addr string, opts ...remote.Option) (*Client, error) {
	c, err := remote.New(addr, opts...)
	if err != nil {
		return nil, err
	}
	return &Client{c}, nil
}

// Wrap gives c the admin calls.
func Wrap(c *remote.Client) *Client { return &Client{c} }

// ImportShare sends the share in plaintext (IMPORT_SHARE, debug builds of
// the runner on the dev platform only). ImportShareSealed is the encrypted
// form.
func (c *Client) ImportShare(ctx context.Context, req backend.ImportShareRequest) (backend.ValidatorKey, error) {
	p := wireadmin.EncodeImport(req)
	defer clear(p)
	b, err := c.RoundTrip(ctx, wireadmin.TypeImportShare, p)
	if err != nil {
		return backend.ValidatorKey{}, err
	}
	return wire.DecodeKey(b)
}

// ConfigUpdate sends a signed config update (CONFIG_UPDATE, the bytes
// setupwire.Update.Encode makes) and returns the outcome
// (wireadmin.ConfigAccepted or wireadmin.ConfigKnown) and the runner's setup state
// after it. A refusal is a *backend.RefusedError whose detail says why.
// Sending the same update again does no harm: the runner answers
// wireadmin.ConfigKnown.
func (c *Client) ConfigUpdate(ctx context.Context, update []byte) (uint8, *backend.SetupState, error) {
	p, err := wireadmin.EncodeConfigUpdate(update)
	if err != nil {
		return 0, nil, err
	}
	b, err := c.RoundTrip(ctx, wireadmin.TypeConfigUpdate, p)
	if err != nil {
		return 0, nil, err
	}
	return wireadmin.DecodeConfigUpdateResponse(b)
}

// ImportShareSealed loads a share without sending it in plaintext: it asks
// the runner for its identity with a fresh nonce, has verify check the
// attestation document, encrypts the share to the attested import key
// (package sealedimport) and sends IMPORT_SHARE_SEALED. sharePubkey is the
// share's public key; the runner refuses the import if the decrypted share
// does not match it. req.Secret is not modified.

func (c *Client) ImportShareSealed(ctx context.Context, req backend.ImportShareRequest, sharePubkey backend.Pubkey,
	verify remote.VerifyFunc) (backend.ValidatorKey, error) {
	return c.ImportShareSealedWith(ctx, req, sharePubkey, verify, nil)
}

// ImportShareSealedWith is ImportShareSealed with the parts of the request
// a runner with a setup needs besides the share: the import order (and the
// fields that come with it) from extra. extra's header fields and Sealed
// are ignored.
func (c *Client) ImportShareSealedWith(ctx context.Context, req backend.ImportShareRequest, sharePubkey backend.Pubkey,
	verify remote.VerifyFunc, extra *backend.SealedImportRequest) (backend.ValidatorKey, error) {
	if verify == nil {
		return backend.ValidatorKey{}, errors.New("remote: sealed import needs an attestation verifier")
	}
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return backend.ValidatorKey{}, err
	}
	id, err := c.Identity(ctx, nonce)
	if err != nil {
		return backend.ValidatorKey{}, err
	}
	if err := verify(ctx, nonce, id); err != nil {
		return backend.ValidatorKey{}, err
	}
	sreq := &backend.SealedImportRequest{}
	if extra != nil {
		*sreq = *extra
	}
	sreq.Pubkey, sreq.SharePubkey, sreq.Index, sreq.Interchange = req.Pubkey, sharePubkey, req.Index, req.Interchange
	if sreq.Sealed, err = sealedimport.Seal(id, sreq, &req.Secret); err != nil {
		return backend.ValidatorKey{}, err
	}
	return c.ImportSealed(ctx, sreq)
}

// ImportSealed sends an already sealed share (IMPORT_SHARE_SEALED).
func (c *Client) ImportSealed(ctx context.Context, req *backend.SealedImportRequest) (backend.ValidatorKey, error) {
	p, err := wireadmin.EncodeImportSealed(req)
	if err != nil {
		return backend.ValidatorKey{}, err
	}
	b, err := c.RoundTrip(ctx, wireadmin.TypeImportSealed, p)
	if err != nil {
		return backend.ValidatorKey{}, err
	}
	return wire.DecodeKey(b)
}
