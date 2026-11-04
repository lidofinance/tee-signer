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
	id, err := c.verifiedIdentity(ctx, verify)
	if err != nil {
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

// verifiedIdentity is the runner's IDENTITY for a fresh nonce, checked by
// verify: the import key to seal shares to.
func (c *Client) verifiedIdentity(ctx context.Context, verify remote.VerifyFunc) (*backend.Identity, error) {
	if verify == nil {
		return nil, errors.New("remote: sealed import needs an attestation verifier")
	}
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	id, err := c.Identity(ctx, nonce)
	if err != nil {
		return nil, err
	}
	if err := verify(ctx, nonce, id); err != nil {
		return nil, err
	}
	return id, nil
}

// BatchImport reports whether the runner takes IMPORT_SHARES_SEALED. It
// sends an empty one, which writes nothing; an older runner refuses the
// type (FORBIDDEN), and one with the sealed import off answers
// UNSUPPORTED.
func (c *Client) BatchImport(ctx context.Context) (bool, error) {
	p, _ := wireadmin.EncodeImportBatch(nil, nil)
	_, err := c.RoundTrip(ctx, wireadmin.TypeImportBatch, p)
	var re *backend.RefusedError
	switch {
	case err == nil:
		return true, nil
	case errors.As(err, &re):
		return false, nil
	}
	return false, err
}

// SealBatches seals each share of reqs to the runner's attested import key
// (one IDENTITY, checked by verify) and splits them into batches that fit
// IMPORT_SHARES_SEALED under order: wireadmin.MaxBatch shares and one
// frame each. reqs[i] carries share i's header and split, secrets[i] its
// secret, which is not modified; Order and Sealed of reqs are ignored.
func (c *Client) SealBatches(ctx context.Context, order []byte, reqs []backend.SealedImportRequest, secrets [][32]byte,
	verify remote.VerifyFunc) ([][]backend.SealedImportRequest, error) {
	id, err := c.verifiedIdentity(ctx, verify)
	if err != nil {
		return nil, err
	}
	var out [][]backend.SealedImportRequest
	size := wire.MaxFrame // past the limit: the first share starts a batch
	for i := range reqs {
		r := reqs[i]
		r.Order = nil
		if r.Sealed, err = sealedimport.Seal(id, &r, &secrets[i]); err != nil {
			return nil, err
		}
		// The frame body holds 6 header bytes and the payload.
		if n := wireadmin.BatchShareLen(&r); size+n > wire.MaxFrame-6 || len(out[len(out)-1]) == wireadmin.MaxBatch {
			out, size = append(out, nil), wireadmin.BatchLen(order)
		}
		out[len(out)-1] = append(out[len(out)-1], r)
		size += wireadmin.BatchShareLen(&r)
	}
	return out, nil
}

// ImportBatch sends one batch of SealBatches (IMPORT_SHARES_SEALED) and
// returns the keys the runner loaded. The runner takes all of it or none.
func (c *Client) ImportBatch(ctx context.Context, order []byte, batch []backend.SealedImportRequest) ([]backend.ValidatorKey, error) {
	p, err := wireadmin.EncodeImportBatch(order, batch)
	if err != nil {
		return nil, err
	}
	b, err := c.RoundTrip(ctx, wireadmin.TypeImportBatch, p)
	if err != nil {
		return nil, err
	}
	return wire.DecodeKeys(b)
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
