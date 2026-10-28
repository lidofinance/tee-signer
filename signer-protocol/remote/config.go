package remote

import (
	"context"
	"crypto/rand"
	"errors"

	"github.com/lidofinance/tee-signer/signer-protocol"
)

// The runner's attested setup state. Sending config updates is in package
// remote/admin.

// SetupState returns the runner's setup state from a fresh IDENTITY: it asks
// with a new nonce, checks that the attestation user data covers the
// identity, and has verify check the attestation document (with the setup
// pins, when attest/runnerclient built verify). The state is the one the
// runner attests now, not the one of the connection's first IDENTITY.
func (c *Client) SetupState(ctx context.Context, verify VerifyFunc) (*backend.SetupState, error) {
	if verify == nil {
		return nil, errors.New("remote: an attested setup state needs an attestation verifier")
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
	s := id.State
	return &s, nil
}
