package remote

import (
	"bytes"
	"context"
	"errors"

	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/wire"
)

// IdentityRaw is Identity with the answer as the runner sent it: a
// handover source decodes the same bytes with its own code.
func (c *Client) IdentityRaw(ctx context.Context, nonce []byte) ([]byte, *backend.Identity, error) {
	p, err := wire.EncodeAttest(nonce)
	if err != nil {
		return nil, nil, err
	}
	b, err := c.roundTrip(ctx, wire.TypeIdentity, p)
	if err != nil {
		return nil, nil, err
	}
	id, err := wire.DecodeIdentity(b)
	if err != nil {
		return nil, nil, err
	}
	if !bytes.Equal(id.Attestation.UserData, backend.IdentityUserData(nonce, id)) {
		return nil, nil, errors.New("remote: identity: attestation user data does not match the identity fields and nonce")
	}
	return b, id, nil
}
