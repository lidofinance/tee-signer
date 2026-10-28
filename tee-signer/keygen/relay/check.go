package relay

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/dkgmsg"
	"github.com/lidofinance/tee-signer/signer-protocol/remote"
)

// PolicyCheck returns a CheckHello that applies the policy's verifiers to
// each hello, as every runner does: the hello names this policy, its
// attestation binds its fields, and the participant's verifier accepts it.
// The runners do not depend on it; it lets the coordinator stop before any
// runner deals when a participant is not what the policy says.
func PolicyCheck(policyHash [32]byte, verifiers []remote.VerifyFunc) func(ctx context.Context, i int, hello []byte) error {
	return func(ctx context.Context, i int, b []byte) error {
		if i >= len(verifiers) {
			return errors.New("more runners than policy participants")
		}
		h, err := dkgmsg.DecodeHello(b)
		if err != nil {
			return err
		}
		if h.PolicyHash != policyHash {
			return fmt.Errorf("hello names policy %x, the coordinator loaded %x", h.PolicyHash[:6], policyHash[:6])
		}
		nonce := h.AttestNonce()
		if !bytes.Equal(h.Identity.Attestation.UserData, backend.DKGHelloUserData(nonce, h.Identity)) {
			return errors.New("attestation does not bind the hello")
		}
		if err := verifiers[i](ctx, nonce, h.Identity); err != nil {
			return fmt.Errorf("attestation: %w", err)
		}
		return nil
	}
}
