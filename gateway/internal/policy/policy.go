// Package policy holds the gateway's signing policy, applied before any
// request reaches the signers.
package policy

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/phase0"

	"github.com/lidofinance/tee-signer/web3signer-api/signing"
)

// RefusedError means policy forbids the request (HTTP 412).
type RefusedError struct{ Reason string }

func (e *RefusedError) Error() string { return "refused by gateway policy: " + e.Reason }

// Policy is the gateway policy. The zero value refuses every registration.
type Policy struct {
	feeRecipients map[bellatrix.ExecutionAddress]bool
}

// New builds a policy from the fee recipient allowlist (0x-prefixed addresses).
func New(feeRecipientAllowlist []string) (*Policy, error) {
	p := &Policy{feeRecipients: make(map[bellatrix.ExecutionAddress]bool)}
	for _, s := range feeRecipientAllowlist {
		b, err := hex.DecodeString(strings.TrimPrefix(strings.TrimSpace(s), "0x"))
		if err != nil || len(b) != 20 {
			return nil, fmt.Errorf("invalid fee recipient %q in allowlist", s)
		}
		var a bellatrix.ExecutionAddress
		copy(a[:], b)
		p.feeRecipients[a] = true
	}

	return p, nil
}

// Check returns a *RefusedError when the job for pubkey must not be signed.
func (p *Policy) Check(pubkey phase0.BLSPubKey, job *signing.Job) error {
	switch job.Type {
	case signing.TypeVoluntaryExit:
		// Only the admin role signs an exit, at the signers (signer-admin exit).
		return &RefusedError{Reason: "voluntary exits are never signed by this gateway"}
	case signing.TypeValidatorRegistration:
		reg := job.Registration
		if reg.Pubkey != pubkey {
			return &RefusedError{Reason: fmt.Sprintf("registration pubkey %#x differs from signing key %#x", reg.Pubkey, pubkey)}
		}
		if !p.feeRecipients[reg.FeeRecipient] {
			return &RefusedError{Reason: fmt.Sprintf("fee recipient %s is not in the allowlist", reg.FeeRecipient.String())}
		}
	}
	if job.Method == signing.MethodNone {
		if job.Refusal != "" {
			return &RefusedError{Reason: job.Type + ": " + job.Refusal}
		}

		return &RefusedError{Reason: "no signing method for " + job.Type}
	}

	return nil
}
