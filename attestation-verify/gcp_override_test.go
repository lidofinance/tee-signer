package attest

import (
	"errors"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/attestation-verify/internal/gcptest"
)

// The operator's launch overrides change what the measured image runs, so
// a token that lists any is refused; empty or absent ones pass.
func TestConfidentialSpaceOverrides(t *testing.T) {
	const digest, hw, aud = csDigest, "GCP_INTEL_TDX", "signer-runner-identity"
	now := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	key := gcptest.NewKey(t)
	ks, err := ParseJWKS(gcptest.JWKS(key))
	if err != nil {
		t.Fatal(err)
	}
	opts := ConfidentialSpaceOptions{Keys: ks, Audience: aud, Now: now, ImageDigests: []string{digest},
		Nonces: []string{"n1"}}
	verify := func(claim string, v any) error {
		c := gcptest.Claims(now.Add(-time.Minute).Unix(), "n1", digest, hw, aud)
		if claim != "" {
			c["submods"].(map[string]any)["container"].(map[string]any)[claim] = v
		}
		_, err := VerifyConfidentialSpace(key.Sign(t, c), opts)
		return err
	}
	if err := verify("", nil); err != nil {
		t.Fatalf("no override: %v", err)
	}
	for _, claim := range []string{"env_override", "cmd_override", "args_override"} {
		for _, empty := range []any{nil, map[string]any{}, []any{}} {
			if err := verify(claim, empty); err != nil {
				t.Fatalf("%s %v: %v", claim, empty, err)
			}
		}
		for _, set := range []any{map[string]any{"X": "1"}, []any{"/bin/sh"}, "x", true} {
			if err := verify(claim, set); !errors.Is(err, ErrClaim) {
				t.Fatalf("%s %v: %v, want ErrClaim", claim, set, err)
			}
		}
	}
}
