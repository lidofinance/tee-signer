//go:build !debugimport

package server

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lidofinance/tee-signer/governance/setupwire"
)

// A handover keeps the signing_mode: a single-mode source hands whole
// keys, which only a single-mode target may hold, and a threshold source
// hands shares, which a single-mode target would hold as if they were
// whole keys. checkTargetPolicy refuses a target of the other mode, in
// both directions, and takes one of the same mode.
func TestHandoverKeepsSigningMode(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "governance", "setupwire", "testdata", "setup-nitro.bin"))
	if err != nil {
		t.Fatal(err)
	}
	single, threshold := setupwire.SigningModeSingle, setupwire.SigningModeThreshold
	for _, c := range []struct{ src, tgt setupwire.SigningMode }{
		{single, single}, {threshold, threshold}, {single, threshold}, {threshold, single},
	} {
		src, err := setupwire.DecodeSetup(raw)
		if err != nil {
			t.Fatal(err)
		}
		src.SigningMode = c.src
		target := src.Policy()
		target.HandoverGeneration++
		target.SigningMode = c.tgt
		err = checkTargetPolicy(src, &src.Locked, &src.Open, target)
		if c.src == c.tgt {
			if err != nil {
				t.Errorf("%s to %s: %v", c.src, c.tgt, err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), "public.signing_mode") {
			t.Errorf("%s to %s: %v, want a refusal naming public.signing_mode", c.src, c.tgt, err)
		}
	}
}
