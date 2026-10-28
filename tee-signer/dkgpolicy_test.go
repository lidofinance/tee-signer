//go:build (peer_azure || peer_aws || peer_gcp || peer_dev) && !debugimport

package main

import (
	"strings"
	"testing"

	"github.com/lidofinance/tee-signer/governance/setupwire"
	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/tee-signer/keygen"
)

// The -dkg-policy path refuses a single-node GCP signer (t = n = 1) on
// every chain and keeps the threshold rule elsewhere, as the DKG and
// import orders do (setupwire.CheckThresholdOn). The check returns an
// error; applyPlainImport turns it into the exit.
func TestDKGPolicyThreshold(t *testing.T) {
	testnet := backend.Version{0x10, 0, 0, 0x38}
	pol := func(k, n int) *keygen.Policy {
		return &keygen.Policy{Version: 1, Threshold: k, Participants: make([]keygen.Participant, n)}
	}
	for _, c := range []struct {
		platform string
		fork     backend.Version
		p        *keygen.Policy
		refuse   string
	}{
		{"gcp", testnet, pol(1, 1), "single-node signer on GCP"},
		{"gcp", setupwire.MainnetForkVersion, pol(1, 1), "single-node signer on GCP"},
		{"gcp", testnet, pol(2, 3), ""},
		{"dev", testnet, pol(1, 1), ""},
		{"nitro", testnet, pol(1, 1), ""},
		{"azure", setupwire.MainnetForkVersion, pol(2, 3), "2t - n >= 2"},
		{"dev", testnet, nil, ""},
	} {
		err := checkDKGPolicy(c.platform, c.fork, c.p)
		if (c.refuse == "") != (err == nil) || (err != nil && !strings.Contains(err.Error(), c.refuse)) {
			t.Errorf("%s %x %+v: %v, want %q", c.platform, c.fork, c.p, err, c.refuse)
		}
	}
}
