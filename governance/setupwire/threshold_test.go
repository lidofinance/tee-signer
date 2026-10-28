package setupwire

import (
	"strings"
	"testing"

	"github.com/lidofinance/tee-signer/signer-protocol"
)

func TestCheckThreshold(t *testing.T) {
	dev := backend.Version{0x10, 0, 0, 0x38}
	for _, c := range []struct {
		fork backend.Version
		t, n int
		ok   bool
	}{
		{dev, 2, 3, true}, {dev, 3, 5, true}, {dev, 2, 4, false}, {dev, 1, 2, false}, {dev, 1, 1, true}, {dev, 4, 3, false},
		{MainnetForkVersion, 2, 3, false}, {MainnetForkVersion, 3, 5, false}, {MainnetForkVersion, 3, 4, true},
		{MainnetForkVersion, 4, 5, true}, {MainnetForkVersion, 1, 1, true}, {MainnetForkVersion, 2, 2, true},
	} {
		if err := CheckThreshold(c.fork, c.t, c.n); (err == nil) != c.ok {
			t.Errorf("fork %x, %d of %d: %v, want ok %v", c.fork, c.t, c.n, err, c.ok)
		}
	}
}

// The threshold rule knows no platform and a single-node signer is not a
// split: t = n = 1 passes on every chain, mainnet included, and
// CheckThreshold is the only rule. The mainnet overlap rule still applies
// to every real split.
func TestSingleNodeOnEveryPlatform(t *testing.T) {
	testnet := backend.Version{0x10, 0, 0, 0x38}
	for _, p := range []Platform{PlatformNitro, PlatformAzure, PlatformGCP, PlatformDev} {
		for _, fork := range []backend.Version{testnet, MainnetForkVersion} {
			if err := CheckThreshold(fork, 1, 1); err != nil {
				t.Errorf("%s: 1 of 1 on %x: %v", p, fork, err)
			}
		}
	}
	if err := CheckThreshold(MainnetForkVersion, 2, 3); err == nil || !strings.Contains(err.Error(), "2t - n >= 2") {
		t.Errorf("2 of 3 on mainnet: %v, want the overlap rule's refusal", err)
	}
}
