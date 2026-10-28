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
		{MainnetForkVersion, 4, 5, true}, {MainnetForkVersion, 1, 1, false}, {MainnetForkVersion, 2, 2, true},
	} {
		if err := CheckThreshold(c.fork, c.t, c.n); (err == nil) != c.ok {
			t.Errorf("fork %x, %d of %d: %v, want ok %v", c.fork, c.t, c.n, err, c.ok)
		}
	}
}

// A single-node signer (t = n = 1) on GCP is refused on every chain; on
// other platforms the threshold rule alone decides.
func TestThresholdOnGCP(t *testing.T) {
	testnet, mainnet := backend.Version{0x10, 0, 0, 0x38}, MainnetForkVersion
	for _, c := range []struct {
		p      Platform
		fork   backend.Version
		t, n   int
		refuse string
	}{
		{PlatformGCP, testnet, 1, 1, "single-node"},
		{PlatformGCP, mainnet, 1, 1, "single-node"},
		{PlatformGCP, testnet, 2, 3, ""},
		{PlatformGCP, mainnet, 3, 4, ""},
		{PlatformGCP, mainnet, 2, 3, "2t - n >= 2"},
		{PlatformNitro, testnet, 1, 1, ""},
		{PlatformDev, testnet, 1, 1, ""},
		{PlatformAzure, mainnet, 1, 1, "2t - n >= 2"},
	} {
		err := CheckThresholdOn(c.p, c.fork, c.t, c.n)
		if (c.refuse == "") != (err == nil) || (err != nil && !strings.Contains(err.Error(), c.refuse)) {
			t.Errorf("%s %d of %d on %x: %v, want %q", c.p, c.t, c.n, c.fork, err, c.refuse)
		}
	}
}
