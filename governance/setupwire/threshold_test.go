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

// A single-node signer (t = n = 1) is refused on GCP on every chain unless
// the setup accepts the risk (sealing_key_release.unsafe_single_key_accepted),
// and the refusal says why and how to accept; on the other platforms it
// passes on every chain, mainnet included, and the threshold rule alone
// decides. The mainnet overlap rule still applies to every real split.
func TestThresholdOnGCP(t *testing.T) {
	testnet, mainnet := backend.Version{0x10, 0, 0, 0x38}, MainnetForkVersion
	for _, c := range []struct {
		p      Platform
		accept bool
		fork   backend.Version
		t, n   int
		refuse string
	}{
		{PlatformGCP, false, testnet, 1, 1, "single-node"},
		{PlatformGCP, false, mainnet, 1, 1, "single-node"},
		{PlatformGCP, true, testnet, 1, 1, ""},
		{PlatformGCP, true, mainnet, 1, 1, ""},
		{PlatformGCP, false, testnet, 2, 3, ""},
		{PlatformGCP, false, mainnet, 3, 4, ""},
		{PlatformGCP, false, mainnet, 2, 3, "2t - n >= 2"},
		{PlatformGCP, true, mainnet, 2, 3, "2t - n >= 2"},
		{PlatformNitro, false, testnet, 1, 1, ""},
		{PlatformNitro, false, mainnet, 1, 1, ""},
		{PlatformAzure, false, mainnet, 1, 1, ""},
		{PlatformAzure, false, mainnet, 2, 3, "2t - n >= 2"},
		{PlatformDev, false, testnet, 1, 1, ""},
	} {
		p := &PlatformConfig{Platform: c.p, SealingKeyRelease: KeyRelease{UnsafeSingleKeyAccepted: c.accept}}
		err := CheckThresholdOn(p, c.fork, c.t, c.n)
		if (c.refuse == "") != (err == nil) || (err != nil && !strings.Contains(err.Error(), c.refuse)) {
			t.Errorf("%s (accepted %v) %d of %d on %x: %v, want %q", c.p, c.accept, c.t, c.n, c.fork, err, c.refuse)
		}
	}
	err := CheckThresholdOn(&PlatformConfig{Platform: PlatformGCP}, testnet, 1, 1)
	for _, want := range []string{"unsafe_single_key_accepted = true", "-allow-gcp-unsafe-single-key", "no lock", "IAM bindings", "slashable"} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal lacks %q: %v", want, err)
		}
	}
}
