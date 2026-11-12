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
		if err := CheckThreshold(c.fork, backend.Root{0x4b, 0x36}, c.t, c.n); (err == nil) != c.ok {
			t.Errorf("fork %x, %d of %d: %v, want ok %v", c.fork, c.t, c.n, err, c.ok)
		}
	}
}

// CheckThresholdOn: every combination of signing_mode, platform, GCP
// acceptance, chain and split. A single-mode setup takes 1 of 1 only, on
// GCP only with the acceptance; a threshold-mode setup refuses 1 of 1 and
// keeps the threshold rule, the prod chain overlap rule included. 1 of 1
// passes on mainnet on every platform whose setup allows it (the GCP
// runner's start rule, no_lock_accepted, is checked at start, not here).
func TestThresholdOn(t *testing.T) {
	testnet, mainnet := backend.Version{0x10, 0, 0, 0x38}, MainnetForkVersion
	single, threshold := SigningModeSingle, SigningModeThreshold
	for _, c := range []struct {
		mode   SigningMode
		p      Platform
		accept bool
		fork   backend.Version
		t, n   int
		refuse string
	}{
		{single, PlatformGCP, false, testnet, 1, 1, "single-node"},
		{single, PlatformGCP, false, mainnet, 1, 1, "single-node"},
		{single, PlatformGCP, true, testnet, 1, 1, ""},
		{single, PlatformGCP, true, mainnet, 1, 1, ""},
		{single, PlatformGCP, true, testnet, 2, 3, "signing_mode = single"},
		{single, PlatformNitro, false, testnet, 1, 1, ""},
		{single, PlatformNitro, false, mainnet, 1, 1, ""},
		{single, PlatformAzure, false, mainnet, 1, 1, ""},
		{single, PlatformDev, false, testnet, 1, 1, ""},
		{single, PlatformNitro, false, testnet, 2, 3, "signing_mode = single"},
		{single, PlatformAzure, false, mainnet, 3, 4, "signing_mode = single"},
		{single, PlatformDev, false, testnet, 2, 2, "signing_mode = single"},
		{threshold, PlatformGCP, false, testnet, 1, 1, "signing_mode = threshold"},
		{threshold, PlatformGCP, true, testnet, 1, 1, "signing_mode = threshold"},
		{threshold, PlatformNitro, false, mainnet, 1, 1, "signing_mode = threshold"},
		{threshold, PlatformAzure, false, testnet, 1, 1, "signing_mode = threshold"},
		{threshold, PlatformDev, false, testnet, 1, 1, "signing_mode = threshold"},
		{threshold, PlatformGCP, false, testnet, 2, 3, ""},
		{threshold, PlatformGCP, false, mainnet, 3, 4, ""},
		{threshold, PlatformGCP, false, mainnet, 2, 3, "2t - n >= 2"},
		{threshold, PlatformNitro, false, testnet, 2, 3, ""},
		{threshold, PlatformAzure, false, mainnet, 2, 3, "2t - n >= 2"},
		{threshold, PlatformDev, false, testnet, 1, 2, "want more than half"},
		{0, PlatformDev, false, testnet, 1, 1, "signing_mode 0"},
	} {
		s := &Setup{SigningMode: c.mode, Chain: Chain{GenesisForkVersion: c.fork},
			Platform: PlatformConfig{Platform: c.p, SealingKeyRelease: KeyRelease{UnsafeSingleKeyAccepted: c.accept}}}
		err := CheckThresholdOn(s, c.t, c.n)
		if (c.refuse == "") != (err == nil) || (err != nil && !strings.Contains(err.Error(), c.refuse)) {
			t.Errorf("%s %s (accepted %v) %d of %d on %x: %v, want %q", c.mode, c.p, c.accept, c.t, c.n, c.fork, err, c.refuse)
		}
	}
	gcp := &Setup{SigningMode: single, Platform: PlatformConfig{Platform: PlatformGCP}}
	err := CheckThresholdOn(gcp, 1, 1)
	for _, want := range []string{"unsafe_single_key_accepted = true", "-allow-gcp-unsafe-single-key", "no lock", "IAM bindings", "slashable"} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal lacks %q: %v", want, err)
		}
	}
}

// One key is held by one runner: a single-mode cluster has one signer.
func TestCheckMembers(t *testing.T) {
	for _, c := range []struct {
		mode    SigningMode
		members int
		refuse  string
	}{
		{SigningModeSingle, 1, ""},
		{SigningModeSingle, 2, "signing_mode = single with 2 signers"},
		{SigningModeSingle, 0, "no signer"},
		{SigningModeThreshold, 1, ""},
		{SigningModeThreshold, 3, ""},
		{0, 1, "signing_mode 0"},
	} {
		err := CheckMembers(c.mode, c.members)
		if (c.refuse == "") != (err == nil) || (err != nil && !strings.Contains(err.Error(), c.refuse)) {
			t.Errorf("%s, %d signers: %v, want %q", c.mode, c.members, err, c.refuse)
		}
	}
}

// Each signer of a split has its own share index, from 1 to n.
func TestCheckShareIndices(t *testing.T) {
	for _, c := range []struct {
		n      int
		shares map[string]uint8
		refuse string
	}{
		{1, map[string]uint8{"a": 1}, ""},
		{3, map[string]uint8{"a": 1, "b": 2, "c": 3}, ""},
		{3, map[string]uint8{"a": 3, "b": 1}, ""},
		{1, map[string]uint8{"a": 1, "b": 1}, "share index 1 is given to a and b"},
		{3, map[string]uint8{"a": 2, "b": 1, "c": 2}, "share index 2 is given to a and c"},
		{3, map[string]uint8{"a": 1, "b": 4}, "b: share index 4, want 1 to 3"},
		{3, map[string]uint8{"a": 0}, "a: share index 0, want 1 to 3"},
	} {
		err := CheckShareIndices(c.n, c.shares)
		if (c.refuse == "") != (err == nil) || (err != nil && !strings.Contains(err.Error(), c.refuse)) {
			t.Errorf("n %d, %v: %v, want %q", c.n, c.shares, err, c.refuse)
		}
	}
}
