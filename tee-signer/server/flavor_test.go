package server

import (
	"testing"

	"github.com/lidofinance/tee-signer/governance/flavor"
)

// HEALTH's version names the build flavour the way clients read it
// (backend/flavor). Run under both tags: go test, go test -tags testnet.
func TestVersionNamesTheFlavor(t *testing.T) {
	if got := flavor.FromVersion(Version); got != flavor.Build {
		t.Errorf("version %q reads as %s, this is a %s build", Version, got, flavor.Build)
	}
	want := map[flavor.Flavor]string{flavor.Default: "0.1.0", flavor.Testnet: "0.1.0+testnet"}[flavor.Build]
	if Version != want {
		t.Errorf("version %q, want %q", Version, want)
	}
}
