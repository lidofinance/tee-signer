package server

import (
	"testing"

	"github.com/lidofinance/tee-signer/governance/runnerchain"
)

// HEALTH's version names the chain of the build the way clients read it
// (governance/runnerchain): "+hoodi", "+devnet" or "+ci-test", nothing for
// mainnet. Run under each build's tags: go test, go test -tags
// nonprod,chain_<name>.
func TestVersionNamesTheBuild(t *testing.T) {
	if got := runnerchain.FromVersion(Version); got != runnerchain.Build {
		t.Errorf("version %q reads as %s, this is a %s build", Version, got, runnerchain.Build)
	}
	want := map[runnerchain.Chain]string{runnerchain.Mainnet: "0.1.0", runnerchain.Hoodi: "0.1.0+hoodi",
		runnerchain.Devnet: "0.1.0+devnet", runnerchain.CITest: "0.1.0+ci-test"}[runnerchain.Build]
	if Version != want {
		t.Errorf("version %q, want %q", Version, want)
	}
}
