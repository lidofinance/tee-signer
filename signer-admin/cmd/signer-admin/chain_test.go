package main

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lidofinance/tee-signer/governance/setupwire"
)

// Genesis values of the tests' chains, as the human setup format writes
// them.
const (
	mainnetFork   = "0x00000000"
	mainnetRoot   = "0x4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95"
	hoodiFork     = "0x10000910"
	hoodiRoot     = "0x212f13fc4df078b6cb7db228f1c8307566dcecf900867401a92023d7ba99cb5f"
	devnetFork    = "0x10000038"
	ciTestFork    = "0x00000001"
	ciTestRoot    = "0x535276eb9690335cc5e4cb926858a79ece25caaf930a7dfad44757c8b7bef420" // governance/chains/chain.ci-test.json
	testChainRoot = "0x4b36000000000000000000000000000000000000000000000000000000000000" // setupText's, no build's own
)

// setLines replaces the value of each key in a human setup text, and fails
// the test on a key the text does not have.
func setLines(t *testing.T, text string, values map[string]string) string {
	t.Helper()
	seen := map[string]bool{}
	lines := strings.Split(text, "\n")
	for i, l := range lines {
		k := keyOf(l)
		if v, ok := values[k]; ok {
			lines[i] = k + " = " + v
			seen[k] = true
		}
	}
	for k := range values {
		if !seen[k] {
			t.Fatalf("the setup text has no %s line", k)
		}
	}
	return strings.Join(lines, "\n")
}

// withChain gives a human setup text these genesis values.
func withChain(t *testing.T, text, fork, root string) string {
	t.Helper()
	return setLines(t, text, map[string]string{"genesis_fork_version": fork, "genesis_validators_root": root})
}

// mainnetChain gives a human setup text mainnet's exact chain values, which
// the mainnet build takes.
func mainnetChain(t *testing.T, text string) string {
	t.Helper()
	return setLines(t, text, map[string]string{
		"genesis_fork_version": mainnetFork, "genesis_validators_root": mainnetRoot,
		"genesis_time": fmt.Sprint(setupwire.MainnetGenesisTime), "seconds_per_slot": fmt.Sprint(setupwire.MainnetSecondsPerSlot),
		"slots_per_epoch": fmt.Sprint(setupwire.MainnetSlotsPerEpoch), "preset": "mainnet",
	})
}

// setup refuses a file whose genesis fork version and genesis validators
// root belong to different chains, and a -build whose runners refuse the
// file's chain at start, so no setup is written that no runner starts on.
// The floor of change_delay_seconds follows the chain: a -build with short
// times does not lower it on a prod chain.
func TestSetupRefusesChainNoBuildRuns(t *testing.T) {
	dir := t.TempDir()
	keys := approvers(t, dir, 3)
	ca := caDER(t)
	floor := int(setupwire.DefaultTimeLock)
	text := func(timeLock int) string {
		return setupText(dir, ca, genesisTime(), lockedText(keys, 2, timeLock, fee1), "a", "b")
	}
	file := func(name, text string) string { return writeFile(t, filepath.Join(t.TempDir(), name), text) }
	out := func() string { return filepath.Join(t.TempDir(), "out") }

	// Values of two chains, at the prod floor so only the chain refuses.
	mixed := file("mixed.conf", withChain(t, text(floor), mainnetFork, testChainRoot))
	wantIn(t, failTool(t, "setup", "-out", out(), mixed), "signer a", "the fork version is mainnet's, the root no public network's", "different chains", "no build runs")
	wantIn(t, failTool(t, "setup", "-build", "hoodi", "-out", out(), mixed), "signer a", "a hoodi runner", "different chains")
	hoodiMixed := file("hoodi-mixed.conf", withChain(t, text(floor), hoodiFork, mainnetRoot))
	wantIn(t, failTool(t, "setup", "-out", out(), hoodiMixed), "signer a", "the fork version is hoodi's, the root mainnet's", "different chains")
	wantIn(t, failTool(t, "setup", "-build", "hoodi", "-out", out(), hoodiMixed), "signer a", "different chains")

	// A -build whose runners refuse the chain: a non-prod build on mainnet,
	// at the prod floor and at its own short default, and on another
	// build's chain. The mainnet build takes mainnet and, on the dev
	// platform, any non-prod chain.
	mainnet := file("mainnet.conf", mainnetChain(t, text(floor)))
	wantIn(t, failTool(t, "setup", "-build", "hoodi", "-out", out(), mainnet), "signer a", "a hoodi runner", "a prod chain", "hoodi with its exact values only")
	short := file("short.conf", mainnetChain(t, text(120)))
	wantIn(t, failTool(t, "setup", "-build", "hoodi", "-out", out(), short), "signer a", "a hoodi runner", "a prod chain")
	wantIn(t, failTool(t, "setup", "-build", "mainnet", "-out", out(), short), "signer a", fmt.Sprintf("change_delay_seconds 120 on a prod chain"), fmt.Sprintf("at least %d", floor))
	wantIn(t, mustTool(t, "setup", "-out", out(), mainnet), "a setup_sha256", "b setup_sha256")
	hoodi := file("hoodi.conf", withChain(t, text(0), hoodiFork, hoodiRoot))
	wantIn(t, failTool(t, "setup", "-build", "ci-test", "-out", out(), hoodi), "signer a", "a ci-test runner", "chain hoodi")
	wantIn(t, failTool(t, "setup", "-build", "devnet", "-out", out(), hoodi), "signer a", "a devnet runner", "chain hoodi")
	mustTool(t, "setup", "-build", "hoodi", "-out", out(), hoodi)
	mustTool(t, "setup", "-out", out(), hoodi)
	ci := file("ci.conf", withChain(t, text(0), ciTestFork, ciTestRoot))
	mustTool(t, "setup", "-build", "ci-test", "-out", out(), ci)
	// The ci-test chain's fork version with another root is no build's own
	// chain: the mainnet build on the dev platform takes it, the ci-test
	// build does not.
	wantIn(t, failTool(t, "setup", "-build", "ci-test", "-out", out(), file("other.conf", text(0))), "signer a", "a ci-test runner", "the ci-test chain")
	mustTool(t, "setup", "-out", out(), file("other.conf", text(0)))
}
