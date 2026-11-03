//go:build nonprod

package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lidofinance/tee-signer/governance/runnerchain"
	"github.com/lidofinance/tee-signer/governance/setupwire"
	"github.com/lidofinance/tee-signer/platform"
	"github.com/lidofinance/tee-signer/platform/setup"
)

// chainSetup is the dev sample setup on a chain with these genesis values.
func chainSetup(t *testing.T, fork, root string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "governance", "setupwire", "testdata", "setup-dev-single.bin"))
	if err != nil {
		t.Fatal(err)
	}
	s, err := setupwire.DecodeSetup(raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := hex.Decode(s.Chain.GenesisForkVersion[:], []byte(fork)); err != nil {
		t.Fatal(err)
	}
	if _, err := hex.Decode(s.Chain.GenesisValidatorsRoot[:], []byte(root)); err != nil {
		t.Fatal(err)
	}
	out, err := s.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

const (
	hoodiFork   = "10000910"
	hoodiRoot   = "212f13fc4df078b6cb7db228f1c8307566dcecf900867401a92023d7ba99cb5f"
	mainnetFork = "00000000"
	mainnetRoot = "4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95"
	devnetFork  = "10000038" // ethereum-package's default
	ciTestFork  = "00000001"
	ciTestRoot  = "535276eb9690335cc5e4cb926858a79ece25caaf930a7dfad44757c8b7bef420"
)

var devnetRoot = func() string { h := sha256.Sum256([]byte("a kurtosis devnet")); return hex.EncodeToString(h[:]) }()

// ownChain is a chain this build starts on.
func ownChain(t *testing.T) (fork, root string) {
	t.Helper()
	switch runnerchain.Build {
	case runnerchain.Hoodi:
		return hoodiFork, hoodiRoot
	case runnerchain.Devnet:
		return devnetFork, devnetRoot
	case runnerchain.CITest:
		return ciTestFork, ciTestRoot
	}
	t.Fatalf("a %s build has no chain check", runnerchain.Build)
	return "", ""
}

// The build starts on its own chain and refuses every other: mainnet
// first, the other non-prod builds' chains, and public networks.
func TestChainSetupCheck(t *testing.T) {
	type tc struct{ name, fork, root, want string }
	cases := []tc{
		{"mainnet", mainnetFork, mainnetRoot, "chain mainnet"},
		{"mainnet root", devnetFork, mainnetRoot, "mainnet has fork version"},
		{"mainnet fork version", mainnetFork, devnetRoot, "chain mainnet (genesis fork version 0x00000000 and genesis validators root 0x" + devnetRoot + "): a prod chain"},
		{"sepolia", "90000069", "d8ea171f3c94aea21ebc42a1ed61052acf3f9209c00e4efbaaddac09ed9b8078", "chain sepolia"},
		{"chiado", "0000006f", "9d642dac73058fbf39c0ae41ab1e34e4d889043cb199851ded7095bc99eb4c1e", "chain chiado"},
		{"gnosis", "00000064", "f5dcb5564e829aab27264b9becd5dfaa017085611224cb3036f573368dbb9d47", "chain gnosis"},
		{"holesky", "01017000", "9143aa7c615a7f7115e2b6aac319c03529df8242ae705fba9df39b79c59fa8b1", "chain holesky"},
	}
	refuse := "a " + string(runnerchain.Build) + " build runs on"
	own := map[runnerchain.Chain]tc{
		runnerchain.Hoodi:  {"hoodi", hoodiFork, hoodiRoot, ""},
		runnerchain.Devnet: {"kurtosis devnet", devnetFork, devnetRoot, ""},
		runnerchain.CITest: {"ci-test", ciTestFork, ciTestRoot, ""},
	}
	for c, x := range own {
		if c != runnerchain.Build {
			x.want = refuse
		}
		cases = append(cases, x)
	}
	if runnerchain.Build != runnerchain.Hoodi {
		cases = append(cases, tc{"hoodi fork version, other root", hoodiFork, devnetRoot, "hoodi has fork version 0x10000910"})
	}
	for _, c := range cases {
		raw := chainSetup(t, c.fork, c.root)
		err := checkChainSetup(raw)
		_, passed := chainPassed.Load(hashOf(t, raw))
		switch {
		case c.want == "" && (err != nil || !passed):
			t.Errorf("%s: %v (passed %v)", c.name, err, passed)
		case c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want) || passed):
			t.Errorf("%s: %v (passed %v), want %q", c.name, err, passed, c.want)
		}
	}
	// A setup that does not decode is left to setup.Load.
	if err := checkChainSetup([]byte{1, 2, 3}); err != nil {
		t.Errorf("undecodable setup: %v", err)
	}
}

func TestChainStart(t *testing.T) {
	if err := chainStart([32]byte{}, "", false); err == nil || !strings.Contains(err.Error(), "setup only") {
		t.Errorf("flag path: %v", err)
	}
	if err := chainStart([32]byte{}, "", true); err != nil {
		t.Errorf("flag path with -clock-check: %v", err)
	}
	dir := t.TempDir()
	write := func(name string, raw []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	// -setup file: is read again and checked.
	good := chainSetup(t, ownFork(t), ownRoot(t))
	goodPath := write("good.bin", good)
	chainPassed.Delete(hashOf(t, good)) // as if no channel had read it
	if err := chainStart(hashOf(t, good), "file:"+goodPath, false); err != nil {
		t.Errorf("own chain file: %v", err)
	}
	bad := chainSetup(t, mainnetFork, mainnetRoot)
	badPath := write("bad.bin", bad)
	if err := chainStart(hashOf(t, bad), "file:"+badPath, false); err == nil || !strings.Contains(err.Error(), "chain mainnet") {
		t.Errorf("mainnet file: %v", err)
	}
	// The file changed after the start read it.
	if err := chainStart(hashOf(t, bad), "file:"+goodPath, false); err == nil || !strings.Contains(err.Error(), "changed") {
		t.Errorf("changed file: %v", err)
	}
	// -setup platform: only a setup the channel checked.
	other := chainSetup(t, ownFork(t), strings.Repeat("ab", 32))
	chainPassed.Delete(hashOf(t, other))
	if err := chainStart(hashOf(t, other), "platform", false); err == nil || !strings.Contains(err.Error(), "not checked") {
		t.Errorf("unchecked setup: %v", err)
	}
}

func ownFork(t *testing.T) string { f, _ := ownChain(t); return f }
func ownRoot(t *testing.T) string { _, r := ownChain(t); return r }

// Every platform and setup channel of this build goes through the check.
func TestChainWrapsEveryPlatform(t *testing.T) {
	if len(platforms) == 0 {
		t.Skip("no platform in this build")
	}
	for name, f := range platforms {
		if _, err := f(platform.Options{}); err == nil || !strings.Contains(err.Error(), "setup only") {
			t.Errorf("platform %s without a setup: %v", name, err)
		}
	}
	for name, f := range setupChannels {
		switch f().(type) {
		case checked, checkedReporter:
		default:
			t.Errorf("setup channel of %s is not checked", name)
		}
	}
	// The dev channel reads SIGNER_SETUP: a mainnet setup there is refused.
	if f, ok := setupChannels["dev"]; ok {
		t.Setenv(setup.EnvVar, encodeB64(chainSetup(t, mainnetFork, mainnetRoot)))
		if _, err := f().Read(context.Background()); err == nil || !strings.Contains(err.Error(), "chain mainnet") {
			t.Errorf("dev channel with a mainnet setup: %v", err)
		}
		t.Setenv(setup.EnvVar, encodeB64(chainSetup(t, ownFork(t), ownRoot(t))))
		if _, err := f().Read(context.Background()); err != nil {
			t.Errorf("dev channel with a setup of its own chain: %v", err)
		}
	}
}

func encodeB64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// hashOf is setup_hash of the encoded setup raw.
func hashOf(t *testing.T, raw []byte) [32]byte {
	t.Helper()
	h, err := setupwire.SetupHash(raw)
	if err != nil {
		t.Fatal(err)
	}
	return h
}
