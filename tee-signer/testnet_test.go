//go:build testnet

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

	"github.com/lidofinance/tee-signer/governance/setupwire"
	"github.com/lidofinance/tee-signer/platform"
	"github.com/lidofinance/tee-signer/platform/setup"
)

// testnetSetup is the dev sample setup on a chain with these genesis values.
func testnetSetup(t *testing.T, fork, root string) []byte {
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
)

var devnetRoot = func() string { h := sha256.Sum256([]byte("a kurtosis devnet")); return hex.EncodeToString(h[:]) }()

func TestTestnetSetupCheck(t *testing.T) {
	for _, c := range []struct{ name, fork, root, want string }{
		{"hoodi", hoodiFork, hoodiRoot, ""},
		{"sepolia", "90000069", "d8ea171f3c94aea21ebc42a1ed61052acf3f9209c00e4efbaaddac09ed9b8078", ""},
		{"chiado", "0000006f", "9d642dac73058fbf39c0ae41ab1e34e4d889043cb199851ded7095bc99eb4c1e", ""},
		{"kurtosis devnet", devnetFork, devnetRoot, ""},
		{"hoodi fork version, other root", hoodiFork, devnetRoot, "hoodi has fork version 0x10000910"},
		{"mainnet", mainnetFork, mainnetRoot, "chain mainnet"},
		{"mainnet root", devnetFork, mainnetRoot, "mainnet has fork version"},
		{"gnosis", "00000064", "f5dcb5564e829aab27264b9becd5dfaa017085611224cb3036f573368dbb9d47", "chain gnosis"},
		{"holesky", "01017000", "9143aa7c615a7f7115e2b6aac319c03529df8242ae705fba9df39b79c59fa8b1", "chain holesky"},
	} {
		raw := testnetSetup(t, c.fork, c.root)
		err := checkTestnetSetup(raw)
		_, passed := testnetPassed.Load(hashOf(t, raw))
		switch {
		case c.want == "" && (err != nil || !passed):
			t.Errorf("%s: %v (passed %v)", c.name, err, passed)
		case c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want) || passed):
			t.Errorf("%s: %v (passed %v), want %q", c.name, err, passed, c.want)
		}
	}
	// A setup that does not decode is left to setup.Load.
	if err := checkTestnetSetup([]byte{1, 2, 3}); err != nil {
		t.Errorf("undecodable setup: %v", err)
	}
}

func TestTestnetStart(t *testing.T) {
	if err := testnetStart([32]byte{}, "", false); err == nil || !strings.Contains(err.Error(), "setup only") {
		t.Errorf("flag path: %v", err)
	}
	if err := testnetStart([32]byte{}, "", true); err != nil {
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
	good := testnetSetup(t, hoodiFork, hoodiRoot)
	goodPath := write("good.bin", good)
	testnetPassed.Delete(hashOf(t, good)) // as if no channel had read it
	if err := testnetStart(hashOf(t, good), "file:"+goodPath, false); err != nil {
		t.Errorf("hoodi file: %v", err)
	}
	bad := testnetSetup(t, mainnetFork, mainnetRoot)
	badPath := write("bad.bin", bad)
	if err := testnetStart(hashOf(t, bad), "file:"+badPath, false); err == nil || !strings.Contains(err.Error(), "chain mainnet") {
		t.Errorf("mainnet file: %v", err)
	}
	// The file changed after the start read it.
	if err := testnetStart(hashOf(t, bad), "file:"+goodPath, false); err == nil || !strings.Contains(err.Error(), "changed") {
		t.Errorf("changed file: %v", err)
	}
	// -setup platform: only a setup the channel checked.
	other := testnetSetup(t, devnetFork, devnetRoot)
	testnetPassed.Delete(hashOf(t, other))
	if err := testnetStart(hashOf(t, other), "platform", false); err == nil || !strings.Contains(err.Error(), "not checked") {
		t.Errorf("unchecked setup: %v", err)
	}
}

// Every platform and setup channel of this build goes through the check.
func TestTestnetWrapsEveryPlatform(t *testing.T) {
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
		t.Setenv(setup.EnvVar, encodeB64(testnetSetup(t, mainnetFork, mainnetRoot)))
		if _, err := f().Read(context.Background()); err == nil || !strings.Contains(err.Error(), "chain mainnet") {
			t.Errorf("dev channel with a mainnet setup: %v", err)
		}
		t.Setenv(setup.EnvVar, encodeB64(testnetSetup(t, hoodiFork, hoodiRoot)))
		if _, err := f().Read(context.Background()); err != nil {
			t.Errorf("dev channel with a hoodi setup: %v", err)
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
