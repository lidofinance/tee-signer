package azure

import (
	"context"
	"strings"
	"testing"

	"github.com/lidofinance/tee-signer/platform"
)

// RBRAZR-01: the runner reads the rule of one key version and must release
// that version, not whatever version the bare key name points at by then.

const newerKeyVersion = "fedcba9876543210fedcba9876543210"

// mainnetOptions is a mainnet start with a setup, so the key rule is read
// and checked.
var mainnetOptions = platform.Options{SetupHash: setupA, Mainnet: true}

// A Key Vault admin adds a version between Get Key and the release. Get Key
// shows version A (immutable policy, locked); a release of the bare name
// would give version B. The runner must release A.
func TestReleaseIsTheCheckedVersion(t *testing.T) {
	f := newKVFixture(t)
	f.kv.immutable = true
	f.kv.newer, f.kv.newerVersion = testRSA(t), newerKeyVersion
	for _, o := range []platform.Options{{SetupHash: setupA}, mainnetOptions} {
		kid := "signer-kek-1"
		if o.Mainnet {
			kid += "/" + testKeyVersion
		}
		rule, key, err := releaseChecked(context.Background(), o, f.releaser, kid)
		if err != nil {
			t.Fatalf("mainnet %v: %v", o.Mainnet, err)
		}
		if !samePrivateKey(key, f.key) {
			t.Fatalf("mainnet %v: released a key version other than the checked one", o.Mainnet)
		}
		if rule == nil || rule.Hash == ([32]byte{}) {
			t.Fatalf("mainnet %v: no key rule", o.Mainnet)
		}
	}
	for _, p := range f.kv.paths {
		if p != "/keys/signer-kek-1/"+testKeyVersion+"/release" {
			t.Fatalf("release path %s, want the checked version", p)
		}
	}
}

// A release that gives another key than the one Get Key described (a
// vault, or a path to it, that does not keep to the version asked for)
// stops the start.
func TestReleasedKeyMustBeTheCheckedKey(t *testing.T) {
	f := newKVFixture(t)
	f.kv.immutable = true
	f.kv.lie = testRSA(t)
	_, _, err := releaseChecked(context.Background(), mainnetOptions, f.releaser, "signer-kek-1/"+testKeyVersion)
	if err == nil || !strings.Contains(err.Error(), "not the key") {
		t.Fatalf("another key released: %v", err)
	}
}

// A mainnet setup names the key version: the setup, which approvers sign,
// then fixes the key, not the vault's newest version at start.
func TestMainnetNeedsAVersionedKid(t *testing.T) {
	f := newKVFixture(t)
	f.kv.immutable = true
	_, _, err := releaseChecked(context.Background(), mainnetOptions, f.releaser, "signer-kek-1")
	if err == nil || !strings.Contains(err.Error(), "version") {
		t.Fatalf("mainnet start with a kid without version: %v", err)
	}
	if len(f.kv.paths) != 0 {
		t.Fatalf("released before the kid check: %v", f.kv.paths)
	}
}

// A versioned kid whose Get Key answer names another version is refused.
func TestGetKeyAnswerOfAnotherVersion(t *testing.T) {
	f := newKVFixture(t)
	f.kv.immutable = true
	// The fake answers Get Key of the bare name; ask for another version
	// through a vault that answers it with testKeyVersion.
	if _, err := checkedVersion("signer-kek-1/"+newerKeyVersion, "https://"+f.kv.host()+"/keys/signer-kek-1/"+testKeyVersion); err == nil {
		t.Fatal("Get Key answer of another version accepted")
	}
	if _, err := checkedVersion("signer-kek-1", "https://"+f.kv.host()+"/keys/other-key/"+testKeyVersion); err == nil {
		t.Fatal("Get Key answer of another key accepted")
	}
	if v, err := checkedVersion("signer-kek-1", "https://"+f.kv.host()+"/keys/signer-kek-1/"+testKeyVersion); err != nil || v != testKeyVersion {
		t.Fatalf("bare name: %q %v", v, err)
	}
}
