package azure

import (
	"bytes"
	"context"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"strings"
	"testing"

	"github.com/lidofinance/tee-signer/platform"
	"github.com/lidofinance/tee-signer/platform/filestore"
)

func b64(n *big.Int) string { return base64.RawURLEncoding.EncodeToString(n.Bytes()) }

// fakeReleaser releases one key, like Key Vault with a policy that the
// caller meets.
type fakeReleaser struct {
	name string
	key  *rsa.PrivateKey
}

func (f fakeReleaser) ReleaseKey(_ context.Context, name string) (*rsa.PrivateKey, error) {
	if name != f.name {
		return nil, errors.New("no such key " + name)
	}
	return f.key, nil
}

// setupA and setupB are two setup_hash values over the same Key Vault key.
var setupA, setupB = [32]byte{0xa}, [32]byte{0xb}

func TestDataKeyStaysTheSameAcrossBoots(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	rel := fakeReleaser{"signer-kek", key}
	ctx := context.Background()

	dek1, wrap1, err := dataKey(ctx, rel, "signer-kek", setupA)
	if err != nil {
		t.Fatal(err)
	}
	dek2, wrap2, err := dataKey(ctx, rel, "signer-kek", setupA)
	if err != nil || !bytes.Equal(dek1, dek2) || len(dek1) != 32 {
		t.Fatalf("data key not stable across boots: %v", err)
	}
	if !bytes.Equal(wrap1, wrap2) || len(wrap1) != 32 || bytes.Equal(wrap1, dek1) {
		t.Fatal("wrapping key not stable, or equal to the data key")
	}
	if _, _, err := dataKey(ctx, rel, "other", setupA); err == nil {
		t.Fatal("release of another key accepted")
	}
	// Another released key (a key that was recreated) gives other keys.
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	dek3, wrap3, err := dataKey(ctx, fakeReleaser{"signer-kek", other}, "signer-kek", setupA)
	if err != nil || bytes.Equal(dek3, dek1) || bytes.Equal(wrap3, wrap1) {
		t.Fatalf("another released key gave the same keys: %v", err)
	}
}

// A second setup over the same Key Vault key derives other keys: nothing
// the first setup's runner sealed opens under the second's sealer, and no
// key the first wrapped (the mark log's, the state copy's) opens under the
// second's platform.Keys.
func TestAnotherSetupOpensNothing(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	rel := fakeReleaser{"signer-kek", key}
	ctx := context.Background()
	sealerOf := func(setup [32]byte) (platform.Sealer, platform.Keys) {
		dek, wrap, err := dataKey(ctx, rel, "signer-kek", setup)
		if err != nil {
			t.Fatal(err)
		}
		s, _ := platform.NewGCMSealer(dek)
		w, _ := platform.NewGCMSealer(wrap)
		return s, platform.SealerKeys{Sealer: w}
	}
	sealA, keysA := sealerOf(setupA)
	sealB, keysB := sealerOf(setupB)
	blob, err := sealA.Seal([]byte("a share"), []byte("aad"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sealB.Unseal(blob, []byte("aad")); err == nil {
		t.Fatal("the second setup unsealed the first setup's data")
	}
	if got, err := sealA.Unseal(blob, []byte("aad")); err != nil || string(got) != "a share" {
		t.Fatalf("the first setup: %q %v", got, err)
	}
	_, kblob, err := keysA.NewKey(ctx, []byte("mark key aad"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := keysB.OpenKey(ctx, kblob, []byte("mark key aad")); !errors.Is(err, platform.ErrNotAuthentic) {
		t.Fatalf("the second setup opened the first setup's wrapped key: %v", err)
	}
}

// The planting path of review A: before, the sealing data key was a random
// key wrapped with RSA-OAEP to the released key's public half, label
// "signer-runner dek", stored at sealing/dek.azure-rsa. Anyone with the
// public key could make such a blob and put it in a host-writable state
// folder before the first start; the runner then sealed under a key the
// host knew. Now the data key is derived: a planted blob under the old name
// (or any name) is never read, and the sealer's key is not the planted one.
func TestPlantedDataKeyIsNotUsed(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	planted := bytes.Repeat([]byte{0x42}, 32)
	blob, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &key.PublicKey, planted, []byte("signer-runner dek"))
	if err != nil {
		t.Fatal(err)
	}
	store, _ := filestore.New(t.TempDir())
	if err := store.Put("sealing/dek.azure-rsa", blob); err != nil {
		t.Fatal(err)
	}
	dek, _, err := dataKey(context.Background(), fakeReleaser{"signer-kek", key}, "signer-kek", setupA)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(dek, planted) {
		t.Fatal("the runner seals under the planted key")
	}
	// What the host can seal with the planted key does not open under the
	// runner's sealer, so the host cannot feed it data either.
	hostSealer, _ := platform.NewGCMSealer(planted)
	runner, _ := platform.NewGCMSealer(dek)
	forged, _ := hostSealer.Seal([]byte("forged share"), []byte("aad"))
	if _, err := runner.Unseal(forged, []byte("aad")); err == nil {
		t.Fatal("the runner opened data sealed under the planted key")
	}
}

// The wrapping key of platform.Keys comes from the released key and the
// setup alone: a boot with an empty store derives the same one and opens
// what an earlier boot wrapped, a boot that gets another key does not.
func TestKeysSurviveALostStore(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	rel := fakeReleaser{"signer-kek", key}
	ctx := context.Background()
	keysOf := func(rel KeyReleaser) platform.Keys {
		_, wrap, err := dataKey(ctx, rel, "signer-kek", setupA)
		if err != nil {
			t.Fatal(err)
		}
		s, _ := platform.NewGCMSealer(wrap)
		return platform.SealerKeys{Sealer: s}
	}
	aad := []byte("signer-mark-key-v1|signer-1")
	k1, blob, err := keysOf(rel).NewKey(ctx, aad)
	if err != nil {
		t.Fatal(err)
	}
	k2, err := keysOf(rel).OpenKey(ctx, blob, aad)
	if err != nil || !bytes.Equal(k1, k2) {
		t.Fatalf("after a lost store: %v", err)
	}
	if _, err := keysOf(rel).OpenKey(ctx, blob, []byte("signer-mark-key-v1|signer-2")); !errors.Is(err, platform.ErrNotAuthentic) {
		t.Fatalf("another signer's aad: %v", err)
	}
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	if _, err := keysOf(fakeReleaser{"signer-kek", other}).OpenKey(ctx, blob, aad); !errors.Is(err, platform.ErrNotAuthentic) {
		t.Fatalf("another released key: %v", err)
	}
}

// The derivation is HKDF-SHA256 over the private exponent with the
// registry's contexts and setup_hash as info, so another implementation
// (a verifier's test, the TA) can recompute it.
func TestDerivedKeysVector(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	dek, wrap, err := derivedKeys(key, setupA)
	if err != nil {
		t.Fatal(err)
	}
	info := func(name string) string {
		return string(append(append([]byte{0, byte(len(name))}, name...), setupA[:]...))
	}
	wantDek, _ := hkdf.Key(sha256.New, key.D.Bytes(), nil, info("signer-runner azure sealing v1"), 32)
	wantWrap, _ := hkdf.Key(sha256.New, key.D.Bytes(), nil, info("signer-runner azure key wrap v1"), 32)
	if !bytes.Equal(dek, wantDek) || !bytes.Equal(wrap, wantWrap) {
		t.Fatal("the derivation is not HKDF over the registry's contexts and setup_hash")
	}
}

// The whole path, in process: hardware report, MAA, managed identity, Key
// Vault, unwrap, then the derived data key. Everything runs against the
// fakes; only the endpoints differ from Azure.
func TestDataKeyFromTheFullRelease(t *testing.T) {
	f := newKVFixture(t)
	dek1, _, err := dataKey(context.Background(), f.releaser, "signer-kek-1", setupA)
	if err != nil {
		t.Fatal(err)
	}
	dek2, _, err := dataKey(context.Background(), f.releaser, "signer-kek-1", setupA)
	if err != nil || !bytes.Equal(dek1, dek2) {
		t.Fatalf("the data key changed: %v", err)
	}
	if n := len(f.kv.seenTargets()); n != 2 {
		t.Fatalf("%d releases for two boots", n)
	}
}

func TestCheckOptions(t *testing.T) {
	good := map[string]string{"maa_endpoint": "x", "akv_endpoint": "y", "kid": "k", "clock": "system", "client_id": "z"}
	if err := checkOptions(good); err != nil {
		t.Fatal(err)
	}
	if err := checkOptions(map[string]string{"maa_endpont": "x"}); err == nil || !strings.Contains(err.Error(), "unknown platform option") {
		t.Fatalf("typo: %v", err)
	}
	// The test options exist in the debug build only.
	err := checkOptions(map[string]string{"test_imds_url": "http://127.0.0.1:1", "test_snp_hostdata": strings.Repeat("00", 32)})
	if (len(debugOptions) == 0) != (err != nil) {
		t.Fatalf("test options with %d debug options: %v", len(debugOptions), err)
	}
}

func TestNewRefusesBadSettings(t *testing.T) {
	ok := func() map[string]string {
		return map[string]string{"maa_endpoint": "sharedneu.neu.attest.azure.net", "akv_endpoint": "signer-poc-kv.vault.azure.net", "kid": "signer-kek-1"}
	}
	for name, mod := range map[string]func(map[string]string){
		"no maa_endpoint":         func(p map[string]string) { delete(p, "maa_endpoint") },
		"no akv_endpoint":         func(p map[string]string) { delete(p, "akv_endpoint") },
		"no kid":                  func(p map[string]string) { delete(p, "kid") },
		"scheme in maa_endpoint":  func(p map[string]string) { p["maa_endpoint"] = "https://sharedneu.neu.attest.azure.net" },
		"path in akv_endpoint":    func(p map[string]string) { p["akv_endpoint"] = "v.vault.azure.net/keys" },
		"userinfo in endpoint":    func(p map[string]string) { p["maa_endpoint"] = "evil@host" },
		"query in kid":            func(p map[string]string) { p["kid"] = "k?x=1" },
		"slash in kid":            func(p map[string]string) { p["kid"] = "../keys/other" },
		"client id with a quote":  func(p map[string]string) { p["client_id"] = `a"b` },
		"the old sidecar address": func(p map[string]string) { p["skr_url"] = "http://localhost:8080" },
	} {
		p := ok()
		mod(p)
		if _, err := New(platform.Options{StateDir: t.TempDir(), Params: p}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	for _, good := range []string{"signer-kek-1", "signer-kek-1/0123456789abcdef0123456789abcdef"} {
		if !kidRE.MatchString(good) {
			t.Errorf("kid %q refused", good)
		}
	}
	for _, good := range []string{"sharedweu.weu.attest.azure.net", "127.0.0.1:8443", "localhost"} {
		if !hostRE.MatchString(good) {
			t.Errorf("host %q refused", good)
		}
	}
}

func TestParseRSAJWK(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	got, err := parseRSAJWK([]byte(jwkOf(key)))
	if err != nil || got.N.Cmp(key.N) != 0 || got.D.Cmp(key.D) != 0 {
		t.Fatal(err)
	}
	if _, err := parseRSAJWK([]byte(`{"kty":"EC"}`)); err == nil {
		t.Fatal("EC key accepted")
	}
	var m map[string]any
	json.Unmarshal([]byte(jwkOf(key)), &m)
	m["d"] = b64(big.NewInt(12345))
	bad, _ := json.Marshal(m)
	if _, err := parseRSAJWK(bad); err == nil {
		t.Fatal("key with a wrong private exponent accepted")
	}
}

// Key Vault releases a JWK whose key_ops member is an array.
func TestParseRSAJWKKeyOpsArray(t *testing.T) {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	b64 := func(x []byte) string { return base64.RawURLEncoding.EncodeToString(x) }
	k.Precompute()
	jwk, _ := json.Marshal(map[string]any{
		"kty": "RSA-HSM", "key_ops": []string{"encrypt", "decrypt", "wrapKey", "unwrapKey"},
		"n": b64(k.N.Bytes()), "e": b64(big.NewInt(int64(k.E)).Bytes()),
		"d": b64(k.D.Bytes()), "p": b64(k.Primes[0].Bytes()), "q": b64(k.Primes[1].Bytes()),
		"dp": b64(k.Precomputed.Dp.Bytes()), "dq": b64(k.Precomputed.Dq.Bytes()), "qi": b64(k.Precomputed.Qinv.Bytes()),
	})
	got, err := parseRSAJWK(jwk)
	if err != nil {
		t.Fatalf("parseRSAJWK: %v", err)
	}
	if got.N.Cmp(k.N) != 0 || got.D.Cmp(k.D) != 0 {
		t.Fatal("key differs")
	}
}
