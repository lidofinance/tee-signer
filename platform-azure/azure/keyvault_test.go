package azure

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/platform/jwtclaims"
	"github.com/lidofinance/tee-signer/signer-protocol"
)

// kvFixture wires a fake MAA, a fake Key Vault and a Releaser, the whole
// in-process release, over TLS to local servers.
type kvFixture struct {
	maa      *maaFixture
	kv       *fakeKV
	key      *rsa.PrivateKey
	tokens   *fakeTokens
	releaser *Releaser
}

const testHostData = "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a"

func newKVFixture(t *testing.T) *kvFixture {
	t.Helper()
	m := newMAAFixture(t)
	key := testRSA(t)
	kvfx := newTLSFixture(t)
	kv := newFakeKV(t, kvfx, "signer-kek-1", key)
	kv.hostData = testHostData
	tokens := &fakeTokens{token: kv.accessToken}
	return &kvFixture{maa: m, kv: kv, key: key, tokens: tokens, releaser: &Releaser{MAA: m.client,
		KV: &KeyVault{Endpoint: kv.host(), Tokens: tokens, HTTP: kv.srv.Client(), Roots: kvfx.pool}}}
}

func samePrivateKey(a, b *rsa.PrivateKey) bool { return a.N.Cmp(b.N) == 0 && a.D.Cmp(b.D) == 0 }

func TestReleaseKeyInProcess(t *testing.T) {
	for _, tc := range []struct{ name, enc, alg string }{
		{"default wrap, PS256", "", "PS256"},
		{"CKM_RSA_AES_KEY_WRAP, RS256", "CKM_RSA_AES_KEY_WRAP", "RS256"},
		{"SHA-256 wrap", "RSA_AES_KEY_WRAP_256", "PS256"},
		{"SHA-384 wrap", "RSA_AES_KEY_WRAP_384", "PS256"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newKVFixture(t)
			f.kv.enc, f.kv.alg = tc.enc, tc.alg
			got, err := f.releaser.ReleaseKey(context.Background(), "signer-kek-1")
			if err != nil {
				t.Fatal(err)
			}
			if !samePrivateKey(got, f.key) {
				t.Fatal("another key came back")
			}
			// What went to Key Vault: the MAA token over the hardware report,
			// and the managed identity token for the vault resource.
			if len(f.tokens.resource) != 1 || f.tokens.resource[0] != "https://vault.azure.net" {
				t.Fatalf("identity token for %v", f.tokens.resource)
			}
			targets := f.kv.seenTargets()
			if len(targets) != 1 {
				t.Fatalf("%d release requests", len(targets))
			}
			c, err := jwtclaims.Claims(targets[0])
			if err != nil || c["x-ms-sevsnpvm-hostdata"] != testHostData || c["x-ms-compliance-status"] != "azure-compliant-uvm" {
				t.Fatalf("target claims %v, %v", c, err)
			}
		})
	}
}

// A release offers a fresh wrapping key: the MAA token of each release has a
// different key and kid in x-ms-runtime, so a recorded answer cannot be
// opened later.
func TestFreshWrappingKeyPerRelease(t *testing.T) {
	f := newKVFixture(t)
	for i := 0; i < 2; i++ {
		if _, err := f.releaser.ReleaseKey(context.Background(), "signer-kek-1"); err != nil {
			t.Fatal(err)
		}
	}
	var kids, ns []string
	for _, tok := range f.kv.seenTargets() {
		c, _ := jwtclaims.Claims(tok)
		k := c["x-ms-runtime"].(map[string]any)["keys"].([]any)[0].(map[string]any)
		kids = append(kids, k["kid"].(string))
		ns = append(ns, k["n"].(string))
	}
	if len(kids) != 2 || kids[0] == kids[1] || ns[0] == ns[1] {
		t.Fatalf("wrapping keys repeat: %v", kids)
	}
}

func TestReleaseRefusals(t *testing.T) {
	ctx := context.Background()
	t.Run("release policy says no", func(t *testing.T) {
		f := newKVFixture(t)
		f.kv.hostData = strings.Repeat("00", 32)
		_, err := f.releaser.ReleaseKey(ctx, "signer-kek-1")
		if err == nil || !strings.Contains(err.Error(), "release policy") || !strings.Contains(err.Error(), "403") {
			t.Fatal(err)
		}
	})
	t.Run("wrong key name", func(t *testing.T) {
		f := newKVFixture(t)
		if _, err := f.releaser.ReleaseKey(ctx, "other-key"); err == nil || !strings.Contains(err.Error(), "404") {
			t.Fatal(err)
		}
	})
	t.Run("identity token fails", func(t *testing.T) {
		f := newKVFixture(t)
		f.tokens.err = fmt.Errorf("no identity")
		if _, err := f.releaser.ReleaseKey(ctx, "signer-kek-1"); err == nil || !strings.Contains(err.Error(), "no identity") {
			t.Fatal(err)
		}
	})
	t.Run("bad bearer token", func(t *testing.T) {
		f := newKVFixture(t)
		f.tokens.token = "someone else"
		if _, err := f.releaser.ReleaseKey(ctx, "signer-kek-1"); err == nil || !strings.Contains(err.Error(), "401") {
			t.Fatal(err)
		}
	})
	t.Run("answer signed by a key the certificate does not hold", func(t *testing.T) {
		f := newKVFixture(t)
		f.kv.signKey = testRSA(t)
		if _, err := f.releaser.ReleaseKey(ctx, "signer-kek-1"); err == nil || !strings.Contains(err.Error(), "signature") {
			t.Fatal(err)
		}
	})
	t.Run("certificate that no trusted root issued", func(t *testing.T) {
		f := newKVFixture(t)
		f.releaser.KV.Roots = newTLSFixture(t).pool
		if _, err := f.releaser.ReleaseKey(ctx, "signer-kek-1"); err == nil || !strings.Contains(err.Error(), "certificate chain") {
			t.Fatal(err)
		}
	})
	t.Run("expired certificate", func(t *testing.T) {
		f := newKVFixture(t)
		f.releaser.KV.Now = func() time.Time { return time.Now().Add(72 * time.Hour) }
		if _, err := f.releaser.ReleaseKey(ctx, "signer-kek-1"); err == nil || !strings.Contains(err.Error(), "certificate chain") {
			t.Fatal(err)
		}
	})
	t.Run("JWS algorithm that is not supported", func(t *testing.T) {
		f := newKVFixture(t)
		f.kv.alg = "ES256"
		if _, err := f.releaser.ReleaseKey(ctx, "signer-kek-1"); err == nil || !strings.Contains(err.Error(), "not supported") {
			t.Fatal(err)
		}
	})
	t.Run("answer without x5c", func(t *testing.T) {
		f := newKVFixture(t)
		f.kv.x5c = nil
		if _, err := f.releaser.ReleaseKey(ctx, "signer-kek-1"); err == nil || !strings.Contains(err.Error(), "x5c") {
			t.Fatal(err)
		}
	})
	t.Run("key wrapped to somebody else's key", func(t *testing.T) {
		f := newKVFixture(t)
		other := testRSA(t)
		f.kv.wrapTo = &other.PublicKey
		if _, err := f.releaser.ReleaseKey(ctx, "signer-kek-1"); err == nil || !strings.Contains(err.Error(), "key encryption key") {
			t.Fatal(err)
		}
	})
	t.Run("unknown key wrap algorithm", func(t *testing.T) {
		f := newKVFixture(t)
		f.kv.enc = "SOMETHING_ELSE"
		if _, err := f.releaser.ReleaseKey(ctx, "signer-kek-1"); err == nil || !strings.Contains(err.Error(), "SOMETHING_ELSE") {
			t.Fatal(err)
		}
	})
}

func TestReleasedKeyAsJWK(t *testing.T) {
	f := newKVFixture(t)
	f.kv.jwk = true
	got, err := f.releaser.ReleaseKey(context.Background(), "signer-kek-1")
	if err != nil || !samePrivateKey(got, f.key) {
		t.Fatal(err)
	}
}

func TestVerifyJWSMalformed(t *testing.T) {
	kv := &KeyVault{Endpoint: "vault.test"}
	for _, s := range []string{"", "a.b", "a.b.c.d", "!!.e30.e30", "e30.e30.e30", "eyJ4NWMiOlsiISEiXX0.e30.e30"} {
		if _, err := kv.verifyJWS(s); err == nil {
			t.Errorf("%q accepted", s)
		}
	}
}

func TestWrapKeyRuntimeData(t *testing.T) {
	k := testRSA(t)
	rt, err := wrapKeyRuntimeData(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.Unmarshal(rt, &doc); err != nil || len(doc.Keys) != 1 {
		t.Fatal(err, string(rt))
	}
	j := doc.Keys[0]
	if len(j) != 5 || j["kty"] != "RSA" || j["e"] != "AQAB" || fmt.Sprint(j["key_ops"]) != "[encrypt]" {
		t.Fatalf("jwk %v", j)
	}
	n, _ := base64.RawURLEncoding.DecodeString(j["n"].(string))
	if new(big.Int).SetBytes(n).Cmp(k.N) != 0 {
		t.Fatal("n differs")
	}
	// kid is the RFC 7638 thumbprint: SHA-256 of the members e, kty, n in
	// that order, without white space.
	sum := sha256.Sum256([]byte(`{"e":"AQAB","kty":"RSA","n":"` + j["n"].(string) + `"}`))
	if j["kid"] != base64.RawURLEncoding.EncodeToString(sum[:]) {
		t.Fatalf("kid %v", j["kid"])
	}
	// MAA reads runtime data of type JSON, so it is a JSON object whose keys
	// are sorted, as in Microsoft's sample token.
	if !strings.HasPrefix(string(rt), `{"keys":[{"e":"AQAB","key_ops":["encrypt"],"kid":"`) {
		t.Fatalf("runtime data %s", rt)
	}
}

func TestParseReleasedKey(t *testing.T) {
	k := testRSA(t)
	der, _ := x509.MarshalPKCS8PrivateKey(k)
	got, err := parseReleasedKey(der)
	if err != nil || !samePrivateKey(got, k) {
		t.Fatal(err)
	}
	got, err = parseReleasedKey([]byte(" \n" + jwkOf(k) + "\n"))
	if err != nil || !samePrivateKey(got, k) {
		t.Fatal(err)
	}
	// An EC key, an AES key and noise are no RSA keys.
	ec := testEC(t)
	if _, err := parseReleasedKey(ec); err == nil || !strings.Contains(err.Error(), "not an RSA key") {
		t.Fatalf("EC key: %v", err)
	}
	for _, bad := range [][]byte{nil, []byte("secret"), bytes.Repeat([]byte{1}, 32)} {
		if _, err := parseReleasedKey(bad); err == nil {
			t.Errorf("%x accepted", bad)
		}
	}
}

func testEC(t *testing.T) []byte {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestUnwrapNeedsAllParts(t *testing.T) {
	k := testRSA(t)
	for _, p := range []string{`{}`, `{"response":{"key":{"key":{}}}}`, `{"response":{"key":{"key":{"key_hsm":"!!"}}}}`,
		`{"response":{"key":{"key":{"key_hsm":"` + b64raw([]byte(`{"ciphertext":""}`)) + `"}}}}`, `not json`} {
		if _, err := unwrapReleased([]byte(p), k); err == nil {
			t.Errorf("payload %s accepted", p)
		}
	}
	// A wrapped blob that is as short as the RSA part.
	if _, err := rsaAESUnwrap("", make([]byte, k.Size()), k); err == nil {
		t.Error("short blob accepted")
	}
	// The wrong OAEP hash does not decrypt.
	kek := make([]byte, 32)
	rand.Read(kek)
	ct, _ := rsa.EncryptOAEP(oaepHash("RSA_AES_KEY_WRAP_256"), rand.Reader, &k.PublicKey, kek, nil)
	if _, err := rsaAESUnwrap("CKM_RSA_AES_KEY_WRAP", append(ct, make([]byte, 24)...), k); err == nil {
		t.Error("an OAEP hash mismatch was accepted")
	}
}

// signJWS makes a compact JWS the way Key Vault does, with the chain in x5c.
func signJWS(t *testing.T, fx *tlsFixture, alg string, payload []byte) string {
	t.Helper()
	hdr, _ := json.Marshal(map[string]any{"alg": alg, "x5c": []string{base64.StdEncoding.EncodeToString(fx.leaf.Raw)}})
	signed := b64raw(hdr) + "." + b64raw(payload)
	sum := sha256.Sum256([]byte(signed))
	sig, err := rsa.SignPSS(rand.Reader, fx.key, crypto.SHA256, sum[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
	if err != nil {
		t.Fatal(err)
	}
	return signed + "." + b64raw(sig)
}

// The leaf of the x5c chain must be valid for the vault's name; a port in
// the endpoint does not count.
func TestVerifyJWSHostName(t *testing.T) {
	fx := newTLSFixture(t)
	jws := signJWS(t, fx, "PS256", []byte(`{"a":1}`))
	for _, ok := range []string{"vault.test", "vault.test:443", "127.0.0.1:8443"} {
		got, err := (&KeyVault{Endpoint: ok, Roots: fx.pool}).verifyJWS(jws)
		if err != nil || string(got) != `{"a":1}` {
			t.Errorf("%s: %q, %v", ok, got, err)
		}
	}
	for _, bad := range []string{"other.example", "vault.test.evil.example", "evil-vault.test"} {
		if _, err := (&KeyVault{Endpoint: bad, Roots: fx.pool}).verifyJWS(jws); err == nil || !strings.Contains(err.Error(), "certificate chain") {
			t.Errorf("%s: %v", bad, err)
		}
	}
}

// key_release_hash is over Get Key's key id, exportable flag, release
// policy and immutable flag; an immutable or another policy gives another
// hash, and an identity without read access gets an error, not a hash.
func TestKeyReleaseHash(t *testing.T) {
	f := newKVFixture(t)
	ctx := context.Background()
	kv := f.releaser.KV
	r, err := kv.KeyRule(ctx, "signer-kek-1")
	if err != nil {
		t.Fatal(err)
	}
	h := r.Hash
	policy := `{"version":"1.0.0","anyOf":[{"authority":"https://` + f.kv.host() + `","allOf":[{"claim":"x-ms-sevsnpvm-hostdata","equals":"` + testHostData + `"}]}]}`
	want := backend.KeyReleaseHash(backend.KeyReleaseAzure, []byte("https://"+f.kv.host()+"/keys/signer-kek-1/0123456789abcdef0123456789abcdef"),
		[]byte{1}, []byte{0}, []byte("application/json; charset=utf-8"), []byte(policy))
	if h != want {
		t.Fatalf("key_release_hash %x, want %x", h, want)
	}
	if r.Lock != backend.KeyLockNotLocked || !strings.Contains(r.Why, "immutable is false") {
		t.Fatalf("mutable policy: lock %s %q", r.Lock, r.Why)
	}
	if f.tokens.resource[len(f.tokens.resource)-1] != "https://vault.azure.net" {
		t.Fatalf("identity token for %v", f.tokens.resource)
	}
	f.kv.immutable = true
	if got, err := kv.KeyRule(ctx, "signer-kek-1"); err != nil || got.Hash == h || got.Lock != backend.KeyLockLocked {
		t.Fatalf("immutable: %+v %v, want another hash, locked", got, err)
	}
	f.kv.policy = `{"version":"1.0.0","anyOf":[]}`
	if got, err := kv.KeyRule(ctx, "signer-kek-1"); err != nil || got.Hash == h {
		t.Fatalf("another policy: %x %v, want another hash", got.Hash, err)
	}
	f.kv.noRead = true
	if _, err := kv.KeyRule(ctx, "signer-kek-1"); err == nil || !strings.Contains(err.Error(), "get key") {
		t.Fatalf("no read access: %v", err)
	}
	if _, err := kv.KeyRule(ctx, "another-key"); err == nil {
		t.Fatal("another key name answered")
	}
}

// The lock is release_policy.immutable of the Get Key answer: true is
// locked; false or absent is not. An answer without a policy is an error.
func TestKeyRuleOfFixtures(t *testing.T) {
	data := base64.RawURLEncoding.EncodeToString([]byte(`{"version":"1.0.0","anyOf":[]}`))
	answer := func(rp string) []byte {
		return []byte(`{"key":{"kid":"https://v.vault.azure.net/keys/k/1"},"attributes":{"exportable":true},"release_policy":` + rp + `}`)
	}
	for _, c := range []struct {
		name, rp string
		want     backend.KeyLock
	}{
		{"immutable", `{"contentType":"application/json; charset=utf-8","data":"` + data + `","immutable":true}`, backend.KeyLockLocked},
		{"mutable", `{"contentType":"application/json; charset=utf-8","data":"` + data + `","immutable":false}`, backend.KeyLockNotLocked},
		{"flag absent", `{"contentType":"application/json; charset=utf-8","data":"` + data + `"}`, backend.KeyLockNotLocked},
	} {
		r, _, err := keyRuleOf(answer(c.rp))
		if err != nil || r.Lock != c.want || r.Hash == ([32]byte{}) {
			t.Errorf("%s: %+v %v, want %s", c.name, r, err, c.want)
		}
	}
	if _, _, err := keyRuleOf(answer(`null`)); err == nil {
		t.Error("an answer without a release policy gave a rule")
	}
}
