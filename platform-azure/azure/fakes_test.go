package azure

// Fakes shared by the tests: SNP hardware, collateral, MAA, Key Vault and
// the metadata service. Each fake checks the request fields the real
// service needs, so a test fails when the runner sends something else.

import (
	"bytes"
	"context"
	"crypto"
	"crypto/aes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/platform/jwtclaims"
)

func init() { retryDelay = time.Millisecond }

const testTCBM = "1c01000000000004"

var testTCB uint64 = 0x1c01000000000004

// ---- SNP hardware ----

type testReports struct {
	mu       sync.Mutex
	hostData [32]byte
	err      error
	// tamper changes the report before it is returned.
	tamper func(report []byte)
	calls  [][reportDataSize]byte
}

func (f *testReports) Report(rd [reportDataSize]byte) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, rd)
	if f.err != nil {
		return nil, f.err
	}
	r := make([]byte, reportSize)
	binary.LittleEndian.PutUint32(r[0:], 2)
	copy(r[reportDataOffset:], rd[:])
	copy(r[hostDataOffset:], f.hostData[:])
	binary.LittleEndian.PutUint64(r[reportedTCBOffset:], testTCB)
	if f.tamper != nil {
		f.tamper(r)
	}
	return r, nil
}

func (f *testReports) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

// ---- collateral ----

type fakeCollateral struct {
	col *Collateral
	err error
	tcb []uint64
}

func (f *fakeCollateral) Collateral(_ context.Context, tcb uint64) (*Collateral, error) {
	f.tcb = append(f.tcb, tcb)
	return f.col, f.err
}

const (
	testVCEK  = "-----BEGIN CERTIFICATE-----\nVkNFSw==\n-----END CERTIFICATE-----\n"
	testChain = "-----BEGIN CERTIFICATE-----\nQVNL\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nQVJL\n-----END CERTIFICATE-----\n"
)

func testCollateral() *Collateral {
	return &Collateral{CertChain: []byte(testVCEK + testChain), UVMReferenceInfo: []byte("cose-sign1 uvm reference info")}
}

// ---- keys, certificates, tokens ----

func testRSA(t testing.TB) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func b64raw(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func signJWT(t testing.TB, key *rsa.PrivateKey, claims map[string]any) string {
	t.Helper()
	hdr, _ := json.Marshal(map[string]any{"alg": "RS256", "kid": "maa-test", "typ": "JWT"})
	pl, _ := json.Marshal(claims)
	signed := b64raw(hdr) + "." + b64raw(pl)
	sum := sha256.Sum256([]byte(signed))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return signed + "." + b64raw(sig)
}

// tlsFixture is a self-signed server certificate for 127.0.0.1 that is also
// the root of its own chain.
type tlsFixture struct {
	cert tls.Certificate
	leaf *x509.Certificate
	key  *rsa.PrivateKey
	pool *x509.CertPool
}

func newTLSFixture(t testing.TB) *tlsFixture {
	t.Helper()
	key := testRSA(t)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "vault.test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:        true, BasicConstraintsValid: true,
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, DNSNames: []string{"vault.test"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return &tlsFixture{cert: tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, leaf: leaf, key: key, pool: pool}
}

func startTLS(t testing.TB, fx *tlsFixture, h http.Handler) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(h)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{fx.cert}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

func hostOf(srv *httptest.Server) string { return strings.TrimPrefix(srv.URL, "https://") }

// ---- MAA ----

// fakeMAA answers POST /attest/SevSnpVM after it has checked the request the
// way the real service needs it: the encodings, the report, the report data,
// the collateral and the runtime data type.
type fakeMAA struct {
	t   testing.TB
	srv *httptest.Server
	key *rsa.PrivateKey
	// want is the collateral the request must carry.
	want *Collateral
	// status, if set, is answered instead (once per entry, in order).
	statuses []int
	// reportDataClaim, if set, replaces the claim of the token.
	reportDataClaim string
	iat             int64

	mu       sync.Mutex
	requests []maaSeen
}

type maaSeen struct {
	path, query, contentType string
	runtime                  []byte // runtimeData.data decoded
	report                   []byte
	certChain, endorsement   []byte
	nonce                    uint64
	rawBody                  []byte
}

func newFakeMAA(t testing.TB, fx *tlsFixture, want *Collateral) *fakeMAA {
	m := &fakeMAA{t: t, key: testRSA(t), want: want, iat: time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC).Unix()}
	m.srv = startTLS(t, fx, http.HandlerFunc(m.serve))
	return m
}

func (m *fakeMAA) host() string { return hostOf(m.srv) }

func (m *fakeMAA) seen() []maaSeen {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]maaSeen(nil), m.requests...)
}

func (m *fakeMAA) serve(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	m.mu.Lock()
	if len(m.statuses) > 0 {
		st := m.statuses[0]
		m.statuses = m.statuses[1:]
		m.mu.Unlock()
		http.Error(w, `{"error":{"code":"Test","message":"fake failure"}}`, st)
		return
	}
	m.mu.Unlock()
	fail := func(format string, a ...any) {
		http.Error(w, fmt.Sprintf(`{"error":{"code":"InvalidParameter","message":%q}}`, fmt.Sprintf(format, a...)), http.StatusBadRequest)
	}
	if r.Method != http.MethodPost || r.URL.Path != "/attest/SevSnpVM" {
		fail("bad route %s %s", r.Method, r.URL.Path)
		return
	}
	var req struct {
		Report       string `json:"report"`
		RuntimeData  struct{ Data, DataType string }
		InitTimeData struct{ Data, DataType string } `json:"initTimeData"`
		Nonce        uint64                          `json:"nonce"`
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	if err := dec.Decode(&req); err != nil {
		fail("body: %v", err)
		return
	}
	if req.RuntimeData.DataType != "JSON" {
		fail("runtimeData.dataType %q", req.RuntimeData.DataType)
		return
	}
	d64 := base64.URLEncoding.DecodeString // padded, as MAA gets it from the sidecar
	runtime, err := d64(req.RuntimeData.Data)
	var obj map[string]any
	if err != nil || json.Unmarshal(runtime, &obj) != nil || obj == nil {
		fail("runtimeData.data is not base64url of a JSON object")
		return
	}
	repJSON, err := d64(req.Report)
	if err != nil {
		fail("report is not base64url: %v", err)
		return
	}
	var rep struct{ SnpReport, VcekCertChain, Endorsements string }
	if err := json.Unmarshal(repJSON, &rep); err != nil {
		fail("report is not JSON: %v", err)
		return
	}
	report, err1 := d64(rep.SnpReport)
	chain, err2 := d64(rep.VcekCertChain)
	endJSON, err3 := d64(rep.Endorsements)
	if err1 != nil || err2 != nil || err3 != nil || len(report) != reportSize {
		fail("report parts do not decode")
		return
	}
	var end struct{ Uvm []string }
	if err := json.Unmarshal(endJSON, &end); err != nil || len(end.Uvm) != 1 {
		fail("endorsements: %v", err)
		return
	}
	uvm, err := d64(end.Uvm[0])
	if err != nil {
		fail("uvm endorsement: %v", err)
		return
	}
	sum := sha256.Sum256(runtime)
	rd := report[reportDataOffset : reportDataOffset+reportDataSize]
	if !bytes.Equal(rd[:32], sum[:]) || !bytes.Equal(rd[32:], make([]byte, 32)) {
		fail("report data is not SHA-256(runtime data) and zeros")
		return
	}
	if m.want != nil && (!bytes.Equal(chain, m.want.CertChain) || !bytes.Equal(uvm, m.want.UVMReferenceInfo)) {
		fail("collateral differs from the host's")
		return
	}
	m.mu.Lock()
	m.requests = append(m.requests, maaSeen{path: r.URL.Path, query: r.URL.RawQuery, contentType: r.Header.Get("Content-Type"),
		runtime: runtime, report: report, certChain: chain, endorsement: uvm, nonce: req.Nonce, rawBody: body})
	m.mu.Unlock()
	claim := m.reportDataClaim
	if claim == "" {
		claim = hex.EncodeToString(rd)
	}
	tok := signJWT(m.t, m.key, map[string]any{
		"iat": m.iat, "iss": "https://" + m.host(), "x-ms-attestation-type": "sevsnpvm",
		"x-ms-compliance-status":   "azure-compliant-uvm",
		"x-ms-sevsnpvm-hostdata":   hex.EncodeToString(report[hostDataOffset : hostDataOffset+32]),
		"x-ms-sevsnpvm-reportdata": claim,
		"x-ms-runtime":             obj,
	})
	json.NewEncoder(w).Encode(map[string]string{"token": tok})
}

// ---- managed identity ----

type fakeTokens struct {
	token    string
	err      error
	resource []string
}

func (f *fakeTokens) Token(_ context.Context, resource string) (string, error) {
	f.resource = append(f.resource, resource)
	return f.token, f.err
}

// ---- Key Vault ----

// fakeKV releases one RSA key the way Key Vault does: it checks the bearer
// token and the MAA token, and answers a JWS whose payload holds the key
// wrapped to the key of x-ms-runtime (RSA-OAEP for an AES key, then RFC 5649
// key wrap with padding for the PKCS#8 key).
type fakeKV struct {
	t           testing.TB
	srv         *httptest.Server
	fx          *tlsFixture
	name        string
	key         *rsa.PrivateKey // the key it releases
	accessToken string
	// hostData, if set, is the release policy: the MAA token must state it.
	hostData string
	// maaHost is the authority of the default release policy.
	maaHost string
	enc     string // enc of the answer; "" is CKM_RSA_AES_KEY_WRAP
	alg     string // JWS algorithm; "" is PS256
	// mangle can change the payload and the signing before the JWS is made.
	signKey *rsa.PrivateKey
	x5c     [][]byte
	// wrapTo, if set, replaces the wrapping key from the token.
	wrapTo *rsa.PublicKey
	// jwk releases the key as JWK JSON instead of PKCS#8.
	jwk bool
	// Get Key: the release policy's immutable flag and the policy JSON
	// (default: deploy/skr-policy.json.tmpl for maaHost and hostData), and noRead answers 403 as
	// Key Vault does to an identity without read access to the key.
	immutable bool
	policy    string
	noRead    bool
	// Key versions. version (default testKeyVersion) is the version key
	// has; Get Key of the bare name answers it. newer, if set, is a version
	// made after that Get Key, with id newerVersion: a release of the bare
	// name releases it, as Key Vault takes the newest version. lie, if set,
	// is released whatever the path names.
	version      string
	newer        *rsa.PrivateKey
	newerVersion string
	lie          *rsa.PrivateKey

	mu      sync.Mutex
	targets []string
	paths   []string
}

// serveGetKey answers Get Key with the KeyBundle fields the runner hashes.
func (kv *fakeKV) serveGetKey(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer "+kv.accessToken || kv.noRead {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, `{"error":{"code":"Forbidden","message":"no keys/read"}}`)
		return
	}
	policy := kv.policy
	if policy == "" {
		policy = renderSKRPolicy(kv.t, kv.maaHost, kv.hostData)
	}
	json.NewEncoder(w).Encode(map[string]any{
		"key": map[string]any{"kid": kv.kid(kv.keyVersion()), "kty": "RSA-HSM",
			"n": b64n(kv.key.N), "e": b64n(big.NewInt(int64(kv.key.E)))},
		"attributes":     map[string]any{"enabled": true, "exportable": true},
		"release_policy": map[string]any{"contentType": "application/json; charset=utf-8", "data": b64raw([]byte(policy)), "immutable": kv.immutable},
	})
}

func newFakeKV(t testing.TB, fx *tlsFixture, name string, key *rsa.PrivateKey) *fakeKV {
	kv := &fakeKV{t: t, fx: fx, name: name, key: key, accessToken: "aad-token-of-the-identity", signKey: fx.key, x5c: [][]byte{fx.leaf.Raw}}
	kv.srv = startTLS(t, fx, http.HandlerFunc(kv.serve))
	return kv
}

func (kv *fakeKV) host() string { return hostOf(kv.srv) }

// testKeyVersion is the version of the fake's key unless a test sets one.
const testKeyVersion = "0123456789abcdef0123456789abcdef"

func (kv *fakeKV) keyVersion() string {
	if kv.version != "" {
		return kv.version
	}
	return testKeyVersion
}

func (kv *fakeKV) kid(version string) string {
	return "https://" + kv.host() + "/keys/" + kv.name + "/" + version
}

// released is the key and version a release of path gives, or false for a
// path that names no key of the fake.
func (kv *fakeKV) released(path string) (*rsa.PrivateKey, string, bool) {
	base := "/keys/" + kv.name
	var key *rsa.PrivateKey
	var version string
	switch path {
	case base + "/release":
		key, version = kv.key, kv.keyVersion()
		if kv.newer != nil {
			key, version = kv.newer, kv.newerVersion
		}
	case base + "/" + kv.keyVersion() + "/release":
		key, version = kv.key, kv.keyVersion()
	case base + "/" + kv.newerVersion + "/release":
		if kv.newer == nil {
			return nil, "", false
		}
		key, version = kv.newer, kv.newerVersion
	default:
		return nil, "", false
	}
	if kv.lie != nil {
		key = kv.lie
	}
	return key, version, true
}

func (kv *fakeKV) seenTargets() []string {
	kv.mu.Lock()
	defer kv.mu.Unlock()
	return append([]string(nil), kv.targets...)
}

func oaepHash(enc string) hash.Hash {
	switch enc {
	case "RSA_AES_KEY_WRAP_256":
		return sha256.New()
	case "RSA_AES_KEY_WRAP_384":
		return sha512.New384()
	}
	return sha1.New()
}

func (kv *fakeKV) serve(w http.ResponseWriter, r *http.Request) {
	deny := func(code int, msg string) {
		w.WriteHeader(code)
		fmt.Fprintf(w, `{"error":{"code":"Forbidden","message":%q}}`, msg)
	}
	if r.Method == http.MethodGet && (r.URL.Path == "/keys/"+kv.name || r.URL.Path == "/keys/"+kv.name+"/"+kv.keyVersion()) && r.URL.RawQuery == "api-version=7.4" {
		kv.serveGetKey(w, r)
		return
	}
	relKey, relVersion, ok := kv.released(r.URL.Path)
	if r.Method != http.MethodPost || !ok || r.URL.RawQuery != "api-version=7.4" {
		deny(404, "bad route "+r.Method+" "+r.URL.String())
		return
	}
	if r.Header.Get("Authorization") != "Bearer "+kv.accessToken {
		deny(401, "bad bearer token")
		return
	}
	var req struct {
		Target string `json:"target"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Target == "" {
		deny(400, "no target")
		return
	}
	kv.mu.Lock()
	kv.targets = append(kv.targets, req.Target)
	kv.paths = append(kv.paths, r.URL.Path)
	kv.mu.Unlock()
	claims, err := jwtclaims.Claims(req.Target)
	if err != nil {
		deny(400, "target is not a JWT")
		return
	}
	if kv.hostData != "" && claims["x-ms-sevsnpvm-hostdata"] != kv.hostData {
		deny(403, "the attestation does not satisfy the release policy of the key")
		return
	}
	// The wrapping key must be an RSA key in x-ms-runtime.keys with key_ops
	// encrypt and a kid.
	rt, _ := claims["x-ms-runtime"].(map[string]any)
	keys, _ := rt["keys"].([]any)
	if len(keys) != 1 {
		deny(400, "x-ms-runtime.keys has no key")
		return
	}
	jwk, _ := keys[0].(map[string]any)
	ops, _ := jwk["key_ops"].([]any)
	if jwk["kty"] != "RSA" || len(ops) != 1 || ops[0] != "encrypt" || jwk["kid"] == "" || jwk["kid"] == nil {
		deny(400, "x-ms-runtime.keys[0] is not an RSA encryption key with a kid")
		return
	}
	nb, _ := base64.RawURLEncoding.DecodeString(fmt.Sprint(jwk["n"]))
	eb, _ := base64.RawURLEncoding.DecodeString(fmt.Sprint(jwk["e"]))
	pub := &rsa.PublicKey{N: new(big.Int).SetBytes(nb), E: int(new(big.Int).SetBytes(eb).Int64())}
	if kv.wrapTo != nil {
		pub = kv.wrapTo
	}

	var plain []byte
	if kv.jwk {
		plain = []byte(jwkOf(relKey))
	} else if plain, err = x509.MarshalPKCS8PrivateKey(relKey); err != nil {
		deny(500, err.Error())
		return
	}
	kek := make([]byte, 32)
	rand.Read(kek)
	rsaPart, err := rsa.EncryptOAEP(oaepHash(kv.enc), rand.Reader, pub, kek, nil)
	if err != nil {
		deny(500, err.Error())
		return
	}
	block, _ := aes.NewCipher(kek)
	ct := append(rsaPart, aesWrapWithPadding(block, plain)...)
	hsm, _ := json.Marshal(map[string]any{"schema_version": "1.0", "header": map[string]any{"alg": "dir", "enc": kv.enc}, "ciphertext": b64raw(ct)})
	payload, _ := json.Marshal(map[string]any{
		"request": map[string]any{"api-version": "7.4", "enc": kv.enc, "kid": kv.kid(relVersion)},
		"response": map[string]any{"key": map[string]any{
			"attributes": map[string]any{"enabled": true, "exportable": true},
			"key":        map[string]any{"kid": kv.kid(relVersion), "kty": "RSA-HSM", "key_ops": []string{"wrapKey", "unwrapKey"}, "key_hsm": b64raw(hsm)},
		}},
	})
	alg := kv.alg
	if alg == "" {
		alg = "PS256"
	}
	var x5c []string
	for _, c := range kv.x5c {
		x5c = append(x5c, base64.StdEncoding.EncodeToString(c))
	}
	hdr, _ := json.Marshal(map[string]any{"alg": alg, "kid": "kv-test", "x5c": x5c})
	signed := b64raw(hdr) + "." + b64raw(payload)
	sum := sha256.Sum256([]byte(signed))
	var sig []byte
	if strings.HasPrefix(alg, "RS") {
		sig, err = rsa.SignPKCS1v15(rand.Reader, kv.signKey, crypto.SHA256, sum[:])
	} else {
		sig, err = rsa.SignPSS(rand.Reader, kv.signKey, crypto.SHA256, sum[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
	}
	if err != nil {
		deny(500, err.Error())
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"value": signed + "." + b64raw(sig)})
}

// ---- JWK ----

func b64n(n *big.Int) string { return base64.RawURLEncoding.EncodeToString(n.Bytes()) }

func jwkOf(k *rsa.PrivateKey) string {
	m := map[string]any{"kty": "RSA-HSM", "key_ops": []string{"wrapKey", "unwrapKey"}, "n": b64n(k.N), "e": b64n(big.NewInt(int64(k.E))), "d": b64n(k.D),
		"p": b64n(k.Primes[0]), "q": b64n(k.Primes[1])}
	b, _ := json.Marshal(m)
	return string(b)
}

// renderSKRPolicy renders deploy/skr-policy.json.tmpl as deploy.sh
// key-create does (envsubst of the two variables).
func renderSKRPolicy(t testing.TB, maaHost, hostData string) string {
	t.Helper()
	tmpl, err := os.ReadFile("../deploy/skr-policy.json.tmpl")
	if err != nil {
		t.Fatal(err)
	}
	return strings.NewReplacer("${MAA_ENDPOINT}", maaHost, "${CCE_POLICY_SHA256}", hostData).Replace(string(tmpl))
}
