//go:build !verifierselect

package runnerclient

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/attestation-verify"
	"github.com/lidofinance/tee-signer/attestation-verify/internal/testgen"
	"github.com/lidofinance/tee-signer/governance/flavor"
	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/wire"
)

// These tests run the real client (backend/remote) against a fake runner: a
// TLS 1.3 server with a self-signed key that demands a client certificate
// and answers IDENTITY and HEALTH with the wire protocol. The attestation
// documents are the dev platform's unsigned one and synthetic MAA tokens
// from internal/testgen. Nothing here ran against a real runner or MAA.

const goodHostData = "73e0d1b6b2d0b0b3c0c8a0d7a8f2b1f3e4d5c6b7a8f9e0d1c2b3a4958677a6b5"

var ctx = context.Background()

// ---- test CA and client files ----

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pool *x509.CertPool
	n    int64
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "runnerclient test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &testCA{cert: cert, key: key, pool: pool, n: 1}
}

// issue writes name.pem and name-key.pem into dir and returns their paths.
// notAfter is one hour from now if zero.
func (ca *testCA) issue(t *testing.T, dir, name string, notAfter time.Time) (certPath, keyPath string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if notAfter.IsZero() {
		notAfter = time.Now().Add(time.Hour)
	}
	ca.n++
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(ca.n), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-2 * time.Hour), NotAfter: notAfter,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPath, keyPath = filepath.Join(dir, name+".pem"), filepath.Join(dir, name+"-key.pem")
	writePEM(t, certPath, "CERTIFICATE", der, 0o644)
	writePEM(t, keyPath, "PRIVATE KEY", keyDER, 0o600)
	return certPath, keyPath
}

// issueAdmin is issue for the admin role (docs/protocol.md, "Client
// roles"): the leaf comes from an intermediate under the CA, and both list
// clientAuth and backend.AdminClientOID. name.pem holds the leaf, then the
// intermediate.
func (ca *testCA) issueAdmin(t *testing.T, dir, name string) (certPath, keyPath string) {
	t.Helper()
	admin := []asn1.ObjectIdentifier{backend.AdminClientOID}
	create := func(tmpl, parent *x509.Certificate, pub *ecdsa.PublicKey, signer *ecdsa.PrivateKey) []byte {
		ca.n++
		tmpl.SerialNumber = big.NewInt(ca.n)
		der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, signer)
		if err != nil {
			t.Fatal(err)
		}
		return der
	}
	interKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	interDER := create(&x509.Certificate{Subject: pkix.Name{CommonName: name + " admin CA"},
		NotBefore: time.Now().Add(-2 * time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, UnknownExtKeyUsage: admin}, ca.cert, &interKey.PublicKey, ca.key)
	inter, err := x509.ParseCertificate(interDER)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafDER := create(&x509.Certificate{Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-2 * time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, UnknownExtKeyUsage: admin},
		inter, &key.PublicKey, interKey)
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPath, keyPath = filepath.Join(dir, name+".pem"), filepath.Join(dir, name+"-key.pem")
	chain := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: interDER})...)
	if err := os.WriteFile(certPath, chain, 0o644); err != nil {
		t.Fatal(err)
	}
	writePEM(t, keyPath, "PRIVATE KEY", keyDER, 0o600)
	return certPath, keyPath
}

func writePEM(t *testing.T, path, kind string, der []byte, mode os.FileMode) {
	t.Helper()
	b := "-----BEGIN " + kind + "-----\n" + base64.StdEncoding.EncodeToString(der) + "\n-----END " + kind + "-----\n"
	if err := os.WriteFile(path, []byte(b), mode); err != nil {
		t.Fatal(err)
	}
}

// ---- fake runner ----

// attestFn builds the attestation of an IDENTITY response.
type attestFn func(nonce []byte, id *backend.Identity) *backend.Attestation

type fakeRunner struct {
	ln   net.Listener
	spki []byte // sha256 of the TLS key it serves
	// claimedKey is the TLS key hash its identity names (spki unless a test
	// plays a relay).
	claimedKey []byte
	attest     attestFn
	replay     bool   // answer every IDENTITY with the first answer
	version    string // HEALTH's version

	mu       sync.Mutex
	first    []byte
	identity int
	// state is the setup state its identity carries: a runner on the flag
	// path unless a test sets another (setState).
	state backend.SetupState
	// frames counts the requests by type, IDENTITY and HEALTH included.
	frames map[wire.MsgType]int
}

func (f *fakeRunner) setState(s backend.SetupState) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.state = s
}

func (f *fakeRunner) seen(t wire.MsgType) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.frames[t]
}

func startFakeRunner(t *testing.T, ca *testCA, attest attestFn) *fakeRunner {
	t.Helper()
	return startFakeRunnerAs(t, ca, attest, flavor.DefaultCertName, "0.1.0")
}

// startFakeRunnerAs is a fake runner whose certificate has the subject
// common name cn and whose HEALTH reports version.
func startFakeRunnerAs(t *testing.T, ca *testCA, attest attestFn, cn, version string) *fakeRunner {
	t.Helper()
	return startFakeRunnerExt(t, ca, attest, cn, version, nil)
}

// startFakeRunnerExt is startFakeRunnerAs with extra extensions in the
// runner's certificate.
func startFakeRunnerExt(t *testing.T, ca *testCA, attest attestFn, cn, version string, exts []pkix.Extension) *fakeRunner {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(99), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		ExtraExtensions: exts,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	cfg := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}},
		ClientAuth:   tls.RequireAndVerifyClientCert, ClientCAs: ca.pool,
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeRunner{ln: ln, spki: h[:], claimedKey: h[:], attest: attest, version: version,
		state: backend.SetupState{SetupHash: fakeConfigHash}, frames: map[wire.MsgType]int{}}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go f.serve(c)
		}
	}()
	return f
}

func (f *fakeRunner) addr() string { return "tcp:" + f.ln.Addr().String() }

func (f *fakeRunner) identities() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.identity
}

func (f *fakeRunner) serve(c net.Conn) {
	defer c.Close()
	for {
		fr, err := wire.ReadFrame(c)
		if err != nil {
			return
		}
		f.mu.Lock()
		f.frames[fr.Type]++
		f.mu.Unlock()
		var body []byte
		switch fr.Type {
		case wire.TypeIdentity:
			nonce, err := wire.DecodeAttest(fr.Payload)
			if err != nil {
				return
			}
			body = f.identityBody(nonce)
		case wire.TypeHealth:
			body, _ = wire.EncodeHealth(&backend.Health{Platform: "fake", Version: f.version})
		default:
			return
		}
		if err := wire.WriteFrame(c, wire.Frame{Type: fr.Type | wire.ResponseFlag, ID: fr.ID, Payload: wire.EncodeOK(body)}); err != nil {
			return
		}
	}
}

func (f *fakeRunner) identityBody(nonce []byte) []byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.identity++
	if f.replay && f.first != nil {
		return f.first
	}
	id := &backend.Identity{
		State: f.state, ImportKEM: 0x647a, ImportKDF: 1, ImportAEAD: 2,
		ImportKey: []byte("fake hpke public key"), TLSKeyHash: f.claimedKey,
	}
	id.Attestation = f.attest(nonce, id)
	b, err := wire.EncodeIdentity(id)
	if err != nil {
		panic(err)
	}
	if f.first == nil {
		f.first = b
	}
	return b
}

// devAttest is the dev platform's unsigned document.
func devAttest(nonce []byte, id *backend.Identity) *backend.Attestation {
	ud := backend.IdentityUserData(nonce, id)
	doc, _ := json.Marshal(map[string]any{"nonce": nonce, "user_data": ud})
	return &backend.Attestation{Platform: "dev", Format: "dev-json", UserData: ud, Document: doc}
}

// ---- fake MAA ----

// maaEnv is a fake attestation provider: an HTTPS server with an OpenID
// configuration and a key set, and a way to mint tokens.
type maaEnv struct {
	t      *testing.T
	srv    *httptest.Server
	host   string // 127.0.0.1:PORT, the maa_host
	issuer string

	mu      sync.Mutex
	jwks    [][]byte // key sets, served in order; the last one repeats
	fetches int
}

func newMAAEnv(t *testing.T, sets ...[]byte) *maaEnv {
	t.Helper()
	e := &maaEnv{t: t, jwks: sets}
	e.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			fmt.Fprintf(w, `{"issuer":%q,"jwks_uri":%q}`, e.issuer, e.issuer+"/certs")
		case "/certs":
			e.mu.Lock()
			i := e.fetches
			if i >= len(e.jwks) {
				i = len(e.jwks) - 1
			}
			e.fetches++
			set := e.jwks[i]
			e.mu.Unlock()
			w.Write(set)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(e.srv.Close)
	e.host = strings.TrimPrefix(e.srv.URL, "https://")
	e.issuer = e.srv.URL
	return e
}

func (e *maaEnv) fetchCount() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.fetches
}

// tokenSpec says what a fake runner's MAA token claims. Zero values give a
// good token from the main key.
type tokenSpec struct {
	issuer     string // default: the environment's
	hostData   string // default: goodHostData
	compliance string // default: azure-compliant-uvm
	debuggable bool
	vmpl       int
	key        *rsa.PrivateKey // default: testgen.RSAKey(0)
	kid        string          // default: maa-1
	flipSig    bool
}

func (e *maaEnv) defaults(s tokenSpec) tokenSpec {
	if s.issuer == "" {
		s.issuer = e.issuer
	}
	if s.hostData == "" {
		s.hostData = goodHostData
	}
	if s.compliance == "" {
		s.compliance = attest.ComplianceACI
	}
	if s.key == nil {
		s.key = testgen.RSAKey(0)
	}
	if s.kid == "" {
		s.kid = "maa-1"
	}
	return s
}

// token mints the MAA token that MAA would return
// for the runtime data rt (a JSON object): the SNP report data is sha256(rt)
// followed by 32 zero bytes, and x-ms-runtime holds the object.
func (e *maaEnv) token(s tokenSpec, rt []byte) string {
	s = e.defaults(s)
	var obj map[string]any
	if err := json.Unmarshal(rt, &obj); err != nil {
		e.t.Error("runtime data is not a JSON object:", err)
	}
	sum := sha256.Sum256(rt)
	now := time.Now()
	tok := testgen.SignJWT(e.t, s.key, s.kid, map[string]any{
		"iss": s.issuer, "iat": now.Add(-10 * time.Second).Unix(), "nbf": now.Add(-10 * time.Second).Unix(),
		"exp":                         now.Add(time.Hour).Unix(),
		"x-ms-attestation-type":       "sevsnpvm",
		"x-ms-compliance-status":      s.compliance,
		"x-ms-sevsnpvm-hostdata":      s.hostData,
		"x-ms-sevsnpvm-is-debuggable": s.debuggable,
		"x-ms-sevsnpvm-vmpl":          s.vmpl,
		"x-ms-sevsnpvm-reportdata":    hex.EncodeToString(sum[:]) + strings.Repeat("00", 32),
		"x-ms-runtime":                obj,
	}, nil)
	if s.flipSig {
		tok = flipSig(tok)
	}
	return tok
}

func (e *maaEnv) attest(s tokenSpec) attestFn {
	return func(nonce []byte, id *backend.Identity) *backend.Attestation {
		ud := backend.IdentityUserData(nonce, id)
		tok := e.token(s, backend.MAARuntimeData(ud))
		return &backend.Attestation{Platform: "azure", Format: "azure-maa-jwt", UserData: ud, Document: []byte(tok)}
	}
}

func flipSig(tok string) string {
	i := strings.LastIndexByte(tok, '.')
	sig, _ := base64.RawURLEncoding.DecodeString(tok[i+1:])
	sig[10] ^= 1
	return tok[:i+1] + base64.RawURLEncoding.EncodeToString(sig)
}

func mainKeySet(t *testing.T) []byte { return testgen.JWKS(t, "maa-1", testgen.RSAKey(0), true) }

// ---- helpers ----

// fakeConfigHash is the setup_hash of a fake runner on the flag path, the
// SHA-256 of its -config file. A cloud verifier reaches such a runner only
// with this hash pinned.
var fakeConfigHash = backend.Root{1, 2, 3}

// configPin is the setup_sha256 of a real runner on the flag path started
// with -config path: the SHA-256 of that file.
func configPin(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func devConn(t *testing.T, ca *testCA, f *fakeRunner) Connection {
	t.Helper()
	cert, key := ca.issue(t, t.TempDir(), "client", time.Time{})
	return Connection{Address: f.addr(), ClientCert: cert, ClientKey: key, Attestation: Attestation{Verifier: VerifierDev}}
}

func maaConn(t *testing.T, ca *testCA, f *fakeRunner, e *maaEnv) Connection {
	t.Helper()
	c := devConn(t, ca, f)
	c.Attestation = Attestation{Verifier: VerifierAzureMAA, MAAHost: e.host, CCEPolicySHA256: goodHostData,
		SetupSHA256: pinOf(fakeConfigHash)}
	return c
}

// health connects and sends HEALTH, the first request after the checks.
func health(t *testing.T, c Connection, opts ...Option) error {
	t.Helper()
	cl, err := c.New(append([]Option{WithTimeout(5 * time.Second)}, opts...)...)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer cl.Close()
	_, err = cl.Health(ctx)
	return err
}

func wantErr(t *testing.T, err error, sub string) {
	t.Helper()
	if err == nil {
		t.Fatalf("no error, want one containing %q", sub)
	}
	if !strings.Contains(err.Error(), sub) {
		t.Fatalf("error %q does not contain %q", err, sub)
	}
}

// ---- config refusals ----

func TestConfigRefusals(t *testing.T) {
	ca := newTestCA(t)
	dir := t.TempDir()
	cert, key := ca.issue(t, dir, "client", time.Time{})
	otherCert, otherKey := ca.issue(t, dir, "other", time.Time{})
	expiredCert, expiredKey := ca.issue(t, dir, "expired", time.Now().Add(-time.Minute))
	garbage := filepath.Join(dir, "garbage.pem")
	os.WriteFile(garbage, []byte("not a pem file"), 0o600)
	_ = otherCert
	unreadable := filepath.Join(dir, "unreadable-key.pem")
	if b, err := os.ReadFile(key); err == nil {
		os.WriteFile(unreadable, b, 0o000)
	}

	maa := Attestation{Verifier: VerifierAzureMAA, MAAHost: "sharedweu.weu.attest.azure.net", CCEPolicySHA256: goodHostData}
	good := Connection{Address: "tcp:signer-1:7100", ClientCert: cert, ClientKey: key, Attestation: Attestation{Verifier: VerifierDev}}
	goodMAA := good
	goodMAA.Attestation = maa

	for name, c := range map[string]Connection{"dev": good, "azure-maa": goodMAA} {
		if err := c.Validate(); err != nil {
			t.Fatalf("good %s config: %v", name, err)
		}
	}
	upper := goodMAA
	upper.Attestation.MAAHost = "SharedWEU.weu.attest.azure.net"
	upper.Attestation.CCEPolicySHA256 = strings.ToUpper(goodHostData)
	upper.Attestation.ComplianceStatus = attest.ComplianceCVM
	if err := upper.Validate(); err != nil {
		t.Fatalf("upper case host and hash, cvm status: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(c *Connection)
		want   string
	}{
		{"no address", func(c *Connection) { c.Address = "" }, "address"},
		{"unix address", func(c *Connection) { c.Address = "unix:/run/runner.sock" }, "tcp: address"},
		{"vsock address", func(c *Connection) { c.Address = "vsock:16:7100" }, "tcp: address"},
		{"no host in address", func(c *Connection) { c.Address = "tcp:7100" }, "address"},
		{"no client cert", func(c *Connection) { c.ClientCert = "" }, "client_cert: not set"},
		{"no client key", func(c *Connection) { c.ClientKey = "" }, "client_key: not set"},
		{"client cert file missing", func(c *Connection) { c.ClientCert = filepath.Join(dir, "nope.pem") }, "client_cert"},
		{"client key file missing", func(c *Connection) { c.ClientKey = filepath.Join(dir, "nope-key.pem") }, "client_key"},
		{"client key unreadable", func(c *Connection) { c.ClientKey = unreadable }, "client_key"},
		{"client key not PEM", func(c *Connection) { c.ClientKey = garbage }, "client_cert and client_key"},
		{"client cert not PEM", func(c *Connection) { c.ClientCert = garbage }, "client_cert and client_key"},
		{"key of another certificate", func(c *Connection) { c.ClientKey = otherKey }, "does not match"},
		{"expired client cert", func(c *Connection) { c.ClientCert, c.ClientKey = expiredCert, expiredKey }, "expired"},
		{"pin too short", func(c *Connection) { c.TLSKeyPin = "abcd" }, "tls_key_pin"},
		{"pin not hex", func(c *Connection) { c.TLSKeyPin = strings.Repeat("zz", 32) }, "tls_key_pin"},
		{"no verifier", func(c *Connection) { c.Attestation = Attestation{} }, "attestation.verifier: not set"},
		{"unknown verifier", func(c *Connection) { c.Attestation.Verifier = "none" }, `unknown verifier "none"`},
		{"verifier skip", func(c *Connection) { c.Attestation.Verifier = "skip" }, `unknown verifier "skip"`},
		{"dev verifier with MAA host", func(c *Connection) { c.Attestation.MAAHost = "sharedweu.weu.attest.azure.net" }, "belong to the verifier"},
		{"dev verifier with hash", func(c *Connection) { c.Attestation.CCEPolicySHA256 = goodHostData }, "belong to the verifier"},
		{"MAA without host", func(c *Connection) { c.Attestation = maa; c.Attestation.MAAHost = "" }, "maa_host: not set"},
		{"MAA host with scheme", func(c *Connection) {
			c.Attestation = maa
			c.Attestation.MAAHost = "https://sharedweu.weu.attest.azure.net"
		}, "maa_host"},
		{"MAA host with path", func(c *Connection) {
			c.Attestation = maa
			c.Attestation.MAAHost = "sharedweu.weu.attest.azure.net/certs"
		}, "maa_host"},
		{"MAA without expected hash", func(c *Connection) { c.Attestation = maa; c.Attestation.CCEPolicySHA256 = "" }, "cce_policy_sha256: not set"},
		{"MAA hash too short", func(c *Connection) { c.Attestation = maa; c.Attestation.CCEPolicySHA256 = goodHostData[:62] }, "cce_policy_sha256: want 64 hex"},
		{"MAA hash not hex", func(c *Connection) { c.Attestation = maa; c.Attestation.CCEPolicySHA256 = strings.Repeat("g", 64) }, "cce_policy_sha256: want 64 hex"},
		{"MAA unknown compliance", func(c *Connection) { c.Attestation = maa; c.Attestation.ComplianceStatus = "azure-compliant-xyz" }, "compliance_status"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.name == "client key unreadable" && os.Geteuid() == 0 {
				t.Skip("root reads any file")
			}
			c := good
			tc.mutate(&c)
			wantErr(t, c.Validate(), tc.want)
			// New refuses the same way, before it connects anywhere.
			_, err := c.New()
			wantErr(t, err, tc.want)
		})
	}
}

func TestResolvePaths(t *testing.T) {
	c := Connection{ClientCert: "client.pem", ClientKey: "/abs/key.pem"}
	c.ResolvePaths("/etc/client")
	if c.ClientCert != "/etc/client/client.pem" || c.ClientKey != "/abs/key.pem" {
		t.Fatalf("%q %q", c.ClientCert, c.ClientKey)
	}
}

func TestFlags(t *testing.T) {
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	a := Flags(fs)
	if err := fs.Parse([]string{"-verifier", "azure-maa", "-maa-host", "sharedneu.neu.attest.azure.net", "-cce-policy-sha256", goodHostData}); err != nil {
		t.Fatal(err)
	}
	if err := a.Validate(); err != nil {
		t.Fatal(err)
	}
	fs = flag.NewFlagSet("t", flag.ContinueOnError)
	a = Flags(fs)
	fs.Parse([]string{"-verifier", "azure-maa", "-maa-host", "sharedneu.neu.attest.azure.net"})
	wantErr(t, a.Validate(), "cce_policy_sha256")
	if _, err := (&Attestation{}).NewVerifier(); err == nil {
		t.Fatal("empty attestation settings gave a verifier")
	}
}

// ---- dev verifier, key pin, relay, replay ----

func TestDevRunnerConnects(t *testing.T) {
	ca := newTestCA(t)
	f := startFakeRunner(t, ca, devAttest)
	c := devConn(t, ca, f)
	if err := health(t, c); err != nil {
		t.Fatal(err)
	}
	// The key pin of the runner's own key is accepted.
	c.TLSKeyPin = hex.EncodeToString(f.spki)
	if err := health(t, c); err != nil {
		t.Fatalf("right pin: %v", err)
	}
}

func TestWrongKeyPinRefused(t *testing.T) {
	ca := newTestCA(t)
	f := startFakeRunner(t, ca, devAttest)
	c := devConn(t, ca, f)
	// The key of another runner: same length, different value.
	other := sha256.Sum256([]byte("another runner's TLS key"))
	c.TLSKeyPin = hex.EncodeToString(other[:])
	wantErr(t, health(t, c), "is not the pinned key")
	if f.identities() != 0 {
		t.Fatal("the client asked for IDENTITY after the pin failed")
	}
}

func TestRelayWithItsOwnKeyRefused(t *testing.T) {
	// A relay that terminates TLS with its own key and forwards another
	// runner's identity: the identity names a key the handshake did not
	// present. Checked with the dev and the MAA verifier.
	ca := newTestCA(t)
	env := newMAAEnv(t, mainKeySet(t))
	for name, mk := range map[string]func(*fakeRunner) Connection{
		"dev":       func(f *fakeRunner) Connection { return devConn(t, ca, f) },
		"azure-maa": func(f *fakeRunner) Connection { return maaConn(t, ca, f, env) },
	} {
		t.Run(name, func(t *testing.T) {
			att := attestFn(devAttest)
			if name == "azure-maa" {
				att = env.attest(tokenSpec{})
			}
			f := startFakeRunner(t, ca, att)
			real := sha256.Sum256([]byte("the real runner's TLS key"))
			f.claimedKey = real[:]
			wantErr(t, health(t, mk(f), WithHTTPClient(env.srv.Client())), "attested identity names")
		})
	}
}

func TestReplayedIdentityRefused(t *testing.T) {
	// A runner (or relay) that answers a new connection with the identity it
	// gave an earlier one: the user data covers the client's nonce.
	ca := newTestCA(t)
	f := startFakeRunner(t, ca, devAttest)
	c := devConn(t, ca, f)
	if err := health(t, c); err != nil {
		t.Fatalf("control: %v", err)
	}
	f.mu.Lock()
	f.replay = true
	f.mu.Unlock()
	wantErr(t, health(t, c), "user data does not match")
}

// ---- MAA verifier ----

func TestMAARunnerConnects(t *testing.T) {
	ca := newTestCA(t)
	env := newMAAEnv(t, mainKeySet(t))
	f := startFakeRunner(t, ca, env.attest(tokenSpec{}))
	c := maaConn(t, ca, f, env)
	cl, err := c.New(WithTimeout(5*time.Second), WithHTTPClient(env.srv.Client()))
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()
	if _, err := cl.Health(ctx); err != nil {
		t.Fatal(err)
	}
	// A reconnect checks the identity again but reuses the key set.
	cl.Close()
	if _, err := cl.Health(ctx); err != nil {
		t.Fatal(err)
	}
	if f.identities() != 2 || env.fetchCount() != 1 {
		t.Fatalf("identities %d (want 2), key set fetches %d (want 1)", f.identities(), env.fetchCount())
	}
	// Upper case in the configured hash and host still matches.
	c.Attestation.CCEPolicySHA256 = strings.ToUpper(goodHostData)
	if err := health(t, c, WithHTTPClient(env.srv.Client())); err != nil {
		t.Fatal(err)
	}
}

func TestMAATokenRefusals(t *testing.T) {
	ca := newTestCA(t)
	env := newMAAEnv(t, mainKeySet(t))
	otherHash := strings.Repeat("ab", 32)
	tests := []struct {
		name string
		spec tokenSpec
		want error
		text string
	}{
		{"wrong hostdata (another runner's policy)", tokenSpec{hostData: otherHash}, attest.ErrMeasurement, "x-ms-sevsnpvm-hostdata"},
		{"wrong issuer", tokenSpec{issuer: "https://other.weu.attest.azure.net"}, attest.ErrIssuer, ""},
		{"debuggable", tokenSpec{debuggable: true}, attest.ErrDebug, "is-debuggable"},
		{"bad signature", tokenSpec{flipSig: true}, attest.ErrSignature, ""},
		{"signed by another key under the provider's kid", tokenSpec{key: testgen.RSAKey(1)}, attest.ErrSignature, ""},
		{"VMPL 2", tokenSpec{vmpl: 2}, attest.ErrClaim, "vmpl"},
		{"confidential VM status where ACI is expected", tokenSpec{compliance: attest.ComplianceCVM}, attest.ErrClaim, "compliance"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := startFakeRunner(t, ca, env.attest(tc.spec))
			err := health(t, maaConn(t, ca, f, env), WithHTTPClient(env.srv.Client()))
			if err == nil {
				t.Fatal("connected")
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("error %q is not %v", err, tc.want)
			}
			if tc.text != "" {
				wantErr(t, err, tc.text)
			}
		})
	}
}

func TestMAAIdentityOfAnotherRunnerRefused(t *testing.T) {
	// Runner 2 holds a good token for its own CCE policy (another key name,
	// so another hash). A client configured for runner 1 must not accept it.
	ca := newTestCA(t)
	env := newMAAEnv(t, mainKeySet(t))
	runner2 := startFakeRunner(t, ca, env.attest(tokenSpec{hostData: strings.Repeat("22", 32)}))
	c := maaConn(t, ca, runner2, env) // expects goodHostData (runner 1)
	err := health(t, c, WithHTTPClient(env.srv.Client()))
	if !errors.Is(err, attest.ErrMeasurement) {
		t.Fatalf("got %v", err)
	}
	// Configured for runner 2, it connects.
	c.Attestation.CCEPolicySHA256 = strings.Repeat("22", 32)
	if err := health(t, c, WithHTTPClient(env.srv.Client())); err != nil {
		t.Fatal(err)
	}
}

func TestMAATokenForAnotherNonceRefused(t *testing.T) {
	// A token the runner minted for an earlier identity request, replayed:
	// its report data covers the old nonce. The fake runner builds the new
	// identity fields itself but copies the old token.
	ca := newTestCA(t)
	env := newMAAEnv(t, mainKeySet(t))
	good := env.attest(tokenSpec{})
	var old *backend.Attestation
	f := startFakeRunner(t, ca, func(nonce []byte, id *backend.Identity) *backend.Attestation {
		fresh := good(nonce, id)
		if old == nil {
			old = fresh
			return fresh
		}
		// Right user data for the new nonce, old token.
		return &backend.Attestation{Platform: old.Platform, Format: old.Format, UserData: fresh.UserData, Document: old.Document}
	})
	c := maaConn(t, ca, f, env)
	if err := health(t, c, WithHTTPClient(env.srv.Client())); err != nil {
		t.Fatal(err)
	}
	err := health(t, c, WithHTTPClient(env.srv.Client()))
	if !errors.Is(err, attest.ErrNonce) {
		t.Fatalf("got %v", err)
	}
}

func TestMAADevDocumentRefused(t *testing.T) {
	// A dev runner behind an azure-maa config: no free pass.
	ca := newTestCA(t)
	env := newMAAEnv(t, mainKeySet(t))
	f := startFakeRunner(t, ca, devAttest)
	err := health(t, maaConn(t, ca, f, env), WithHTTPClient(env.srv.Client()))
	wantErr(t, err, "not an Azure MAA token")
	if env.fetchCount() != 0 {
		t.Fatal("the client fetched the provider's keys for a document that is not an Azure token")
	}
}

func TestMAAKeyRotation(t *testing.T) {
	ca := newTestCA(t)
	oldRefresh := keyRefreshGap
	t.Cleanup(func() { keyRefreshGap = oldRefresh })

	// The provider serves its old key first and a set with the new key
	// from the second fetch on. The runner's token is under the new key.
	newKey := testgen.RSAKey(2)
	newSet := testgen.JWKS(t, "maa-2", newKey, true)

	t.Run("refetch on an unknown key id", func(t *testing.T) {
		keyRefreshGap = 0
		env := newMAAEnv(t, mainKeySet(t), newSet)
		f := startFakeRunner(t, ca, env.attest(tokenSpec{key: newKey, kid: "maa-2"}))
		if err := health(t, maaConn(t, ca, f, env), WithHTTPClient(env.srv.Client())); err != nil {
			t.Fatal(err)
		}
		if env.fetchCount() != 2 {
			t.Fatalf("fetches %d, want 2", env.fetchCount())
		}
	})
	t.Run("no refetch inside the gap", func(t *testing.T) {
		keyRefreshGap = time.Hour
		env := newMAAEnv(t, mainKeySet(t), newSet)
		f := startFakeRunner(t, ca, env.attest(tokenSpec{key: newKey, kid: "maa-2"}))
		err := health(t, maaConn(t, ca, f, env), WithHTTPClient(env.srv.Client()))
		if !errors.Is(err, attest.ErrUnknownKey) {
			t.Fatalf("got %v", err)
		}
		if env.fetchCount() != 1 {
			t.Fatalf("fetches %d, want 1", env.fetchCount())
		}
	})
	t.Run("key set unreachable", func(t *testing.T) {
		env := newMAAEnv(t, mainKeySet(t))
		f := startFakeRunner(t, ca, env.attest(tokenSpec{}))
		c := maaConn(t, ca, f, env)
		env.srv.Close()
		wantErr(t, health(t, c, WithHTTPClient(env.srv.Client())), "MAA key set")
	})
}
