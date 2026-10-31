//go:build !verifierselect

package runnerclient

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/attestation-verify"
	"github.com/lidofinance/tee-signer/attestation-verify/internal/testgen"
	"github.com/lidofinance/tee-signer/signer-protocol"
)

// Tests of the aws-nitro and gcp-cs verifiers, in the way the azure-maa ones
// in runnerclient_test.go work: the real client against the fake runner, with
// synthetic NSM documents (a local P-384 test CA, which the tests make the
// trust anchor) and synthetic Confidential Space tokens (the fake provider
// of maaEnv, which serves any OpenID configuration and key set). The real
// files from testdata/ are used where they fit: a real AWS document that must
// be refused here, and Google's real key set. Nothing here ran against a real
// enclave, a real Confidential Space VM or Google.

// ---- aws-nitro ----

func pcrHex(i uint64) string { return hex.EncodeToString(testgen.DefaultPCRs()[i]) }

// nitroGood is a good aws-nitro configuration for the documents of
// nitroEnv.attest with the default PCRs.
func nitroGood() Attestation {
	return Attestation{Verifier: VerifierAWSNitro, NitroPCRs: map[string]string{"0": pcrHex(0), "1": pcrHex(1), "2": pcrHex(2)}}
}

// withNitroRoots makes the verifier trust a test CA instead of the AWS root.
func withNitroRoots(roots ...*x509.Certificate) Option {
	return func(o *options) { o.nitroRoots = roots }
}

type nitroEnv struct {
	t  *testing.T
	ca *testgen.CA
}

func newNitroEnv(t *testing.T) *nitroEnv { return &nitroEnv{t: t, ca: testgen.NewCA(t, time.Now())} }

// nitroSpec says what a fake runner's NSM document claims. Zero values give
// a good document that the environment's CA signed.
type nitroSpec struct {
	pcrs     map[uint64][]byte // default testgen.DefaultPCRs()
	ca       *testgen.CA       // signing CA, default the environment's
	nonce    []byte            // document nonce, default the request's
	userData []byte            // document user data, default the identity's
	skew     time.Duration     // added to the document timestamp
	flipSig  bool
}

func (e *nitroEnv) attest(s nitroSpec) attestFn {
	return func(nonce []byte, id *backend.Identity) *backend.Attestation {
		ud := backend.IdentityUserData(nonce, id)
		ca := e.ca
		if s.ca != nil {
			ca = s.ca
		}
		docNonce, docUD := nonce, ud
		if s.nonce != nil {
			docNonce = s.nonce
		}
		if s.userData != nil {
			docUD = s.userData
		}
		doc := ca.NitroDoc(e.t, testgen.NitroSpec{TS: time.Now().Add(s.skew), PCRs: s.pcrs, Nonce: docNonce, UserData: docUD})
		if s.flipSig {
			doc[len(doc)-1] ^= 1 // a bit of the ES384 signature
		}
		return &backend.Attestation{Platform: nitroPlatform, Format: nitroFormat, UserData: ud, Document: doc}
	}
}

func nitroConn(t *testing.T, ca *testCA, f *fakeRunner) Connection {
	t.Helper()
	c := devConn(t, ca, f)
	c.Attestation = nitroGood()
	c.Attestation.SetupSHA256 = pinOf(fakeConfigHash)
	return c
}

func TestNitroRunnerConnects(t *testing.T) {
	ca := newTestCA(t)
	env := newNitroEnv(t)
	f := startFakeRunner(t, ca, env.attest(nitroSpec{}))
	c := nitroConn(t, ca, f)
	cl, err := c.New(WithTimeout(5*time.Second), withNitroRoots(env.ca.Root))
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()
	if _, err := cl.Health(ctx); err != nil {
		t.Fatal(err)
	}
	// A reconnect asks for a new identity with a new nonce and checks it again.
	cl.Close()
	if _, err := cl.Health(ctx); err != nil {
		t.Fatal(err)
	}
	if f.identities() != 2 {
		t.Fatalf("identities %d, want 2", f.identities())
	}

	// More PCRs (the parent role, the EIF signing certificate), the root
	// pin of this build and upper case hex are accepted too.
	c.Attestation.NitroPCRs["3"] = pcrHex(3)
	c.Attestation.NitroPCRs["8"] = strings.ToUpper(pcrHex(8))
	c.Attestation.NitroRootSHA256 = strings.ToUpper(attest.NitroRootSHA256)
	if err := health(t, c, withNitroRoots(env.ca.Root)); err != nil {
		t.Fatal(err)
	}
}

func TestNitroDocumentRefusals(t *testing.T) {
	ca := newTestCA(t)
	env := newNitroEnv(t)
	otherCA := testgen.NewCA(t, time.Now())
	expiredCA := testgen.NewCA(t, time.Now().Add(-5*time.Hour)) // its leaf ended 3 hours ago

	withPCR := func(i uint64, v []byte) map[uint64][]byte {
		m := testgen.DefaultPCRs()
		m[i] = v
		return m
	}
	zero := make([]byte, 48)
	debug := testgen.DefaultPCRs()
	debug[0], debug[1], debug[2] = zero, zero, zero

	tests := []struct {
		name  string
		spec  nitroSpec
		trust *testgen.CA // the root the client trusts, default the environment's
		want  error
		text  string
	}{
		{"wrong PCR0 (another image)", nitroSpec{pcrs: withPCR(0, testgen.PCRValue(0xee))}, nil, attest.ErrMeasurement, "pcr0"},
		{"wrong PCR1 (another kernel)", nitroSpec{pcrs: withPCR(1, testgen.PCRValue(0xee))}, nil, attest.ErrMeasurement, "pcr1"},
		{"wrong PCR2 (another application)", nitroSpec{pcrs: withPCR(2, testgen.PCRValue(0xee))}, nil, attest.ErrMeasurement, "pcr2"},
		{"debug mode, PCR0 to PCR2 zero", nitroSpec{pcrs: debug}, nil, attest.ErrDebug, "debug-mode"},
		{"bad signature", nitroSpec{flipSig: true}, nil, attest.ErrSignature, ""},
		{"signed under a CA the client does not trust", nitroSpec{ca: otherCA}, nil, attest.ErrChain, ""},
		{"leaf certificate expired", nitroSpec{ca: expiredCA}, expiredCA, attest.ErrChain, "expired"},
		{"document for another nonce", nitroSpec{nonce: []byte("another request's nonce")}, nil, attest.ErrNonce, ""},
		{"document for other user data", nitroSpec{userData: []byte("another identity")}, nil, attest.ErrUserData, ""},
		{"timestamp in the future", nitroSpec{skew: time.Hour}, nil, attest.ErrStale, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := startFakeRunner(t, ca, env.attest(tc.spec))
			trust := tc.trust
			if trust == nil {
				trust = env.ca
			}
			err := health(t, nitroConn(t, ca, f), withNitroRoots(trust.Root))
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

func TestNitroExpectedPCR3Refused(t *testing.T) {
	// The configuration pins PCR3 (the parent's IAM role); the document
	// carries another one, as an enclave on another parent would.
	ca := newTestCA(t)
	env := newNitroEnv(t)
	pcrs := testgen.DefaultPCRs()
	pcrs[3] = testgen.PCRValue(0xdd)
	f := startFakeRunner(t, ca, env.attest(nitroSpec{pcrs: pcrs}))
	c := nitroConn(t, ca, f)
	if err := health(t, c, withNitroRoots(env.ca.Root)); err != nil {
		t.Fatalf("control, PCR3 not pinned: %v", err)
	}
	c.Attestation.NitroPCRs["3"] = pcrHex(3)
	err := health(t, c, withNitroRoots(env.ca.Root))
	if !errors.Is(err, attest.ErrMeasurement) {
		t.Fatalf("got %v", err)
	}
	wantErr(t, err, "pcr3")
}

func TestNitroTrustsTheAWSRootOnly(t *testing.T) {
	// Without the test-only option the client trusts the pinned AWS root, so a
	// document from a local CA is refused.
	ca := newTestCA(t)
	env := newNitroEnv(t)
	f := startFakeRunner(t, ca, env.attest(nitroSpec{}))
	err := health(t, nitroConn(t, ca, f))
	if !errors.Is(err, attest.ErrChain) {
		t.Fatalf("got %v", err)
	}
	wantErr(t, err, "not a pinned root")
}

func TestNitroRealAWSDocumentRefused(t *testing.T) {
	// A real NSM document (testdata/nitro/blocky-nitrite). It chains to the
	// real AWS root, so it passes the checks of the document's format, but
	// its leaf certificate ended long ago, and its PCRs, nonce and user data
	// are not ours.
	b, err := os.ReadFile("../testdata/nitro/blocky-nitrite/nitro_attestation.b64")
	if err != nil {
		t.Fatal(err)
	}
	doc, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
	if err != nil {
		t.Fatal(err)
	}
	ca := newTestCA(t)
	f := startFakeRunner(t, ca, func(nonce []byte, id *backend.Identity) *backend.Attestation {
		return &backend.Attestation{Platform: nitroPlatform, Format: nitroFormat, UserData: backend.IdentityUserData(nonce, id), Document: doc}
	})
	err = health(t, nitroConn(t, ca, f))
	if !errors.Is(err, attest.ErrChain) {
		t.Fatalf("got %v", err)
	}
	wantErr(t, err, "expired")
}

func TestNitroDocumentOfAnotherPlatformRefused(t *testing.T) {
	// No free pass for a dev, Azure or GCP document behind an aws-nitro
	// configuration.
	ca := newTestCA(t)
	maa := newMAAEnv(t, mainKeySet(t))
	for name, att := range map[string]attestFn{
		"dev":   devAttest,
		"azure": maa.attest(tokenSpec{}),
		"gcp":   maa.gcpAttest(gcpSpec{}),
	} {
		t.Run(name, func(t *testing.T) {
			f := startFakeRunner(t, ca, att)
			wantErr(t, health(t, nitroConn(t, ca, f)), "is not an AWS Nitro document")
		})
	}
}

func TestNitroChannelBinding(t *testing.T) {
	ca := newTestCA(t)
	env := newNitroEnv(t)

	t.Run("relay with its own TLS key", func(t *testing.T) {
		f := startFakeRunner(t, ca, env.attest(nitroSpec{}))
		real := sha256.Sum256([]byte("the real runner's TLS key"))
		f.claimedKey = real[:]
		wantErr(t, health(t, nitroConn(t, ca, f), withNitroRoots(env.ca.Root)), "attested identity names")
	})
	t.Run("wrong key pin", func(t *testing.T) {
		f := startFakeRunner(t, ca, env.attest(nitroSpec{}))
		c := nitroConn(t, ca, f)
		other := sha256.Sum256([]byte("another runner's TLS key"))
		c.TLSKeyPin = hex.EncodeToString(other[:])
		wantErr(t, health(t, c, withNitroRoots(env.ca.Root)), "is not the pinned key")
		if f.identities() != 0 {
			t.Fatal("the client asked for IDENTITY after the pin failed")
		}
	})
	t.Run("right key pin", func(t *testing.T) {
		f := startFakeRunner(t, ca, env.attest(nitroSpec{}))
		c := nitroConn(t, ca, f)
		c.TLSKeyPin = hex.EncodeToString(f.spki)
		if err := health(t, c, withNitroRoots(env.ca.Root)); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("replayed identity", func(t *testing.T) {
		f := startFakeRunner(t, ca, env.attest(nitroSpec{}))
		c := nitroConn(t, ca, f)
		if err := health(t, c, withNitroRoots(env.ca.Root)); err != nil {
			t.Fatalf("control: %v", err)
		}
		f.mu.Lock()
		f.replay = true
		f.mu.Unlock()
		wantErr(t, health(t, c, withNitroRoots(env.ca.Root)), "user data does not match")
	})
	t.Run("document of an earlier request under the new identity fields", func(t *testing.T) {
		good := env.attest(nitroSpec{})
		var old *backend.Attestation
		f := startFakeRunner(t, ca, func(nonce []byte, id *backend.Identity) *backend.Attestation {
			fresh := good(nonce, id)
			if old == nil {
				old = fresh
				return fresh
			}
			return &backend.Attestation{Platform: old.Platform, Format: old.Format, UserData: fresh.UserData, Document: old.Document}
		})
		c := nitroConn(t, ca, f)
		if err := health(t, c, withNitroRoots(env.ca.Root)); err != nil {
			t.Fatal(err)
		}
		err := health(t, c, withNitroRoots(env.ca.Root))
		if !errors.Is(err, attest.ErrNonce) {
			t.Fatalf("got %v", err)
		}
	})
}

func TestNitroConfigRefusals(t *testing.T) {
	ca := newTestCA(t)
	dir := t.TempDir()
	cert, key := ca.issue(t, dir, "client", time.Time{})
	good := Connection{Address: "tcp:signer-1:7100", ClientCert: cert, ClientKey: key, Attestation: nitroGood()}
	if err := good.Validate(); err != nil {
		t.Fatalf("good aws-nitro config: %v", err)
	}
	pcr := func(c *Connection, k, v string) {
		m := map[string]string{}
		for kk, vv := range c.Attestation.NitroPCRs {
			m[kk] = vv
		}
		if v == "" {
			delete(m, k)
		} else {
			m[k] = v
		}
		c.Attestation.NitroPCRs = m
	}
	zeros := strings.Repeat("00", 48)
	tests := []struct {
		name   string
		mutate func(c *Connection)
		want   string
	}{
		{"no PCRs", func(c *Connection) { c.Attestation.NitroPCRs = nil }, "nitro_pcrs: not set"},
		{"empty PCRs", func(c *Connection) { c.Attestation.NitroPCRs = map[string]string{} }, "nitro_pcrs: not set"},
		{"PCR0 missing", func(c *Connection) { pcr(c, "0", "") }, "pcr0 not set"},
		{"PCR1 missing", func(c *Connection) { pcr(c, "1", "") }, "pcr1 not set"},
		{"PCR2 missing", func(c *Connection) { pcr(c, "2", "") }, "pcr2 not set"},
		{"only PCR3", func(c *Connection) { c.Attestation.NitroPCRs = map[string]string{"3": pcrHex(3)} }, "pcr0 not set"},
		{"PCR0 too short", func(c *Connection) { pcr(c, "0", pcrHex(0)[:94]) }, "pcr0 want 96 hex"},
		{"PCR0 of 32 bytes (SHA-256)", func(c *Connection) { pcr(c, "0", strings.Repeat("ab", 32)) }, "pcr0 want 96 hex"},
		{"PCR1 not hex", func(c *Connection) { pcr(c, "1", strings.Repeat("g", 96)) }, "pcr1 want 96 hex"},
		{"PCR0 with 0x prefix", func(c *Connection) { pcr(c, "0", "0x"+pcrHex(0)) }, "pcr0 want 96 hex"},
		{"PCR0 all zero (debug mode)", func(c *Connection) { pcr(c, "0", zeros) }, "pcr0 is all zero"},
		{"PCR2 all zero (debug mode)", func(c *Connection) { pcr(c, "2", zeros) }, "pcr2 is all zero"},
		{"PCR name instead of index", func(c *Connection) { pcr(c, "pcr3", pcrHex(3)) }, `key "pcr3"`},
		{"PCR index 32", func(c *Connection) { pcr(c, "32", pcrHex(3)) }, `key "32"`},
		{"negative PCR index", func(c *Connection) { pcr(c, "-1", pcrHex(3)) }, `key "-1"`},
		{"PCR index with a leading zero", func(c *Connection) { pcr(c, "03", pcrHex(3)) }, `key "03"`},
		{"root pin of another root", func(c *Connection) { c.Attestation.NitroRootSHA256 = strings.Repeat("ab", 32) }, "this build pins the AWS Nitro root"},
		{"root pin too short", func(c *Connection) { c.Attestation.NitroRootSHA256 = "abcd" }, "nitro_root_sha256: want 64 hex"},
		{"root pin not hex", func(c *Connection) { c.Attestation.NitroRootSHA256 = strings.Repeat("z", 64) }, "nitro_root_sha256: want 64 hex"},
		{"MAA settings on aws-nitro", func(c *Connection) { c.Attestation.MAAHost = "sharedweu.weu.attest.azure.net" }, `belong to the verifier "azure-maa", not "aws-nitro"`},
		{"CCE policy hash on aws-nitro", func(c *Connection) { c.Attestation.CCEPolicySHA256 = goodHostData }, `belong to the verifier "azure-maa"`},
		{"GCP settings on aws-nitro", func(c *Connection) { c.Attestation.GCPAudience = "signer-runner-identity" }, `belong to the verifier "gcp-cs", not "aws-nitro"`},
		{"GCP image digest on aws-nitro", func(c *Connection) { c.Attestation.GCPImageDigest = gcpDigest }, `belong to the verifier "gcp-cs"`},
		{"vsock address", func(c *Connection) { c.Address = "vsock:16:7100" }, "tcp: address"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := Connection{Address: "tcp:signer-1:7100", ClientCert: cert, ClientKey: key, Attestation: nitroGood()}
			tc.mutate(&c)
			wantErr(t, c.Validate(), tc.want)
			_, err := c.New()
			wantErr(t, err, tc.want)
		})
	}

	// Settings of aws-nitro on every other verifier.
	for name, att := range map[string]Attestation{
		"dev":       {Verifier: VerifierDev},
		"azure-maa": {Verifier: VerifierAzureMAA, MAAHost: "sharedweu.weu.attest.azure.net", CCEPolicySHA256: goodHostData},
		"gcp-cs":    gcpGood("https://confidentialcomputing.googleapis.com"),
	} {
		for field, set := range map[string]func(a *Attestation){
			"nitro_pcrs":        func(a *Attestation) { a.NitroPCRs = map[string]string{"0": pcrHex(0)} },
			"nitro_root_sha256": func(a *Attestation) { a.NitroRootSHA256 = attest.NitroRootSHA256 },
		} {
			t.Run(field+" on "+name, func(t *testing.T) {
				a := att
				set(&a)
				wantErr(t, a.Validate(), `belong to the verifier "aws-nitro"`)
			})
		}
	}
}

// ---- gcp-cs ----

const (
	gcpDigest   = "sha256:1f0a6d4b3c2e9a8b7c6d5e4f30211a2b3c4d5e6f708192a3b4c5d6e7f8091a2b"
	gcpAudience = "signer-runner-identity"
	gcpAccount  = "signer@p.iam.gserviceaccount.com"
)

// gcpGood is a good gcp-cs configuration for the tokens of
// maaEnv.gcpAttest, with the issuer of the fake provider.
func gcpGood(issuer string) Attestation {
	return Attestation{
		Verifier: VerifierGCPCS, GCPImageDigest: gcpDigest, GCPAudience: gcpAudience,
		GCPHWModels: []string{"GCP_AMD_SEV", "GCP_INTEL_TDX"}, GCPIssuer: issuer,
	}
}

// gcpSpec says what a fake runner's Confidential Space token claims. Zero
// values give a good token from the main key. claims changes the claims
// before the token is signed.
type gcpSpec struct {
	claims  func(c map[string]any)
	key     *rsa.PrivateKey // default testgen.RSAKey(0)
	kid     string          // default maa-1, the kid of mainKeySet
	flipSig bool
}

// setPath assigns a dotted path in a claims map; nil deletes it.
func setPath(m map[string]any, path string, v any) {
	parts := strings.Split(path, ".")
	cur := m
	for _, p := range parts[:len(parts)-1] {
		cur = cur[p].(map[string]any)
	}
	if v == nil {
		delete(cur, parts[len(parts)-1])
	} else {
		cur[parts[len(parts)-1]] = v
	}
}

// gcpToken mints the token the launcher would return for the identity's
// user data: eat_nonce carries hex(user data), the way the runner asks.
func (e *maaEnv) gcpToken(s gcpSpec, ud []byte) string {
	now := time.Now()
	claims := map[string]any{
		"iss":                     e.issuer,
		"aud":                     gcpAudience,
		"sub":                     "https://www.googleapis.com/compute/v1/projects/p/zones/europe-west4-a/instances/123",
		"iat":                     now.Add(-10 * time.Second).Unix(),
		"nbf":                     now.Add(-10 * time.Second).Unix(),
		"exp":                     now.Add(time.Hour).Unix(),
		"eat_nonce":               []string{hex.EncodeToString(ud)},
		"secboot":                 true,
		"hwmodel":                 "GCP_AMD_SEV",
		"swname":                  "CONFIDENTIAL_SPACE",
		"swversion":               []string{"250301"},
		"dbgstat":                 "disabled-since-boot",
		"google_service_accounts": []string{gcpAccount},
		"submods": map[string]any{
			"confidential_space": map[string]any{"support_attributes": []string{"LATEST", "STABLE", "USABLE"}},
			"container":          map[string]any{"image_reference": "europe-docker.pkg.dev/p/r/signer-runner@" + gcpDigest, "image_digest": gcpDigest},
			"gce":                map[string]any{"project_id": "p", "zone": "europe-west4-a", "instance_id": "123", "instance_name": "signer-1"},
		},
	}
	if s.claims != nil {
		s.claims(claims)
	}
	key, kid := s.key, s.kid
	if key == nil {
		key = testgen.RSAKey(0)
	}
	if kid == "" {
		kid = "maa-1"
	}
	tok := testgen.SignJWT(e.t, key, kid, claims, nil)
	if s.flipSig {
		tok = flipSig(tok)
	}
	return tok
}

func (e *maaEnv) gcpAttest(s gcpSpec) attestFn {
	return func(nonce []byte, id *backend.Identity) *backend.Attestation {
		ud := backend.IdentityUserData(nonce, id)
		return &backend.Attestation{Platform: gcpPlatform, Format: gcpFormat, UserData: ud, Document: []byte(e.gcpToken(s, ud))}
	}
}

func gcpConn(t *testing.T, ca *testCA, f *fakeRunner, e *maaEnv) Connection {
	t.Helper()
	c := devConn(t, ca, f)
	c.Attestation = gcpGood(e.issuer)
	c.Attestation.SetupSHA256 = pinOf(fakeConfigHash)
	return c
}

func TestGCPRunnerConnects(t *testing.T) {
	ca := newTestCA(t)
	env := newMAAEnv(t, mainKeySet(t))
	f := startFakeRunner(t, ca, env.gcpAttest(gcpSpec{}))
	c := gcpConn(t, ca, f, env)
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

	// The service account, and the digest without "sha256:" and in upper
	// case, are fine too.
	c.Attestation.GCPServiceAccount = gcpAccount
	c.Attestation.GCPImageDigest = strings.ToUpper(strings.TrimPrefix(gcpDigest, "sha256:"))
	if err := health(t, c, WithHTTPClient(env.srv.Client())); err != nil {
		t.Fatal(err)
	}
}

func TestGCPDefaultIssuerIsGoogle(t *testing.T) {
	// Without gcp_issuer the verifier expects Google's issuer. No connection
	// here: that would ask Google for its key set.
	a := gcpGood("")
	s, err := a.gcp()
	if err != nil {
		t.Fatal(err)
	}
	if s.issuer != attest.ConfidentialSpaceIssuer || s.opts.Issuer != attest.ConfidentialSpaceIssuer {
		t.Fatalf("issuer %q, options issuer %q", s.issuer, s.opts.Issuer)
	}
	if s.pinned != nil {
		t.Fatal("a key set is pinned without gcp_jwks_file")
	}
}

func TestGCPTokenRefusals(t *testing.T) {
	ca := newTestCA(t)
	env := newMAAEnv(t, mainKeySet(t))
	claim := func(path string, v any) gcpSpec {
		return gcpSpec{claims: func(c map[string]any) { setPath(c, path, v) }}
	}
	otherDigest := "sha256:" + strings.Repeat("00", 31) + "aa"
	tests := []struct {
		name string
		spec gcpSpec
		conf func(a *Attestation)
		want error
		text string
	}{
		{"wrong image digest", claim("submods.container.image_digest", otherDigest), nil, attest.ErrMeasurement, "image_digest"},
		{"no image digest in the token", claim("submods.container.image_digest", nil), nil, attest.ErrMeasurement, "image_digest"},
		{"wrong audience", claim("aud", "another-audience"), nil, attest.ErrAudience, ""},
		{"STS audience (a credential for the KMS key)", claim("aud", attest.STSAudience), nil, attest.ErrAudience, ""},
		{"wrong issuer", claim("iss", "https://portal.trustauthority.intel.com"), nil, attest.ErrIssuer, ""},
		{"debug image", claim("dbgstat", "enabled"), nil, attest.ErrDebug, "dbgstat"},
		{"no dbgstat", claim("dbgstat", nil), nil, attest.ErrDebug, "dbgstat"},
		{"not Confidential Space (plain GCE)", claim("swname", "GCE"), nil, attest.ErrClaim, "swname"},
		{"secure boot off", claim("secboot", false), nil, attest.ErrClaim, "secboot"},
		{"image without STABLE support", claim("submods.confidential_space.support_attributes", []string{"LATEST", "USABLE"}), nil, attest.ErrClaim, "STABLE"},
		{"Shielded VM, no memory encryption", claim("hwmodel", "GCP_SHIELDED_VM"), nil, attest.ErrClaim, "hwmodel"},
		{"hardware model not in the list", claim("hwmodel", "GCP_AMD_SEV_ES"), nil, attest.ErrClaim, "hwmodel"},
		{"service account not in the token", claim("google_service_accounts", []string{"other@p.iam.gserviceaccount.com"}),
			func(a *Attestation) { a.GCPServiceAccount = gcpAccount }, attest.ErrClaim, "google_service_accounts"},
		{"runner in another project", claim("submods.gce.project_id", "someone-elses"),
			func(a *Attestation) { a.GCPProjectID = "signer-project" }, attest.ErrClaim, "project_id"},
		{"expired", claim("exp", time.Now().Add(-10*time.Minute).Unix()), nil, attest.ErrExpired, ""},
		{"bad signature", gcpSpec{flipSig: true}, nil, attest.ErrSignature, ""},
		{"signed by another key under the issuer's kid", gcpSpec{key: testgen.RSAKey(1)}, nil, attest.ErrSignature, ""},
		{"nonce of another identity", claim("eat_nonce", []string{hex.EncodeToString([]byte("another identity"))}), nil, attest.ErrNonce, ""},
		{"no nonce", claim("eat_nonce", nil), nil, attest.ErrNonce, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := startFakeRunner(t, ca, env.gcpAttest(tc.spec))
			c := gcpConn(t, ca, f, env)
			if tc.conf != nil {
				tc.conf(&c.Attestation)
			}
			err := health(t, c, WithHTTPClient(env.srv.Client()))
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

func TestGCPTokenOfAnotherRunnerImageRefused(t *testing.T) {
	// Runner 2 runs another image and holds a good token for it. A client
	// configured for the digest of runner 1 must not accept it; configured
	// for runner 2's digest it does.
	ca := newTestCA(t)
	env := newMAAEnv(t, mainKeySet(t))
	digest2 := "sha256:" + strings.Repeat("22", 32)
	runner2 := startFakeRunner(t, ca, env.gcpAttest(gcpSpec{claims: func(c map[string]any) {
		setPath(c, "submods.container.image_digest", digest2)
	}}))
	c := gcpConn(t, ca, runner2, env) // expects gcpDigest (runner 1)
	err := health(t, c, WithHTTPClient(env.srv.Client()))
	if !errors.Is(err, attest.ErrMeasurement) {
		t.Fatalf("got %v", err)
	}
	c.Attestation.GCPImageDigest = digest2
	if err := health(t, c, WithHTTPClient(env.srv.Client())); err != nil {
		t.Fatal(err)
	}
}

func TestGCPDocumentOfAnotherPlatformRefused(t *testing.T) {
	// A dev, Azure or Nitro document behind a gcp-cs configuration: refused
	// before the client asks the issuer for keys.
	ca := newTestCA(t)
	env := newMAAEnv(t, mainKeySet(t))
	nitro := newNitroEnv(t)
	for name, att := range map[string]attestFn{
		"dev":   devAttest,
		"azure": env.attest(tokenSpec{}),
		"nitro": nitro.attest(nitroSpec{}),
	} {
		t.Run(name, func(t *testing.T) {
			f := startFakeRunner(t, ca, att)
			wantErr(t, health(t, gcpConn(t, ca, f, env), WithHTTPClient(env.srv.Client())), "is not a Confidential Space token")
			if env.fetchCount() != 0 {
				t.Fatal("the client fetched keys for a document that is not a Confidential Space token")
			}
		})
	}
}

func TestGCPChannelBinding(t *testing.T) {
	ca := newTestCA(t)
	env := newMAAEnv(t, mainKeySet(t))
	hc := WithHTTPClient(env.srv.Client())

	t.Run("relay with its own TLS key", func(t *testing.T) {
		f := startFakeRunner(t, ca, env.gcpAttest(gcpSpec{}))
		real := sha256.Sum256([]byte("the real runner's TLS key"))
		f.claimedKey = real[:]
		wantErr(t, health(t, gcpConn(t, ca, f, env), hc), "attested identity names")
	})
	t.Run("wrong key pin", func(t *testing.T) {
		f := startFakeRunner(t, ca, env.gcpAttest(gcpSpec{}))
		c := gcpConn(t, ca, f, env)
		other := sha256.Sum256([]byte("another runner's TLS key"))
		c.TLSKeyPin = hex.EncodeToString(other[:])
		wantErr(t, health(t, c, hc), "is not the pinned key")
		if f.identities() != 0 {
			t.Fatal("the client asked for IDENTITY after the pin failed")
		}
	})
	t.Run("replayed identity", func(t *testing.T) {
		f := startFakeRunner(t, ca, env.gcpAttest(gcpSpec{}))
		c := gcpConn(t, ca, f, env)
		if err := health(t, c, hc); err != nil {
			t.Fatalf("control: %v", err)
		}
		f.mu.Lock()
		f.replay = true
		f.mu.Unlock()
		wantErr(t, health(t, c, hc), "user data does not match")
	})
	t.Run("token of an earlier request under the new identity fields", func(t *testing.T) {
		good := env.gcpAttest(gcpSpec{})
		var old *backend.Attestation
		f := startFakeRunner(t, ca, func(nonce []byte, id *backend.Identity) *backend.Attestation {
			fresh := good(nonce, id)
			if old == nil {
				old = fresh
				return fresh
			}
			return &backend.Attestation{Platform: old.Platform, Format: old.Format, UserData: fresh.UserData, Document: old.Document}
		})
		c := gcpConn(t, ca, f, env)
		if err := health(t, c, hc); err != nil {
			t.Fatal(err)
		}
		err := health(t, c, hc)
		if !errors.Is(err, attest.ErrNonce) {
			t.Fatalf("got %v", err)
		}
	})
}

func TestGCPRealGoogleKeySet(t *testing.T) {
	// The issuer serves Google's real key set (testdata/jwks).
	// A runner token signed with a local key under one of Google's key ids
	// fails the signature check, and a token under a kid the set lacks is an
	// unknown key.
	ca := newTestCA(t)
	b, err := os.ReadFile("../testdata/jwks/gcp-confidentialspace-20261013.json")
	if err != nil {
		t.Fatal(err)
	}
	var set struct {
		Keys []struct {
			Kid string `json:"kid"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(b, &set); err != nil || len(set.Keys) == 0 {
		t.Fatalf("key set: %v", err)
	}
	env := newMAAEnv(t, b)
	oldRefresh := keyRefreshGap
	t.Cleanup(func() { keyRefreshGap = oldRefresh })
	keyRefreshGap = time.Hour

	f := startFakeRunner(t, ca, env.gcpAttest(gcpSpec{kid: set.Keys[0].Kid}))
	err = health(t, gcpConn(t, ca, f, env), WithHTTPClient(env.srv.Client()))
	if !errors.Is(err, attest.ErrSignature) {
		t.Fatalf("local key under Google's kid: %v", err)
	}
	f = startFakeRunner(t, ca, env.gcpAttest(gcpSpec{kid: "not-a-google-kid"}))
	err = health(t, gcpConn(t, ca, f, env), WithHTTPClient(env.srv.Client()))
	if !errors.Is(err, attest.ErrUnknownKey) {
		t.Fatalf("unknown kid: %v", err)
	}
}

func TestGCPKeySetSources(t *testing.T) {
	ca := newTestCA(t)
	oldRefresh := keyRefreshGap
	t.Cleanup(func() { keyRefreshGap = oldRefresh })
	newKey := testgen.RSAKey(2)
	newSet := testgen.JWKS(t, "cs-2", newKey, false)

	t.Run("refetch on an unknown key id", func(t *testing.T) {
		keyRefreshGap = 0
		env := newMAAEnv(t, mainKeySet(t), newSet)
		f := startFakeRunner(t, ca, env.gcpAttest(gcpSpec{key: newKey, kid: "cs-2"}))
		if err := health(t, gcpConn(t, ca, f, env), WithHTTPClient(env.srv.Client())); err != nil {
			t.Fatal(err)
		}
		if env.fetchCount() != 2 {
			t.Fatalf("fetches %d, want 2", env.fetchCount())
		}
	})
	t.Run("no refetch inside the gap", func(t *testing.T) {
		keyRefreshGap = time.Hour
		env := newMAAEnv(t, mainKeySet(t), newSet)
		f := startFakeRunner(t, ca, env.gcpAttest(gcpSpec{key: newKey, kid: "cs-2"}))
		err := health(t, gcpConn(t, ca, f, env), WithHTTPClient(env.srv.Client()))
		if !errors.Is(err, attest.ErrUnknownKey) {
			t.Fatalf("got %v", err)
		}
		if env.fetchCount() != 1 {
			t.Fatalf("fetches %d, want 1", env.fetchCount())
		}
	})
	t.Run("key set unreachable", func(t *testing.T) {
		env := newMAAEnv(t, mainKeySet(t))
		f := startFakeRunner(t, ca, env.gcpAttest(gcpSpec{}))
		c := gcpConn(t, ca, f, env)
		env.srv.Close()
		wantErr(t, health(t, c, WithHTTPClient(env.srv.Client())), "Confidential Space key set")
	})
	t.Run("issuer names itself differently", func(t *testing.T) {
		// The OpenID configuration must name the configured issuer.
		env := newMAAEnv(t, mainKeySet(t))
		f := startFakeRunner(t, ca, env.gcpAttest(gcpSpec{}))
		c := gcpConn(t, ca, f, env)
		env.issuer = "https://other.example"
		wantErr(t, health(t, c, WithHTTPClient(env.srv.Client())), "Confidential Space key set")
	})
	t.Run("pinned key set, no network", func(t *testing.T) {
		env := newMAAEnv(t, mainKeySet(t))
		f := startFakeRunner(t, ca, env.gcpAttest(gcpSpec{}))
		c := gcpConn(t, ca, f, env)
		c.Attestation.GCPJWKSFile = filepath.Join(t.TempDir(), "keys.json")
		if err := os.WriteFile(c.Attestation.GCPJWKSFile, mainKeySet(t), 0o600); err != nil {
			t.Fatal(err)
		}
		env.srv.Close() // the issuer is not asked
		if err := health(t, c, WithHTTPClient(env.srv.Client())); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("pinned key set without the token's key", func(t *testing.T) {
		keyRefreshGap = 0
		env := newMAAEnv(t, mainKeySet(t))
		f := startFakeRunner(t, ca, env.gcpAttest(gcpSpec{key: newKey, kid: "cs-2"}))
		c := gcpConn(t, ca, f, env)
		c.Attestation.GCPJWKSFile = filepath.Join(t.TempDir(), "keys.json")
		if err := os.WriteFile(c.Attestation.GCPJWKSFile, mainKeySet(t), 0o600); err != nil {
			t.Fatal(err)
		}
		err := health(t, c, WithHTTPClient(env.srv.Client()))
		if !errors.Is(err, attest.ErrUnknownKey) {
			t.Fatalf("got %v", err)
		}
		if env.fetchCount() != 0 {
			t.Fatal("the client fetched a key set although one is pinned")
		}
	})
}

func TestGCPConfigRefusals(t *testing.T) {
	ca := newTestCA(t)
	dir := t.TempDir()
	cert, key := ca.issue(t, dir, "client", time.Time{})
	garbage := filepath.Join(dir, "garbage.json")
	os.WriteFile(garbage, []byte("not json"), 0o600)
	empty := filepath.Join(dir, "empty.json")
	os.WriteFile(empty, []byte(`{"keys":[]}`), 0o600)
	goodSet := filepath.Join(dir, "keys.json")
	os.WriteFile(goodSet, mainKeySet(t), 0o600)

	base := gcpGood("")
	conn := func() Connection {
		return Connection{Address: "tcp:signer-1:7100", ClientCert: cert, ClientKey: key, Attestation: base}
	}
	good := conn()
	if err := good.Validate(); err != nil {
		t.Fatalf("good gcp-cs config: %v", err)
	}
	full := conn()
	full.Attestation.GCPIssuer = "https://confidentialcomputing.googleapis.com"
	full.Attestation.GCPJWKSFile = goodSet
	full.Attestation.GCPServiceAccount = gcpAccount
	full.Attestation.GCPImageDigest = strings.TrimPrefix(gcpDigest, "sha256:")
	if err := full.Validate(); err != nil {
		t.Fatalf("full gcp-cs config: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(a *Attestation)
		want   string
	}{
		{"no image digest", func(a *Attestation) { a.GCPImageDigest = "" }, "gcp_image_digest: not set"},
		{"image digest too short", func(a *Attestation) { a.GCPImageDigest = gcpDigest[:70] }, "gcp_image_digest: want sha256:"},
		{"image digest not hex", func(a *Attestation) { a.GCPImageDigest = "sha256:" + strings.Repeat("g", 64) }, "gcp_image_digest: want sha256:"},
		{"image digest of another algorithm", func(a *Attestation) { a.GCPImageDigest = "sha512:" + strings.Repeat("ab", 32) }, "gcp_image_digest: want sha256:"},
		{"no audience", func(a *Attestation) { a.GCPAudience = "" }, "gcp_audience: not set"},
		{"STS audience", func(a *Attestation) { a.GCPAudience = attest.STSAudience }, "STS audience"},
		{"WIF resource name as audience", func(a *Attestation) {
			a.GCPAudience = "//iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/p/providers/q"
		}, "Workload Identity Federation"},
		{"WIF https name as audience", func(a *Attestation) {
			a.GCPAudience = "https://iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/p/providers/q"
		}, "Workload Identity Federation"},
		{"no hardware models", func(a *Attestation) { a.GCPHWModels = nil }, "gcp_hwmodels: not set"},
		{"empty hardware model", func(a *Attestation) { a.GCPHWModels = []string{"GCP_AMD_SEV", ""} }, "gcp_hwmodels"},
		{"hardware model with a space", func(a *Attestation) { a.GCPHWModels = []string{" GCP_AMD_SEV"} }, "gcp_hwmodels"},
		{"Shielded VM as hardware model", func(a *Attestation) { a.GCPHWModels = []string{"GCP_AMD_SEV", "GCP_SHIELDED_VM"} }, "without memory encryption"},
		{"http issuer", func(a *Attestation) { a.GCPIssuer = "http://confidentialcomputing.googleapis.com" }, "gcp_issuer"},
		{"issuer with a path", func(a *Attestation) { a.GCPIssuer = "https://confidentialcomputing.googleapis.com/v1" }, "gcp_issuer"},
		{"issuer with a trailing slash", func(a *Attestation) { a.GCPIssuer = "https://confidentialcomputing.googleapis.com/" }, "gcp_issuer"},
		{"issuer with a query", func(a *Attestation) { a.GCPIssuer = "https://confidentialcomputing.googleapis.com?x=1" }, "gcp_issuer"},
		{"issuer is a bare host", func(a *Attestation) { a.GCPIssuer = "confidentialcomputing.googleapis.com" }, "gcp_issuer"},
		{"service account without @", func(a *Attestation) { a.GCPServiceAccount = "signer" }, "gcp_service_account"},
		{"project ID with capitals", func(a *Attestation) { a.GCPProjectID = "Signer-Project" }, "gcp_project_id"},
		{"JWKS file missing", func(a *Attestation) { a.GCPJWKSFile = filepath.Join(dir, "nope.json") }, "gcp_jwks_file"},
		{"JWKS file not JSON", func(a *Attestation) { a.GCPJWKSFile = garbage }, "gcp_jwks_file"},
		{"JWKS file without keys", func(a *Attestation) { a.GCPJWKSFile = empty }, "gcp_jwks_file"},
		{"MAA settings on gcp-cs", func(a *Attestation) { a.MAAHost = "sharedweu.weu.attest.azure.net" }, `belong to the verifier "azure-maa", not "gcp-cs"`},
		{"CCE policy hash on gcp-cs", func(a *Attestation) { a.CCEPolicySHA256 = goodHostData }, `belong to the verifier "azure-maa"`},
		{"Nitro PCRs on gcp-cs", func(a *Attestation) { a.NitroPCRs = map[string]string{"0": pcrHex(0)} }, `belong to the verifier "aws-nitro", not "gcp-cs"`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := conn()
			a := c.Attestation
			a.GCPHWModels = append([]string(nil), a.GCPHWModels...)
			tc.mutate(&a)
			c.Attestation = a
			wantErr(t, c.Validate(), tc.want)
			_, err := c.New()
			wantErr(t, err, tc.want)
		})
	}

	// Settings of gcp-cs on every other verifier.
	for name, att := range map[string]Attestation{
		"dev":       {Verifier: VerifierDev},
		"azure-maa": {Verifier: VerifierAzureMAA, MAAHost: "sharedweu.weu.attest.azure.net", CCEPolicySHA256: goodHostData},
		"aws-nitro": nitroGood(),
	} {
		for field, set := range map[string]func(a *Attestation){
			"gcp_image_digest":    func(a *Attestation) { a.GCPImageDigest = gcpDigest },
			"gcp_audience":        func(a *Attestation) { a.GCPAudience = gcpAudience },
			"gcp_hwmodels":        func(a *Attestation) { a.GCPHWModels = []string{"GCP_AMD_SEV"} },
			"gcp_issuer":          func(a *Attestation) { a.GCPIssuer = attest.ConfidentialSpaceIssuer },
			"gcp_jwks_file":       func(a *Attestation) { a.GCPJWKSFile = goodSet },
			"gcp_service_account": func(a *Attestation) { a.GCPServiceAccount = gcpAccount },
			"gcp_project_id":      func(a *Attestation) { a.GCPProjectID = "signer-project" },
		} {
			t.Run(field+" on "+name, func(t *testing.T) {
				a := att
				set(&a)
				wantErr(t, a.Validate(), `belong to the verifier "gcp-cs"`)
			})
		}
	}
}

func TestVerifierNames(t *testing.T) {
	// The verifier name is required, exact, and has no skip value.
	for _, name := range []string{"", "none", "skip", "off", "nitro", "gcp", "azure", "aws_nitro", "GCP-CS", "Aws-Nitro"} {
		a := Attestation{Verifier: name}
		err := a.Validate()
		if err == nil {
			t.Fatalf("verifier %q accepted", name)
		}
		if name == "" {
			wantErr(t, err, "attestation.verifier: not set")
		} else {
			wantErr(t, err, "unknown verifier")
		}
		wantErr(t, err, `"aws-nitro"`)
		wantErr(t, err, `"gcp-cs"`)
	}
}

func TestResolvePathsJWKSFile(t *testing.T) {
	c := Connection{ClientCert: "client.pem", ClientKey: "key.pem", Attestation: Attestation{GCPJWKSFile: "keys.json"}}
	c.ResolvePaths("/etc/client")
	if c.Attestation.GCPJWKSFile != "/etc/client/keys.json" {
		t.Fatalf("%q", c.Attestation.GCPJWKSFile)
	}
	c.Attestation.GCPJWKSFile = "/abs/keys.json"
	c.ResolvePaths("/etc/client")
	if c.Attestation.GCPJWKSFile != "/abs/keys.json" {
		t.Fatalf("%q", c.Attestation.GCPJWKSFile)
	}
}

func TestFlagsNitroAndGCP(t *testing.T) {
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	a := Flags(fs)
	err := fs.Parse([]string{"-verifier", "aws-nitro",
		"-nitro-pcr", "0=" + pcrHex(0), "-nitro-pcr", "1=" + pcrHex(1), "-nitro-pcr", "2=" + pcrHex(2),
		"-nitro-root-sha256", attest.NitroRootSHA256})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Validate(); err != nil {
		t.Fatal(err)
	}
	if len(a.NitroPCRs) != 3 || a.NitroPCRs["1"] != pcrHex(1) {
		t.Fatalf("%v", a.NitroPCRs)
	}

	fs = flag.NewFlagSet("t", flag.ContinueOnError)
	a = Flags(fs)
	fs.Parse([]string{"-verifier", "aws-nitro", "-nitro-pcr", "0=" + pcrHex(0)})
	wantErr(t, a.Validate(), "pcr1 not set")

	for name, args := range map[string][]string{
		"PCR without a value":  {"-nitro-pcr", "0"},
		"PCR with empty value": {"-nitro-pcr", "0="},
		"PCR given twice":      {"-nitro-pcr", "0=" + pcrHex(0), "-nitro-pcr", "0=" + pcrHex(1)},
	} {
		fs = flag.NewFlagSet("t", flag.ContinueOnError)
		fs.SetOutput(&strings.Builder{})
		Flags(fs)
		if err := fs.Parse(args); err == nil {
			t.Fatalf("%s: parsed", name)
		}
	}

	fs = flag.NewFlagSet("t", flag.ContinueOnError)
	a = Flags(fs)
	err = fs.Parse([]string{"-verifier", "gcp-cs", "-gcp-image-digest", gcpDigest, "-gcp-audience", gcpAudience,
		"-gcp-hwmodel", "GCP_AMD_SEV", "-gcp-hwmodel", "GCP_INTEL_TDX", "-gcp-issuer", "https://cs.example",
		"-gcp-service-account", gcpAccount})
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Validate(); err != nil {
		t.Fatal(err)
	}
	if len(a.GCPHWModels) != 2 || a.GCPIssuer != "https://cs.example" || a.GCPServiceAccount != gcpAccount {
		t.Fatalf("%+v", a)
	}

	fs = flag.NewFlagSet("t", flag.ContinueOnError)
	a = Flags(fs)
	fs.Parse([]string{"-verifier", "gcp-cs", "-gcp-image-digest", gcpDigest, "-gcp-audience", gcpAudience})
	wantErr(t, a.Validate(), "gcp_hwmodels: not set")

	// A flag of another verifier is refused, as in a configuration file.
	fs = flag.NewFlagSet("t", flag.ContinueOnError)
	a = Flags(fs)
	fs.Parse([]string{"-verifier", "dev", "-gcp-audience", gcpAudience})
	wantErr(t, a.Validate(), "belong to the verifier")
}

func TestAttestationJSONNames(t *testing.T) {
	// The names of the signing client's backend.cloud.config.
	in := `{"verifier":"aws-nitro","nitro_pcrs":{"0":"` + pcrHex(0) + `","1":"` + pcrHex(1) + `","2":"` + pcrHex(2) + `"},"nitro_root_sha256":"` + attest.NitroRootSHA256 + `"}`
	var a Attestation
	if err := json.Unmarshal([]byte(in), &a); err != nil {
		t.Fatal(err)
	}
	if err := a.Validate(); err != nil {
		t.Fatal(err)
	}
	in = `{"verifier":"gcp-cs","gcp_image_digest":"` + gcpDigest + `","gcp_audience":"` + gcpAudience +
		`","gcp_hwmodels":["GCP_AMD_SEV"],"gcp_issuer":"https://confidentialcomputing.googleapis.com","gcp_service_account":"` + gcpAccount + `"}`
	a = Attestation{}
	if err := json.Unmarshal([]byte(in), &a); err != nil {
		t.Fatal(err)
	}
	if err := a.Validate(); err != nil {
		t.Fatal(err)
	}
}
