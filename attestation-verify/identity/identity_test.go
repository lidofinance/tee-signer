//go:build !verifierselect

package identity

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/attestation-verify"
	"github.com/lidofinance/tee-signer/attestation-verify/internal/testgen"
	"github.com/lidofinance/tee-signer/signer-protocol"
)

// The runner's IDENTITY response, bound to each platform document the way
// runner/platform does it, then checked through Config.Verify. All
// documents are synthetic.

var now = time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)

func identity(platform, format string) *backend.Identity {
	return &backend.Identity{
		State:     backend.SetupState{SetupHash: backend.Root{1, 2, 3}},
		ImportKEM: 0x0041, ImportKDF: 1, ImportAEAD: 3,
		ImportKey:   []byte("hpke public key"),
		TLSKeyHash:  make([]byte, 32),
		Attestation: &backend.Attestation{Platform: platform, Format: format},
	}
}

func TestNitroIdentity(t *testing.T) {
	ca := testgen.NewCA(t, now)
	nonce := []byte("client nonce 0123456789abcdef")
	id := identity("nitro", "aws-nitro-cose-sign1")
	ud := backend.IdentityUserData(nonce, id)
	id.Attestation.UserData = ud
	id.Attestation.Document = ca.NitroDoc(t, testgen.NitroSpec{TS: now, Nonce: nonce, UserData: ud})
	cfg := Config{Nitro: &attest.NitroOptions{Roots: []*x509.Certificate{ca.Root}, Now: now,
		PCRs: map[int][]byte{0: testgen.PCRValue(0xa0), 1: testgen.PCRValue(0xa1), 2: testgen.PCRValue(0xa2)}}}
	if err := cfg.Verify(context.Background(), nonce, id); err != nil {
		t.Fatal(err)
	}
	// Replay to a client that sent another nonce.
	if err := cfg.Verify(context.Background(), []byte("other nonce"), id); err == nil {
		t.Fatal("replayed identity accepted")
	}
	// A changed identity field (the HPKE key) breaks the user data.
	id.ImportKey = []byte("attacker key")
	if err := cfg.Verify(context.Background(), nonce, id); err == nil {
		t.Fatal("changed import key accepted")
	}
	// Platform not configured.
	if err := (Config{}).Verify(context.Background(), nonce, id); err == nil {
		t.Fatal("unconfigured platform accepted")
	}
}

func TestGCPIdentity(t *testing.T) {
	key := testgen.RSAKey(0)
	ks, err := attest.ParseJWKS(testgen.JWKS(t, "k1", key, false))
	if err != nil {
		t.Fatal(err)
	}
	nonce := []byte("client nonce gcp")
	id := identity("gcp", "gcp-confidential-space-jwt")
	ud := backend.IdentityUserData(nonce, id)
	id.Attestation.UserData = ud
	digest := "sha256:" + strings.Repeat("ab", 32)
	claims := func(aud string) map[string]any {
		return map[string]any{
			"iss": attest.ConfidentialSpaceIssuer, "aud": aud,
			"iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
			"eat_nonce": hex.EncodeToString(ud), "secboot": true,
			"swname": "CONFIDENTIAL_SPACE", "dbgstat": "disabled-since-boot",
			"submods": map[string]any{
				"confidential_space": map[string]any{"support_attributes": []string{"STABLE"}},
				"container":          map[string]any{"image_digest": digest},
			},
		}
	}
	id.Attestation.Document = []byte(testgen.SignJWT(t, key, "k1", claims("signer-runner-identity"), nil))
	cfg := Config{GCP: &attest.ConfidentialSpaceOptions{Keys: ks, Audience: "signer-runner-identity", Now: now, ImageDigests: []string{digest}}}
	if err := cfg.Verify(context.Background(), nonce, id); err != nil {
		t.Fatal(err)
	}
	if err := cfg.Verify(context.Background(), []byte("other nonce"), id); err == nil {
		t.Fatal("replayed identity accepted")
	}
	// The runner's default audience is STS; refuse it for identities.
	id.Attestation.Document = []byte(testgen.SignJWT(t, key, "k1", claims(attest.STSAudience), nil))
	cfg.GCP.Audience = attest.STSAudience
	if err := cfg.Verify(context.Background(), nonce, id); !errors.Is(err, attest.ErrConfig) {
		t.Fatalf("STS audience: %v", err)
	}
}

func TestAzureIdentity(t *testing.T) {
	key := testgen.RSAKey(1)
	ks, err := attest.ParseJWKS(testgen.JWKS(t, "maa", key, true))
	if err != nil {
		t.Fatal(err)
	}
	nonce := []byte("client nonce azure")
	id := identity("azure", "azure-maa-jwt")
	ud := backend.IdentityUserData(nonce, id)
	id.Attestation.UserData = ud
	// The runner sends this JSON object as runtime data (to MAA with
	// dataType JSON); the SNP report data hashes its bytes.
	runtime := []byte(`{"signer-runner-identity":"` + hex.EncodeToString(ud) + `"}`)
	if string(backend.MAARuntimeData(ud)) != string(runtime) {
		t.Fatalf("MAARuntimeData %q, want %q", backend.MAARuntimeData(ud), runtime)
	}
	hostdata := strings.Repeat("cd", 32)
	doc := func(runtimeData []byte) []byte {
		sum := sha256.Sum256(runtimeData)
		return []byte(testgen.SignJWT(t, key, "maa", map[string]any{
			"iss": "https://signer.weu.attest.azure.net", "iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
			"x-ms-attestation-type": "sevsnpvm", "x-ms-compliance-status": attest.ComplianceACI,
			"x-ms-sevsnpvm-hostdata": hostdata, "x-ms-sevsnpvm-is-debuggable": false, "x-ms-sevsnpvm-vmpl": 0,
			"x-ms-sevsnpvm-reportdata": hex.EncodeToString(sum[:]) + strings.Repeat("00", 32),
			"x-ms-runtime":             map[string]any{"signer-runner-identity": hex.EncodeToString(ud)},
		}, nil))
	}
	id.Attestation.Document = doc(runtime)
	cfg := Config{Azure: &attest.MAAOptions{Issuer: "https://signer.weu.attest.azure.net", Keys: ks, Now: now,
		ComplianceStatus: attest.ComplianceACI, HostData: []string{hostdata}}}
	if err := cfg.Verify(context.Background(), nonce, id); err != nil {
		t.Fatal(err)
	}
	if err := cfg.Verify(context.Background(), []byte("other nonce"), id); err == nil {
		t.Fatal("replayed identity accepted")
	}
	// A token over the raw user data (the binding before the JSON fix) does
	// not verify.
	id.Attestation.Document = doc(ud)
	if err := cfg.Verify(context.Background(), nonce, id); !errors.Is(err, attest.ErrNonce) {
		t.Fatalf("raw runtime data: %v", err)
	}
}
