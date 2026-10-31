package attest

import (
	"crypto/x509"
	"os"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/attestation-verify/internal/testgen"
	"github.com/lidofinance/tee-signer/devkit/fuzzcheck"
)

// Fuzz targets for the attestation evidence a runner checks: a peer's
// IDENTITY and ATTEST documents (Nitro COSE_Sign1, MAA and Confidential
// Space tokens) and the key sets they are checked under. The oracles
// (fuzzcheck): no panic, and an allocation bounded by the input.
// Certificates, JSON and RSA take more per byte than the wire decoders,
// so the bound is wider.

func evidenceBound(n int) uint64 { return uint64(64*n + 1<<20) }

func FuzzVerifyNitro(f *testing.F) {
	now := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	ca := testgen.NewCA(f, now)
	nonce := []byte("fresh nonce from the verifier 01")
	f.Add(ca.NitroDoc(f, testgen.NitroSpec{TS: now.Add(-10 * time.Second), Nonce: nonce, UserData: []byte("ud"), PublicKey: []byte("pk")}))
	for _, r := range realNitroDocs {
		if !r.b64 {
			f.Add(readFileF(f, r.file))
		}
	}
	opts := NitroOptions{Roots: []*x509.Certificate{ca.Root}, Now: now, AcceptAnyPCRs: true, AllowDebug: true, MaxAge: time.Minute}
	f.Fuzz(func(t *testing.T, doc []byte) {
		fuzzcheck.Watch(t)
		fuzzcheck.BoundedBy(t, evidenceBound(len(doc)), func() { VerifyNitro(doc, opts) })
	})
}

func FuzzVerifyMAA(f *testing.F) {
	now := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	key := testgen.RSAKey(0)
	ks, err := ParseJWKS(testgen.JWKS(f, "maa-test-kid", key, true))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(testgen.SignJWT(f, key, "maa-test-kid", aciClaims(now), nil))
	f.Add(testgen.SignJWT(f, key, "maa-test-kid", cvmGuestClaims(now), nil))
	opts := MAAOptions{Issuer: maaIssuer, Keys: ks, Now: now, ComplianceStatus: ComplianceACI,
		HostData: []string{maaHostData}, RuntimeData: maaRuntime}
	f.Fuzz(func(t *testing.T, tok string) {
		fuzzcheck.Watch(t)
		fuzzcheck.BoundedBy(t, evidenceBound(len(tok)), func() { VerifyMAA(tok, opts) })
	})
}

func FuzzVerifyConfidentialSpace(f *testing.F) {
	now := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	key := testgen.RSAKey(0)
	ks, err := ParseJWKS(testgen.JWKS(f, "test-kid-1", key, false))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(testgen.SignJWT(f, key, "test-kid-1", csClaims(now), nil))
	opts := ConfidentialSpaceOptions{Keys: ks, Audience: "signer-runner-identity", Now: now,
		ImageDigests: []string{csDigest}, Nonces: []string{"6e6f6e63652d74776f"}, MaxAge: 5 * time.Minute}
	f.Fuzz(func(t *testing.T, tok string) {
		fuzzcheck.Watch(t)
		fuzzcheck.BoundedBy(t, evidenceBound(len(tok)), func() { VerifyConfidentialSpace(tok, opts) })
	})
}

func FuzzParseJWKS(f *testing.F) {
	f.Add(testgen.JWKS(f, "kid", testgen.RSAKey(0), true))
	f.Add(testgen.JWKS(f, "kid", testgen.RSAKey(1), false))
	f.Fuzz(func(t *testing.T, b []byte) {
		fuzzcheck.Watch(t)
		fuzzcheck.BoundedBy(t, evidenceBound(len(b)), func() { ParseJWKS(b) })
	})
}

func readFileF(f *testing.F, path string) []byte {
	b, err := os.ReadFile(path)
	if err != nil {
		f.Fatal(err)
	}
	return b
}
