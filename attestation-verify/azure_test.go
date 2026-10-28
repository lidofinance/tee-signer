//go:build !peerselect

package attest

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

// Synthetic MAA tokens. The claim layout follows Microsoft's SEV-SNP
// sample token and the SKR policy examples (see azure.go); a local RSA key
// with a self-signed x5c certificate signs them, like an MAA provider key.

const (
	maaIssuer   = "https://signer.weu.attest.azure.net"
	maaHostData = "73e0d1b6b2d0b0b3c0c8a0d7a8f2b1f3e4d5c6b7a8f9e0d1c2b3a4958677a6b5"
	maaVMID     = "B958DC88-E41D-47F1-8D20-E57B6B7E9825"
)

var maaRuntime = []byte(`{"signer-runner-identity":"00112233"}`)

func reportData(rt []byte) string {
	s := sha256.Sum256(rt)
	return hex.EncodeToString(s[:]) + strings.Repeat("00", 32)
}

func snpClaims() map[string]any {
	return map[string]any{
		"x-ms-attestation-type":           "sevsnpvm",
		"x-ms-compliance-status":          ComplianceACI,
		"x-ms-sevsnpvm-hostdata":          maaHostData,
		"x-ms-sevsnpvm-is-debuggable":     false,
		"x-ms-sevsnpvm-vmpl":              0,
		"x-ms-sevsnpvm-reportdata":        reportData(maaRuntime),
		"x-ms-sevsnpvm-launchmeasurement": strings.Repeat("ab", 48),
		"x-ms-sevsnpvm-migration-allowed": false,
	}
}

// aciClaims: confidential containers on ACI.
func aciClaims(now time.Time) map[string]any {
	c := snpClaims()
	c["iss"] = maaIssuer
	c["jti"] = "5f65006d573bc1c04f67820348c20f5d"
	c["iat"] = now.Add(-20 * time.Second).Unix()
	c["nbf"] = now.Add(-20 * time.Second).Unix()
	c["exp"] = now.Add(8 * time.Hour).Unix()
	c["x-ms-ver"] = "1.0"
	c["x-ms-policy-hash"] = "LTPRQQju-test-policy-hash"
	c["x-ms-runtime"] = map[string]any{"signer-runner-identity": "00112233"}
	return c
}

// cvmGuestClaims: confidential VM guest attestation, with the hardware
// claims nested in x-ms-isolation-tee.
func cvmGuestClaims(now time.Time) map[string]any {
	tee := snpClaims()
	tee["x-ms-compliance-status"] = ComplianceCVM
	tee["x-ms-sevsnpvm-hostdata"] = strings.Repeat("00", 32)
	return map[string]any{
		"iss": maaIssuer, "iat": now.Unix(), "nbf": now.Unix(), "exp": now.Add(8 * time.Hour).Unix(),
		"x-ms-ver":              "1.0",
		"x-ms-attestation-type": "azurevm",
		"x-ms-azurevm-vmid":     maaVMID,
		"x-ms-isolation-tee":    tee,
		"x-ms-runtime":          map[string]any{"client-payload": map[string]any{"nonce": "abc"}},
	}
}

// cvmHCLClaims: the SEV-SNP sample shape (HCL report), VM id in
// x-ms-runtime.vm-configuration.vmUniqueId.
func cvmHCLClaims(now time.Time) map[string]any {
	c := aciClaims(now)
	c["x-ms-compliance-status"] = ComplianceCVM
	c["x-ms-runtime"] = map[string]any{
		"keys":             []any{map[string]any{"kid": "HCLTransferKey", "kty": "RSA", "e": "AQAB", "n": "AQAB"}},
		"vm-configuration": map[string]any{"secure-boot": true, "tpm-enabled": true, "vmUniqueId": strings.ToLower(maaVMID)},
	}
	return c
}

func renderedSKRPolicy(t *testing.T) *ReleasePolicy {
	t.Helper()
	tmpl := string(readFile(t, "../platform-azure/deploy/skr-policy.json.tmpl"))
	r := strings.NewReplacer("${MAA_ENDPOINT}", strings.TrimPrefix(maaIssuer, "https://"), "${CCE_POLICY_SHA256}", maaHostData)
	p, err := ParseReleasePolicy([]byte(r.Replace(tmpl)))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// skrExampleCVM is SKR policy example 2 for confidential VMs from
// Microsoft's skr-policy-examples page, with our issuer and VM id.
const skrExampleCVM = `{
  "version": "1.0.0",
  "allOf": [
    {
      "authority": "` + maaIssuer + `",
      "allOf": [
        {"claim": "x-ms-isolation-tee.x-ms-attestation-type", "equals": "sevsnpvm"},
        {"claim": "x-ms-isolation-tee.x-ms-compliance-status", "equals": "azure-compliant-cvm"},
        {"claim": "x-ms-azurevm-vmid", "equals": "` + maaVMID + `"}
      ]
    }
  ]
}`

func TestMAA(t *testing.T) {
	now := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	key := testRSA(t, 0)
	ks := keySet(t, jwksFor(t, "maa-test-kid", key, true))
	sign := func(c map[string]any) string { return signJWT(t, key, "maa-test-kid", c, nil) }
	aci := aciClaims(now)
	good := sign(aci)
	opts := func() MAAOptions {
		return MAAOptions{Issuer: maaIssuer, Keys: ks, Now: now, ComplianceStatus: ComplianceACI,
			HostData: []string{maaHostData}, RuntimeData: maaRuntime, Policy: renderedSKRPolicy(t)}
	}

	t.Run("ACI good, with our SKR policy", func(t *testing.T) {
		tok, err := VerifyMAA(good, opts())
		if err != nil {
			t.Fatal(err)
		}
		if tok.TEEType != "sevsnpvm" || tok.HostData != maaHostData || tok.IsDebuggable || tok.Runtime["signer-runner-identity"] != "00112233" {
			t.Fatalf("%+v", tok)
		}
	})
	t.Run("CVM guest attestation with VM id and SKR example 2", func(t *testing.T) {
		p, err := ParseReleasePolicy([]byte(skrExampleCVM))
		if err != nil {
			t.Fatal(err)
		}
		o := MAAOptions{Issuer: maaIssuer, Keys: ks, Now: now, ComplianceStatus: ComplianceCVM, VMID: strings.ToLower(maaVMID), MaxAge: time.Minute, Policy: p}
		tok, err := VerifyMAA(sign(cvmGuestClaims(now)), o)
		if err != nil {
			t.Fatal(err)
		}
		if tok.AttestationType != "azurevm" || tok.VMID != maaVMID {
			t.Fatalf("%+v", tok)
		}
		o.VMID = "00000000-0000-0000-0000-000000000000"
		_, err = VerifyMAA(sign(cvmGuestClaims(now)), o)
		wantErr(t, err, ErrClaim)
		o.VMID = ""
		_, err = VerifyMAA(sign(set(cvmGuestClaims(now), "x-ms-azurevm-vmid", "00000000-0000-0000-0000-000000000000")), MAAOptions{
			Issuer: maaIssuer, Keys: ks, Now: now, ComplianceStatus: ComplianceCVM, AcceptAnyWorkload: true, MaxAge: time.Minute, Policy: p})
		wantErr(t, err, ErrClaim)
	})
	t.Run("CVM HCL report shape with VM id", func(t *testing.T) {
		o := MAAOptions{Issuer: maaIssuer, Keys: ks, Now: now, ComplianceStatus: ComplianceCVM, VMID: maaVMID, RuntimeData: maaRuntime}
		if _, err := VerifyMAA(sign(cvmHCLClaims(now)), o); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("tampered signature", func(t *testing.T) {
		_, err := VerifyMAA(flipSig(good), opts())
		wantErr(t, err, ErrSignature)
	})
	t.Run("tampered payload", func(t *testing.T) {
		_, err := VerifyMAA(swapPayload(t, good, set(clone(aci), "x-ms-sevsnpvm-is-debuggable", true)), opts())
		wantErr(t, err, ErrSignature)
	})
	t.Run("key of another provider", func(t *testing.T) {
		o := opts()
		o.Keys = keySet(t, jwksFor(t, "maa-test-kid", testRSA(t, 1), true))
		_, err := VerifyMAA(good, o)
		wantErr(t, err, ErrSignature)
	})
	t.Run("wrong issuer", func(t *testing.T) {
		_, err := VerifyMAA(sign(set(clone(aci), "iss", "https://sharedweu.weu.attest.azure.net")), opts())
		wantErr(t, err, ErrIssuer)
	})
	t.Run("expired", func(t *testing.T) {
		o := opts()
		o.Now = now.Add(9 * time.Hour)
		_, err := VerifyMAA(good, o)
		wantErr(t, err, ErrExpired)
	})
	t.Run("debug", func(t *testing.T) {
		tok := sign(set(clone(aci), "x-ms-sevsnpvm-is-debuggable", true))
		o := opts()
		o.Policy = nil
		_, err := VerifyMAA(tok, o)
		wantErr(t, err, ErrDebug)
		// With AllowDebug the SKR policy still refuses it, as Key Vault would.
		o = opts()
		o.AllowDebug = true
		_, err = VerifyMAA(tok, o)
		wantErr(t, err, ErrDebug)
	})
	t.Run("debug in isolation-tee", func(t *testing.T) {
		tok := sign(set(cvmGuestClaims(now), "x-ms-isolation-tee.x-ms-sevsnpvm-is-debuggable", true))
		_, err := VerifyMAA(tok, MAAOptions{Issuer: maaIssuer, Keys: ks, Now: now, ComplianceStatus: ComplianceCVM, VMID: maaVMID, MaxAge: time.Minute})
		wantErr(t, err, ErrDebug)
	})
	t.Run("is-debuggable missing", func(t *testing.T) {
		o := opts()
		o.Policy = nil
		_, err := VerifyMAA(sign(set(clone(aci), "x-ms-sevsnpvm-is-debuggable", nil)), o)
		wantErr(t, err, ErrDebug)
	})
	t.Run("CVM token where ACI is expected", func(t *testing.T) {
		_, err := VerifyMAA(sign(cvmHCLClaims(now)), opts())
		wantErr(t, err, ErrClaim)
	})
	t.Run("wrong host data", func(t *testing.T) {
		_, err := VerifyMAA(sign(set(clone(aci), "x-ms-sevsnpvm-hostdata", strings.Repeat("11", 32))), opts())
		wantErr(t, err, ErrMeasurement)
	})
	t.Run("stale runtime data", func(t *testing.T) {
		o := opts()
		o.RuntimeData = []byte(`{"signer-runner-identity":"44556677"}`)
		_, err := VerifyMAA(good, o)
		wantErr(t, err, ErrNonce)
	})
	t.Run("vmpl 2", func(t *testing.T) {
		_, err := VerifyMAA(sign(set(clone(aci), "x-ms-sevsnpvm-vmpl", 2)), opts())
		wantErr(t, err, ErrClaim)
	})
	t.Run("not SEV-SNP", func(t *testing.T) {
		_, err := VerifyMAA(sign(set(clone(aci), "x-ms-attestation-type", "sgx")), opts())
		wantErr(t, err, ErrClaim)
	})
	t.Run("policy of another authority", func(t *testing.T) {
		p, err := ParseReleasePolicy([]byte(strings.Replace(skrExampleCVM, maaIssuer, "https://other.weu.attest.azure.net", 1)))
		if err != nil {
			t.Fatal(err)
		}
		_, err = VerifyMAA(sign(cvmGuestClaims(now)), MAAOptions{Issuer: maaIssuer, Keys: ks, Now: now, ComplianceStatus: ComplianceCVM, VMID: maaVMID, MaxAge: time.Minute, Policy: p})
		wantErr(t, err, ErrIssuer)
	})
	t.Run("policy parser refuses what it cannot evaluate", func(t *testing.T) {
		for _, p := range []string{
			`{"version":"1.0.0","anyOf":[{"authority":"x","allOf":[{"claim":"a","greater":1}]}]}`,
			`{"version":"2.0.0","anyOf":[{"authority":"x","allOf":[{"claim":"a","equals":"b"}]}]}`,
			`{"version":"1.0.0","anyOf":[{"authority":"x","allOf":[{"claim":"a","equals":{"o":1}}]}]}`,
			`{"version":"1.0.0","anyOf":[{"authority":"x","claim":"a","equals":"b"}]}`,
			`{"version":"1.0.0","anyOf":[]}`,
		} {
			if _, err := ParseReleasePolicy([]byte(p)); err == nil {
				t.Fatalf("accepted %s", p)
			}
		}
	})
	t.Run("config", func(t *testing.T) {
		for _, o := range []MAAOptions{
			{Keys: ks, ComplianceStatus: ComplianceACI, HostData: []string{maaHostData}, MaxAge: time.Minute},
			{Issuer: maaIssuer, ComplianceStatus: ComplianceACI, HostData: []string{maaHostData}, MaxAge: time.Minute},
			{Issuer: maaIssuer, Keys: ks, HostData: []string{maaHostData}, MaxAge: time.Minute},
			{Issuer: maaIssuer, Keys: ks, ComplianceStatus: ComplianceACI, MaxAge: time.Minute},
			{Issuer: maaIssuer, Keys: ks, ComplianceStatus: ComplianceACI, HostData: []string{maaHostData}},
		} {
			_, err := VerifyMAA(good, o)
			wantErr(t, err, ErrConfig)
		}
	})
}

// TestMAAJWKSSnapshot parses the key set of the shared West Europe
// provider in testdata (ParseJWKS checks each n/e against its
// x5c certificate) and checks that a token signed by a local key under a
// real key id fails.
func TestMAAJWKSSnapshot(t *testing.T) {
	ks := keySet(t, readFile(t, "testdata/jwks/maa-sharedweu-20261013.json"))
	ids := ks.KeyIDs()
	if len(ids) != 4 {
		t.Fatalf("key ids %v", ids)
	}
	now := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	c := set(aciClaims(now), "iss", "https://sharedweu.weu.attest.azure.net")
	tok := signJWT(t, testRSA(t, 0), ids[0], c, nil)
	_, err := VerifyMAA(tok, MAAOptions{Issuer: "https://sharedweu.weu.attest.azure.net", Keys: ks, Now: now,
		ComplianceStatus: ComplianceACI, HostData: []string{maaHostData}, MaxAge: time.Minute})
	wantErr(t, err, ErrSignature)
}

func TestJWKSConsistency(t *testing.T) {
	// n/e of one key, x5c of another: refused.
	a := jwksFor(t, "k", testRSA(t, 0), false)
	b := jwksFor(t, "k", testRSA(t, 1), true)
	mixed := strings.Replace(string(b), `"n":"`+between(string(b), `"n":"`, `"`), `"n":"`+between(string(a), `"n":"`, `"`), 1)
	if _, err := ParseJWKS([]byte(mixed)); err == nil {
		t.Fatal("accepted a JWK whose n differs from its x5c")
	}
	// Duplicate kid: refused.
	dup := `{"keys":[` + between(string(a), `{"keys":[`, `]}`) + `,` + between(string(a), `{"keys":[`, `]}`) + `]}`
	if _, err := ParseJWKS([]byte(dup)); err == nil {
		t.Fatal("accepted a duplicate kid")
	}
}

func between(s, start, end string) string {
	i := strings.Index(s, start) + len(start)
	j := strings.Index(s[i:], end)
	return s[i : i+j]
}
