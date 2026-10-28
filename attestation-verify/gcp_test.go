//go:build !peerselect

package attest

import (
	"testing"
	"time"
)

// Synthetic Confidential Space tokens. The claim layout follows Google's
// token claims reference (see gcp.go); a local RSA key signs them.

const (
	csDigest    = "sha256:1f0a6d4b3c2e9a8b7c6d5e4f30211a2b3c4d5e6f708192a3b4c5d6e7f8091a2b"
	otherDigest = "sha256:00000000000000000000000000000000000000000000000000000000000000aa"
)

func csClaims(now time.Time) map[string]any {
	return map[string]any{
		"iss":                     ConfidentialSpaceIssuer,
		"aud":                     "signer-runner-identity",
		"sub":                     "https://www.googleapis.com/compute/v1/projects/p/zones/europe-west4-a/instances/123",
		"iat":                     now.Add(-30 * time.Second).Unix(),
		"nbf":                     now.Add(-30 * time.Second).Unix(),
		"exp":                     now.Add(30 * time.Minute).Unix(),
		"eat_nonce":               []string{"6e6f6e63652d6f6e65", "6e6f6e63652d74776f"},
		"secboot":                 true,
		"oemid":                   11129,
		"hwmodel":                 "GCP_AMD_SEV",
		"swname":                  "CONFIDENTIAL_SPACE",
		"swversion":               []string{"250301"},
		"dbgstat":                 "disabled-since-boot",
		"google_service_accounts": []string{"signer@p.iam.gserviceaccount.com"},
		"submods": map[string]any{
			"confidential_space": map[string]any{"support_attributes": []string{"LATEST", "STABLE", "USABLE"}},
			"container": map[string]any{
				"image_reference": "europe-docker.pkg.dev/p/r/signer-runner@" + csDigest,
				"image_digest":    csDigest,
				"restart_policy":  "Never",
			},
			"gce": map[string]any{"project_id": "p", "zone": "europe-west4-a", "instance_id": "123", "instance_name": "signer-1"},
		},
	}
}

func TestConfidentialSpace(t *testing.T) {
	now := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	key := testRSA(t, 0)
	ks := keySet(t, jwksFor(t, "test-kid-1", key, false))
	base := csClaims(now)
	good := signJWT(t, key, "test-kid-1", base, nil)
	opts := func() ConfidentialSpaceOptions {
		return ConfidentialSpaceOptions{Keys: ks, Audience: "signer-runner-identity", Now: now,
			ImageDigests: []string{csDigest}, Nonces: []string{"6e6f6e63652d74776f"}, MaxAge: 5 * time.Minute}
	}
	resign := func(path string, v any) string {
		return signJWT(t, key, "test-kid-1", set(clone(base), path, v), nil)
	}

	t.Run("good", func(t *testing.T) {
		tok, err := VerifyConfidentialSpace(good, opts())
		if err != nil {
			t.Fatal(err)
		}
		if tok.ImageDigest != csDigest || tok.DbgStat != "disabled-since-boot" || tok.ProjectID != "p" || len(tok.Nonces) != 2 {
			t.Fatalf("%+v", tok)
		}
	})
	t.Run("eat_nonce as a string", func(t *testing.T) {
		_, err := VerifyConfidentialSpace(resign("eat_nonce", "6e6f6e63652d74776f"), opts())
		if err != nil {
			t.Fatal(err)
		}
	})
	t.Run("tampered signature", func(t *testing.T) {
		_, err := VerifyConfidentialSpace(flipSig(good), opts())
		wantErr(t, err, ErrSignature)
	})
	t.Run("tampered payload", func(t *testing.T) {
		bad := swapPayload(t, good, set(clone(base), "submods.container.image_digest", otherDigest))
		_, err := VerifyConfidentialSpace(bad, opts())
		wantErr(t, err, ErrSignature)
	})
	t.Run("wrong key, same kid", func(t *testing.T) {
		bad := signJWT(t, testRSA(t, 1), "test-kid-1", base, nil)
		_, err := VerifyConfidentialSpace(bad, opts())
		wantErr(t, err, ErrSignature)
	})
	t.Run("unknown kid", func(t *testing.T) {
		bad := signJWT(t, key, "other-kid", base, nil)
		_, err := VerifyConfidentialSpace(bad, opts())
		wantErr(t, err, ErrUnknownKey)
	})
	t.Run("alg none and HS256 refused", func(t *testing.T) {
		for _, alg := range []string{"none", "HS256", "PS256"} {
			bad := signJWT(t, key, "test-kid-1", base, map[string]any{"alg": alg})
			_, err := VerifyConfidentialSpace(bad, opts())
			wantErr(t, err, ErrSignature)
		}
	})
	t.Run("wrong issuer", func(t *testing.T) {
		_, err := VerifyConfidentialSpace(resign("iss", "https://portal.trustauthority.intel.com"), opts())
		wantErr(t, err, ErrIssuer)
	})
	t.Run("wrong audience", func(t *testing.T) {
		_, err := VerifyConfidentialSpace(resign("aud", STSAudience), opts())
		wantErr(t, err, ErrAudience)
	})
	t.Run("expired", func(t *testing.T) {
		o := opts()
		o.Now, o.MaxAge = now.Add(31*time.Minute+DefaultSkew), 0
		_, err := VerifyConfidentialSpace(good, o)
		wantErr(t, err, ErrExpired)
	})
	t.Run("not yet valid", func(t *testing.T) {
		_, err := VerifyConfidentialSpace(resign("nbf", now.Add(10*time.Minute).Unix()), opts())
		wantErr(t, err, ErrExpired)
	})
	t.Run("old iat", func(t *testing.T) {
		_, err := VerifyConfidentialSpace(resign("iat", now.Add(-10*time.Minute).Unix()), opts())
		wantErr(t, err, ErrStale)
	})
	t.Run("wrong image digest", func(t *testing.T) {
		o := opts()
		o.ImageDigests = []string{otherDigest}
		_, err := VerifyConfidentialSpace(good, o)
		wantErr(t, err, ErrMeasurement)
	})
	t.Run("stale nonce", func(t *testing.T) {
		o := opts()
		o.Nonces = []string{"6e6f6e63652d7468726565"}
		_, err := VerifyConfidentialSpace(good, o)
		wantErr(t, err, ErrNonce)
	})
	t.Run("debug image", func(t *testing.T) {
		dbg := clone(base)
		set(dbg, "dbgstat", "enabled")
		set(dbg, "submods.confidential_space.support_attributes", nil)
		tok := signJWT(t, key, "test-kid-1", dbg, nil)
		_, err := VerifyConfidentialSpace(tok, opts())
		wantErr(t, err, ErrDebug)
		o := opts()
		o.AllowDebug = true
		if _, err := VerifyConfidentialSpace(tok, o); err != nil {
			t.Fatalf("AllowDebug: %v", err)
		}
	})
	t.Run("missing dbgstat", func(t *testing.T) {
		_, err := VerifyConfidentialSpace(resign("dbgstat", nil), opts())
		wantErr(t, err, ErrDebug)
	})
	t.Run("not STABLE", func(t *testing.T) {
		_, err := VerifyConfidentialSpace(resign("submods.confidential_space.support_attributes", []string{"USABLE"}), opts())
		wantErr(t, err, ErrClaim)
	})
	t.Run("plain GCE VM", func(t *testing.T) {
		_, err := VerifyConfidentialSpace(resign("swname", "GCE"), opts())
		wantErr(t, err, ErrClaim)
	})
	t.Run("secboot false", func(t *testing.T) {
		_, err := VerifyConfidentialSpace(resign("secboot", false), opts())
		wantErr(t, err, ErrClaim)
	})
	t.Run("hwmodel and service account", func(t *testing.T) {
		o := opts()
		o.HWModels = []string{"GCP_INTEL_TDX"}
		_, err := VerifyConfidentialSpace(good, o)
		wantErr(t, err, ErrClaim)
		o = opts()
		o.ServiceAccount = "other@p.iam.gserviceaccount.com"
		_, err = VerifyConfidentialSpace(good, o)
		wantErr(t, err, ErrClaim)
		o = opts()
		o.ProjectID = "other-project"
		_, err = VerifyConfidentialSpace(good, o)
		wantErr(t, err, ErrClaim)
		o.ProjectID = "p"
		if _, err = VerifyConfidentialSpace(good, o); err != nil {
			t.Fatalf("matching project: %v", err)
		}
	})
	t.Run("duplicate claim", func(t *testing.T) {
		// Hand-built payload with dbgstat twice; the signature is valid.
		raw := `{"iss":"` + ConfidentialSpaceIssuer + `","dbgstat":"enabled","dbgstat":"disabled-since-boot"}`
		tok := signRaw(t, key, "test-kid-1", raw)
		_, err := VerifyConfidentialSpace(tok, opts())
		wantErr(t, err, ErrFormat)
	})
	t.Run("config", func(t *testing.T) {
		for _, o := range []ConfidentialSpaceOptions{
			{Audience: "a", ImageDigests: []string{csDigest}, MaxAge: time.Minute},
			{Keys: ks, ImageDigests: []string{csDigest}, MaxAge: time.Minute},
			{Keys: ks, Audience: "a", MaxAge: time.Minute},
			{Keys: ks, Audience: "a", ImageDigests: []string{csDigest}},
		} {
			_, err := VerifyConfidentialSpace(good, o)
			wantErr(t, err, ErrConfig)
		}
	})
}

// TestGoogleJWKSSnapshot parses the key set fetched from Google (testdata)
// and checks that a token signed by a local key under one of
// Google's key ids fails against Google's real key.
func TestGoogleJWKSSnapshot(t *testing.T) {
	ks := keySet(t, readFile(t, "testdata/jwks/gcp-confidentialspace-20261013.json"))
	ids := ks.KeyIDs()
	if len(ids) != 2 {
		t.Fatalf("key ids %v", ids)
	}
	now := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	tok := signJWT(t, testRSA(t, 0), ids[0], csClaims(now), nil)
	_, err := VerifyConfidentialSpace(tok, ConfidentialSpaceOptions{Keys: ks, Audience: "signer-runner-identity",
		Now: now, ImageDigests: []string{csDigest}, MaxAge: time.Minute})
	wantErr(t, err, ErrSignature)
}
