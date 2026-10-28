// Package gcptest makes synthetic Confidential Space tokens for tests: the
// claim layout of circuits/gcp/scripts/make_vectors.py (Google's token
// claims reference), signed RS256 by throwaway RSA-2048 keys. Nothing here
// is a real Google key or token.
package gcptest

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"testing"
)

// Key is a throwaway signing key with the kid make_vectors.py gives its
// keys: the first 40 hex digits of SHA-256 over the 256-byte modulus.
type Key struct {
	Priv *rsa.PrivateKey
	Kid  string
}

// NewKey makes a key.
func NewKey(tb testing.TB) *Key {
	tb.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		tb.Fatal(err)
	}
	h := sha256.Sum256(k.N.FillBytes(make([]byte, 256)))
	return &Key{Priv: k, Kid: hex.EncodeToString(h[:])[:40]}
}

// JWKS is a key set (RFC 7517) with the keys, as Google publishes its own.
func JWKS(keys ...*Key) []byte {
	type jwk struct {
		Kid string `json:"kid"`
		Kty string `json:"kty"`
		Alg string `json:"alg"`
		Use string `json:"use"`
		N   string `json:"n"`
		E   string `json:"e"`
	}
	var set struct {
		Keys []jwk `json:"keys"`
	}
	for _, k := range keys {
		set.Keys = append(set.Keys, jwk{Kid: k.Kid, Kty: "RSA", Alg: "RS256", Use: "sig",
			N: base64.RawURLEncoding.EncodeToString(k.Priv.N.Bytes()),
			E: base64.RawURLEncoding.EncodeToString(big.NewInt(int64(k.Priv.E)).Bytes())})
	}
	b, _ := json.Marshal(set)
	return b
}

// Claims are the claims of a good token, as make_vectors.py's claims():
// issued at iat, valid for an hour, with the nonce (a string, or a list
// for the array form), the image digest ("sha256:..."), the hardware model
// and the audience.
func Claims(iat int64, nonce any, digest, hwmodel, aud string) map[string]any {
	const project, zone, inst = "lido-signer-test", "europe-west4-a", "1234567890123456789"
	return map[string]any{
		"aud":          aud,
		"exp":          iat + 3600,
		"iat":          iat,
		"iss":          "https://confidentialcomputing.googleapis.com",
		"nbf":          iat,
		"sub":          "https://www.googleapis.com/compute/v1/projects/" + project + "/zones/" + zone + "/instances/" + inst,
		"eat_nonce":    nonce,
		"eat_profile":  "https://cloud.google.com/confidential-computing/confidential-space/docs/reference/token-claims",
		"secboot":      true,
		"oemid":        11129,
		"hwmodel":      hwmodel,
		"swname":       "CONFIDENTIAL_SPACE",
		"swversion":    []string{"260900"},
		"attester_tcb": []string{"INTEL"},
		"dbgstat":      "disabled-since-boot",
		"submods": map[string]any{
			"confidential_space": map[string]any{
				"monitoring_enabled": map[string]any{"memory": false},
				"support_attributes": []string{"LATEST", "STABLE", "USABLE"},
			},
			"container": map[string]any{
				"args": []string{"/signer-runner", "-platform", "gcp", "-listen", ":7100",
					"-state-dir", "/var/lib/signer", "-param", "clock=token-iat"},
				"env": map[string]any{
					"HOSTNAME":      "signer-gcp-1",
					"PATH":          "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
					"SSL_CERT_FILE": "/etc/ssl/certs/ca-certificates.crt",
				},
				"image_digest":    digest,
				"image_id":        "sha256:" + hex.EncodeToString(sum([]byte("image-id"))),
				"image_reference": "europe-docker.pkg.dev/" + project + "/signer/signer-runner@" + digest,
				"restart_policy":  "Never",
			},
			"gce": map[string]any{
				"instance_id":    inst,
				"instance_name":  "signer-gcp-1",
				"project_id":     project,
				"project_number": "123456789012",
				"zone":           zone,
			},
		},
		"google_service_accounts": []string{"signer-runner@" + project + ".iam.gserviceaccount.com"},
	}
}

func sum(b []byte) []byte { h := sha256.Sum256(b); return h[:] }

// Sign makes a compact JWS of the claims with header alg RS256, the key's
// kid and typ JWT.
func (k *Key) Sign(tb testing.TB, claims map[string]any) string {
	tb.Helper()
	hb, err := json.Marshal(map[string]string{"alg": "RS256", "kid": k.Kid, "typ": "JWT"})
	if err != nil {
		tb.Fatal(err)
	}
	pb, err := json.Marshal(claims)
	if err != nil {
		tb.Fatal(err)
	}
	return k.SignRaw(tb, hb, pb)
}

// SignRaw signs header and payload JSON exactly as given.
func (k *Key) SignRaw(tb testing.TB, header, payload []byte) string {
	tb.Helper()
	signed := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	h := sha256.Sum256([]byte(signed))
	sig, err := rsa.SignPKCS1v15(rand.Reader, k.Priv, crypto.SHA256, h[:])
	if err != nil {
		tb.Fatal(err)
	}
	return signed + "." + base64.RawURLEncoding.EncodeToString(sig)
}
