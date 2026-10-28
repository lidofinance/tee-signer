// Package maatest makes synthetic Microsoft Azure Attestation tokens for
// tests: the claim layout of circuits/azure/scripts/make_vectors.py (an
// SEV-SNP container group, attestation type sevsnpvm), signed RS256 by
// throwaway RSA-2048 keys, and key sets in the form of an MAA instance's
// /certs (each key an x5c certificate, no n and e). Nothing here is a real
// Microsoft key or token.
package maatest

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/signer-protocol"
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

// Certs is a key set as an MAA instance serves it at /certs: each key
// only as a self-signed x5c certificate.
func Certs(tb testing.TB, keys ...*Key) []byte {
	tb.Helper()
	var set struct {
		Keys []map[string]any `json:"keys"`
	}
	for i, k := range keys {
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(int64(i + 1)), Subject: pkix.Name{CommonName: "https://maatest.attest.example"},
			NotBefore: time.Unix(0, 0), NotAfter: time.Unix(0, 0).Add(100 * 365 * 24 * time.Hour)}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.Priv.PublicKey, k.Priv)
		if err != nil {
			tb.Fatal(err)
		}
		set.Keys = append(set.Keys, map[string]any{"kid": k.Kid, "kty": "RSA", "x5c": []string{base64.StdEncoding.EncodeToString(der)}})
	}
	b, err := json.Marshal(set)
	if err != nil {
		tb.Fatal(err)
	}
	return b
}

func hexOf(tag string, n int) string {
	var out []byte
	for i := 0; len(out) < n; i++ {
		h := sha256.Sum256([]byte(tag + " " + string(rune('0'+i))))
		out = append(out, h[:]...)
	}
	return hex.EncodeToString(out[:n])
}

// ReportData is x-ms-sevsnpvm-reportdata for runtime data: the hex of its
// SHA-256 and 32 zero bytes.
func ReportData(runtime []byte) string {
	h := sha256.Sum256(runtime)
	return hex.EncodeToString(h[:]) + strings.Repeat("00", 32)
}

// Claims are the claims of a good token, as make_vectors.py's claims():
// issued at iat by the MAA instance host, valid for 8 hours, for an SNP
// report over the runner's runtime data for userData
// (backend.MAARuntimeData) and a container group with the CCE policy hash
// hostData.
func Claims(iat int64, host string, userData []byte, hostData [32]byte) map[string]any {
	runtime := backend.MAARuntimeData(userData)
	var rt map[string]any
	if err := json.Unmarshal(runtime, &rt); err != nil {
		panic(err)
	}
	ph := sha256.Sum256([]byte("maa default policy"))
	launch := hexOf("launch measurement", 48)
	return map[string]any{
		"exp":                             iat + 8*3600,
		"iat":                             iat,
		"iss":                             "https://" + host,
		"jti":                             hexOf("jti", 32),
		"nbf":                             iat,
		"nonce":                           "13775958611543712385",
		"x-ms-attestation-type":           "sevsnpvm",
		"x-ms-compliance-status":          "azure-compliant-uvm",
		"x-ms-policy-hash":                base64.RawURLEncoding.EncodeToString(ph[:]),
		"x-ms-runtime":                    rt,
		"x-ms-sevsnpvm-authorkeydigest":   strings.Repeat("00", 48),
		"x-ms-sevsnpvm-bootloader-svn":    4,
		"x-ms-sevsnpvm-familyId":          "01000000000000000000000000000000",
		"x-ms-sevsnpvm-guestsvn":          2,
		"x-ms-sevsnpvm-hostdata":          hex.EncodeToString(hostData[:]),
		"x-ms-sevsnpvm-idkeydigest":       hexOf("id key digest", 48),
		"x-ms-sevsnpvm-imageId":           "02000000000000000000000000000000",
		"x-ms-sevsnpvm-is-debuggable":     false,
		"x-ms-sevsnpvm-launchmeasurement": launch,
		"x-ms-sevsnpvm-microcode-svn":     219,
		"x-ms-sevsnpvm-migration-allowed": false,
		"x-ms-sevsnpvm-reportdata":        ReportData(runtime),
		"x-ms-sevsnpvm-reportid":          hexOf("report id", 32),
		"x-ms-sevsnpvm-smt-allowed":       true,
		"x-ms-sevsnpvm-snpfw-svn":         24,
		"x-ms-sevsnpvm-tee-svn":           0,
		"x-ms-sevsnpvm-uvm-endorsement": map[string]any{
			"x-ms-sevsnpvm-guestsvn":          "100",
			"x-ms-sevsnpvm-launchmeasurement": launch,
		},
		"x-ms-sevsnpvm-vmpl": 0,
		"x-ms-ver":           "1.0",
	}
}

// Header is an MAA token header: the instance's key set URL and the kid.
func (k *Key) Header(host string) []byte {
	b, _ := json.Marshal(map[string]string{"alg": "RS256", "jku": "https://" + host + "/certs", "kid": k.Kid, "typ": "JWT"})
	return b
}

// Sign makes a compact JWS of the claims with the MAA header of host.
func (k *Key) Sign(tb testing.TB, host string, claims map[string]any) string {
	tb.Helper()
	pb, err := json.Marshal(claims)
	if err != nil {
		tb.Fatal(err)
	}
	return k.SignRaw(tb, k.Header(host), pb)
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
