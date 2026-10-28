// Package testgen builds synthetic attestation documents for tests: a
// local test CA (root, intermediate, leaf, all ECDSA P-384 like the AWS
// chain) signs documents in the NSM COSE_Sign1 layout, and local RSA keys
// sign JWTs in the Confidential Space and MAA layouts. Nothing here is
// trusted by the verifiers unless a test passes it in.
package testgen

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
)

// CA is a three-level ECDSA P-384 test chain.
type CA struct {
	Root, Inter, Leaf          *x509.Certificate
	RootKey, InterKey, LeafKey *ecdsa.PrivateKey
}

func key384(tb testing.TB) *ecdsa.PrivateKey {
	tb.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		tb.Fatal(err)
	}
	return k
}

func makeCert(tb testing.TB, tmpl, parent *x509.Certificate, pub, signer crypto.Signer) *x509.Certificate {
	tb.Helper()
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub.Public(), signer)
	if err != nil {
		tb.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		tb.Fatal(err)
	}
	return c
}

// NewCA builds a chain valid around at. The leaf is valid from one hour
// before at to two hours after it, close to the three-hour lifetime of
// the leaf certificates in the real AWS samples.
func NewCA(tb testing.TB, at time.Time) *CA {
	tb.Helper()
	ca := &CA{RootKey: key384(tb), InterKey: key384(tb), LeafKey: key384(tb)}
	caTmpl := func(cn string, serial int64) *x509.Certificate {
		return &x509.Certificate{
			SerialNumber:          big.NewInt(serial),
			Subject:               pkix.Name{CommonName: cn, Organization: []string{"tee-signer test CA"}},
			NotBefore:             at.Add(-24 * time.Hour),
			NotAfter:              at.Add(365 * 24 * time.Hour),
			IsCA:                  true,
			BasicConstraintsValid: true,
			KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		}
	}
	rt := caTmpl("test.nitro-enclaves", 1)
	ca.Root = makeCert(tb, rt, rt, ca.RootKey, ca.RootKey)
	ca.Inter = makeCert(tb, caTmpl("test-zonal", 2), ca.Root, ca.InterKey, ca.RootKey)
	lt := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "i-test-enc0000000000000000"},
		NotBefore:    at.Add(-time.Hour),
		NotAfter:     at.Add(2 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	ca.Leaf = makeCert(tb, lt, ca.Inter, ca.LeafKey, ca.InterKey)
	return ca
}

// NitroSpec describes a synthetic NSM document.
type NitroSpec struct {
	TS        time.Time
	PCRs      map[uint64][]byte // nil: DefaultPCRs()
	Nonce     []byte
	UserData  []byte
	PublicKey []byte
	Alg       int64    // 0: ES384 (-35)
	Tagged    bool     // prefix CBOR tag 18
	Bundle    [][]byte // nil: [root, intermediate]
	Payload   []byte   // if set, used as the payload as is
}

// PCRValue returns 48 bytes of b.
func PCRValue(b byte) []byte {
	v := make([]byte, 48)
	for i := range v {
		v[i] = b
	}
	return v
}

// DefaultPCRs returns PCR0 to PCR15 with PCR0-4 and PCR8 set to
// 0xa0..0xa4 and 0xa8 bytes and the rest zero, the shape of a real
// document from a signed EIF with an IAM role.
func DefaultPCRs() map[uint64][]byte {
	m := map[uint64][]byte{}
	for i := uint64(0); i < 16; i++ {
		m[i] = make([]byte, 48)
	}
	for _, i := range []uint64{0, 1, 2, 3, 4, 8} {
		m[i] = PCRValue(0xa0 + byte(i))
	}
	return m
}

// NitroDoc builds a COSE_Sign1 document in the NSM layout, signed by the
// leaf key. Absent optional fields are CBOR null, as in the real samples.
func (ca *CA) NitroDoc(tb testing.TB, s NitroSpec) []byte {
	tb.Helper()
	if s.PCRs == nil {
		s.PCRs = DefaultPCRs()
	}
	if s.Alg == 0 {
		s.Alg = -35
	}
	if s.Bundle == nil {
		s.Bundle = [][]byte{ca.Root.Raw, ca.Inter.Raw}
	}
	nullable := func(b []byte) any {
		if b == nil {
			return nil
		}
		return b
	}
	payload := s.Payload
	if payload == nil {
		var err error
		payload, err = cbor.Marshal(map[string]any{
			"module_id":   "i-test-enc0000000000000000",
			"digest":      "SHA384",
			"timestamp":   uint64(s.TS.UnixMilli()),
			"pcrs":        s.PCRs,
			"certificate": ca.Leaf.Raw,
			"cabundle":    s.Bundle,
			"public_key":  nullable(s.PublicKey),
			"user_data":   nullable(s.UserData),
			"nonce":       nullable(s.Nonce),
		})
		if err != nil {
			tb.Fatal(err)
		}
	}
	protected, err := cbor.Marshal(map[int64]int64{1: s.Alg})
	if err != nil {
		tb.Fatal(err)
	}
	tbs, err := cbor.Marshal([]any{"Signature1", protected, []byte{}, payload})
	if err != nil {
		tb.Fatal(err)
	}
	h := sha512.Sum384(tbs)
	r, sv, err := ecdsa.Sign(rand.Reader, ca.LeafKey, h[:])
	if err != nil {
		tb.Fatal(err)
	}
	sig := make([]byte, 96)
	r.FillBytes(sig[:48])
	sv.FillBytes(sig[48:])
	doc, err := cbor.Marshal([]any{protected, map[int64]any{}, payload, sig})
	if err != nil {
		tb.Fatal(err)
	}
	if s.Tagged {
		doc = append([]byte{0xd2}, doc...)
	}
	return doc
}

var (
	rsaOnce sync.Once
	rsaKeys [3]*rsa.PrivateKey
)

// RSAKey returns test RSA key i (0 to 2), generated once per process.
func RSAKey(i int) *rsa.PrivateKey {
	rsaOnce.Do(func() {
		for j := range rsaKeys {
			k, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				panic(err)
			}
			rsaKeys[j] = k
		}
	})
	return rsaKeys[i]
}

// JWKS returns a key set with one key. With x5c, the key also carries a
// self-signed certificate, the way MAA key sets do.
func JWKS(tb testing.TB, kid string, k *rsa.PrivateKey, x5c bool) []byte {
	tb.Helper()
	jwk := map[string]any{
		"kid": kid, "kty": "RSA", "alg": "RS256", "use": "sig",
		"n": base64.RawURLEncoding.EncodeToString(k.N.Bytes()),
		"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(k.E)).Bytes()),
	}
	if x5c {
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "https://test.attest.example"},
			NotBefore: time.Unix(0, 0), NotAfter: time.Unix(0, 0).Add(100 * 365 * 24 * time.Hour)}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
		if err != nil {
			tb.Fatal(err)
		}
		jwk["x5c"] = []string{base64.StdEncoding.EncodeToString(der)}
	}
	b, err := json.Marshal(map[string]any{"keys": []any{jwk}})
	if err != nil {
		tb.Fatal(err)
	}
	return b
}

// SignRaw signs payload (raw JSON text) with RS256 under kid. header
// overrides header fields.
func SignRaw(tb testing.TB, k *rsa.PrivateKey, kid string, payload []byte, header map[string]any) string {
	tb.Helper()
	h := map[string]any{"alg": "RS256", "kid": kid, "typ": "JWT"}
	for key, v := range header {
		h[key] = v
	}
	hb, err := json.Marshal(h)
	if err != nil {
		tb.Fatal(err)
	}
	signed := base64.RawURLEncoding.EncodeToString(hb) + "." + base64.RawURLEncoding.EncodeToString(payload)
	sum := sha256.Sum256([]byte(signed))
	sig, err := rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, sum[:])
	if err != nil {
		tb.Fatal(err)
	}
	return signed + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// SignJWT signs claims with RS256 under kid.
func SignJWT(tb testing.TB, k *rsa.PrivateKey, kid string, claims map[string]any, header map[string]any) string {
	tb.Helper()
	cb, err := json.Marshal(claims)
	if err != nil {
		tb.Fatal(err)
	}
	return SignRaw(tb, k, kid, cb, header)
}
