//go:build !verifierselect

package attest

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/attestation-verify/internal/testgen"
)

// Synthetic documents come from internal/testgen.

func wantErr(t *testing.T, err, target error) {
	t.Helper()
	if !errors.Is(err, target) {
		t.Fatalf("got error %v, want %v", err, target)
	}
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func readB64(t *testing.T, path string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(readFile(t, path))))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func newTestCA(t *testing.T, at time.Time) *testgen.CA { return testgen.NewCA(t, at) }

func pcrValue(b byte) []byte { return testgen.PCRValue(b) }

func defaultPCRs() map[uint64][]byte { return testgen.DefaultPCRs() }

func expectPCRs(idx ...int) map[int][]byte {
	all := defaultPCRs()
	m := map[int][]byte{}
	for _, i := range idx {
		m[i] = all[uint64(i)]
	}
	return m
}

func testRSA(t *testing.T, i int) *rsa.PrivateKey { return testgen.RSAKey(i) }

func jwksFor(t *testing.T, kid string, k *rsa.PrivateKey, withX5C bool) []byte {
	return testgen.JWKS(t, kid, k, withX5C)
}

func keySet(t *testing.T, b []byte) *KeySet {
	t.Helper()
	ks, err := ParseJWKS(b)
	if err != nil {
		t.Fatal(err)
	}
	return ks
}

func signJWT(t *testing.T, k *rsa.PrivateKey, kid string, claims map[string]any, header map[string]any) string {
	return testgen.SignJWT(t, k, kid, claims, header)
}

func signRaw(t *testing.T, k *rsa.PrivateKey, kid, payload string) string {
	return testgen.SignRaw(t, k, kid, []byte(payload), nil)
}

// flipSig changes one bit in the signature part of a JWT.
func flipSig(tok string) string {
	i := strings.LastIndexByte(tok, '.')
	sig, _ := base64.RawURLEncoding.DecodeString(tok[i+1:])
	sig[10] ^= 1
	return tok[:i+1] + base64.RawURLEncoding.EncodeToString(sig)
}

// swapPayload replaces the payload of a signed JWT with other claims and
// keeps the old signature.
func swapPayload(t *testing.T, tok string, claims map[string]any) string {
	t.Helper()
	p := strings.Split(tok, ".")
	cb, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	return p[0] + "." + base64.RawURLEncoding.EncodeToString(cb) + "." + p[2]
}

// clone deep-copies a claims map built from plain Go values.
func clone(m map[string]any) map[string]any {
	b, _ := json.Marshal(m)
	var out map[string]any
	_ = json.Unmarshal(b, &out)
	return out
}

// set assigns a dotted path in a claims map; nil deletes it.
func set(m map[string]any, path string, v any) map[string]any {
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
	return m
}
