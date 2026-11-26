package certreload

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// chainPair is a client certificate under n intermediates, each signed
// by the next, the last by a root that the file leaves out, so all n+1
// certificates of the file count against the runner bound.
func chainPair(t *testing.T, n int, leafCurve elliptic.Curve) pemPair {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "root"},
		NotBefore: t0.Add(-time.Hour), NotAfter: t0.Add(time.Hour), IsCA: true, BasicConstraintsValid: true}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	parent, _ := x509.ParseCertificate(der)
	parentKey := k
	var cas [][]byte
	for i := 0; i < n; i++ {
		ck, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(int64(i + 2)), Subject: pkix.Name{CommonName: "CA"},
			NotBefore: t0.Add(-time.Hour), NotAfter: t0.Add(time.Hour), IsCA: true, BasicConstraintsValid: true}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &ck.PublicKey, parentKey)
		if err != nil {
			t.Fatal(err)
		}
		cas = append([][]byte{der}, cas...)
		parent, _ = x509.ParseCertificate(der)
		parentKey = ck
	}
	lk, err := ecdsa.GenerateKey(leafCurve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(100), Subject: pkix.Name{CommonName: "gateway"},
		NotBefore: t0.Add(-time.Hour), NotAfter: t0.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err = x509.CreateCertificate(rand.Reader, leaf, parent, &lk.PublicKey, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	var certPEM []byte
	for _, d := range append([][]byte{der}, cas...) {
		certPEM = append(certPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: d})...)
	}
	keyDER, _ := x509.MarshalPKCS8PrivateKey(lk)
	return pemPair{certPEM, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})}
}

// The gateway does not start with a client certificate file the runners
// would refuse in the handshake, and says which bound it breaks.
func TestStartRefusesAListTheRunnerRefuses(t *testing.T) {
	for _, tc := range []struct {
		name string
		pair pemPair
		want string // "": starts
	}{
		{"leaf and two CAs", chainPair(t, 2, elliptic.P256()), ""},
		{"leaf and three CAs", chainPair(t, 3, elliptic.P256()), "at most 3"},
		{"P-521 leaf", chainPair(t, 1, elliptic.P521()), "P-521"},
	} {
		dir := t.TempDir()
		cert, key := filepath.Join(dir, "c.pem"), filepath.Join(dir, "k.pem")
		_ = os.WriteFile(cert, tc.pair.cert, 0o600)
		_ = os.WriteFile(key, tc.pair.key, 0o600)
		_, err := newWatcher(cert, key, slog.New(slog.DiscardHandler), func() time.Time { return t0 })
		switch {
		case tc.want == "" && err != nil:
			t.Errorf("%s: %v", tc.name, err)
		case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
			t.Errorf("%s: %v, want a refusal that says %q", tc.name, err, tc.want)
		}
	}
}
