package runnerclient

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// listFiles writes a client certificate file that holds a leaf with a key
// on curve leafCurve and n CA certificates above it, the last one a
// self-signed root, and the leaf key file. dropRoot leaves the root out.
func listFiles(t *testing.T, n int, leafCurve elliptic.Curve, dropRoot bool) (certPath, keyPath string) {
	t.Helper()
	mk := func(name string, k crypto.Signer, parent *x509.Certificate, parentKey crypto.Signer, isCA bool, serial int64) *x509.Certificate {
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: name},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, IsCA: isCA, BasicConstraintsValid: isCA}
		if parent == nil {
			parent, parentKey = tmpl, k
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, k.Public(), parentKey)
		if err != nil {
			t.Fatal(err)
		}
		c, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	// cas[0] issues the leaf; cas[len-1] is the root.
	var cas []*x509.Certificate
	var caKey crypto.Signer
	for i := 0; i < n; i++ {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		var parent *x509.Certificate
		if i > 0 {
			parent = cas[0]
		}
		cas = append([]*x509.Certificate{mk("CA", k, parent, caKey, true, int64(i+1))}, cas...)
		caKey = k
	}
	lk, err := ecdsa.GenerateKey(leafCurve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var leaf *x509.Certificate
	if n == 0 {
		leaf = mk("client", lk, nil, nil, false, 100)
	} else {
		leaf = mk("client", lk, cas[0], caKey, false, 100)
	}
	if dropRoot && n > 0 {
		cas = cas[:n-1]
	}
	var certPEM []byte
	for _, c := range append([]*x509.Certificate{leaf}, cas...) {
		certPEM = append(certPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})...)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(lk)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certPath, keyPath = filepath.Join(dir, "client.pem"), filepath.Join(dir, "client-key.pem")
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

// A client certificate file the runner would refuse in the handshake is
// refused when the connection is loaded, with the bound in the message.
func TestLoadPairRefusesAListTheRunnerRefuses(t *testing.T) {
	for _, tc := range []struct {
		name     string
		n        int
		curve    elliptic.Curve
		dropRoot bool
		want     string // "": accepted
	}{
		{"leaf and its CA", 1, elliptic.P256(), false, ""},
		{"leaf, two CAs and the root", 3, elliptic.P256(), false, ""},
		{"leaf and three CAs without the root", 4, elliptic.P256(), true, "at most 3"},
		{"P-521 leaf", 1, elliptic.P521(), false, "P-521"},
	} {
		c, k := listFiles(t, tc.n, tc.curve, tc.dropRoot)
		_, err := loadPair(c, k)
		switch {
		case tc.want == "" && err != nil:
			t.Errorf("%s: %v", tc.name, err)
		case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
			t.Errorf("%s: %v, want a refusal that says %q", tc.name, err, tc.want)
		}
	}
}
