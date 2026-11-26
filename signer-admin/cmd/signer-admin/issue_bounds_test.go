package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// issue-client-cert writes no file with an out-of-bounds issuer. The leaf is
// always P-256, but the file also holds the issuer when the issuer is an
// intermediate, and an intermediate made outside signer-admin may have a
// key or a size outside the bounds of signer-protocol/clientcert. A root
// issuer is not in the file, so its key does not matter.
func TestIssueClientCertOutputFitsTheRunner(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "out")
	root := testCA(t, dir, "root", elliptic.P256(), nil, nil)
	p521Root := testCA(t, dir, "p521-root", elliptic.P521(), nil, nil)
	p521CA := testCA(t, dir, "p521-ca", elliptic.P521(), &root, nil)
	bigCA := testCA(t, dir, "big-ca", elliptic.P256(), &root,
		[]pkix.Extension{{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1}, Value: make([]byte, 9000)}})
	issueArgs := func(ca testCAFiles, name string) []string {
		return []string{"issue-client-cert", "-ca-cert", ca.cert, "-ca-key", ca.key, "-role", "signing", "-name", name, "-out", out}
	}
	for _, tc := range []struct {
		ca   testCAFiles
		name string
		want string
	}{
		{p521CA, "x1", "ECDSA P-521"},
		{bigCA, "x2", "more than 8192"},
	} {
		// The runner takes such a leaf when the issuer is pinned in
		// allowed_client_ca, so the message must not say it always refuses.
		wantIn(t, failTool(t, issueArgs(tc.ca, tc.name)...), "not issuing",
			"issuer is outside the client certificate bounds",
			"unless the issuer is pinned in allowed_client_ca", tc.want)
		for _, f := range []string{tc.name + ".pem", tc.name + "-key.pem"} {
			if _, err := os.Stat(filepath.Join(out, f)); err == nil {
				t.Errorf("%s written after a refusal", f)
			}
		}
	}
	wantIn(t, mustTool(t, issueArgs(p521Root, "lane-1")...), "role signing")
	if c := readCerts(t, filepath.Join(out, "lane-1.pem")); len(c) != 1 {
		t.Fatalf("leaf from a root: %d certificates in the file, want 1", len(c))
	}
	wantIn(t, mustTool(t, issueArgs(root, "lane-2")...), "role signing")
}

type testCAFiles struct {
	cert, key string
	c         *x509.Certificate
	k         crypto.Signer
}

// testCA writes a CA certificate and its key (mode 0600) to dir, under
// parent or self-signed if parent is nil.
func testCA(t *testing.T, dir, name string, curve elliptic.Curve, parent *testCAFiles, ext []pkix.Extension) testCAFiles {
	t.Helper()
	k, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(48 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, ExtraExtensions: ext,
	}
	issuer, signer := tmpl, crypto.Signer(k)
	if parent != nil {
		issuer, signer = parent.c, parent.k
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, issuer, &k.PublicKey, signer)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	f := testCAFiles{cert: filepath.Join(dir, name+".pem"), key: filepath.Join(dir, name+"-key.pem"), c: c, k: k}
	if err := os.WriteFile(f.cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.key, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return f
}
