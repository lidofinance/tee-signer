package clientcert

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strings"
	"testing"
	"time"
)

type node struct {
	cert *x509.Certificate
	key  crypto.Signer
}

func key(t *testing.T, c elliptic.Curve) crypto.Signer {
	t.Helper()
	k, err := ecdsa.GenerateKey(c, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

var serial int64

// issue makes a certificate named name for k under parent, self-signed if
// parent is nil.
func issue(t *testing.T, parent *node, name string, k crypto.Signer, isCA bool) node {
	t.Helper()
	serial++
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, IsCA: isCA, BasicConstraintsValid: isCA}
	issuer, signer := tmpl, k
	if parent != nil {
		issuer, signer = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, issuer, k.Public(), signer)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return node{c, k}
}

func certs(ns ...node) []*x509.Certificate {
	out := make([]*x509.Certificate, len(ns))
	for i, n := range ns {
		out[i] = n.cert
	}
	return out
}

func ders(ns ...node) [][]byte {
	out := make([][]byte, len(ns))
	for i, n := range ns {
		out[i] = n.cert.Raw
	}
	return out
}

// The runner side: copies of a pinned CA after the leaf do not count and
// are not checked; every other certificate is.
func TestCheck(t *testing.T) {
	p256, p521 := elliptic.P256(), elliptic.P521()
	root := issue(t, nil, "root", key(t, p256), true)
	bigRoot := issue(t, nil, "P-521 root", key(t, p521), true)
	sub := issue(t, &root, "sub CA", key(t, p256), true)
	issuing := issue(t, &sub, "issuing CA", key(t, p256), true)
	leaf := issue(t, &issuing, "leaf", key(t, p256), false)
	extra := issue(t, &root, "old intermediate", key(t, p256), true)
	p521CA := issue(t, &root, "P-521 CA", key(t, p521), true)
	// A deployment may pin an intermediate (not self-signed) and run two
	// CAs below it.
	pinnedCA := issue(t, &root, "pinned intermediate", key(t, p256), true)
	lowSub := issue(t, &pinnedCA, "sub CA below the pinned one", key(t, p256), true)
	lowIssuing := issue(t, &lowSub, "issuing CA below the pinned one", key(t, p256), true)
	lowLeaf := issue(t, &lowIssuing, "leaf", key(t, p256), false)
	pinned := func(c *x509.Certificate) bool {
		return c.Equal(root.cert) || c.Equal(bigRoot.cert) || c.Equal(pinnedCA.cert)
	}

	for _, tc := range []struct {
		name string
		list []node
		want int // certificates Check returns, each once; 0: refused
	}{
		{"leaf, two CAs", []node{leaf, issuing, sub}, 3},
		{"leaf, two CAs and the pinned root", []node{leaf, issuing, sub, root}, 4},
		{"pinned P-521 root sent along", []node{issue(t, &bigRoot, "leaf", key(t, p256), false), bigRoot}, 2},
		{"pinned root sent twice", []node{leaf, issuing, sub, root, root}, 4},
		{"leaf, two CAs below a pinned intermediate", []node{lowLeaf, lowIssuing, lowSub}, 3},
		{"leaf, two CAs and the pinned intermediate", []node{lowLeaf, lowIssuing, lowSub, pinnedCA}, 4},
		{"leaf, two CAs, the pinned intermediate and the root", []node{lowLeaf, lowIssuing, lowSub, pinnedCA, root}, 5},
		{"a CA sent twice", []node{leaf, issuing, issuing}, 2},
		{"four certificates besides the root", []node{leaf, issuing, sub, extra}, 0},
		{"P-521 CA that is not pinned", []node{issue(t, &p521CA, "leaf", key(t, p256), false), p521CA}, 0},
		{"P-521 leaf", []node{issue(t, &root, "leaf", key(t, p521), false)}, 0},
		{"pinned root as the leaf with a P-521 key", []node{bigRoot}, 0},
		{"empty", nil, 0},
	} {
		got, err := Check(certs(tc.list...), pinned)
		switch {
		case tc.want == 0 && err == nil:
			t.Errorf("%s: kept %d certificates, want a refusal", tc.name, len(got))
		case tc.want != 0 && err != nil:
			t.Errorf("%s: %v", tc.name, err)
		case tc.want != 0 && len(got) != tc.want:
			t.Errorf("%s: kept %d certificates, want %d", tc.name, len(got), tc.want)
		}
	}
	if _, err := Check(certs(leaf, issuing, sub, root), nil); err == nil {
		t.Error("without a pinned set the root copy counts: want a refusal of 4 certificates")
	}
}

// A refusal names a certificate in a bounded number of bytes, however
// long its subject name.
func TestRefusalNameIsShort(t *testing.T) {
	long := issue(t, nil, strings.Repeat("n", 9000), key(t, elliptic.P256()), false)
	_, err := Check(certs(long), nil)
	if err == nil {
		t.Fatal("a certificate over 8 KiB passed")
	}
	if len(err.Error()) > 300 {
		t.Fatalf("refusal of %d bytes: %.120s...", len(err.Error()), err)
	}
	k521 := issue(t, nil, strings.Repeat("m", 4000), key(t, elliptic.P521()), false)
	if _, err := Check(certs(k521), nil); err == nil || len(err.Error()) > 300 {
		t.Fatalf("P-521 key with a long name: %d bytes: %v", len(err.Error()), err)
	}
}

// The client side does not know the pinned CAs: a self-signed certificate
// after the leaf counts as a copy of a pinned root.
func TestCheckFile(t *testing.T) {
	p256, p521 := elliptic.P256(), elliptic.P521()
	root := issue(t, nil, "root", key(t, p521), true)
	sub := issue(t, &root, "sub CA", key(t, p256), true)
	issuing := issue(t, &sub, "issuing CA", key(t, p256), true)
	leaf := issue(t, &issuing, "leaf", key(t, p256), false)
	extra := issue(t, &sub, "old intermediate", key(t, p256), true)
	if err := CheckFile(ders(leaf, issuing, sub, root)); err != nil {
		t.Errorf("leaf, two CAs and a P-521 root: %v", err)
	}
	// Below a pinned intermediate the file holds the leaf and the two CAs
	// and leaves out the pinned one, which the client cannot tell from
	// another intermediate.
	pinnedCA := issue(t, &root, "pinned intermediate", key(t, p256), true)
	lowSub := issue(t, &pinnedCA, "sub CA", key(t, p256), true)
	lowIssuing := issue(t, &lowSub, "issuing CA", key(t, p256), true)
	lowLeaf := issue(t, &lowIssuing, "leaf", key(t, p256), false)
	if err := CheckFile(ders(lowLeaf, lowIssuing, lowSub)); err != nil {
		t.Errorf("leaf and two CAs below a pinned intermediate: %v", err)
	}
	err := CheckFile(ders(leaf, issuing, sub, extra))
	if err == nil || !strings.Contains(err.Error(), "at most 3") {
		t.Errorf("four certificates besides the root: %v, want a refusal that names the bound", err)
	}
	if err := CheckFile([][]byte{[]byte("junk")}); err == nil {
		t.Error("junk passed")
	}
}
