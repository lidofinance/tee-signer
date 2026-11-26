package attls

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/buildchain"
)

// chainChecks counts the chain checks of this package (verifyChain) while
// a test runs: how many ran and the longest list one got.
type chainChecks struct {
	calls, maxCerts atomic.Int64
}

func countChainChecks(t *testing.T) *chainChecks {
	t.Helper()
	cc := &chainChecks{}
	old := verifyChain
	verifyChain = func(certs []*x509.Certificate, opts x509.VerifyOptions) ([][]*x509.Certificate, error) {
		cc.calls.Add(1)
		for n := int64(len(certs)); ; {
			m := cc.maxCerts.Load()
			if n <= m || cc.maxCerts.CompareAndSwap(m, n) {
				break
			}
		}
		return old(certs, opts)
	}
	t.Cleanup(func() { verifyChain = old })
	return cc
}

// wantNoTLSChainCheck fails t if crypto/tls checks the client chain itself
// under cfg or under the config cfg picks for a client. crypto/tls does
// that before any code of this package runs, with every certificate the
// peer sent as an intermediate, so the counts of chainChecks would miss it.
func wantNoTLSChainCheck(t *testing.T, cfg *tls.Config) {
	t.Helper()
	cfgs := []*tls.Config{cfg}
	if cfg.GetConfigForClient != nil {
		c, err := cfg.GetConfigForClient(&tls.ClientHelloInfo{})
		if err != nil {
			t.Fatal(err)
		}
		if c != nil {
			cfgs = append(cfgs, c)
		}
	}
	for _, c := range cfgs {
		if c.ClientAuth >= tls.VerifyClientCertIfGiven {
			t.Errorf("ClientAuth is %v: crypto/tls builds chains from the whole client list before the list is checked", c.ClientAuth)
		}
	}
}

func keyOf(t *testing.T, kind string) crypto.Signer {
	t.Helper()
	var k crypto.Signer
	var err error
	switch kind {
	case "P-256":
		k, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case "P-384":
		k, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case "P-521":
		k, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	case "Ed25519":
		_, k, err = ed25519.GenerateKey(rand.Reader)
	case "RSA-2048":
		k, err = rsa.GenerateKey(rand.Reader, 2048)
	default:
		t.Fatalf("key kind %q", kind)
	}
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// node is a certificate and its key.
type node struct {
	cert *x509.Certificate
	key  crypto.Signer
}

// issue makes a certificate for key under parent (self-signed if parent is
// nil). A CA allows clientAuth and has no path length limit.
func issue(t *testing.T, parent *node, name string, key crypto.Signer, isCA bool, marks []asn1.ObjectIdentifier, ext ...pkix.Extension) node {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: nextSerial(), Subject: pkix.Name{CommonName: name},
		NotBefore: now0.Add(-time.Hour), NotAfter: now0.Add(day(1)),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, UnknownExtKeyUsage: marks, ExtraExtensions: ext,
	}
	if isCA {
		tmpl.IsCA, tmpl.BasicConstraintsValid, tmpl.KeyUsage = true, true, x509.KeyUsageCertSign
	} else {
		tmpl.KeyUsage = x509.KeyUsageDigitalSignature
	}
	issuer, signer := tmpl, key
	if parent != nil {
		issuer, signer = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, issuer, key.Public(), signer)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return node{c, key}
}

// list is the client Certificate message of leaf followed by cas.
func list(leaf node, cas ...node) tls.Certificate {
	out := tls.Certificate{Certificate: [][]byte{leaf.cert.Raw}, PrivateKey: leaf.key}
	for _, c := range cas {
		out.Certificate = append(out.Certificate, c.cert.Raw)
	}
	return out
}

// sameNamed is n P-521 CA certificates named "x" and a leaf whose issuer
// is named "x": every one of them is a candidate issuer of the leaf. With
// ladder each CA signs the one before it and the first signs the leaf;
// without it each is self-signed and a key outside the list signs the
// leaf. None of them chains to the pinned root.
func sameNamed(t *testing.T, n int, ladder bool) tls.Certificate {
	t.Helper()
	cas := make([]node, n)
	for i := n - 1; i >= 0; i-- {
		var parent *node
		if ladder && i < n-1 {
			parent = &cas[i+1]
		}
		cas[i] = issue(t, parent, "x", keyOf(t, "P-521"), true, nil)
	}
	issuer := cas[0]
	if !ladder {
		issuer = issue(t, nil, "x", keyOf(t, "P-521"), true, nil)
	}
	return list(issue(t, &issuer, "stranger", keyOf(t, "P-256"), false, nil), cas...)
}

// A client certificate list that no client chain of the role model can
// have is refused before any chain check: no such list goes to
// crypto/x509. The longest list of the model is a leaf, its role
// intermediate and the root. Each refusal runs with and without trusted
// time at ClientHello.
func TestImpossibleClientListRefusedBeforeChainCheck(t *testing.T) {
	root := issue(t, nil, "root", keyOf(t, "P-256"), true, nil)

	deep := []node{issue(t, &root, "intermediate 1", keyOf(t, "P-256"), true, nil)}
	for i := 2; i <= 5; i++ {
		deep = append([]node{issue(t, &deep[0], "intermediate", keyOf(t, "P-256"), true, nil)}, deep...)
	}
	big := pkix.Extension{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1}, Value: make([]byte, 9<<10)}
	p521 := issue(t, &root, "P-521 intermediate", keyOf(t, "P-521"), true, nil)

	cases := []struct {
		name string
		cert tls.Certificate
	}{
		{"150 same-named P-521 CAs that did not sign the leaf", sameNamed(t, 150, false)},
		{"150 same-named P-521 CAs, each signed by the next", sameNamed(t, 150, true)},
		{"a chain to the root through five intermediates", list(issue(t, &deep[0], "deep leaf", keyOf(t, "P-256"), false, nil), deep...)},
		{"a leaf over 8 KiB under the root", list(issue(t, &root, "big leaf", keyOf(t, "P-256"), false, nil, big))},
		{"an intermediate with a P-521 key", list(issue(t, &p521, "leaf", keyOf(t, "P-256"), false, nil), p521)},
	}
	for _, tc := range cases {
		cert := tc.cert
		client := &tls.Config{GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return &cert, nil }}
		for _, mode := range []struct {
			name   string
			before func(*testClock)
		}{
			{"trusted time", func(*testClock) {}},
			{"no trusted time", func(c *testClock) { c.fail(errors.New("clock: no recent reading")) }},
		} {
			t.Run(tc.name+", "+mode.name, func(t *testing.T) {
				clk := &testClock{t: now0}
				cfg, _, err := ServerConfig(certPEM(root.cert), clk.Now)
				if err != nil {
					t.Fatal(err)
				}
				mode.before(clk)
				wantNoTLSChainCheck(t, cfg)
				cc := countChainChecks(t)
				addr, hs := start(t, cfg)
				_, cerr := try(t, addr, client)
				serr := handshakeResult(t, hs)
				if cerr == nil || serr == nil {
					t.Errorf("a %d-certificate list got in (client %v, server %v)", len(cert.Certificate), cerr, serr)
				}
				if n := cc.calls.Load(); n != 0 {
					t.Errorf("%d chain checks ran on a %d-certificate list the model has no room for, want none (server: %v)", n, len(cert.Certificate), serr)
				}
			})
		}
	}
}

// Every client list of the role model still gets in with its role, its
// chain checked once with at most three certificates.
func TestModelClientListsAccepted(t *testing.T) {
	admin, attest := backend.AdminClientOID, backend.AttestOnlyClientOID
	root := issue(t, nil, "root", keyOf(t, "P-256"), true, nil)
	signingCA := issue(t, &root, "signing CA", keyOf(t, "P-256"), true, nil)
	attestCA := issue(t, &root, "attest CA", keyOf(t, "P-256"), true, []asn1.ObjectIdentifier{attest})
	adminCA := roleCAPath(t, &ca{cert: root.cert, key: root.key.(*ecdsa.PrivateKey)}, "admin CA", clientAuth, 0, admin)
	adminCANode := node{adminCA.cert, adminCA.key}
	p384CA := issue(t, &root, "P-384 CA", keyOf(t, "P-384"), true, nil)
	rsaCA := issue(t, &root, "RSA CA", keyOf(t, "RSA-2048"), true, nil)
	rootDirect := RoleNone
	if buildchain.AdminRootDirect {
		rootDirect = RoleAdminRootDirect
	}
	leaf := func(parent node, kind string, marks ...asn1.ObjectIdentifier) node {
		return issue(t, &parent, "client", keyOf(t, kind), false, marks)
	}
	cases := []struct {
		name string
		cert tls.Certificate
		want Role
	}{
		{"signing leaf and its CA", list(leaf(signingCA, "P-256"), signingCA), RoleSigning},
		{"signing leaf, its CA and the root", list(leaf(signingCA, "P-256"), signingCA, root), RoleSigning},
		{"signing leaf under the root", list(leaf(root, "P-256")), RoleSigning},
		{"attest leaf and its CA", list(leaf(attestCA, "P-256"), attestCA), RoleAttestOnly},
		{"admin leaf and the admin CA", list(leaf(adminCANode, "P-256", admin), adminCANode), RoleAdmin},
		{"admin leaf, the admin CA and the root", list(leaf(adminCANode, "P-256", admin), adminCANode, root), RoleAdmin},
		{"admin leaf under the root", list(leaf(root, "P-256", admin)), rootDirect},
		{"P-384 CA, Ed25519 leaf", list(leaf(p384CA, "Ed25519"), p384CA), RoleSigning},
		{"RSA-2048 CA and leaf", list(leaf(rsaCA, "RSA-2048"), rsaCA), RoleSigning},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, _, err := ServerConfig(certPEM(root.cert), nil)
			if err != nil {
				t.Fatal(err)
			}
			wantNoTLSChainCheck(t, cfg)
			cc := countChainChecks(t)
			cs := handshake(t, cfg, tc.cert)
			if got := RoleOf(&cs); got != tc.want {
				t.Errorf("role %v, want %v", got, tc.want)
			}
			if n, m := cc.calls.Load(), cc.maxCerts.Load(); n != 1 || m > 3 {
				t.Errorf("%d chain checks, the longest with %d certificates; want one with at most 3", n, m)
			}
		})
	}
}

// Copies of a pinned CA after the leaf neither count nor meet the key
// rule: a client that sends the root along keeps working, also with a
// pinned root of a key kind its own list may not hold.
func TestPinnedCACopiesDoNotCount(t *testing.T) {
	bigRoot := issue(t, nil, "P-521 root", keyOf(t, "P-521"), true, nil)
	bigCA := issue(t, &bigRoot, "signing CA", keyOf(t, "P-256"), true, nil)
	root := issue(t, nil, "root", keyOf(t, "P-256"), true, nil)
	sub := issue(t, &root, "sub CA", keyOf(t, "P-256"), true, nil)
	issuing := issue(t, &sub, "issuing CA", keyOf(t, "P-256"), true, nil)
	for _, tc := range []struct {
		name string
		root node
		cert tls.Certificate
	}{
		{"leaf, CA and a pinned P-521 root", bigRoot, list(issue(t, &bigCA, "client", keyOf(t, "P-256"), false, nil), bigCA, bigRoot)},
		{"leaf, two CAs and the pinned root", root, list(issue(t, &issuing, "client", keyOf(t, "P-256"), false, nil), issuing, sub, root)},
		{"leaf, two CAs and the pinned root twice", root, list(issue(t, &issuing, "client", keyOf(t, "P-256"), false, nil), issuing, sub, root, root)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, _, err := ServerConfig(certPEM(tc.root.cert), nil)
			if err != nil {
				t.Fatal(err)
			}
			cc := countChainChecks(t)
			cs := handshake(t, cfg, tc.cert)
			if got := RoleOf(&cs); got != RoleSigning {
				t.Errorf("role %v, want signing", got)
			}
			// At most three that count, and the root copy once.
			if n, m := cc.calls.Load(), cc.maxCerts.Load(); n != 1 || m > 4 {
				t.Errorf("%d chain checks, the longest with %d certificates; want one with at most 4", n, m)
			}
		})
	}
}

// A deployment may pin an intermediate (not self-signed) in
// allowed_client_ca and run two CAs below it. The client sends the leaf
// and the two CAs, three that count; a copy of the pinned intermediate or
// of the root sent along does not count. Such a chain gives the signing
// and the attest-only role, never admin (RoleOf, rule 2).
func TestPinnedIntermediateWithTwoCAsBelow(t *testing.T) {
	root := issue(t, nil, "root", keyOf(t, "P-256"), true, nil)
	pinnedCA := issue(t, &root, "pinned intermediate", keyOf(t, "P-256"), true, nil)
	sub := issue(t, &pinnedCA, "sub CA", keyOf(t, "P-256"), true, nil)
	issuing := issue(t, &sub, "issuing CA", keyOf(t, "P-256"), true, nil)
	signing := issue(t, &issuing, "client", keyOf(t, "P-256"), false, nil)
	attest := issue(t, &issuing, "dashboard", keyOf(t, "P-256"), false, []asn1.ObjectIdentifier{backend.AttestOnlyClientOID})
	for _, tc := range []struct {
		name string
		pins []byte
		cert tls.Certificate
		want Role
	}{
		{"leaf and two CAs", certPEM(pinnedCA.cert), list(signing, issuing, sub), RoleSigning},
		{"leaf, two CAs and the pinned intermediate", certPEM(pinnedCA.cert), list(signing, issuing, sub, pinnedCA), RoleSigning},
		{"leaf, two CAs, the pinned intermediate and the pinned root",
			append(certPEM(root.cert), certPEM(pinnedCA.cert)...), list(signing, issuing, sub, pinnedCA, root), RoleSigning},
		{"attest leaf and two CAs", certPEM(pinnedCA.cert), list(attest, issuing, sub), RoleAttestOnly},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, _, err := ServerConfig(tc.pins, nil)
			if err != nil {
				t.Fatal(err)
			}
			cc := countChainChecks(t)
			cs := handshake(t, cfg, tc.cert)
			if got := RoleOf(&cs); got != tc.want {
				t.Errorf("role %v, want %v", got, tc.want)
			}
			if n := cc.calls.Load(); n != 1 {
				t.Errorf("%d chain checks, want 1", n)
			}
		})
	}
	// A third CA below the pinned one is one too many.
	third := issue(t, &issuing, "third CA", keyOf(t, "P-256"), true, nil)
	cfg, _, err := ServerConfig(certPEM(pinnedCA.cert), nil)
	if err != nil {
		t.Fatal(err)
	}
	addr, hs := start(t, cfg)
	cert := list(issue(t, &third, "client", keyOf(t, "P-256"), false, nil), third, issuing, sub)
	client := &tls.Config{GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return &cert, nil }}
	_, _ = try(t, addr, client)
	if serr := handshakeResult(t, hs); serr == nil || !strings.Contains(serr.Error(), "at most 3") {
		t.Fatalf("leaf and three CAs below a pinned intermediate: %v, want a refusal that names the bound", serr)
	}
}

// The refusal of a large certificate, which goes to the runner log, names
// it in a few bytes, however long its subject name.
func TestRefusalOfALongNameIsShort(t *testing.T) {
	root := issue(t, nil, "root", keyOf(t, "P-256"), true, nil)
	cert := list(issue(t, &root, strings.Repeat("n", 9000), keyOf(t, "P-256"), false, nil))
	clk := &testClock{t: now0}
	cfg, _, err := ServerConfig(certPEM(root.cert), clk.Now)
	if err != nil {
		t.Fatal(err)
	}
	addr, hs := start(t, cfg)
	client := &tls.Config{GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return &cert, nil }}
	_, _ = try(t, addr, client)
	serr := handshakeResult(t, hs)
	if serr == nil {
		t.Fatal("a certificate over 8 KiB got in")
	}
	if len(serr.Error()) > 400 {
		t.Fatalf("refusal of %d bytes: %.120s...", len(serr.Error()), serr)
	}
}
