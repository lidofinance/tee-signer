package attls

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"strings"
	"testing"
	"time"
)

// strangerChain is a client Certificate message of a peer with no
// certificate under the pinned CA: a leaf whose issuer name is "x" and n
// CA certificates named "x" with keys of their own. Every one of them is
// a candidate issuer of the leaf. With ladder each signs the one before
// it, so every signature on the way down verifies; without it none of
// them signed the leaf.
func strangerChain(t *testing.T, n int, ladder bool) tls.Certificate {
	t.Helper()
	ca := func(parent *x509.Certificate, parentKey any) (*x509.Certificate, *ecdsa.PrivateKey) {
		key := newKey(t)
		tmpl := &x509.Certificate{SerialNumber: nextSerial(), Subject: pkix.Name{CommonName: "x"},
			NotBefore: now0.Add(-time.Hour), NotAfter: now0.Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
			KeyUsage: x509.KeyUsageCertSign}
		if parent == nil {
			parent, parentKey = tmpl, key
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
		if err != nil {
			t.Fatal(err)
		}
		c, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return c, key
	}
	// cas[0] issues the leaf. In a ladder cas[i] is signed by cas[i+1].
	cas := make([]*x509.Certificate, n)
	keys := make([]*ecdsa.PrivateKey, n)
	for i := n - 1; i >= 0; i-- {
		if ladder && i < n-1 {
			cas[i], keys[i] = ca(cas[i+1], keys[i+1])
		} else {
			cas[i], keys[i] = ca(nil, nil)
		}
	}
	issuer, issuerKey := cas[0], keys[0]
	if !ladder {
		// A key outside the list signs the leaf.
		issuer, issuerKey = ca(nil, nil)
	}
	leafKey := newKey(t)
	leaf := &x509.Certificate{SerialNumber: nextSerial(), Subject: pkix.Name{CommonName: "stranger"},
		NotBefore: now0.Add(-time.Hour), NotAfter: now0.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, issuer, &leafKey.PublicKey, issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	out := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: leafKey}
	for _, c := range cas {
		out.Certificate = append(out.Certificate, c.Raw)
	}
	return out
}

// chainBuildingRan reports whether a handshake error says crypto/x509
// built chains from the presented certificates: the check of crypto/tls
// (CertificateVerificationError), or the runner's own check without
// dates (verifyUndated) that found no authority or reached x509's cap of
// signature checks.
func chainBuildingRan(err error) bool {
	var cve *tls.CertificateVerificationError
	var unknown x509.UnknownAuthorityError
	return errors.As(err, &cve) || errors.As(err, &unknown) ||
		strings.Contains(err.Error(), "signature check attempts limit")
}

// A stranger's client Certificate message
// longer than any client chain the runner takes is refused before any
// signature check. Today crypto/x509 builds chains from the whole list,
// up to its cap of 100 signature checks per handshake (0.1 to 0.2 s of
// CPU with P-521 or RSA-8192 candidates), for a peer with no certificate
// of the client CA. The list here has 151 certificates; the admin chain,
// the longest the role rules know, is three (TestAdminCAKeyMintsNoSigningLeaf
// keeps a three-certificate list accepted). P-256 keys keep the test fast:
// the property is where the refusal happens, not what it costs.
func TestStrangerChainRefusedBeforeSignatureChecks(t *testing.T) {
	const candidates = 150
	root := newRoot(t, "root", now0.Add(-day(365)), now0.Add(day(365)))
	for _, shape := range []struct {
		name   string
		ladder bool
	}{
		{"same-named CAs that did not sign the leaf", false},
		{"same-named CAs, each signed by the next", true},
	} {
		cert := strangerChain(t, candidates, shape.ladder)
		client := &tls.Config{GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return &cert, nil }}
		for _, mode := range []struct {
			name   string
			before func(*testClock)
		}{
			{"trusted time", func(*testClock) {}},
			{"no trusted time", func(c *testClock) { c.fail(errors.New("clock: no recent reading")) }},
		} {
			t.Run(shape.name+", "+mode.name, func(t *testing.T) {
				clk := &testClock{t: now0}
				cfg, _ := clk.config(t, root)
				mode.before(clk)
				addr, hs := start(t, cfg)
				_, cerr := try(t, addr, client)
				serr := handshakeResult(t, hs)
				if cerr == nil || serr == nil {
					t.Fatalf("a stranger's %d-certificate list got in (client %v, server %v)", len(cert.Certificate), cerr, serr)
				}
				if chainBuildingRan(serr) {
					t.Errorf("the server refused the stranger's %d-certificate list only after crypto/x509 built chains from it (%v); "+
						"a list longer than the client chain shape must be refused before any signature check", len(cert.Certificate), serr)
				}
			})
		}
	}
}
