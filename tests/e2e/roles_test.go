package e2e

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	remoteadmin "github.com/lidofinance/tee-signer/signer-admin/remote/admin"
	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/remote"
)

// Client roles (docs/protocol.md, "Client roles"): the runners sign only
// for a signing certificate and take imports, config updates, orders and
// key generation only from an admin certificate. The tests' PKI has both
// under one root; a signing configuration knows its admin twin, so a test
// that imports and then signs over TLS uses the right certificate for
// each.

// testRoles is the client PKI of one test.
type testRoles struct {
	caFile                     string
	signing, admin, attestOnly *tls.Config
}

var (
	twinsMu sync.Mutex
	// adminTwin maps a signing configuration to the admin one of its PKI.
	adminTwin = map[*tls.Config]*tls.Config{}
	// adminPeers maps a client of a signing configuration to a client of
	// the same runner with the admin twin.
	adminPeers = map[*remote.Client]*remote.Client{}
)

// rolePKI makes a root, an admin intermediate (clientAuth and
// AdminClientOID) and a signing intermediate, and one leaf each: signing,
// admin, and attest-only. caFor and clientFor are the CA's and the leaves'
// validity from now.
func rolePKI(t *testing.T, dir, name string, caFor, clientFor time.Duration) *testRoles {
	t.Helper()
	serial := int64(0)
	cert := func(tmpl, parent *x509.Certificate, pub *ecdsa.PublicKey, signer *ecdsa.PrivateKey) *x509.Certificate {
		serial++
		tmpl.SerialNumber = big.NewInt(serial)
		der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, signer)
		if err != nil {
			t.Fatal(err)
		}
		c, _ := x509.ParseCertificate(der)
		return c
	}
	key := func() *ecdsa.PrivateKey { k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader); return k }
	nb := time.Now().Add(-time.Hour)
	rootKey := key()
	rootTmpl := &x509.Certificate{Subject: pkix.Name{CommonName: name + " CA"}, NotBefore: nb, NotAfter: time.Now().Add(caFor),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	root := cert(rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	inter := func(cn string, marks []asn1.ObjectIdentifier) (*x509.Certificate, *ecdsa.PrivateKey) {
		k := key()
		return cert(&x509.Certificate{Subject: pkix.Name{CommonName: cn}, NotBefore: nb, NotAfter: time.Now().Add(caFor),
			IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign,
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, UnknownExtKeyUsage: marks}, root, &k.PublicKey, rootKey), k
	}
	adminCA, adminKey := inter(name+" admin CA", []asn1.ObjectIdentifier{backend.AdminClientOID})
	signCA, signKey := inter(name+" signing CA", nil)
	leaf := func(cn string, ca *x509.Certificate, caKey *ecdsa.PrivateKey, marks []asn1.ObjectIdentifier) *tls.Config {
		k := key()
		c := cert(&x509.Certificate{Subject: pkix.Name{CommonName: cn}, NotBefore: nb, NotAfter: time.Now().Add(clientFor),
			KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, UnknownExtKeyUsage: marks},
			ca, &k.PublicKey, caKey)
		return &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{c.Raw, ca.Raw}, PrivateKey: k}}}
	}
	r := &testRoles{caFile: filepath.Join(dir, name+"-ca.pem"),
		signing:    leaf(name+" dirk", signCA, signKey, nil),
		admin:      leaf(name+" admin", adminCA, adminKey, []asn1.ObjectIdentifier{backend.AdminClientOID}),
		attestOnly: leaf(name+" prover", signCA, signKey, []asn1.ObjectIdentifier{backend.AttestOnlyClientOID}),
	}
	if err := os.WriteFile(r.caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root.Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	twinsMu.Lock()
	adminTwin[r.signing] = r.admin
	twinsMu.Unlock()
	return r
}

// adminConfig is the admin twin of cfg, or cfg when it has none.
func adminConfig(cfg *tls.Config) *tls.Config {
	twinsMu.Lock()
	defer twinsMu.Unlock()
	if a := adminTwin[cfg]; a != nil {
		return a
	}
	return cfg
}

// newTLSClient is remote.New with mutual TLS. When cfg is a signing
// configuration of rolePKI, a second client with its admin twin serves the
// admin calls of adminOf.
func newTLSClient(addr string, cfg *tls.Config, verify remote.VerifyFunc, opts ...remote.Option) (*remote.Client, error) {
	c, err := remote.New(addr, append([]remote.Option{remote.WithTLS(cfg, verify)}, opts...)...)
	if err != nil {
		return nil, err
	}
	if a := adminConfig(cfg); a != cfg {
		ac, err := remote.New(addr, append([]remote.Option{remote.WithTLS(a, verify)}, opts...)...)
		if err != nil {
			return nil, err
		}
		twinsMu.Lock()
		adminPeers[c] = ac
		twinsMu.Unlock()
	}
	return c, nil
}

// adminOf is the client for c's admin calls: c's admin twin when it has
// one, else c itself (a client without TLS is a local one).
func adminOf(c *remote.Client) *remoteadmin.Client {
	twinsMu.Lock()
	a := adminPeers[c]
	twinsMu.Unlock()
	if a != nil {
		return remoteadmin.Wrap(a)
	}
	return remoteadmin.Wrap(c)
}
