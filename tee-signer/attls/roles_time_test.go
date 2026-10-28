package attls

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/signer-protocol"
)

// onceClock answers its first call and fails every later one: trusted time
// that is there at ClientHello and gone at the certificate check.
type onceClock struct {
	mu    sync.Mutex
	calls int
	t     time.Time
}

func (c *onceClock) Now() (time.Time, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls++
	if c.calls > 1 {
		return time.Time{}, errors.New("test clock: no quorum")
	}
	return c.t, nil
}

// ATTEST-ROLES-03: when trusted time fails between ClientHello and the
// check of the client certificate, crypto/tls must not fall back to the
// system clock. The certificate is valid by the system clock and expired
// by the trusted one.
func TestClockFailureDuringHandshakeRefusesExpiredCertificate(t *testing.T) {
	root := newRoot(t, "root", now0.Add(-day(30)), now0.Add(day(365)))
	cert := root.client(t, "client", now0.Add(-day(2)), now0.Add(day(2)))
	clk := &onceClock{t: now0.Add(day(10))}
	cfg, _, err := ServerConfig(certPEM(root.cert), clk.Now)
	if err != nil {
		t.Fatal(err)
	}
	addr, hs := start(t, cfg)
	_, cerr := try(t, addr, &tls.Config{Certificates: []tls.Certificate{cert}})
	if herr := handshakeResult(t, hs); herr == nil || cerr == nil {
		t.Fatalf("an expired certificate got in while trusted time failed (client %v, server %v)", cerr, herr)
	}
}

// roleCAPath is roleCA with a path length: -1 leaves it out, 0 is
// pathlen:0, n > 0 is pathlen:n.
func roleCAPath(t *testing.T, parent *ca, name string, ekus []x509.ExtKeyUsage, pathLen int, marks ...asn1.ObjectIdentifier) *ca {
	t.Helper()
	key := newKey(t)
	tmpl := &x509.Certificate{
		SerialNumber: nextSerial(), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign, ExtKeyUsage: ekus, UnknownExtKeyUsage: marks,
		MaxPathLen: pathLen, MaxPathLenZero: pathLen == 0,
	}
	issuer, signer := tmpl, key
	var chain [][]byte
	if parent != nil {
		issuer, signer, chain = parent.cert, parent.key, parent.chain
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, issuer, &key.PublicKey, signer)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	if parent == nil {
		return &ca{cert: cert, key: key}
	}
	return &ca{cert: cert, key: key, chain: append([][]byte{der}, chain...)}
}

// ATTEST-ROLES-02: an admin-marked CA below an unmarked intermediate gives
// no admin role, and neither does an admin intermediate that may issue
// further CAs, or one whose chain ends at an intermediate of the CA file
// instead of a root.
func TestAdminNeedsRootIssuedPathLenZeroIntermediate(t *testing.T) {
	admin := backend.AdminClientOID
	ca := []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	root := roleCAPath(t, nil, "root", nil, -1)
	signing := roleCAPath(t, root, "signing CA that may issue CAs", ca, -1)
	adminBelowSigning := roleCAPath(t, signing, "admin CA below the signing CA", ca, 0, admin)
	adminOpen := roleCAPath(t, root, "admin CA without pathlen:0", ca, -1, admin)
	adminZero := roleCAPath(t, root, "admin CA with pathlen:0", ca, 0, admin)

	rootCfg, _, err := ServerConfig(certPEM(root.cert), nil)
	if err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		cert tls.Certificate
		want Role
	}{
		"admin leaf, admin CA under an unmarked CA": {roleLeaf(t, adminBelowSigning, admin), RoleSigning},
		"admin leaf, admin CA without pathlen:0":    {roleLeaf(t, adminOpen, admin), RoleSigning},
		"admin leaf, admin CA with pathlen:0":       {roleLeaf(t, adminZero, admin), RoleAdmin},
	} {
		cs := handshake(t, rootCfg, tc.cert)
		if got := RoleOf(&cs); got != tc.want {
			t.Errorf("%s: %v, want %v", name, got, tc.want)
		}
	}

	// A CA file that also names the signing intermediate: a chain then
	// ends at that intermediate, three certificates long, at no root.
	interCfg, _, err := ServerConfig(append(certPEM(root.cert), certPEM(signing.cert)...), nil)
	if err != nil {
		t.Fatal(err)
	}
	cs := handshake(t, interCfg, roleLeaf(t, adminBelowSigning, admin))
	if got := RoleOf(&cs); got != RoleSigning {
		t.Errorf("admin CA whose chain ends at an intermediate of the CA file: %v, want %v", got, RoleSigning)
	}
}

// Without trusted time the handshake still verifies the chain, its
// signatures, key usages and path length rules, but not its dates: the
// connection then has no verified chain (RoleOf gives RoleNone) and the
// server lets it read HEALTH only. A certificate of another CA, or one
// without clientAuth, is refused as before.
func TestHandshakeWithoutTrustedTimeChecksChainButNotDates(t *testing.T) {
	root := newRoot(t, "root", now0.Add(-day(30)), now0.Add(day(365)))
	other := newRoot(t, "other root", now0.Add(-day(30)), now0.Add(day(365)))
	clk := &testClock{t: now0}
	clk.fail(errors.New("test clock: no quorum"))
	cfg, _ := clk.config(t, root)

	for name, cert := range map[string]tls.Certificate{
		"valid":   root.client(t, "dirk", now0.Add(-time.Hour), now0.Add(time.Hour)),
		"expired": root.client(t, "dirk", now0.Add(-day(20)), now0.Add(-day(10))),
	} {
		cs := handshake(t, cfg, cert)
		if len(cs.PeerCertificates) != 1 || len(cs.VerifiedChains) != 0 || RoleOf(&cs) != RoleNone {
			t.Errorf("%s certificate without trusted time: %d peer certificates, %d verified chains, role %v; want 1, 0, none",
				name, len(cs.PeerCertificates), len(cs.VerifiedChains), RoleOf(&cs))
		}
	}

	addr, hs := start(t, cfg)
	forced := func(c tls.Certificate) *tls.Config {
		return &tls.Config{GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return &c, nil }}
	}
	for name, cert := range map[string]tls.Certificate{
		"other CA":        other.client(t, "dirk", now0.Add(-time.Hour), now0.Add(time.Hour)),
		"serverAuth only": root.client(t, "dirk", now0.Add(-time.Hour), now0.Add(time.Hour), x509.ExtKeyUsageServerAuth),
	} {
		_, cerr := try(t, addr, forced(cert))
		if herr := handshakeResult(t, hs); herr == nil || cerr == nil {
			t.Errorf("%s without trusted time: got in (client %v, server %v)", name, cerr, herr)
		}
	}
	_, cerr := try(t, addr, &tls.Config{})
	if herr := handshakeResult(t, hs); herr == nil || cerr == nil {
		t.Errorf("no certificate without trusted time: got in (client %v, server %v)", cerr, herr)
	}
}

// VerifyAt, the check of a connection opened without trusted time once
// the clock has a reading: the chain must hold at that reading, dates
// included, and chain to the CA file with clientAuth.
func TestVerifyAtChecksChainAndDates(t *testing.T) {
	root := newRoot(t, "root", now0.Add(-day(30)), now0.Add(day(365)))
	other := newRoot(t, "other root", now0.Add(-day(30)), now0.Add(day(365)))
	pool, _, err := parseCAs(certPEM(root.cert))
	if err != nil {
		t.Fatal(err)
	}
	leaf := func(c tls.Certificate) []*x509.Certificate {
		x, err := x509.ParseCertificate(c.Certificate[0])
		if err != nil {
			t.Fatal(err)
		}
		return []*x509.Certificate{x}
	}
	valid := leaf(root.client(t, "dirk", now0.Add(-time.Hour), now0.Add(time.Hour)))
	chains, err := VerifyAt(pool, valid, now0)
	if err != nil || len(chains) == 0 {
		t.Fatalf("valid certificate: %v", err)
	}
	cs := tls.ConnectionState{PeerCertificates: valid, VerifiedChains: chains}
	if RoleOf(&cs) != RoleSigning || !NotAfter(&cs).Equal(valid[0].NotAfter) {
		t.Fatalf("role %v, NotAfter %v", RoleOf(&cs), NotAfter(&cs))
	}
	for name, tc := range map[string]struct {
		roots *x509.CertPool
		peer  []*x509.Certificate
		at    time.Time
	}{
		"expired":             {pool, valid, now0.Add(2 * time.Hour)},
		"not yet valid":       {pool, valid, now0.Add(-2 * time.Hour)},
		"other CA":            {pool, leaf(other.client(t, "dirk", now0.Add(-time.Hour), now0.Add(time.Hour))), now0},
		"serverAuth only":     {pool, leaf(root.client(t, "dirk", now0.Add(-time.Hour), now0.Add(time.Hour), x509.ExtKeyUsageServerAuth)), now0},
		"zero time":           {pool, valid, time.Time{}},
		"no CA":               {nil, valid, now0},
		"no peer certificate": {pool, nil, now0},
	} {
		if _, err := VerifyAt(tc.roots, tc.peer, tc.at); err == nil {
			t.Errorf("%s: verified", name)
		}
	}
}
