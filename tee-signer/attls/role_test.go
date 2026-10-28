package attls

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/buildflavor"
)

const makeTestCA = "../../scripts/make-test-ca.sh"

// The test PKI script names the roles' OIDs itself (openssl takes them as
// text); they must be backend.AttestOnlyClientOID and backend.AdminClientOID.
func TestTestPKIOID(t *testing.T) {
	b, err := os.ReadFile(makeTestCA)
	if err != nil {
		t.Fatal(err)
	}
	for name, oid := range map[string]string{"ATTEST_ONLY_OID": backend.AttestOnlyClientOID.String(), "ADMIN_OID": backend.AdminClientOID.String()} {
		m := regexp.MustCompile(`(?m)^` + name + `=([0-9.]+)$`).FindSubmatch(b)
		if m == nil || string(m[1]) != oid {
			t.Fatalf("make-test-ca.sh has %s %q, backend %s", name, m, oid)
		}
	}
}

// makeTestPKI runs make-test-ca.sh into a fresh directory.
func makeTestPKI(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl not installed")
	}
	dir := filepath.Join(t.TempDir(), "pki")
	if out, err := exec.Command("bash", makeTestCA, dir).CombinedOutput(); err != nil {
		t.Fatalf("make-test-ca.sh: %v\n%s", err, out)
	}
	return dir
}

// readCerts parses every certificate of a PEM file.
func readCerts(t *testing.T, path string) []*x509.Certificate {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var out []*x509.Certificate
	for {
		var blk *pem.Block
		blk, b = pem.Decode(b)
		if blk == nil {
			return out
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, c)
	}
}

// Every client certificate of the test PKI verifies under its root for
// clientAuth, the check crypto/tls runs, and carries the marks of its role.
func TestTestPKIChainsVerify(t *testing.T) {
	dir := makeTestPKI(t)
	roots := x509.NewCertPool()
	for _, c := range readCerts(t, filepath.Join(dir, "root-ca.pem")) {
		roots.AddCert(c)
	}
	has := func(c *x509.Certificate, oid asn1.ObjectIdentifier) bool {
		for _, u := range c.UnknownExtKeyUsage {
			if u.Equal(oid) {
				return true
			}
		}
		return false
	}
	for name, want := range map[string]struct{ leafAdmin, issuerAdmin, attest bool }{
		"client":            {},
		"attest-client":     {attest: true},
		"admin-client":      {leafAdmin: true, issuerAdmin: true},
		"root-admin-client": {leafAdmin: true},
	} {
		certs := readCerts(t, filepath.Join(dir, name+".pem"))
		inter := x509.NewCertPool()
		for _, c := range certs[1:] {
			inter.AddCert(c)
		}
		chains, err := certs[0].Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
		if err != nil {
			t.Fatalf("%s.pem: %v", name, err)
		}
		issuer := chains[0][1]
		if has(certs[0], backend.AdminClientOID) != want.leafAdmin || has(issuer, backend.AdminClientOID) != want.issuerAdmin ||
			has(certs[0], backend.AttestOnlyClientOID) != want.attest {
			t.Errorf("%s.pem: leaf %v, issuer %s %v", name, certs[0].UnknownExtKeyUsage, issuer.Subject.CommonName, issuer.UnknownExtKeyUsage)
		}
		if name == "root-admin-client" && len(chains[0]) != 2 {
			t.Errorf("root-admin-client.pem: chain of %d, want leaf and root", len(chains[0]))
		}
	}
}

// The certificates of make-test-ca.sh, made by openssl, pass the runner's
// handshake under its root, and the role check tells them apart: the
// attest-only one is, the plain client certificate is not.
func TestTestPKIRoles(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl not installed")
	}
	dir := filepath.Join(t.TempDir(), "pki")
	if out, err := exec.Command("bash", makeTestCA, dir).CombinedOutput(); err != nil {
		t.Fatalf("make-test-ca.sh: %v\n%s", err, out)
	}
	root, err := os.ReadFile(filepath.Join(dir, "root-ca.pem"))
	if err != nil {
		t.Fatal(err)
	}
	cfg, _, err := ServerConfig(root, nil)
	if err != nil {
		t.Fatal(err)
	}
	rootDirect := RoleSigning // the admin mark on a leaf straight under the root
	if buildflavor.AdminRootDirect {
		rootDirect = RoleAdminRootDirect
	}
	for name, want := range map[string]Role{"client": RoleSigning, "attest-client": RoleAttestOnly,
		"admin-client": RoleAdmin, "root-admin-client": rootDirect} {
		cert, err := tls.LoadX509KeyPair(filepath.Join(dir, name+".pem"), filepath.Join(dir, name+"-key.pem"))
		if err != nil {
			t.Fatal(err)
		}
		cs := handshake(t, cfg, cert)
		if got := RoleOf(&cs); got != want {
			t.Errorf("%s.pem: role %v, want %v", name, got, want)
		}
	}
	// The script refuses to overwrite the PKI.
	if err := exec.Command("bash", makeTestCA, dir).Run(); err == nil {
		t.Fatal("make-test-ca.sh overwrote an existing PKI")
	}
	// The leaf's mark is in the certificate itself.
	b, _ := os.ReadFile(filepath.Join(dir, "attest-client.pem"))
	blk, _ := pem.Decode(b)
	leaf, err := x509.ParseCertificate(blk.Bytes)
	if err != nil || len(leaf.UnknownExtKeyUsage) != 1 || !leaf.UnknownExtKeyUsage[0].Equal(backend.AttestOnlyClientOID) {
		t.Fatalf("attest-client.pem extended key usages %v %v (%v)", leaf.ExtKeyUsage, leaf.UnknownExtKeyUsage, err)
	}
}

// handshake runs a mutual TLS handshake with cfg on the server side and
// returns the server's view of it.
func handshake(t *testing.T, cfg *tls.Config, cert tls.Certificate) tls.ConnectionState {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	got := make(chan tls.ConnectionState, 1)
	go func() {
		c, err := l.Accept()
		if err != nil {
			close(got)
			return
		}
		defer c.Close()
		s := tls.Server(c, cfg)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := s.HandshakeContext(ctx); err != nil {
			t.Errorf("server handshake: %v", err)
			close(got)
			return
		}
		got <- s.ConnectionState()
	}()
	c, err := tls.Dial("tcp", l.Addr().String(), &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13,
		Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	// TLS 1.3: the server's check of the client certificate ends after the
	// client's handshake; a read makes it finish.
	c.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	c.Read(make([]byte, 1))
	cs, ok := <-got
	if !ok {
		t.FailNow()
	}
	return cs
}

// roleCA is a CA for the role table test, with the extended key usages it
// lists.
func roleCA(t *testing.T, parent *ca, name string, ekus []x509.ExtKeyUsage, marks ...asn1.ObjectIdentifier) *ca {
	t.Helper()
	key := newKey(t)
	tmpl := &x509.Certificate{
		SerialNumber: nextSerial(), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign, ExtKeyUsage: ekus, UnknownExtKeyUsage: marks,
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

// roleLeaf issues a client certificate with clientAuth and marks under c.
func roleLeaf(t *testing.T, c *ca, marks ...asn1.ObjectIdentifier) tls.Certificate {
	t.Helper()
	key := newKey(t)
	tmpl := &x509.Certificate{
		SerialNumber: nextSerial(), Subject: pkix.Name{CommonName: "role leaf"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, UnknownExtKeyUsage: marks,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, &key.PublicKey, c.key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: append([][]byte{der}, c.chain...), PrivateKey: key}
}

// RoleOf over leaf marks, issuer marks, a leaf under the root and both
// marks, through real handshakes.
func TestRoleOf(t *testing.T) {
	admin, attest := backend.AdminClientOID, backend.AttestOnlyClientOID
	ca := []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	root := roleCA(t, nil, "root", nil)
	adminCA := roleCAPath(t, root, "admin CA", ca, 0, admin)
	plainCA := roleCA(t, root, "signing CA", ca)
	attestCA := roleCA(t, root, "attest CA", ca, attest)
	bothCA := roleCA(t, root, "admin and attest CA", ca, admin, attest)
	adminSub := roleCA(t, roleCA(t, root, "admin CA that may issue CAs", ca, admin), "admin sub CA", ca)
	// A leaf with the admin mark straight under the root: admin only in a
	// testnet build. Run under both tags.
	rootDirect := RoleSigning
	if buildflavor.AdminRootDirect {
		rootDirect = RoleAdminRootDirect
	}
	cfg, _, err := ServerConfig(certPEM(root.cert), nil)
	if err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		cert tls.Certificate
		want Role
	}{
		"plain leaf under signing CA":   {roleLeaf(t, plainCA), RoleSigning},
		"admin leaf under admin CA":     {roleLeaf(t, adminCA, admin), RoleAdmin},
		"admin leaf under signing CA":   {roleLeaf(t, plainCA, admin), RoleSigning},
		"plain leaf under admin CA":     {roleLeaf(t, adminCA), RoleSigning},
		"admin leaf under the root":     {roleLeaf(t, root, admin), rootDirect},
		"both marks under the root":     {roleLeaf(t, root, admin, attest), RoleAttestOnly},
		"plain leaf under the root":     {roleLeaf(t, root), RoleSigning},
		"admin leaf, unmarked sub CA":   {roleLeaf(t, adminSub, admin), RoleSigning},
		"attest leaf under signing CA":  {roleLeaf(t, plainCA, attest), RoleAttestOnly},
		"attest leaf under the root":    {roleLeaf(t, root, attest), RoleAttestOnly},
		"plain leaf under attest CA":    {roleLeaf(t, attestCA), RoleAttestOnly},
		"admin leaf under attest CA":    {roleLeaf(t, attestCA, admin), RoleAttestOnly},
		"both marks on leaf, admin CA":  {roleLeaf(t, adminCA, admin, attest), RoleAttestOnly},
		"admin leaf under both-mark CA": {roleLeaf(t, bothCA, admin), RoleAttestOnly},
	} {
		cs := handshake(t, cfg, tc.cert)
		if got := RoleOf(&cs); got != tc.want {
			t.Errorf("%s: %v, want %v", name, got, tc.want)
		}
	}
	if got := RoleOf(&tls.ConnectionState{}); got != RoleNone {
		t.Errorf("no certificate: %v, want none", got)
	}
}

// An intermediate whose extended key usages lack clientAuth issues no
// client certificate the runner takes, admin mark or not.
func TestRoleIntermediateWithoutClientAuth(t *testing.T) {
	root := roleCA(t, nil, "root", nil)
	bad := roleCA(t, root, "server-only admin CA", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, backend.AdminClientOID)
	cfg, _, err := ServerConfig(certPEM(root.cert), nil)
	if err != nil {
		t.Fatal(err)
	}
	addr, hs := start(t, cfg)
	cert := roleLeaf(t, bad, backend.AdminClientOID)
	_, err = try(t, addr, &tls.Config{Certificates: []tls.Certificate{cert}})
	herr := handshakeResult(t, hs)
	if err == nil || herr == nil {
		t.Fatalf("a leaf under an intermediate without clientAuth got in (client %v, server %v)", err, herr)
	}
	wantContains(t, "server side", herr, "usage")
}
