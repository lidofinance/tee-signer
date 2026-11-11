package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/governance/setupwire"
	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/remote"
	"github.com/lidofinance/tee-signer/signer-protocol/wire"
	wireadmin "github.com/lidofinance/tee-signer/signer-protocol/wire/admin"
	"github.com/lidofinance/tee-signer/slashing-log"
	"github.com/lidofinance/tee-signer/tee-signer/attls"
)

// longAdminCA is a root, an admin intermediate under it and an admin leaf
// under that, valid from 1980 to 2200 like longCA. leaf carries the
// intermediate.
func longAdminCA(t *testing.T) (rootPEM []byte, leaf tls.Certificate) {
	t.Helper()
	nb, na := time.Date(1980, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2200, 1, 1, 0, 0, 0, 0, time.UTC)
	admin := []asn1.ObjectIdentifier{backend.AdminClientOID}
	issue := func(tmpl, parent *x509.Certificate, parentKey, key *ecdsa.PrivateKey) *x509.Certificate {
		der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
		if err != nil {
			t.Fatal(err)
		}
		c, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	rk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rt := &x509.Certificate{SerialNumber: big.NewInt(11), Subject: pkix.Name{CommonName: "remote test CA"}, NotBefore: nb, NotAfter: na,
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	root := issue(rt, rt, rk, rk)
	ik, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	it := &x509.Certificate{SerialNumber: big.NewInt(12), Subject: pkix.Name{CommonName: "remote test admin CA"}, NotBefore: nb, NotAfter: na,
		IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign,
		ExtKeyUsage: clientAuth, UnknownExtKeyUsage: admin}
	inter := issue(it, root, rk, ik)
	lk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	lt := &x509.Certificate{SerialNumber: big.NewInt(13), Subject: pkix.Name{CommonName: "remote test admin"}, NotBefore: nb, NotAfter: na,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: clientAuth, UnknownExtKeyUsage: admin}
	l := issue(lt, inter, ik, lk)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root.Raw}),
		tls.Certificate{Certificate: [][]byte{l.Raw, inter.Raw}, PrivateKey: lk}
}

// remoteClients serves s over the runner's TLS configuration with the
// revoked set r and returns a maker of signer-protocol/remote clients of
// it with cert, pinned to the server's TLS key. Like every remote client,
// each sends IDENTITY first on each new connection.
func remoteClients(t *testing.T, s *Server, rootPEM []byte, cert tls.Certificate, r *attls.Revoked) func() *remote.Client {
	t.Helper()
	cfg, keyHash, err := attls.ServerConfig(rootPEM, nil, attls.WithRevoked(r))
	if err != nil {
		t.Fatal(err)
	}
	s.ClientCAs, s.TLSKeyHash = cfg.ClientCAs, keyHash
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go s.handleConn(context.Background(), tls.Server(c, cfg))
		}
	}()
	return func() *remote.Client {
		ccfg := &tls.Config{GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return &cert, nil }}
		c, err := remote.New("tcp:"+l.Addr().String(), remote.WithTLS(ccfg, nil), remote.WithTLSKeyPin(keyHash), remote.WithTimeout(10*time.Second))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		return c
	}
}

// rv-nsd.6: while the revoked set is incomplete, an admin client of
// signer-protocol/remote, which sends IDENTITY on each new connection
// before anything else, still gets to send the CONFIG_UPDATE that restores
// the body. A request outside HEALTH, IDENTITY, ATTEST and CONFIG_UPDATE
// stays refused until then.
func TestIncompleteRevocationsResendThroughRemote(t *testing.T) {
	e := newEnv(t, u64(0))
	h := [32]byte{0x62}
	raw := signed(t, openWith(e, 1, e.groupHash(open), e.now()+600, withBase(e, h)...), first2, nil)
	e.mustSend(raw, wireadmin.ConfigAccepted)
	if err := e.upd.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	e.signer.Close()
	if err := os.Remove(filepath.Join(e.dir, "marks", markstore.BodyName(e.hash, open, 1, 1))); err != nil {
		t.Fatal(err)
	}
	e.start()
	r := useRevoked(e)
	if !r.Incomplete() {
		t.Fatal("the set is complete with the pending body gone")
	}
	rootPEM, leaf := longAdminCA(t)
	clients := remoteClients(t, e.srv, rootPEM, leaf, r)
	// A refused request closes its connection, so the refusal gets its own
	// client.
	if _, err := clients().PublicKeys(ctx); refusedWith(err) != backend.StatusForbidden || !strings.Contains(err.Error(), "unknown") {
		t.Fatalf("PUBLIC_KEYS through remote while the set is incomplete: %v, want FORBIDDEN", err)
	}
	c := clients()
	if _, err := c.Health(ctx); err != nil {
		t.Fatalf("HEALTH through remote while the set is incomplete: %v", err)
	}
	p, err := wireadmin.EncodeConfigUpdate(raw)
	if err != nil {
		t.Fatal(err)
	}
	b, err := c.RoundTrip(ctx, wireadmin.TypeConfigUpdate, p)
	if err != nil {
		t.Fatalf("CONFIG_UPDATE through remote while the set is incomplete: %v", err)
	}
	if o, _, err := wireadmin.DecodeConfigUpdateResponse(b); err != nil || o != wireadmin.ConfigKnown {
		t.Fatalf("CONFIG_UPDATE answer: outcome %d, %v; want known", o, err)
	}
	if r.Incomplete() || r.Len() != len(e.setup.Open.RevokedClientCerts)+1 {
		t.Fatalf("after the resend: incomplete %v, %d entries", r.Incomplete(), r.Len())
	}
	if _, err := c.PublicKeys(ctx); err != nil {
		t.Fatalf("PUBLIC_KEYS through remote with the set complete: %v", err)
	}
}

// rv-nsd.7: Accept takes the change rules from setupwire Decide. An open
// update that drops a revocation in force with the usual count is refused,
// and the entry holds; with every approver it is taken.
func TestRevocationDropNeedsEveryApprover(t *testing.T) {
	h := [32]byte{0x43}
	e := newEnvWith(t, u64(0), func(s *setupwire.Setup) { s.Open.RevokedClientCerts = [][32]byte{h} })
	r := useRevoked(e)
	drop := openWith(e, 1, e.groupHash(open), e.now())
	_, _, err := e.send(signed(t, drop, first2, nil))
	if refusedWith(err) != backend.StatusBadRequest || !strings.Contains(err.Error(), "every approver") {
		t.Fatalf("a drop with 2 of 3: %v, want BAD_REQUEST for every approver", err)
	}
	if r.Len() != 1 || e.upd.SetupState().Open.Version != 0 {
		t.Fatalf("after the refused drop: %d entries, open version %d", r.Len(), e.upd.SetupState().Open.Version)
	}
	e.mustSend(signed(t, drop, every, nil), wireadmin.ConfigAccepted)
	if r.Len() != 0 {
		t.Fatalf("after the drop by every approver: %d entries", r.Len())
	}
}

// rv-nsd.8: a new open update replaces the pending one. One that leaves
// out a revocation only the pending update holds drops it, so it needs
// every approver too; one that keeps it takes the usual count.
func TestReplacingPendingKeepsItsRevocation(t *testing.T) {
	e := newEnv(t, u64(0))
	r := useRevoked(e)
	h, g := [32]byte{0x52}, [32]byte{0x53}
	base := len(e.setup.Open.RevokedClientCerts)
	t0 := e.now()
	e.mustSend(signed(t, openWith(e, 1, e.groupHash(open), t0+600, withBase(e, h)...), first2, nil), wireadmin.ConfigAccepted)
	without := openWith(e, 2, e.groupHash(open), t0+600, withBase(e)...)
	_, _, err := e.send(signed(t, without, first2, nil))
	if refusedWith(err) != backend.StatusBadRequest || !strings.Contains(err.Error(), "pending open version 1") {
		t.Fatalf("a replacement without the pending revocation, 2 of 3: %v, want BAD_REQUEST", err)
	}
	if r.Len() != base+1 {
		t.Fatalf("after the refused replacement: %d entries, want %d", r.Len(), base+1)
	}
	// Keeping it and adding one: the usual count.
	e.mustSend(signed(t, openWith(e, 2, e.groupHash(open), t0+600, withBase(e, h, g)...), first2, nil), wireadmin.ConfigAccepted)
	if r.Len() != base+2 {
		t.Fatalf("after the replacement that keeps it: %d entries, want %d", r.Len(), base+2)
	}
	// Every approver may drop both.
	e.mustSend(signed(t, openWith(e, 3, e.groupHash(open), t0+600, withBase(e)...), every, nil), wireadmin.ConfigAccepted)
	if r.Len() != base {
		t.Fatalf("after the drop by every approver: %d entries, want %d", r.Len(), base)
	}
}

// rv-nsd.10: an entry may name a public key (the SHA-256 of its DER
// SubjectPublicKeyInfo): it revokes every certificate of that key.
func TestRevokedPublicKey(t *testing.T) {
	root := newTestCA(t, nil, nil, nil)
	s := roleServer(t)
	s.Revoked = &attls.Revoked{}
	clk := &movingClock{t: time.Now()}
	s.Platform.Clock = clk
	cert := root.leaf(t, clientAuth, nil)
	c := dialClock(t, s, root.pem(), cert, clk)
	if _, err := c.call(wire.TypeHealth, nil); err != nil {
		t.Fatalf("HEALTH before the revocation: %v", err)
	}
	s.Revoked.Set([][32]byte{sha256.Sum256(root.cert.RawSubjectPublicKeyInfo)})
	if _, err := c.call(wire.TypeHealth, nil); refusedWith(err) != backend.StatusForbidden || !strings.Contains(err.Error(), "the key of certificate") {
		t.Fatalf("HEALTH after its CA's key was revoked: %v, want FORBIDDEN for the revocation", err)
	}
}
