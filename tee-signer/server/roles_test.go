package server

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/wire"
	wireadmin "github.com/lidofinance/tee-signer/signer-protocol/wire/admin"
	"github.com/lidofinance/tee-signer/tee-signer/attls"
	"github.com/lidofinance/tee-signer/trusted-time/clock"
)

// testCA issues client certificates for the role tests.
type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

var serial int64 = 100

func newTestCA(t *testing.T, parent *testCA, ekus []x509.ExtKeyUsage, unknown []asn1.ObjectIdentifier) *testCA {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serial++
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "role test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, ExtKeyUsage: ekus, UnknownExtKeyUsage: unknown}
	issuer, signer := tmpl, key
	if parent != nil {
		// A role intermediate has pathlen:0, as make-test-ca.sh and
		// signer-admin issue it; an admin one needs it (attls.RoleOf).
		issuer, signer = parent.cert, parent.key
		tmpl.MaxPathLenZero = true
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, issuer, &key.PublicKey, signer)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return &testCA{cert: c, key: key}
}

func (ca *testCA) pem() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.cert.Raw})
}

// leaf issues a client certificate; chain are the intermediates it sends.
func (ca *testCA) leaf(t *testing.T, ekus []x509.ExtKeyUsage, unknown []asn1.ObjectIdentifier, chain ...*testCA) tls.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serial++
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "role test client"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: ekus, UnknownExtKeyUsage: unknown}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	c := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	for _, i := range chain {
		c.Certificate = append(c.Certificate, i.cert.Raw)
	}
	return c
}

var (
	clientAuth = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	attestOnly = []asn1.ObjectIdentifier{backend.AttestOnlyClientOID}
)

// conn is a client connection to s over mutual TLS with cert.
type conn struct {
	t  *testing.T
	c  *tls.Conn
	id uint32
}

func dial(t *testing.T, s *Server, rootPEM []byte, cert tls.Certificate) (*conn, error) {
	t.Helper()
	cfg, _, err := attls.ServerConfig(rootPEM, nil)
	if err != nil {
		t.Fatal(err)
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		if c, err := l.Accept(); err == nil {
			s.handleConn(context.Background(), tls.Server(c, cfg))
		}
	}()
	peer, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { peer.Close() })
	c := tls.Client(peer, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13,
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return &cert, nil }})
	if err := c.Handshake(); err != nil {
		return nil, err
	}
	// TLS 1.3: the server checks the client certificate after the client's
	// handshake ends; a refusal shows at the first read.
	return &conn{t: t, c: c}, nil
}

// call sends one request and returns the body or the refusal.
func (c *conn) call(typ wire.MsgType, payload []byte) ([]byte, error) {
	c.t.Helper()
	c.id++
	if err := wire.WriteFrame(c.c, wire.Frame{Type: typ, ID: c.id, Payload: payload}); err != nil {
		return nil, err
	}
	f, err := wire.ReadFrame(c.c)
	if err != nil {
		return nil, err
	}
	if f.Type != typ|wire.ResponseFlag || f.ID != c.id {
		c.t.Fatalf("answer %v id %d to %v id %d", f.Type, f.ID, typ, c.id)
	}
	return wire.DecodeResponse(f.Payload)
}

func refusedWith(err error) backend.Status {
	var r *backend.RefusedError
	if errors.As(err, &r) {
		return r.Code
	}
	return backend.StatusOK
}

// roleServer is a server with a signer, for the role tests.
func roleServer(t *testing.T) *Server {
	t.Helper()
	s := shareServer(t, &shareStore{m: map[string][]byte{}}, [32]byte{0xa}, [32]byte{1})
	s.State = constState(backend.SetupState{SetupHash: backend.Root{0xa}})
	s.Platform.Attester, s.Platform.Clock = fakeAttester{}, clock.System{}
	return s
}

// A certificate with the attest-only extended key usage may ask for
// health, keys and attestations, and gets FORBIDDEN for everything else,
// a signing request first. A certificate without a mark may sign.
func TestAttestOnlyRole(t *testing.T) {
	root := newTestCA(t, nil, nil, nil)
	s := roleServer(t)
	nonce := bytes.Repeat([]byte{5}, 32)
	attestReq, _ := wire.EncodeAttest(nonce)
	sign := append(bytes.Repeat([]byte{0xb0}, 48), make([]byte, 1+32+64)...)

	ac, err := dial(t, s, root.pem(), root.leaf(t, clientAuth, attestOnly))
	if err != nil {
		t.Fatal(err)
	}
	for _, typ := range []wire.MsgType{wire.TypeHealth, wire.TypePublicKeys} {
		if _, err := ac.call(typ, nil); err != nil {
			t.Fatalf("attest-only %v: %v", typ, err)
		}
	}
	for _, typ := range []wire.MsgType{wire.TypeAttest, wire.TypeIdentity} {
		if _, err := ac.call(typ, attestReq); err != nil {
			t.Fatalf("attest-only %v: %v", typ, err)
		}
	}
	forbidden := map[string]wire.MsgType{"SIGN": wire.TypeSign, "IMPORT_SHARE": wireadmin.TypeImportShare,
		"IMPORT_SHARE_SEALED": wireadmin.TypeImportSealed, "CONFIG_UPDATE": wireadmin.TypeConfigUpdate,
		"type 0x30": 0x30, "DKG_HELLO": 0x20, "DKG_OPERATOR": 0x25, "DKG_ORDER": 0x27, "unknown": 0x7f}
	for name, typ := range forbidden {
		_, err := ac.call(typ, sign)
		if refusedWith(err) != backend.StatusForbidden || !strings.Contains(err.Error(), "attest-only") {
			t.Errorf("attest-only %s: %v, want FORBIDDEN", name, err)
		}
	}

	// The same request with a certificate that has no role mark (signing)
	// reaches the signer, which refuses it for its own reasons.
	fc, err := dial(t, s, root.pem(), root.leaf(t, clientAuth, nil))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fc.call(wire.TypeSign, sign); err == nil || refusedWith(err) == backend.StatusForbidden {
		t.Fatalf("signing client SIGN: %v, want a refusal other than FORBIDDEN", err)
	}
}

// The role also comes from a CA: a plain client certificate under a CA
// marked attest-only is attest-only. A certificate with the mark and no
// clientAuth fails the handshake.
func TestAttestOnlyFromTheChain(t *testing.T) {
	root := newTestCA(t, nil, nil, nil)
	inter := newTestCA(t, root, clientAuth, attestOnly)
	s := roleServer(t)
	c, err := dial(t, s, root.pem(), inter.leaf(t, clientAuth, nil, inter))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.call(wire.TypeHealth, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := c.call(wire.TypeSign, make([]byte, 49)); refusedWith(err) != backend.StatusForbidden {
		t.Fatalf("leaf under an attest-only CA: SIGN %v, want FORBIDDEN", err)
	}

	bad, err := dial(t, s, root.pem(), root.leaf(t, nil, attestOnly))
	if err == nil {
		_, err = bad.call(wire.TypeHealth, nil)
	}
	if err == nil {
		t.Fatal("a certificate with the attest-only mark and no clientAuth got in")
	}
	t.Logf("attest-only mark without clientAuth: %v", err)
}

// RoleOf reads the leaf and the verified chains, nothing else.
func TestAttestOnlyState(t *testing.T) {
	root := newTestCA(t, nil, nil, nil)
	marked := root.leaf(t, clientAuth, attestOnly)
	plain := root.leaf(t, clientAuth, []asn1.ObjectIdentifier{{1, 2, 3, 4}})
	parse := func(c tls.Certificate) *x509.Certificate { x, _ := x509.ParseCertificate(c.Certificate[0]); return x }
	for name, tc := range map[string]struct {
		cs   tls.ConnectionState
		want bool
	}{
		"marked leaf":     {tls.ConnectionState{PeerCertificates: []*x509.Certificate{parse(marked)}, VerifiedChains: [][]*x509.Certificate{{parse(marked), root.cert}}}, true},
		"another oid":     {tls.ConnectionState{PeerCertificates: []*x509.Certificate{parse(plain)}}, false},
		"no certificate":  {tls.ConnectionState{}, false},
		"marked chain CA": {tls.ConnectionState{PeerCertificates: []*x509.Certificate{parse(plain)}, VerifiedChains: [][]*x509.Certificate{{parse(plain), newTestCA(t, root, clientAuth, attestOnly).cert}}}, true},
		"plain verified":  {tls.ConnectionState{PeerCertificates: []*x509.Certificate{parse(plain)}, VerifiedChains: [][]*x509.Certificate{{parse(plain), root.cert}}}, false},
	} {
		if got := attls.RoleOf(&tc.cs) == attls.RoleAttestOnly; got != tc.want {
			t.Errorf("%s: %v, want %v", name, got, tc.want)
		}
	}
}
