package server

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/governance/setupwire"
	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/wire"
	wireadmin "github.com/lidofinance/tee-signer/signer-protocol/wire/admin"
	"github.com/lidofinance/tee-signer/slashing-log"
	"github.com/lidofinance/tee-signer/tee-signer/attls"
)

// A revocation that comes while a connection is open closes it at its
// next frame, HEALTH too.
func TestRevokedCertificateLosesItsOpenConnection(t *testing.T) {
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
	s.Revoked.Set([][32]byte{sha256.Sum256(cert.Certificate[0])})
	if _, err := c.call(wire.TypeHealth, nil); refusedWith(err) != backend.StatusForbidden || !strings.Contains(err.Error(), "revoked") {
		t.Fatalf("HEALTH after the revocation: %v, want FORBIDDEN for the revocation", err)
	}
	if _, err := c.call(wire.TypeHealth, nil); err == nil {
		t.Fatal("the connection stays open after its certificate was revoked")
	}
}

// rv-nsd.3: a connection whose handshake had no trusted time keeps the
// chains the handshake checked, CA included: a revoked CA closes it at
// the next frame, before the clock has a reading.
func TestUndatedConnectionChecksItsCA(t *testing.T) {
	root := newTestCA(t, nil, nil, nil)
	s := roleServer(t)
	s.Revoked = &attls.Revoked{}
	var err error
	if s.UndatedRoots, err = attls.UndatedRoots(root.pem()); err != nil {
		t.Fatal(err)
	}
	clk := &movingClock{}
	clk.fail(errors.New("test clock: no quorum"))
	s.Platform.Clock = clk
	c := dialClock(t, s, root.pem(), root.leaf(t, clientAuth, nil), clk)
	if _, err := c.call(wire.TypeHealth, nil); err != nil {
		t.Fatalf("HEALTH without trusted time: %v", err)
	}
	s.Revoked.Set([][32]byte{sha256.Sum256(root.cert.Raw)})
	if _, err := c.call(wire.TypeHealth, nil); refusedWith(err) != backend.StatusForbidden || !strings.Contains(err.Error(), "revoked") {
		t.Fatalf("HEALTH after its CA was revoked: %v, want FORBIDDEN for the revocation", err)
	}
}

// The set of a view is the open values in force, version 0 the setup's own
// list, plus the pending update's; an unreadable body makes it incomplete.
func TestRevokedOfView(t *testing.T) {
	setupOpen := &setupwire.Open{RevokedClientCerts: [][32]byte{{1}}}
	v1 := &setupwire.Open{} // drops {1}
	v2 := &setupwire.Open{RevokedClientCerts: [][32]byte{{2}}}
	ref2 := updateRef{2, [32]byte{0xb2}}
	pend := &markstore.Pending{Version: 2, Hash: ref2.hash, EffectiveAt: 99}
	withPending := markstore.ConfigState{Open: markstore.GroupState{Version: 1, Pending: pend}}
	for _, c := range []struct {
		name     string
		v        view
		want     [][32]byte
		complete bool
	}{
		{"setup's list", view{open: setupOpen, newest: setupOpen}, [][32]byte{{1}}, true},
		{"a drop in force", view{open: v1, newest: v1}, nil, true},
		{"pending readable", view{state: withPending, open: v1, newest: v2, newestRef: ref2}, [][32]byte{{2}}, true},
		{"pending unreadable", view{state: withPending, open: v1, newest: v1, newestRef: updateRef{1, [32]byte{0xb1}}}, nil, false},
		{"open in force unreadable", view{}, nil, false},
	} {
		got, complete := revokedOf(&c.v)
		if !slices.Equal(got, c.want) || complete != c.complete {
			t.Errorf("%s: %x complete %v, want %x complete %v", c.name, got, complete, c.want, c.complete)
		}
	}
}

// ---- the config updates drive the set ----

// longCA is a root and a leaf valid from 1980 to 2200, so that the fake
// clock of the config tests and the system clock both hold them.
func longCA(t *testing.T) (rootPEM []byte, leaf tls.Certificate, leafHash [32]byte) {
	t.Helper()
	nb, na := time.Date(1980, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2200, 1, 1, 0, 0, 0, 0, time.UTC)
	rk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rt := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "revocation test CA"}, NotBefore: nb, NotAfter: na,
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	rder, err := x509.CreateCertificate(rand.Reader, rt, rt, &rk.PublicKey, rk)
	if err != nil {
		t.Fatal(err)
	}
	rc, _ := x509.ParseCertificate(rder)
	lk, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	lt := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "revocation test client"}, NotBefore: nb, NotAfter: na,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: clientAuth}
	lder, err := x509.CreateCertificate(rand.Reader, lt, rc, &lk.PublicKey, rk)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rder}), tls.Certificate{Certificate: [][]byte{lder}, PrivateKey: lk},
		sha256.Sum256(lder)
}

// dialRevoked connects to s over the runner's TLS configuration with the
// revoked set r (attls.WithRevoked) and sends HEALTH. A refused handshake
// is an error.
func dialRevoked(t *testing.T, s *Server, rootPEM []byte, cert tls.Certificate, r *attls.Revoked) (*conn, error) {
	t.Helper()
	cfg, _, err := attls.ServerConfig(rootPEM, nil, attls.WithRevoked(r))
	if err != nil {
		t.Fatal(err)
	}
	s.ClientCAs = cfg.ClientCAs
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
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	cn := &conn{t: t, c: c}
	// TLS 1.3: a refused client certificate shows at the first read.
	if _, err := cn.call(wire.TypeHealth, nil); err != nil {
		return nil, err
	}
	return cn, nil
}

// useRevoked gives the env's runner a revoked set, as main does.
func useRevoked(e *env) *attls.Revoked {
	r := &attls.Revoked{}
	e.upd.UseRevoked(r)
	e.srv.Revoked = r
	return r
}

// openWith is an open update of version v on prev whose
// revoked_client_certs is list, sorted.
func openWith(e *env, v uint64, prev [32]byte, at uint64, list ...[32]byte) *setupwire.UpdateBody {
	b := e.body(open, v, prev, at)
	b.Open.RevokedClientCerts = slices.Clone(list)
	slices.SortFunc(b.Open.RevokedClientCerts, func(a, b [32]byte) int { return bytes.Compare(a[:], b[:]) })
	return b
}

// withBase is the setup's revoked_client_certs plus add: an update that
// adds and drops nothing.
func withBase(e *env, add ...[32]byte) [][32]byte {
	return append(slices.Clone(e.setup.Open.RevokedClientCerts), add...)
}

// every is a signature by each approver of the setup's set: a drop needs
// them all.
var every = []by{{0, 1}, {1, 2}, {2, 3}}

// rv-nsd.2: an open update that adds the leaf's hash closes its open
// connection at the next frame, and a new handshake with it fails.
func TestConfigUpdateRevokesClient(t *testing.T) {
	e := newEnv(t, u64(0))
	r := useRevoked(e)
	rootPEM, leaf, h := longCA(t)
	c, err := dialRevoked(t, e.srv, rootPEM, leaf, r)
	if err != nil {
		t.Fatalf("before the revocation: %v", err)
	}
	e.mustSend(signed(t, openWith(e, 1, e.groupHash(open), e.now(), withBase(e, h)...), first2, nil), wireadmin.ConfigAccepted)
	if _, err := c.call(wire.TypeHealth, nil); refusedWith(err) != backend.StatusForbidden || !strings.Contains(err.Error(), "revoked") {
		t.Fatalf("open connection after the update: %v, want FORBIDDEN for the revocation", err)
	}
	if _, err := dialRevoked(t, e.srv, rootPEM, leaf, r); err == nil {
		t.Fatal("a new handshake with the revoked leaf passed")
	}
}

// rv-nsd.4: a drop of an entry of the setup's own list takes effect once
// the update is in force; until then the entry holds.
func TestRevocationDropOfSetupEntry(t *testing.T) {
	h := [32]byte{0x42}
	e := newEnvWith(t, u64(0), func(s *setupwire.Setup) { s.Open.RevokedClientCerts = [][32]byte{h} })
	r := useRevoked(e)
	if r.Len() != 1 || r.Incomplete() {
		t.Fatalf("setup's list: %d entries, incomplete %v", r.Len(), r.Incomplete())
	}
	t0 := e.now()
	e.mustSend(signed(t, openWith(e, 1, e.groupHash(open), t0+600), every, nil), wireadmin.ConfigAccepted)
	if r.Len() != 1 {
		t.Fatal("the drop took effect while pending")
	}
	e.clock.add(601)
	e.upd.reconcile()
	if r.Len() != 0 || r.Incomplete() {
		t.Fatalf("after the drop came into force: %d entries, incomplete %v", r.Len(), r.Incomplete())
	}
}

// rv-nsd.1: a revocation in a pending update holds from its arrival and
// stays when the update comes into force.
func TestPendingRevocationComesIntoForce(t *testing.T) {
	e := newEnv(t, u64(0))
	r := useRevoked(e)
	h := [32]byte{0x51}
	n := len(e.setup.Open.RevokedClientCerts) + 1
	t0 := e.now()
	e.mustSend(signed(t, openWith(e, 1, e.groupHash(open), t0+600, withBase(e, h)...), first2, nil), wireadmin.ConfigAccepted)
	if r.Len() != n {
		t.Fatal("a pending revocation does not hold")
	}
	e.clock.add(601)
	e.upd.reconcile()
	if r.Len() != n || r.Incomplete() {
		t.Fatalf("in force: %d entries, incomplete %v", r.Len(), r.Incomplete())
	}
}

// rv-nsd.1: with the open body in force, or the pending one, unreadable
// at start the set is incomplete: TLS clients get HEALTH and CONFIG_UPDATE
// only. Sending the update again restores the body and its revocation.
func TestRevocationBodyUnreadableAtStart(t *testing.T) {
	for _, pendingAtStart := range []bool{false, true} {
		e := newEnv(t, u64(0))
		h := [32]byte{0x61}
		at := e.now()
		if pendingAtStart {
			at += 600
		}
		raw := signed(t, openWith(e, 1, e.groupHash(open), at, withBase(e, h)...), first2, nil)
		// What is readable while the body is gone: nothing with the body
		// in force gone, the setup's list with the pending body gone.
		base, n := 0, len(e.setup.Open.RevokedClientCerts)+1
		if pendingAtStart {
			base = n - 1
		}
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
		if !r.Incomplete() || r.Len() != base {
			t.Fatalf("pending %v: body unreadable: incomplete %v, %d entries", pendingAtStart, r.Incomplete(), r.Len())
		}
		cl := &client{role: attls.RoleSigning, notAfter: time.Unix(1<<40, 0), chains: [][]*x509.Certificate{{{Raw: []byte("leaf")}}}}
		if err := e.srv.stillValid(cl, wire.TypePublicKeys); refusedWith(err) != backend.StatusForbidden || !strings.Contains(err.Error(), "unknown") {
			t.Fatalf("pending %v: PUBLIC_KEYS while the set is incomplete: %v", pendingAtStart, err)
		}
		for _, typ := range []wire.MsgType{wire.TypeHealth, wireadmin.TypeConfigUpdate} {
			if err := e.srv.stillValid(cl, typ); err != nil {
				t.Fatalf("pending %v: %v while the set is incomplete: %v", pendingAtStart, typ, err)
			}
		}
		e.mustSend(raw, wireadmin.ConfigKnown)
		if r.Incomplete() || r.Len() != n {
			t.Fatalf("pending %v: body back: incomplete %v, %d entries", pendingAtStart, r.Incomplete(), r.Len())
		}
		if err := e.srv.stillValid(cl, wire.TypePublicKeys); err != nil {
			t.Fatalf("pending %v: PUBLIC_KEYS with the set complete: %v", pendingAtStart, err)
		}
	}
}

// rv-nsd.1: a record write whose reply is lost may have landed. The
// runner follows the log's state, and the revocation holds.
func TestRevocationAfterLostRecordReply(t *testing.T) {
	e := newEnv(t, u64(0))
	r := useRevoked(e)
	h := [32]byte{0x7a}
	e.log.loseSet = true
	if _, _, err := e.send(signed(t, openWith(e, 1, e.groupHash(open), e.now(), withBase(e, h)...), first2, nil)); refusedWith(err) != backend.StatusStorage {
		t.Fatalf("lost reply: %v, want STORAGE", err)
	}
	if r.Len() != len(e.setup.Open.RevokedClientCerts)+1 || r.Incomplete() {
		t.Fatalf("after the lost reply: %d entries, incomplete %v", r.Len(), r.Incomplete())
	}
}
