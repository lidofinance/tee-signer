package attls

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"testing"
	"time"
)

// The handshake refuses a client whose verified chain holds a revoked
// leaf, intermediate or CA certificate, and takes the set in force at each
// handshake.
func TestRevokedClientCertificates(t *testing.T) {
	root := newRoot(t, "root", now0.Add(-day(365)), now0.Add(day(3650)))
	inter := root.sub(t, "intermediate", now0.Add(-day(1)), now0.Add(day(90)))
	leaf := inter.client(t, "client", now0.Add(-time.Hour), now0.Add(day(1)))
	other := inter.client(t, "other client", now0.Add(-time.Hour), now0.Add(day(1)))
	leafCert, err := x509.ParseCertificate(leaf.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	hash := func(c *x509.Certificate) [32]byte { return sha256.Sum256(c.Raw) }

	clk := &testClock{t: now0}
	revoked := &Revoked{}
	cfg, _, err := ServerConfig(certPEM(root.cert), clk.Now, WithRevoked(revoked))
	if err != nil {
		t.Fatal(err)
	}
	addr, hs := start(t, cfg)
	expect := func(name string, c tls.Certificate, ok bool) {
		t.Helper()
		_, err := try(t, addr, &tls.Config{Certificates: []tls.Certificate{c}})
		srv := handshakeResult(t, hs)
		if ok && (err != nil || srv != nil) {
			t.Fatalf("%s: refused: client %v, server %v", name, err, srv)
		}
		if !ok {
			if err == nil {
				t.Fatalf("%s: accepted", name)
			}
			wantContains(t, name, srv, "is revoked")
		}
	}

	expect("nothing revoked", leaf, true)
	revoked.Set([][32]byte{{0x01}})
	expect("another certificate revoked", leaf, true)

	// The set changes while the server runs: the next handshake takes it.
	revoked.Set([][32]byte{{0x01}}, [][32]byte{hash(leafCert)})
	expect("revoked leaf", leaf, false)
	expect("another leaf of the same intermediate", other, true)

	revoked.Set([][32]byte{hash(inter.cert)})
	expect("revoked intermediate", leaf, false)
	expect("another leaf of the revoked intermediate", other, false)

	revoked.Set([][32]byte{hash(root.cert)})
	expect("revoked CA", leaf, false)

	revoked.Set(nil)
	expect("revocations gone", leaf, true)
}

// Without trusted time at ClientHello the handshake checks the chain
// without its dates, and refuses a revoked certificate there too.
func TestRevokedWithoutTrustedTime(t *testing.T) {
	root := newRoot(t, "root", now0.Add(-day(365)), now0.Add(day(3650)))
	inter := root.sub(t, "intermediate", now0.Add(-day(1)), now0.Add(day(90)))
	leaf := inter.client(t, "client", now0.Add(-time.Hour), now0.Add(day(1)))
	clk := &testClock{t: now0}
	clk.fail(errors.New("test clock: no quorum"))
	revoked := &Revoked{}
	revoked.Set([][32]byte{sha256.Sum256(inter.cert.Raw)})
	cfg, _, err := ServerConfig(certPEM(root.cert), clk.Now, WithRevoked(revoked))
	if err != nil {
		t.Fatal(err)
	}
	addr, hs := start(t, cfg)
	if _, err := try(t, addr, &tls.Config{Certificates: []tls.Certificate{leaf}}); err == nil {
		t.Fatal("a revoked intermediate passed the handshake without trusted time")
	}
	wantContains(t, "handshake without trusted time", handshakeResult(t, hs), "is revoked")
}

func TestRevokedNilAndZero(t *testing.T) {
	root := newRoot(t, "root", now0.Add(-day(365)), now0.Add(day(3650)))
	chains := [][]*x509.Certificate{{root.cert}}
	var none *Revoked
	if err := none.Check(chains); err != nil || none.Len() != 0 {
		t.Fatalf("nil Revoked: %v, len %d", err, none.Len())
	}
	if err := (&Revoked{}).Check(chains); err != nil {
		t.Fatalf("zero Revoked: %v", err)
	}
	r := &Revoked{}
	r.Set([][32]byte{{1}, {2}}, [][32]byte{{2}, {3}})
	if r.Len() != 3 {
		t.Fatalf("union of two lists: %d entries, want 3", r.Len())
	}
	// Incomplete: never smaller, and Incomplete until a complete Update.
	r.Update([][32]byte{{4}}, false)
	if r.Len() != 4 || !r.Incomplete() {
		t.Fatalf("incomplete update: %d entries, incomplete %v", r.Len(), r.Incomplete())
	}
	r.Update([][32]byte{{4}}, true)
	if r.Len() != 1 || r.Incomplete() {
		t.Fatalf("complete update: %d entries, incomplete %v", r.Len(), r.Incomplete())
	}
}
