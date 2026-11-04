package servertls

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
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

var serial atomic.Int64

// issued is a certificate with its key.
type issued struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

// issue makes a certificate from tmpl, signed by parent, or self-signed
// when parent is nil.
func issue(t *testing.T, tmpl *x509.Certificate, parent *issued) *issued {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl.SerialNumber = big.NewInt(serial.Add(1))
	if tmpl.NotBefore.IsZero() {
		tmpl.NotBefore, tmpl.NotAfter = time.Now().Add(-time.Hour), time.Now().Add(time.Hour)
	}
	signer, signerCert := key, tmpl
	if parent != nil {
		signer, signerCert = parent.key, parent.cert
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signerCert, &key.PublicKey, signer)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)

	return &issued{c, key}
}

func newCA(t *testing.T, name string) *issued {
	return issue(t, &x509.Certificate{Subject: pkix.Name{CommonName: name}, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign}, nil)
}

func clientCert(t *testing.T, ca *issued, nb, na time.Time) *issued {
	return issue(t, &x509.Certificate{Subject: pkix.Name{CommonName: "validator client"}, NotBefore: nb, NotAfter: na,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}, ca)
}

func serverCert(t *testing.T, ca *issued, nb, na time.Time) *issued {
	return issue(t, &x509.Certificate{Subject: pkix.Name{CommonName: "gateway"}, NotBefore: nb, NotAfter: na,
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}, ca)
}

func certPEM(cs ...*issued) []byte {
	var b []byte
	for _, c := range cs {
		b = append(b, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.cert.Raw})...)
	}
	return b
}

func keyPEM(t *testing.T, c *issued) []byte {
	der, err := x509.MarshalPKCS8PrivateKey(c.key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

func write(t *testing.T, path string, b []byte) {
	t.Helper()
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// pki is a server CA, a server certificate, and a client CA with one
// client, written to dir.
type pki struct {
	dir               string
	serverCA, server  *issued
	clientCA, client  *issued
	certFile, keyFile string
	clientCAFile      string
	serverRoots       *x509.CertPool
	logBuf            *bytes.Buffer
	log               *slog.Logger
}

func newPKI(t *testing.T) *pki {
	t.Helper()
	p := &pki{dir: t.TempDir(), logBuf: &bytes.Buffer{}}
	p.log = slog.New(slog.NewTextHandler(p.logBuf, nil))
	p.serverCA = newCA(t, "server CA")
	p.server = serverCert(t, p.serverCA, time.Time{}, time.Time{})
	p.clientCA = newCA(t, "client CA")
	p.client = clientCert(t, p.clientCA, time.Time{}, time.Time{})
	p.certFile, p.keyFile, p.clientCAFile = filepath.Join(p.dir, "server.pem"), filepath.Join(p.dir, "server-key.pem"),
		filepath.Join(p.dir, "client-ca.pem")
	write(t, p.certFile, certPEM(p.server, p.serverCA))
	write(t, p.keyFile, keyPEM(t, p.server))
	write(t, p.clientCAFile, certPEM(p.clientCA))
	p.serverRoots = x509.NewCertPool()
	p.serverRoots.AddCert(p.serverCA.cert)

	return p
}

func (p *pki) settings() Settings {
	return Settings{CertFile: p.certFile, KeyFile: p.keyFile, ClientCAFile: p.clientCAFile, MinVersion: tls.VersionTLS13}
}

// serve starts an HTTPS server with s that answers OK, and returns its
// address.
func serve(t *testing.T, s *Server) string { return serveWith(t, s, true) }

// serveWith is serve with the client check of Config(verifyClients).
func serveWith(t *testing.T, s *Server, verifyClients bool) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "OK") }),
		TLSConfig: s.Config(verifyClients), ErrorLog: slog.NewLogLogger(slog.DiscardHandler, slog.LevelWarn)}
	go func() { _ = srv.ServeTLS(ln, "", "") }()
	t.Cleanup(func() { srv.Close() })

	return ln.Addr().String()
}

// get sends GET /upcheck with the client certificate chain of chain (none
// if empty), and returns the body or the error.
func (p *pki) get(t *testing.T, addr string, maxVersion uint16, chain ...*issued) (string, error) {
	t.Helper()
	cfg := &tls.Config{RootCAs: p.serverRoots, MaxVersion: maxVersion}
	if len(chain) > 0 {
		c := tls.Certificate{PrivateKey: chain[0].key}
		for _, x := range chain {
			c.Certificate = append(c.Certificate, x.cert.Raw)
		}
		cfg.Certificates = []tls.Certificate{c}
	}
	cl := &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}, Timeout: 5 * time.Second}
	defer cl.CloseIdleConnections()
	resp, err := cl.Get("https://" + addr + "/upcheck")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", errors.New(resp.Status)
	}

	return string(b), err
}

func mustServe(t *testing.T, p *pki, s Settings) string {
	t.Helper()
	srv, err := New(s, p.log)
	if err != nil {
		t.Fatal(err)
	}
	return serve(t, srv)
}

func fingerprint(c *issued) [32]byte { return sha256.Sum256(c.cert.Raw) }

// With a client CA: a client it issued gets service; no certificate, one
// from another CA, an expired one, one not for client authentication,
// and TLS below the minimum get none.
func TestClientCA(t *testing.T) {
	p := newPKI(t)
	addr := mustServe(t, p, p.settings())
	if body, err := p.get(t, addr, 0, p.client); err != nil || body != "OK" {
		t.Fatalf("client of the CA: %q %v", body, err)
	}
	other := newCA(t, "other CA")
	serverOnly := issue(t, &x509.Certificate{Subject: pkix.Name{CommonName: "server-auth only"},
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}, p.clientCA)
	inter := issue(t, &x509.Certificate{Subject: pkix.Name{CommonName: "client intermediate"}, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign}, p.clientCA)
	viaInter := clientCert(t, inter, time.Time{}, time.Time{})
	if body, err := p.get(t, addr, 0, viaInter, inter); err != nil || body != "OK" {
		t.Fatalf("client of an intermediate it sent: %q %v", body, err)
	}
	for name, chain := range map[string][]*issued{
		"no certificate":         nil,
		"another CA":             {clientCert(t, other, time.Time{}, time.Time{})},
		"expired":                {clientCert(t, p.clientCA, time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour))},
		"not yet valid":          {clientCert(t, p.clientCA, time.Now().Add(time.Hour), time.Now().Add(2*time.Hour))},
		"server auth only":       {serverOnly},
		"intermediate not sent":  {viaInter},
		"self-signed, same name": {issue(t, &x509.Certificate{Subject: p.client.cert.Subject, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}, nil)},
	} {
		if body, err := p.get(t, addr, 0, chain...); err == nil {
			t.Errorf("%s: served %q", name, body)
		}
	}
	if body, err := p.get(t, addr, tls.VersionTLS12, p.client); err == nil {
		t.Errorf("TLS 1.2 client with min_version 1.3: served %q", body)
	}
}

// Fingerprints alone: a listed certificate gets service whoever issued
// it, another does not, and a listed one that expired does not either.
func TestClientFingerprints(t *testing.T) {
	p := newPKI(t)
	selfSigned := clientCert(t, nil, time.Time{}, time.Time{})
	expired := clientCert(t, nil, time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour))
	s := p.settings()
	s.ClientCAFile = ""
	s.ClientFingerprints = [][32]byte{fingerprint(selfSigned), fingerprint(expired)}
	addr := mustServe(t, p, s)
	if body, err := p.get(t, addr, 0, selfSigned); err != nil || body != "OK" {
		t.Fatalf("listed: %q %v", body, err)
	}
	for name, c := range map[string]*issued{
		"not listed":                 clientCert(t, nil, time.Time{}, time.Time{}),
		"from a CA, but no CA named": p.client,
		"listed, expired":            expired,
	} {
		if body, err := p.get(t, addr, 0, c); err == nil {
			t.Errorf("%s: served %q", name, body)
		}
	}
	if body, err := p.get(t, addr, 0); err == nil {
		t.Errorf("no certificate: served %q", body)
	}

	// Both: either way in.
	s.ClientCAFile = p.clientCAFile
	addr = mustServe(t, p, s)
	for name, c := range map[string]*issued{"listed": selfSigned, "from the CA": p.client} {
		if body, err := p.get(t, addr, 0, c); err != nil || body != "OK" {
			t.Errorf("CA and fingerprints, %s: %q %v", name, body, err)
		}
	}
}

func TestParseFingerprint(t *testing.T) {
	want := sha256.Sum256([]byte("x"))
	// openssl x509 -fingerprint -sha256 prints upper case with colons.
	var parts []string
	for _, c := range want {
		parts = append(parts, fmt.Sprintf("%02X", c))
	}
	colons := strings.Join(parts, ":")
	for _, s := range []string{colons, strings.ToLower(strings.ReplaceAll(colons, ":", "")), " " + colons + "\n"} {
		if got, err := ParseFingerprint(s); err != nil || got != want {
			t.Errorf("%s: %x %v", s, got, err)
		}
	}
	for _, s := range []string{"", "ab", strings.Repeat("g", 64), strings.Repeat("ab", 33)} {
		if _, err := ParseFingerprint(s); err == nil {
			t.Errorf("%q accepted", s)
		}
	}
}

// Plain HTTP to the TLS port gets no service: Go's server answers 400.
func TestPlainHTTPToTLSPort(t *testing.T) {
	p := newPKI(t)
	addr := mustServe(t, p, p.settings())
	resp, err := http.Get("http://" + addr + "/upcheck")
	if err != nil {
		return
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusOK || string(b) == "OK" {
		t.Fatalf("plain HTTP served: %d %q", resp.StatusCode, b)
	}
}

// Without the client check (unsafe_open_tls) any client gets service,
// with or without a certificate, even when clients are named for another
// listener. With the check and no client named, none does.
func TestClientCheckOff(t *testing.T) {
	p := newPKI(t)
	srv, err := New(p.settings(), p.log)
	if err != nil {
		t.Fatal(err)
	}
	open := serveWith(t, srv, false)
	stranger := clientCert(t, newCA(t, "other CA"), time.Time{}, time.Time{})
	for name, chain := range map[string][]*issued{"no certificate": nil, "another CA": {stranger}, "the CA's client": {p.client}} {
		if body, err := p.get(t, open, 0, chain...); err != nil || body != "OK" {
			t.Errorf("open listener, %s: %q %v", name, body, err)
		}
	}
	// The same Server, checked, on a second listener.
	if body, err := p.get(t, serve(t, srv), 0, stranger); err == nil {
		t.Errorf("checked listener of the same server, another CA: served %q", body)
	}

	s := p.settings()
	s.ClientCAFile = ""
	none, err := New(s, p.log)
	if err != nil {
		t.Fatal(err)
	}
	addr := serve(t, none)
	for name, chain := range map[string][]*issued{"no certificate": nil, "the CA's client": {p.client}} {
		if body, err := p.get(t, addr, 0, chain...); err == nil {
			t.Errorf("checked, no client named, %s: served %q", name, body)
		}
	}
}

// TLS 1.2 is served when min_version is 1.2, with forward secret AEAD
// suites only.
func TestMinVersion12(t *testing.T) {
	p := newPKI(t)
	s := p.settings()
	s.MinVersion = tls.VersionTLS12
	addr := mustServe(t, p, s)
	if body, err := p.get(t, addr, tls.VersionTLS12, p.client); err != nil || body != "OK" {
		t.Fatalf("TLS 1.2: %q %v", body, err)
	}
	cfg := &tls.Config{RootCAs: p.serverRoots, MaxVersion: tls.VersionTLS12,
		CipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA},
		Certificates: []tls.Certificate{{Certificate: [][]byte{p.client.cert.Raw}, PrivateKey: p.client.key}}}
	if c, err := tls.Dial("tcp", addr, cfg); err == nil {
		c.Close()
		t.Fatal("TLS 1.2 with CBC suites only: handshake passed")
	}
}

// New refuses files that do not pass the checks and settings that do not
// say who gets in.
func TestNewRefuses(t *testing.T) {
	p := newPKI(t)
	expired := serverCert(t, p.serverCA, time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour))
	expiredFile, otherKeyFile, badCA, keyInCA := filepath.Join(p.dir, "expired.pem"), filepath.Join(p.dir, "other-key.pem"),
		filepath.Join(p.dir, "bad-ca.pem"), filepath.Join(p.dir, "key-ca.pem")
	write(t, expiredFile, certPEM(expired))
	write(t, otherKeyFile, keyPEM(t, p.client))
	write(t, badCA, []byte("not PEM"))
	write(t, keyInCA, append(certPEM(p.clientCA), keyPEM(t, p.client)...))
	for name, mod := range map[string]func(*Settings){
		"expired certificate":   func(s *Settings) { s.CertFile, s.KeyFile = expiredFile, filepath.Join(p.dir, "x") },
		"key of another cert":   func(s *Settings) { s.KeyFile = otherKeyFile },
		"missing cert file":     func(s *Settings) { s.CertFile = filepath.Join(p.dir, "missing") },
		"client CA not PEM":     func(s *Settings) { s.ClientCAFile = badCA },
		"client CA holds a key": func(s *Settings) { s.ClientCAFile = keyInCA },
		"TLS 1.1":               func(s *Settings) { s.MinVersion = tls.VersionTLS11 },
	} {
		s := p.settings()
		mod(&s)
		if _, err := New(s, p.log); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// The expired one with its own key, to be sure the refusal is the date.
	write(t, filepath.Join(p.dir, "expired-key.pem"), keyPEM(t, expired))
	s := p.settings()
	s.CertFile, s.KeyFile = expiredFile, filepath.Join(p.dir, "expired-key.pem")
	if _, err := New(s, p.log); err == nil || !strings.Contains(err.Error(), "not now") {
		t.Errorf("expired server certificate: %v", err)
	}
}

// A renewed server certificate and a new client CA bundle take effect at
// the next poll; files that fail a check are logged once and the ones in
// force stay.
func TestReload(t *testing.T) {
	p := newPKI(t)
	srv, err := New(p.settings(), p.log)
	if err != nil {
		t.Fatal(err)
	}
	addr := serve(t, srv)
	first := srv.Leaf().SerialNumber
	if srv.Poll() {
		t.Fatal("unchanged files reloaded")
	}

	// A broken key: refused, logged once over three polls, still served.
	write(t, p.keyFile, []byte("garbage"))
	for range 3 {
		if srv.Poll() {
			t.Fatal("a broken key was swapped in")
		}
	}
	if n := strings.Count(p.logBuf.String(), msgRefused); n != 1 {
		t.Fatalf("%d refusals logged, want 1:\n%s", n, p.logBuf)
	}
	if body, err := p.get(t, addr, 0, p.client); err != nil || body != "OK" {
		t.Fatalf("after a refused reload: %q %v", body, err)
	}

	// A renewed server certificate and a new client CA.
	renewed := serverCert(t, p.serverCA, time.Time{}, time.Time{})
	newClientCA := newCA(t, "client CA 2")
	newClient := clientCert(t, newClientCA, time.Time{}, time.Time{})
	write(t, p.certFile, certPEM(renewed, p.serverCA))
	write(t, p.keyFile, keyPEM(t, renewed))
	write(t, p.clientCAFile, certPEM(newClientCA))
	if !srv.Poll() {
		t.Fatalf("renewed files not reloaded:\n%s", p.logBuf)
	}
	if got := srv.Leaf().SerialNumber; got.Cmp(renewed.cert.SerialNumber) != 0 || got.Cmp(first) == 0 {
		t.Fatalf("serial %v after the reload, want %v", got, renewed.cert.SerialNumber)
	}
	if body, err := p.get(t, addr, 0, newClient); err != nil || body != "OK" {
		t.Fatalf("client of the new CA: %q %v", body, err)
	}
	if body, err := p.get(t, addr, 0, p.client); err == nil {
		t.Fatalf("client of the CA no longer in the bundle: served %q", body)
	}
	if n := strings.Count(p.logBuf.String(), msgReloaded); n != 1 {
		t.Fatalf("%d reloads logged, want 1", n)
	}
}

// The server certificate is logged as expiring when it ends within 30
// days: at start, after a reload, and again a day later, not at every
// poll. A certificate with longer left is not.
func TestExpiryWarning(t *testing.T) {
	p := newPKI(t) // the server certificate ends in an hour
	clock := time.Now()
	now := func() time.Time { return clock }
	srv, err := newServer(p.settings(), p.log, now)
	if err != nil {
		t.Fatal(err)
	}
	count := func() int { return strings.Count(p.logBuf.String(), msgExpiring) }
	if count() != 1 {
		t.Fatalf("%d expiry warnings at start, want 1:\n%s", count(), p.logBuf)
	}
	clock = clock.Add(time.Minute)
	srv.Poll()
	if count() != 1 {
		t.Fatalf("%d expiry warnings after a poll, want 1", count())
	}

	renew := func(validFor time.Duration) {
		t.Helper()
		c := serverCert(t, p.serverCA, clock.Add(-time.Hour), clock.Add(validFor))
		write(t, p.certFile, certPEM(c, p.serverCA))
		write(t, p.keyFile, keyPEM(t, c))
		if !srv.Poll() {
			t.Fatalf("renewed certificate not reloaded:\n%s", p.logBuf)
		}
	}
	renew(90 * 24 * time.Hour)
	if count() != 1 {
		t.Fatalf("%d expiry warnings after a 90-day certificate, want 1", count())
	}
	clock = clock.Add(time.Minute)
	renew(10 * 24 * time.Hour)
	if count() != 2 {
		t.Fatalf("%d expiry warnings after a 10-day certificate, want 2", count())
	}
	clock = clock.Add(time.Hour)
	srv.Poll()
	if count() != 2 {
		t.Fatalf("%d expiry warnings an hour later, want 2", count())
	}
	clock = clock.Add(24 * time.Hour)
	srv.Poll()
	if count() != 3 {
		t.Fatalf("%d expiry warnings a day later, want 3", count())
	}
	if !strings.Contains(p.logBuf.String(), "days_left=8") {
		t.Fatalf("no days_left=8 in\n%s", p.logBuf)
	}
}

// getResumable is get with a client session cache, so a later call can
// resume the session. It reports whether the connection resumed one.
func (p *pki) getResumable(t *testing.T, addr string, version uint16, cache tls.ClientSessionCache, client *issued) (bool, error) {
	t.Helper()
	cfg := &tls.Config{RootCAs: p.serverRoots, MinVersion: version, MaxVersion: version, ClientSessionCache: cache}
	if client != nil {
		cfg.Certificates = []tls.Certificate{{Certificate: [][]byte{client.cert.Raw}, PrivateKey: client.key}}
	}
	cl := &http.Client{Transport: &http.Transport{TLSClientConfig: cfg, DisableKeepAlives: true}, Timeout: 5 * time.Second}
	defer cl.CloseIdleConnections()
	resp, err := cl.Get("https://" + addr + "/upcheck")
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(b) != "OK" {
		return false, errors.New(resp.Status)
	}

	return resp.TLS.DidResume, nil
}

// A resumed session passes the client check in force at the resumption,
// not the one of its first handshake: after the client CA is replaced, a
// client of the old CA cannot resume its session, with or without a
// certificate of its own, on TLS 1.2 and 1.3.
func TestResumedSessionCheckedAfterReload(t *testing.T) {
	for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		t.Run(tls.VersionName(version), func(t *testing.T) {
			p := newPKI(t)
			s := p.settings()
			s.MinVersion = tls.VersionTLS12
			srv, err := New(s, p.log)
			if err != nil {
				t.Fatal(err)
			}
			addr := serve(t, srv)
			withCert, noCert := tls.NewLRUClientSessionCache(8), tls.NewLRUClientSessionCache(8)
			for _, cache := range []tls.ClientSessionCache{withCert, noCert} {
				if _, err := p.getResumable(t, addr, version, cache, p.client); err != nil {
					t.Fatalf("first connection: %v", err)
				}
			}
			// The session resumes while the CA is in force: the test below
			// does test resumption.
			if resumed, err := p.getResumable(t, addr, version, withCert, p.client); err != nil || !resumed {
				t.Fatalf("second connection before the reload: resumed %v, %v", resumed, err)
			}

			caB := newCA(t, "client CA B")
			write(t, p.clientCAFile, certPEM(caB))
			if !srv.Poll() {
				t.Fatalf("new client CA not reloaded:\n%s", p.logBuf)
			}
			if resumed, err := p.getResumable(t, addr, version, withCert, p.client); err == nil {
				t.Errorf("client of the removed CA with its session: served (resumed %v)", resumed)
			}
			if resumed, err := p.getResumable(t, addr, version, noCert, nil); err == nil {
				t.Errorf("session of the removed CA's client, no certificate: served (resumed %v)", resumed)
			}
			if _, err := p.getResumable(t, addr, version, tls.NewLRUClientSessionCache(8), clientCert(t, caB, time.Time{}, time.Time{})); err != nil {
				t.Errorf("client of the new CA: %v", err)
			}
		})
	}
}

// Run polls the files: a renewed server certificate is served without a
// call to Poll.
func TestRunReloads(t *testing.T) {
	p := newPKI(t)
	srv, err := New(p.settings(), p.log)
	if err != nil {
		t.Fatal(err)
	}
	addr := serve(t, srv)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.Run(ctx, 20*time.Millisecond)
	renewed := serverCert(t, p.serverCA, time.Time{}, time.Time{})
	write(t, p.certFile, certPEM(renewed, p.serverCA))
	write(t, p.keyFile, keyPEM(t, renewed))
	deadline := time.Now().Add(5 * time.Second)
	for {
		cfg := &tls.Config{RootCAs: p.serverRoots, Certificates: []tls.Certificate{{Certificate: [][]byte{p.client.cert.Raw}, PrivateKey: p.client.key}}}
		c, err := tls.Dial("tcp", addr, cfg)
		if err != nil {
			t.Fatal(err)
		}
		serial := c.ConnectionState().PeerCertificates[0].SerialNumber
		c.Close()
		if serial.Cmp(renewed.cert.SerialNumber) == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("still serving serial %v, want %v", serial, renewed.cert.SerialNumber)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
