// Package servertls is the TLS of the gateway's Web3Signer listener. It
// holds the server certificate and the client CA bundle, reads both again
// at every poll, and accepts a client by its certificate: one that chains
// to the client CA bundle, or one whose SHA-256 fingerprint is listed.
// Changed files take effect only if every file parses and the server
// certificate is valid at the gateway's clock; otherwise the files in
// force stay, and the refusal is logged once per content.
package servertls

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"
)

// The log messages, also counted by the tests.
const (
	msgReloaded = "server TLS files reloaded"
	msgRefused  = "server TLS files on disk refused, keeping the ones in force"
	msgExpiring = "server certificate expires in under 30 days"
)

// ExpiryWarning is how long before its end the server certificate in
// force is logged as expiring: at start, at a reload, and once a day.
const ExpiryWarning = 30 * 24 * time.Hour

// Settings are the files and the accepted clients. A listener that
// checks clients (Config(true)) accepts a client that ClientCAFile or
// ClientFingerprints names, and none when both are empty.
type Settings struct {
	// CertFile is the server certificate chain, leaf first; KeyFile its key.
	CertFile, KeyFile string
	// ClientCAFile, if set, is a PEM bundle: a client whose certificate
	// chains to one of them, for client authentication, is accepted.
	ClientCAFile string
	// ClientFingerprints are the SHA-256 digests of client certificates
	// (DER) that are accepted whatever their issuer.
	ClientFingerprints [][32]byte
	// MinVersion is tls.VersionTLS12 or tls.VersionTLS13.
	MinVersion uint16
}

// ParseFingerprint reads a SHA-256 fingerprint: 64 hex digits, in any
// case, with or without colons between the bytes (openssl x509
// -fingerprint -sha256 prints them with colons).
func ParseFingerprint(s string) ([32]byte, error) {
	var fp [32]byte
	b, err := hex.DecodeString(strings.ReplaceAll(strings.TrimSpace(s), ":", ""))
	if err != nil || len(b) != len(fp) {
		return fp, fmt.Errorf("fingerprint %q is not a SHA-256 digest (64 hex digits)", s)
	}
	copy(fp[:], b)

	return fp, nil
}

// files is one checked read of the files.
type files struct {
	cert   *tls.Certificate
	pool   *x509.CertPool
	digest [32]byte
}

// Server holds the files in force.
type Server struct {
	s   Settings
	log *slog.Logger
	now func() time.Time

	mu      sync.Mutex
	cur     *files
	refused [32]byte
	// expiryLogged is when the expiry of cur was last logged.
	expiryLogged time.Time
}

// New reads the files. It fails if they do not pass the checks of a
// reload.
func New(s Settings, log *slog.Logger) (*Server, error) {
	return newServer(s, log, time.Now)
}

func newServer(s Settings, log *slog.Logger, now func() time.Time) (*Server, error) {
	if s.MinVersion != tls.VersionTLS12 && s.MinVersion != tls.VersionTLS13 {
		return nil, errors.New("servertls: MinVersion must be TLS 1.2 or 1.3")
	}
	srv := &Server{s: s, log: log, now: now}
	raw, err := srv.read()
	if err != nil {
		return nil, err
	}
	f, err := srv.check(raw, now())
	if err != nil {
		return nil, err
	}
	srv.cur = f
	srv.logExpiry(now())

	return srv, nil
}

// logExpiry warns when the certificate in force ends within
// ExpiryWarning, at most once a day. The caller holds mu, or no other
// goroutine has srv yet.
func (srv *Server) logExpiry(now time.Time) {
	leaf := srv.cur.cert.Leaf
	left := leaf.NotAfter.Sub(now)
	if left >= ExpiryWarning || (!srv.expiryLogged.IsZero() && now.Sub(srv.expiryLogged) < 24*time.Hour) {
		return
	}
	srv.expiryLogged = now
	srv.log.Warn(msgExpiring, "cert", srv.s.CertFile, "serial", leaf.SerialNumber.String(),
		"not_after", leaf.NotAfter.UTC().Format(time.RFC3339), "days_left", int(left.Hours()/24))
}

// read returns the content of the certificate, the key and the client CA
// bundle (nil when not set).
func (srv *Server) read() ([3][]byte, error) {
	var out [3][]byte
	for i, p := range []string{srv.s.CertFile, srv.s.KeyFile, srv.s.ClientCAFile} {
		if p == "" {
			continue
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return out, fmt.Errorf("tls: %w", err)
		}
		out[i] = b
	}

	return out, nil
}

func digest(raw [3][]byte) [32]byte {
	h := sha256.New()
	for _, b := range raw {
		h.Write(binary.LittleEndian.AppendUint64(nil, uint64(len(b))))
		h.Write(b)
	}

	return [32]byte(h.Sum(nil))
}

// check parses the files: the key belongs to the certificate, the
// certificate is valid at now, and the CA bundle holds certificates only.
func (srv *Server) check(raw [3][]byte, now time.Time) (*files, error) {
	cert, err := tls.X509KeyPair(raw[0], raw[1])
	if err != nil {
		return nil, fmt.Errorf("tls.cert %s and tls.key %s: %w", srv.s.CertFile, srv.s.KeyFile, err)
	}
	if leaf := cert.Leaf; now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
		return nil, fmt.Errorf("tls.cert %s: valid from %s to %s, not now", srv.s.CertFile,
			leaf.NotBefore.UTC().Format(time.RFC3339), leaf.NotAfter.UTC().Format(time.RFC3339))
	}
	f := &files{cert: &cert, digest: digest(raw)}
	if srv.s.ClientCAFile != "" {
		if f.pool, err = parseBundle(raw[2]); err != nil {
			return nil, fmt.Errorf("tls.client_ca %s: %w", srv.s.ClientCAFile, err)
		}
	}

	return f, nil
}

// parseBundle reads a PEM file of certificates only, at least one.
func parseBundle(b []byte) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	n := 0
	for {
		var blk *pem.Block
		blk, b = pem.Decode(b)
		if blk == nil {
			break
		}
		if blk.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("a %s block, want CERTIFICATE only", blk.Type)
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return nil, err
		}
		pool.AddCert(c)
		n++
	}
	if n == 0 {
		return nil, errors.New("no certificate")
	}

	return pool, nil
}

func (srv *Server) current() *files {
	srv.mu.Lock()
	defer srv.mu.Unlock()

	return srv.cur
}

// Leaf is the server certificate in force.
func (srv *Server) Leaf() *x509.Certificate { return srv.current().cert.Leaf }

// Poll reads the files once and swaps in changed files that pass the
// checks. It reports whether it did.
func (srv *Server) Poll() bool {
	now := srv.now()
	raw, err := srv.read()
	var d [32]byte
	if err != nil {
		d = sha256.Sum256([]byte(err.Error()))
	} else {
		d = digest(raw)
	}
	srv.mu.Lock()
	defer srv.mu.Unlock()
	// Runs last, under mu, on the certificate in force after this poll.
	defer func() { srv.logExpiry(now) }()
	if err == nil && d == srv.cur.digest {
		srv.refused = [32]byte{}
		return false
	}
	var f *files
	if err == nil {
		f, err = srv.check(raw, now)
	}
	if err != nil {
		if d != srv.refused {
			srv.refused = d
			srv.log.Error(msgRefused, "err", err.Error())
		}
		return false
	}
	srv.cur, srv.refused, srv.expiryLogged = f, [32]byte{}, time.Time{}
	srv.log.Info(msgReloaded, "cert", srv.s.CertFile, "serial", f.cert.Leaf.SerialNumber.String(),
		"not_after", f.cert.Leaf.NotAfter.UTC().Format(time.RFC3339))

	return true
}

// Run polls every interval until ctx ends.
func (srv *Server) Run(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			srv.Poll()
		}
	}
}

// Config is the tls.Config of a listener. Each handshake uses the files
// in force at that moment. With verifyClients, a client that is not
// accepted fails the handshake and never reaches the HTTP handlers;
// without, no client certificate is asked for.
func (srv *Server) Config(verifyClients bool) *tls.Config {
	c := &tls.Config{
		MinVersion: srv.s.MinVersion,
		// TLS 1.2: forward secret AEAD suites only. TLS 1.3 has its own.
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		},
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			return srv.current().cert, nil
		},
		ClientAuth: tls.NoClientCert,
	}
	if verifyClients {
		// VerifyClient does the whole check, so a listed fingerprint can
		// accept a certificate that no CA of the bundle issued. It runs in
		// VerifyConnection, which Go calls on every handshake, a resumed
		// one too (VerifyPeerCertificate is skipped on resumption), so a
		// session from before a reload passes the clients in force now.
		c.ClientAuth = tls.RequireAnyClientCert
		c.VerifyConnection = func(cs tls.ConnectionState) error {
			raw := make([][]byte, 0, len(cs.PeerCertificates))
			for _, pc := range cs.PeerCertificates {
				raw = append(raw, pc.Raw)
			}

			return srv.VerifyClient(raw)
		}
	}

	return c
}

// VerifyClient accepts a client's certificate chain, leaf first, if the
// leaf is valid now and either its fingerprint is listed or it chains to
// the client CA bundle for client authentication.
func (srv *Server) VerifyClient(rawCerts [][]byte) error {
	if len(rawCerts) == 0 {
		return errors.New("no client certificate")
	}
	leaf, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return fmt.Errorf("client certificate: %w", err)
	}
	now := srv.now()
	if now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
		return fmt.Errorf("client certificate %q is valid from %s to %s, not now", leaf.Subject,
			leaf.NotBefore.UTC().Format(time.RFC3339), leaf.NotAfter.UTC().Format(time.RFC3339))
	}
	fp := sha256.Sum256(rawCerts[0])
	for _, want := range srv.s.ClientFingerprints {
		if subtle.ConstantTimeCompare(fp[:], want[:]) == 1 {
			return nil
		}
	}
	pool := srv.current().pool
	if pool == nil {
		return fmt.Errorf("client certificate %q (sha256 %x) is not in tls.client_fingerprints", leaf.Subject, fp)
	}
	inter := x509.NewCertPool()
	for _, der := range rawCerts[1:] {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return fmt.Errorf("client certificate chain: %w", err)
		}
		inter.AddCert(c)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, Intermediates: inter, CurrentTime: now,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return fmt.Errorf("client certificate %q (sha256 %x) is not in tls.client_fingerprints, and tls.client_ca refuses it: %w",
			leaf.Subject, fp, err)
	}

	return nil
}
