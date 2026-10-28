// Package attls is the runner's mutual TLS: TLS 1.3, a self-signed server
// certificate with a key made at start (the attested identity names its hash,
// so clients need no CA), and a client certificate chained to the pinned CA.
//
// The same configuration serves every network listener: tcp on GCP and
// Azure, vsock inside a Nitro enclave. The network in between is not
// trusted. On AWS the parent instance forwards bytes into the enclave over
// vsock and could send its own requests, so the vsock listener needs the
// client certificate as much as a TCP listener does.
package attls

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"strings"
	"time"

	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/buildflavor"
	"github.com/lidofinance/tee-signer/signer-protocol/transport"
)

// ServerConfig returns a TLS 1.3 server config that requires a client
// certificate issued by one of the CAs in caPEM, and the sha256 of the
// server certificate's SubjectPublicKeyInfo.
//
// caPEM holds CA certificates only. A private key in it is refused: the
// file goes into a measured image that leaves the build machine.
//
// now is the runner's trusted clock (the platform's Clock). The validity
// dates of the client certificate and of its chain are checked against it,
// never against the system clock, which on Nitro is set by the host.
// Short-lived client certificates rely on this: the CA is pinned in the
// image, the certificates are not.
//
// If now fails at ClientHello, for example because an anchored clock has
// no recent reading, the handshake checks the chain without its dates
// (signatures, key usages, path lengths) and the connection gets no
// verified chain: RoleOf gives RoleNone, and the server answers HEALTH
// only until a trusted reading checks the chain with its dates (VerifyAt).
// If now fails later in the handshake, the handshake fails.
//
// Session tickets are off. Every connection does the full handshake and
// so the full certificate check.
func ServerConfig(caPEM []byte, now func() (time.Time, error), opts ...Option) (*tls.Config, []byte, error) {
	var o options
	for _, f := range opts {
		f(&o)
	}
	pool, cas, err := parseCAs(caPEM)
	if err != nil {
		return nil, nil, err
	}
	undatedRoots := x509.NewCertPool()
	for _, c := range cas {
		undatedRoots.AddCert(undated(c))
	}
	if now == nil {
		now = func() (time.Time, error) { return time.Now(), nil }
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, nil, err
	}
	// Clients do not check these dates (they pin the key through the
	// attestation), so the system clock may set them.
	t0 := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: buildflavor.CertName}, // names a testnet build
		NotBefore:             t0.Add(-time.Hour),
		NotAfter:              t0.Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	if o.chain != nil {
		v, err := asn1.Marshal(o.chain[:])
		if err != nil {
			return nil, nil, err
		}
		tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, pkix.Extension{Id: backend.RunnerChainOID, Value: v})
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}
	h := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	cfg := &tls.Config{
		MinVersion:             tls.VersionTLS13,
		Certificates:           []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}},
		ClientAuth:             tls.RequireAndVerifyClientCert,
		ClientCAs:              pool,
		SessionTicketsDisabled: true,
		// crypto/tls verifies the client chain at cfg.Time(). On a clock
		// error it gets 1970-01-01T00:00:01Z, before every certificate's
		// NotBefore. Not the zero time: crypto/x509 reads a zero
		// CurrentTime as "use the system clock" (ATTEST-ROLES-03).
		Time: func() time.Time {
			t, err := now()
			if err != nil {
				return noTrustedTime
			}
			return t
		},
		// After the chain check, one more trusted reading: the handshake
		// fails if the clock failed in between, or if a certificate of a
		// verified chain is outside its dates at that reading.
		VerifyConnection: func(cs tls.ConnectionState) error {
			t, err := now()
			if err != nil {
				return fmt.Errorf("attls: no trusted time to check the client certificate: %w", err)
			}
			return CheckDates(&cs, t)
		},
	}
	// Without trusted time at ClientHello: the chain check without dates,
	// and no verified chain in the connection state.
	noTime := cfg.Clone()
	noTime.ClientAuth = tls.RequireAnyClientCert
	noTime.VerifyConnection = func(cs tls.ConnectionState) error {
		if err := verifyUndated(undatedRoots, cs.PeerCertificates); err != nil {
			return fmt.Errorf("attls: no trusted time, and the client certificate chain fails even without its dates: %w", err)
		}
		return nil
	}
	cfg.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) {
		if _, err := now(); err != nil {
			return noTime, nil
		}
		return nil, nil // keep this config
	}
	return cfg, h[:], nil
}

// clientAuth is the key usage crypto/tls asks of a client chain.
var clientAuth = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}

// undated is a copy of c that is valid at any time. Its signed bytes are
// c's, so signatures still check against it; only the parsed dates
// differ. verifyUndated uses it, never a check with trusted time.
func undated(c *x509.Certificate) *x509.Certificate {
	d := *c
	d.NotBefore, d.NotAfter = time.Unix(0, 0), time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC)
	return &d
}

// verifyUndated is the chain check of crypto/tls without the dates: certs
// (leaf first) must chain to a CA of roots, an undated copy of the CA
// file, with clientAuth allowed at every step. It gives x509 a fixed
// nonzero time, never the system clock.
func verifyUndated(roots *x509.CertPool, certs []*x509.Certificate) error {
	if len(certs) == 0 {
		return errors.New("attls: no client certificate")
	}
	opts := x509.VerifyOptions{Roots: roots, Intermediates: x509.NewCertPool(), CurrentTime: noTrustedTime, KeyUsages: clientAuth}
	for _, c := range certs[1:] {
		opts.Intermediates.AddCert(undated(c))
	}
	_, err := undated(certs[0]).Verify(opts)
	return err
}

// VerifyAt checks the client certificates of a connection whose handshake
// had no trusted time (ServerConfig) at the trusted reading t: the chain
// check crypto/tls makes in a handshake with trusted time, against roots
// (the config's ClientCAs), then CheckDates. It returns the verified
// chains, for RoleOf and NotAfter. A zero t is refused: x509 would take
// the system clock for it.
func VerifyAt(roots *x509.CertPool, peer []*x509.Certificate, t time.Time) ([][]*x509.Certificate, error) {
	switch {
	case roots == nil:
		return nil, errors.New("attls: no client CA to check the certificate against")
	case t.IsZero():
		return nil, errors.New("attls: no trusted time to check the certificate at")
	case len(peer) == 0:
		return nil, errors.New("attls: no client certificate")
	}
	opts := x509.VerifyOptions{Roots: roots, Intermediates: x509.NewCertPool(), CurrentTime: t, KeyUsages: clientAuth}
	for _, c := range peer[1:] {
		opts.Intermediates.AddCert(c)
	}
	chains, err := peer[0].Verify(opts)
	if err != nil {
		return nil, fmt.Errorf("attls: client certificate at the trusted time %s: %w", t.UTC().Format(time.RFC3339), err)
	}
	if err := CheckDates(&tls.ConnectionState{VerifiedChains: chains}, t); err != nil {
		return nil, err
	}
	return chains, nil
}

// Option changes the server configuration.
type Option func(*options)

type options struct {
	chain *backend.Version
}

// WithChain names the chain the runner signs for in its TLS certificate:
// the genesis fork version in extension backend.RunnerChainOID. A client
// refuses a mainnet runner unless its settings say mainnet, so a client
// that leaves the setting out cannot skip the mainnet rules.
func WithChain(genesisForkVersion backend.Version) Option {
	return func(o *options) { o.chain = &genesisForkVersion }
}

// noTrustedTime is what cfg.Time gives crypto/tls when the trusted clock
// fails: a nonzero time before any certificate's NotBefore.
var noTrustedTime = time.Unix(1, 0)

// CheckDates refuses a connection with no verified chain, or with a
// certificate of a verified chain whose dates do not hold t. A server that
// requires client certificates calls it for every TLS connection.
func CheckDates(cs *tls.ConnectionState, t time.Time) error {
	if len(cs.VerifiedChains) == 0 {
		return errors.New("attls: no verified client certificate chain")
	}
	for _, chain := range cs.VerifiedChains {
		for _, c := range chain {
			if t.Before(c.NotBefore) || t.After(c.NotAfter) {
				return fmt.Errorf("attls: certificate %q is valid from %s to %s, not at the trusted time %s",
					c.Subject.CommonName, c.NotBefore.UTC().Format(time.RFC3339), c.NotAfter.UTC().Format(time.RFC3339), t.UTC().Format(time.RFC3339))
			}
		}
	}
	return nil
}

// NotAfter is the earliest NotAfter of the certificates of the verified
// chains: from then on the connection's client has no valid chain
// (ATTEST-ROLES-01). The zero time if there is no verified chain.
func NotAfter(cs *tls.ConnectionState) time.Time {
	var end time.Time
	for _, chain := range cs.VerifiedChains {
		for _, c := range chain {
			if end.IsZero() || c.NotAfter.Before(end) {
				end = c.NotAfter
			}
		}
	}
	return end
}

// Role is the client role of a verified TLS client (docs/protocol.md,
// "Client roles"). The zero value, RoleNone, is allowed nothing.
type Role uint8

const (
	RoleNone Role = iota
	// RoleSigning: a client certificate without a role mark that counts.
	RoleSigning
	// RoleAttestOnly: backend.AttestOnlyClientOID on the leaf or on any CA
	// of a verified chain.
	RoleAttestOnly
	// RoleAdmin: backend.AdminClientOID on the leaf and on the leaf's
	// direct issuer, an intermediate with pathlen:0 that a pinned root
	// signed.
	RoleAdmin
	// RoleAdminRootDirect: testnet builds only. backend.AdminClientOID on a
	// leaf signed straight by a pinned root. Same rights as RoleAdmin.
	RoleAdminRootDirect
)

func (r Role) String() string {
	switch r {
	case RoleSigning:
		return "signing"
	case RoleAttestOnly:
		return "attest-only"
	case RoleAdmin:
		return "admin"
	case RoleAdminRootDirect:
		// The name lives in the testnet flavour only, so a default
		// binary does not hold it (scripts/release-gate.sh).
		if buildflavor.AdminRootDirect {
			return buildflavor.AdminRootDirectRole
		}
	}
	return "none"
}

// hasEKU reports whether c lists oid as an extended key usage.
func hasEKU(c *x509.Certificate, oid asn1.ObjectIdentifier) bool {
	for _, u := range c.UnknownExtKeyUsage {
		if u.Equal(oid) {
			return true
		}
	}
	return false
}

// RoleOf returns the role of the client of a finished handshake. The rules,
// in order:
//
//  1. Attest-only if the leaf or any CA certificate of a verified chain
//     lists backend.AttestOnlyClientOID. A mark that restricts may come
//     from anywhere: a CA marked attest-only makes every certificate below
//     it attest-only, whatever the leaf says.
//  2. Admin if some verified chain is exactly leaf, intermediate and
//     root (adminChain): the leaf and the intermediate list
//     backend.AdminClientOID, the intermediate has pathlen:0, and the
//     chain ends at a self-signed root of the CA file. A leaf signed
//     straight by the root is never admin, nor is a marked leaf under an
//     unmarked intermediate, nor a marked CA below another intermediate,
//     nor a chain that ends at an intermediate the CA file lists. A key
//     that reaches only an unmarked intermediate thus cannot mint an
//     admin certificate, whatever path length that intermediate allows
//     (ATTEST-ROLES-02).
//  3. Testnet builds only (buildflavor.AdminRootDirect): admin-root-direct
//     if, in some verified chain, the leaf lists backend.AdminClientOID and
//     its issuer is the chain's root. Default builds skip this rule.
//  4. Otherwise signing.
//
// No peer certificate or no verified chain: RoleNone. Every certificate of
// the chain must still allow clientAuth (or list no extended key usage),
// or the handshake fails before this.
func RoleOf(cs *tls.ConnectionState) Role {
	if cs == nil || len(cs.PeerCertificates) == 0 || len(cs.VerifiedChains) == 0 {
		return RoleNone
	}
	if hasEKU(cs.PeerCertificates[0], backend.AttestOnlyClientOID) {
		return RoleAttestOnly
	}
	for _, chain := range cs.VerifiedChains {
		for _, c := range chain {
			if hasEKU(c, backend.AttestOnlyClientOID) {
				return RoleAttestOnly
			}
		}
	}
	for _, chain := range cs.VerifiedChains {
		if adminChain(chain, cs.PeerCertificates[0]) {
			return RoleAdmin
		}
	}
	if buildflavor.AdminRootDirect {
		for _, chain := range cs.VerifiedChains {
			if len(chain) == 2 && chain[0].Equal(cs.PeerCertificates[0]) && hasEKU(chain[0], backend.AdminClientOID) {
				return RoleAdminRootDirect
			}
		}
	}
	return RoleSigning
}

// adminChain reports whether chain is an admin chain: the peer's leaf,
// an admin intermediate with pathlen:0, and a self-signed root.
func adminChain(chain []*x509.Certificate, leaf *x509.Certificate) bool {
	if len(chain) != 3 || !chain[0].Equal(leaf) {
		return false
	}
	inter, root := chain[1], chain[2]
	return hasEKU(chain[0], backend.AdminClientOID) && hasEKU(inter, backend.AdminClientOID) &&
		inter.BasicConstraintsValid && inter.IsCA && inter.MaxPathLen == 0 && inter.MaxPathLenZero &&
		selfSigned(root)
}

// selfSigned reports whether c is a root: its issuer is its subject and
// its own key signed it. An intermediate in the CA file ends a verified
// chain too, but it is not one.
func selfSigned(c *x509.Certificate) bool {
	return bytes.Equal(c.RawSubject, c.RawIssuer) && c.CheckSignatureFrom(c) == nil
}

// parseCAs reads the CA certificates in caPEM.
func parseCAs(caPEM []byte) (*x509.CertPool, []*x509.Certificate, error) {
	pool := x509.NewCertPool()
	var cas []*x509.Certificate
	for rest := caPEM; ; {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		if strings.Contains(b.Type, "PRIVATE KEY") {
			return nil, nil, errors.New("attls: the client CA file holds a private key; it may hold CA certificates only")
		}
		if b.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			return nil, nil, fmt.Errorf("attls: client CA file: %w", err)
		}
		pool.AddCert(c)
		cas = append(cas, c)
	}
	if len(cas) == 0 {
		return nil, nil, errors.New("attls: no CA certificate in the client CA file")
	}
	return pool, cas, nil
}

// Listen opens a with open and, if cfg is not nil, wraps the listener in
// TLS when a is a network address: tcp or vsock. A unix socket stays plain,
// it does not leave the host. The second result says whether TLS is on.
//
// open is transport.Listen in the runner. A test passes a loopback listener
// in place of vsock.
func Listen(a transport.Addr, cfg *tls.Config, open func(transport.Addr) (net.Listener, error)) (net.Listener, bool, error) {
	l, err := open(a)
	if err != nil {
		return nil, false, err
	}
	if cfg == nil || (a.Network != "tcp" && a.Network != "vsock") {
		return l, false, nil
	}
	return tls.NewListener(l, cfg), true, nil
}
