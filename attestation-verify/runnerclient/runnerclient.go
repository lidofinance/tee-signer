// Package runnerclient connects to a cloud runner over mutual TLS and checks
// its attestation before it trusts the connection. The signing
// client, its cloud-import tool and share-import build their client here,
// so all of them apply the same checks; the attestation check has no switch.
//
// On every new connection, as docs/protocol.md ("Channel binding") says:
//
//  1. TLS 1.3 handshake, with the client certificate. The runner's own
//     certificate is self-signed inside the TEE, so it is not checked
//     against a CA. A certificate that names a testnet build is refused
//     unless allow_testnet_build is set (tlsConfig).
//  2. IDENTITY with a fresh nonce, over the new channel.
//  3. The verifier checks the attestation document: "dev" for the dev
//     platform's unsigned document, "azure-maa" for an MAA token (signature
//     of the attestation provider, issuer, compliance status, debug off,
//     VMPL 0, the CCE policy hash, and the binding to this identity and
//     nonce), "aws-nitro" for an NSM document (chain to the pinned AWS
//     Nitro root, signature, PCRs, debug mode, nonce and user data) and
//     "gcp-cs" for a Confidential Space token (Google key set, issuer,
//     audience, image digest, debug status, hardware model, nonce).
//  4. The setup state in the verified identity must pass the setup pins:
//     setup_sha256, the minimum config versions, and the refusal of a
//     runner with a setup that no setup_sha256 pins (setup.go).
//  5. The TLS key hash in the verified identity must equal the key the
//     handshake presented. That is the key pin, taken from the verified
//     identity. tls_key_pin, if set, must match as well.
//
// Only then does the client send a request. A restarted runner has a new
// TLS key and identity, so the next connection goes through every step again.
package runnerclient

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/lidofinance/tee-signer/attestation-verify/runnerclient/internal/optset"
	"github.com/lidofinance/tee-signer/attestation-verify/runnerclient/verify"
	"github.com/lidofinance/tee-signer/governance/setupwire"
	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/buildflavor"
	"github.com/lidofinance/tee-signer/signer-protocol/remote"
	"github.com/lidofinance/tee-signer/signer-protocol/transport"
)

// The attestation settings, options and verifier names are package
// verify's; these names keep the tools' code and configuration as they
// were.
type (
	Attestation = verify.Attestation
	Option      = verify.Option
)

const (
	VerifierDev      = verify.VerifierDev
	VerifierAzureMAA = verify.VerifierAzureMAA
	VerifierAWSNitro = verify.VerifierAWSNitro
	VerifierGCPCS    = verify.VerifierGCPCS
)

// Connection is everything needed to reach one runner and trust it. The signing
// client embeds it in its configuration.
type Connection struct {
	// Address is tcp:HOST:PORT. Unix and vsock addresses are refused: this
	// client dials TCP. A Nitro runner listens on vsock, with mutual TLS
	// that ends inside the enclave, so the address is the TCP port of the
	// plain forwarder on the parent instance in front of it. The forwarder
	// is not trusted: it copies bytes, and the check of the runner's
	// identity (the TLS key hash against the attested identity) is what
	// ties the connection to the enclave.
	Address string `json:"address"`
	// ClientCert and ClientKey are the PEM files of the client certificate
	// the runner's -tls-client-ca accepts. Both required.
	ClientCert string `json:"client_cert"`
	ClientKey  string `json:"client_key"`
	// TLSKeyPin, optional, is the sha256 of the runner's TLS key (DER
	// SubjectPublicKeyInfo), 64 hex digits. A runner makes a new key at
	// every start, so a pin only holds for one run of the runner. The
	// attested identity binds the key in any case.
	TLSKeyPin string `json:"tls_key_pin,omitempty"`
	// Attestation says how to verify the runner's identity. Required.
	Attestation Attestation `json:"attestation"`
	// AllowTestnetBuild accepts a runner of a testnet build (tlsConfig). Default: refused.
	AllowTestnetBuild bool `json:"allow_testnet_build,omitempty"`
}

// ResolvePaths makes relative client_cert, client_key and gcp_jwks_file
// paths relative to dir (the folder of the configuration file).
func (c *Connection) ResolvePaths(dir string) {
	for _, p := range []*string{&c.ClientCert, &c.ClientKey, &c.Attestation.GCPJWKSFile} {
		if *p != "" && !filepath.IsAbs(*p) {
			*p = filepath.Join(dir, *p)
		}
	}
}

// WithTimeout sets the per-request timeout of the client (default 10 s).
func WithTimeout(d time.Duration) Option { return func(o *optset.Options) { o.Timeout = d } }

// WithVerified calls f with the identity of each new connection once it
// passed every check, before the client sends a request on it. The signing
// client logs the runner's setup state with it. f must not keep id.
func WithVerified(f func(id *backend.Identity)) Option {
	return func(o *optset.Options) { o.Verified = f }
}

// Client is a runner client that checks the runner's attestation on every
// connection.
type Client struct {
	*remote.Client
	// Verify is the verifier the client runs on every connection. A caller
	// that checks the identity again (ImportShareSealed) passes it on.
	Verify remote.VerifyFunc
}

// Validate checks the settings and reads the client certificate and key. It
// makes no network connection.
func (c *Connection) Validate() error {
	_, err := c.prepare(optset.New(nil))
	return err
}

// New returns a client for the runner. It does not connect until the first
// request. It refuses an invalid configuration, and testnet runners (tlsConfig).
func (c *Connection) New(opts ...Option) (*Client, error) {
	o := optset.New(opts)
	p, err := c.prepare(o)
	if err != nil {
		return nil, err
	}
	tlsCfg := c.tlsConfig(p.cert)
	verify := p.verify
	if o.Verified != nil {
		// The connection's verifier runs last in the dial, after the TLS key
		// check, so its success means the connection passed everything.
		verify = func(ctx context.Context, nonce []byte, id *backend.Identity) error {
			if err := p.verify(ctx, nonce, id); err != nil {
				return err
			}
			o.Verified(id)
			return nil
		}
	}
	ropts := []remote.Option{remote.WithTLS(tlsCfg, verify)}
	if o.Timeout > 0 {
		ropts = append(ropts, remote.WithTimeout(o.Timeout))
	}
	if p.pin != nil {
		ropts = append(ropts, remote.WithTLSKeyPin(p.pin))
	}
	rc, err := remote.New(c.Address, ropts...)
	if err != nil {
		return nil, err
	}
	return &Client{Client: rc, Verify: p.verify}, nil
}

type prepared struct {
	cert   tls.Certificate
	pin    []byte
	verify remote.VerifyFunc
}

func (c *Connection) prepare(o *optset.Options) (*prepared, error) {
	addr, err := transport.Parse(c.Address)
	if err != nil {
		return nil, fmt.Errorf("address: %w", err)
	}
	if addr.Network != "tcp" {
		return nil, fmt.Errorf("address: %q is not a tcp: address; connect to the runner's TCP port (on AWS, the forwarder in front of the enclave)", c.Address)
	}
	p := &prepared{}
	if p.cert, err = loadPair(c.ClientCert, c.ClientKey); err != nil {
		return nil, err
	}
	if c.TLSKeyPin != "" {
		if p.pin, err = hex.DecodeString(strings.TrimPrefix(c.TLSKeyPin, "0x")); err != nil || len(p.pin) != 32 {
			return nil, errors.New("tls_key_pin: want 64 hex digits, the sha256 of the runner's TLS key")
		}
	}
	if p.verify, err = c.Attestation.VerifierWith(o); err != nil {
		return nil, err
	}
	return p, nil
}

// loadPair reads the client certificate and key. Both must exist, be
// readable and belong together, and the certificate must not be expired.
func loadPair(certPath, keyPath string) (tls.Certificate, error) {
	var zero tls.Certificate
	if certPath == "" {
		return zero, errors.New("client_cert: not set")
	}
	if keyPath == "" {
		return zero, errors.New("client_key: not set")
	}
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return zero, fmt.Errorf("client_cert: %w", err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return zero, fmt.Errorf("client_key: %w", err)
	}
	defer clear(keyPEM)
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return zero, fmt.Errorf("client_cert and client_key: %w", err)
	}
	if cert.Leaf != nil && time.Now().After(cert.Leaf.NotAfter) {
		return zero, fmt.Errorf("client_cert: expired on %s", cert.Leaf.NotAfter.UTC().Format(time.RFC3339))
	}
	return cert, nil
}

// The build flavour of a runner (backend/flavor). A testnet build runs its
// governance time locks in minutes and starts on devnets and test networks
// only, so a client takes one only when its connection says so:
// allow_testnet_build. The check runs in the TLS handshake of every
// connection, before IDENTITY and before any request: the runner's
// certificate names its flavour. Only the runner holds the certificate's
// key, and the attestation check after the handshake ties that key to the
// attested identity, so the name comes from the runner's code.
//
// The verifier of a cloud image pins its measurement too, and a testnet
// image has measurements of its own, so cloud.json names either a default
// or a testnet image. The dev verifier pins no measurement; there this
// check is what keeps the builds apart.
//
// Tools print the flavour from HEALTH's version (backend/flavor
// FromVersion).
//
// This code is at the end of the file, and the package imports only the
// constants of backend/buildflavor for it, so that the runners, which
// link this package, stay byte for byte as they were in
// their default build: the functions above keep their lines, and no
// package with code joins the binary.

// tlsConfig is the client's TLS configuration: the client certificate,
// TLS 1.3, and the flavour check.
func (c *Connection) tlsConfig(cert tls.Certificate) *tls.Config {
	allow, mainnet := c.AllowTestnetBuild, c.Attestation.Mainnet
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if err := checkFlavor(cs, allow); err != nil {
				return err
			}
			return checkChain(cs, mainnet)
		},
	}
}

// checkChain refuses a runner whose certificate says it signs for mainnet
// when the settings do not say mainnet, and the reverse. The setting
// decides the mainnet rules of the client (key_release_sha256 for
// azure-maa and aws-nitro), and the identity names no chain, so without
// this a setting left out failed open. The certificate's key is the one
// the attested identity names (checked after the handshake), so the mark
// comes from the runner's code. Without a mark the setting alone
// decides.
func checkChain(cs tls.ConnectionState, mainnet bool) error {
	if len(cs.PeerCertificates) == 0 {
		return nil // the dial refuses a runner without a certificate
	}
	gfv, ok, err := runnerChain(cs.PeerCertificates[0])
	switch {
	case err != nil:
		return err
	case !ok:
		return nil
	case setupwire.IsMainnet(gfv) && !mainnet:
		return fmt.Errorf("the runner signs for mainnet (genesis fork version %#x in its certificate); "+
			"set mainnet in its attestation settings, which makes key_release_sha256 mandatory for azure-maa and aws-nitro", gfv[:])
	case !setupwire.IsMainnet(gfv) && mainnet:
		return fmt.Errorf("the attestation settings say mainnet, but the runner signs for genesis fork version %#x", gfv[:])
	}
	return nil
}

// runnerChain reads the chain mark of a runner's certificate
// (backend.RunnerChainOID). ok is false without one.
func runnerChain(c *x509.Certificate) (gfv backend.Version, ok bool, err error) {
	for _, e := range c.Extensions {
		if !e.Id.Equal(backend.RunnerChainOID) {
			continue
		}
		var b []byte
		if rest, err := asn1.Unmarshal(e.Value, &b); err != nil || len(rest) != 0 || len(b) != len(gfv) {
			return gfv, false, errors.New("the runner's certificate has a chain mark that does not read as 4 bytes")
		}
		copy(gfv[:], b)
		return gfv, true, nil
	}
	return gfv, false, nil
}

// checkFlavor refuses a testnet runner unless allow.
func checkFlavor(cs tls.ConnectionState, allow bool) error {
	if len(cs.PeerCertificates) == 0 {
		return nil // the dial refuses a runner without a certificate
	}
	if cs.PeerCertificates[0].Subject.CommonName == buildflavor.TestnetCertName && !allow {
		return errors.New("the runner is a testnet build (governance time locks in minutes, test networks only); " +
			"set allow_testnet_build in its connection settings to accept it")
	}
	return nil
}
