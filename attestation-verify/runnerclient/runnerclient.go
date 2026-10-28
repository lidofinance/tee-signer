// Package runnerclient connects to a cloud runner over mutual TLS and checks
// its attestation before it trusts the connection. The Dirk fork's cloud
// adapter, its cloud-import tool and share-import build their client here,
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
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/lidofinance/tee-signer/governance/setupwire"
	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/buildflavor"
	"github.com/lidofinance/tee-signer/signer-protocol/remote"
	"github.com/lidofinance/tee-signer/signer-protocol/transport"
)

// The attestation verifiers.
const (
	// VerifierDev accepts the dev platform's unsigned document. It proves
	// nothing about the code that answered. Use it for local runners only.
	VerifierDev = "dev"
	// VerifierAzureMAA verifies a Microsoft Azure Attestation token.
	VerifierAzureMAA = "azure-maa"
	// VerifierAWSNitro verifies an AWS Nitro Enclaves attestation document.
	VerifierAWSNitro = "aws-nitro"
	// VerifierGCPCS verifies a Google Confidential Space attestation token.
	VerifierGCPCS = "gcp-cs"
)

// verifierList is the "want" part of the errors about the verifier name.
var verifierList = fmt.Sprintf("%q, %q, %q or %q", VerifierDev, VerifierAzureMAA, VerifierAWSNitro, VerifierGCPCS)

// Attestation says how to check a runner's attestation document. The JSON
// names are the ones of the Dirk fork's backend.cloud.config. The settings
// of one verifier are refused on any other verifier, and a required one
// that is missing stops the start.
//
// For azure-maa the signature must come from a key of MAAHost, the token's
// issuer must be that host, and the token must bind this identity and
// nonce. Besides the settings below the verifier always requires
// x-ms-sevsnpvm-is-debuggable false, x-ms-sevsnpvm-vmpl 0 and TEE type
// sevsnpvm. Those checks have no setting.
//
// For aws-nitro the document must chain to the AWS Nitro Enclaves root
// pinned in package attest, carry the expected PCRs, the client's nonce and
// the identity's user data, and not come from a debug-mode enclave. There
// is no setting for debug mode, for accepting other PCRs or for another
// root.
//
// For gcp-cs the token must come from the issuer's key set, carry the
// audience, the expected image digest and a hardware model from the list,
// bind this identity and nonce, and say CONFIDENTIAL_SPACE, secure boot,
// STABLE support and debug status disabled-since-boot. Those last four
// have no setting.
//
// The setup settings (setup_sha256, min_locked_version, min_open_version,
// allow_unpinned_setup) work with every verifier. They check the setup
// state of the verified identity; setup.go has the rules.
type Attestation struct {
	// Verifier is "dev", "azure-maa", "aws-nitro" or "gcp-cs". Required.
	Verifier string `json:"verifier"`

	// SetupSHA256 is the setup_hash the runner's identity must carry, 64
	// hex digits: the setup_sha256 that setup-tool prints for the setup the
	// operator built (research/setup-phase.md in the threshold-signer-poc repo,
	// section 11). Required for a runner that reports a setup. A runner
	// without one (the flag path of tests and local runners, whose
	// setup_hash is the SHA-256 of its -config file) is accepted without
	// it, and refused with it unless that hash is the one pinned.
	SetupSHA256 string `json:"setup_sha256,omitempty"`
	// MinLockedVersion and MinOpenVersion, optional, refuse a runner whose
	// effective version of that config group is lower. The effective
	// version counts a pending update whose effective activation time has
	// passed on this machine's clock. Both need SetupSHA256.
	MinLockedVersion uint64 `json:"min_locked_version,omitempty"`
	MinOpenVersion   uint64 `json:"min_open_version,omitempty"`
	// AllowUnpinnedSetup accepts a runner that reports a setup while
	// SetupSHA256 is not set. For tests only: the dev verifier only, and
	// not together with SetupSHA256.
	AllowUnpinnedSetup bool `json:"allow_unpinned_setup,omitempty"`
	// KeyReleaseSHA256, optional, is the key_release_hash the runner's
	// identity must carry, 64 hex digits: the hash of the rule of the key
	// that releases the runner's sealing key, as the runner read it at
	// start (the Azure release policy, the AWS key policy). Pin the hash of
	// a rule you reviewed; a runner whose rule changed, or that read none,
	// is refused. GCP has no rule to read (zero hash), so a GCP runner
	// cannot be pinned this way. Needs SetupSHA256.
	KeyReleaseSHA256 string `json:"key_release_sha256,omitempty"`
	// Mainnet says the runner signs for Ethereum mainnet. An azure-maa or
	// aws-nitro runner on mainnet is then reached only with
	// KeyReleaseSHA256 set; gcp-cs never
	// needs it. The runner's identity does not name its chain, so the
	// client's settings must.
	Mainnet bool `json:"mainnet,omitempty"`

	// MAAHost is the attestation provider (the token issuer is
	// "https://" + MAAHost), for example sharedweu.weu.attest.azure.net.
	// azure-maa only, required.
	MAAHost string `json:"maa_host,omitempty"`
	// CCEPolicySHA256 is the expected x-ms-sevsnpvm-hostdata claim: the
	// SHA-256 of the runner's CCE policy, 64 hex digits (deploy.sh policy
	// prints it). It pins the container images and the runner's command
	// line. azure-maa only, required.
	CCEPolicySHA256 string `json:"cce_policy_sha256,omitempty"`
	// ComplianceStatus is the expected x-ms-compliance-status:
	// "azure-compliant-uvm" (default, confidential containers on ACI) or
	// "azure-compliant-cvm". azure-maa only.
	ComplianceStatus string `json:"compliance_status,omitempty"`

	// NitroPCRs maps a PCR index ("0" to "31", plain decimal) to the value
	// the document must hold, 96 hex digits (SHA-384). PCR0, PCR1 and PCR2
	// (image, kernel and ramdisk, application) are required and may not be
	// all zero, the value of a debug-mode enclave. Add PCR3 (the parent's
	// IAM role) or PCR8 (the EIF signing certificate) to pin them as well.
	// scripts/nitro-eif.sh prints PCR0 to PCR2 of an image. aws-nitro only,
	// required.
	NitroPCRs map[string]string `json:"nitro_pcrs,omitempty"`
	// NitroRootSHA256 is the SHA-256 of the AWS Nitro Enclaves root
	// certificate (DER) the operator expects, 64 hex digits. Optional. The
	// verifier carries one root, AWS's root G1 (attest.NitroRootSHA256), and
	// refuses to start if this value is another. aws-nitro only.
	NitroRootSHA256 string `json:"nitro_root_sha256,omitempty"`

	// GCPImageDigest is the expected submods.container.image_digest of the
	// runner image, "sha256:" and 64 hex digits (the "sha256:" is optional
	// here). gcp-cs only, required.
	GCPImageDigest string `json:"gcp_image_digest,omitempty"`
	// GCPAudience is the audience the identity token carries, the runner's
	// attest_audience (default signer-runner-identity). Never the STS
	// audience or a Workload Identity Federation name: a token with one of
	// those is a credential for the KMS key. gcp-cs only, required.
	GCPAudience string `json:"gcp_audience,omitempty"`
	// GCPHWModels lists the accepted hwmodel claims, for example
	// "GCP_AMD_SEV", "GCP_AMD_SEV_ES" or "GCP_INTEL_TDX". GCP_SHIELDED_VM,
	// a VM without memory encryption, is refused. gcp-cs only, required.
	//
	// In the three-cloud layout (Azure on AMD SEV-SNP, AWS Nitro, GCP) list
	// GCP_INTEL_TDX only, so one chip family never holds two shares: a flaw
	// in one chip family then reaches one share, not two.
	GCPHWModels []string `json:"gcp_hwmodels,omitempty"`
	// GCPIssuer is the token issuer, an https URL without path. Default
	// https://confidentialcomputing.googleapis.com. The key set comes from
	// its .well-known/openid-configuration unless GCPJWKSFile is set.
	// gcp-cs only.
	GCPIssuer string `json:"gcp_issuer,omitempty"`
	// GCPJWKSFile is a pinned key set (JWKS file) to use instead of the
	// issuer's. It does not follow Google's key rotation. gcp-cs only.
	GCPJWKSFile string `json:"gcp_jwks_file,omitempty"`
	// GCPServiceAccount, if set, must be one of the token's
	// google_service_accounts. gcp-cs only.
	GCPServiceAccount string `json:"gcp_service_account,omitempty"`
	// GCPProjectID, if set, must equal the token's submods.gce.project_id,
	// the project the runner's VM runs in. gcp-cs only.
	GCPProjectID string `json:"gcp_project_id,omitempty"`
}

// Connection is everything needed to reach one runner and trust it. The
// Dirk fork's cloud adapter embeds it in its configuration.
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

// Option changes how a client is built.
type Option func(*options)

type options struct {
	timeout time.Duration
	http    *http.Client
	// nitroRoots replaces the pinned AWS root, for this package's tests only
	// (a local test CA); there is no exported way and no setting.
	nitroRoots []*x509.Certificate
	// now is the minimum version check's clock (time.Now); tests set it.
	now func() time.Time
	// verified is called with each connection's identity once it passed
	// every check (WithVerified).
	verified func(*backend.Identity)
}

// WithTimeout sets the per-request timeout of the client (default 10 s).
func WithTimeout(d time.Duration) Option { return func(o *options) { o.timeout = d } }

// WithHTTPClient sets the HTTP client that fetches the MAA or Confidential
// Space key set (default: a client with a 15 s timeout and the system
// roots).
func WithHTTPClient(c *http.Client) Option { return func(o *options) { o.http = c } }

// WithVerified calls f with the identity of each new connection once it
// passed every check, before the client sends a request on it. The Dirk
// fork logs the runner's setup state with it. f must not keep id.
func WithVerified(f func(id *backend.Identity)) Option {
	return func(o *options) { o.verified = f }
}

func newOptions(opts []Option) *options {
	o := &options{}
	for _, f := range opts {
		f(o)
	}
	if o.http == nil {
		o.http = &http.Client{Timeout: 15 * time.Second}
	}
	if o.now == nil {
		o.now = time.Now
	}
	return o
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
	_, err := c.prepare(newOptions(nil))
	return err
}

// New returns a client for the runner. It does not connect until the first
// request. It refuses an invalid configuration, and testnet runners (tlsConfig).
func (c *Connection) New(opts ...Option) (*Client, error) {
	o := newOptions(opts)
	p, err := c.prepare(o)
	if err != nil {
		return nil, err
	}
	tlsCfg := c.tlsConfig(p.cert)
	verify := p.verify
	if o.verified != nil {
		// The connection's verifier runs last in the dial, after the TLS key
		// check, so its success means the connection passed everything.
		verify = func(ctx context.Context, nonce []byte, id *backend.Identity) error {
			if err := p.verify(ctx, nonce, id); err != nil {
				return err
			}
			o.verified(id)
			return nil
		}
	}
	ropts := []remote.Option{remote.WithTLS(tlsCfg, verify)}
	if o.timeout > 0 {
		ropts = append(ropts, remote.WithTimeout(o.timeout))
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

func (c *Connection) prepare(o *options) (*prepared, error) {
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
	if p.verify, err = c.Attestation.verifier(o); err != nil {
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

// foreign refuses the settings that belong to another verifier than the
// one named, so a configuration written for one platform cannot be run
// against another and leave a check out unnoticed.
func (a *Attestation) foreign() error {
	groups := []struct {
		verifier string
		names    string
		set      bool
	}{
		{VerifierAzureMAA, "maa_host, cce_policy_sha256 and compliance_status",
			a.MAAHost != "" || a.CCEPolicySHA256 != "" || a.ComplianceStatus != ""},
		{VerifierAWSNitro, "nitro_pcrs and nitro_root_sha256",
			len(a.NitroPCRs) > 0 || a.NitroRootSHA256 != ""},
		{VerifierGCPCS, "gcp_image_digest, gcp_audience, gcp_hwmodels, gcp_issuer, gcp_jwks_file, gcp_service_account and gcp_project_id",
			a.GCPImageDigest != "" || a.GCPAudience != "" || len(a.GCPHWModels) > 0 || a.GCPIssuer != "" ||
				a.GCPJWKSFile != "" || a.GCPServiceAccount != "" || a.GCPProjectID != ""},
	}
	for _, g := range groups {
		if g.set && g.verifier != a.Verifier {
			return fmt.Errorf("attestation: %s belong to the verifier %q, not %q", g.names, g.verifier, a.Verifier)
		}
	}
	return nil
}

// Validate checks the attestation settings.
func (a *Attestation) Validate() error {
	_, err := a.verifier(newOptions(nil))
	return err
}

// NewVerifier returns the verifier the settings name. A tool that checks an
// identity itself (share-import) uses it.
func (a *Attestation) NewVerifier(opts ...Option) (remote.VerifyFunc, error) {
	return a.verifier(newOptions(opts))
}

func (a *Attestation) verifier(o *options) (remote.VerifyFunc, error) {
	switch a.Verifier {
	case "":
		return nil, fmt.Errorf("attestation.verifier: not set, want %s", verifierList)
	case VerifierDev, VerifierAzureMAA, VerifierAWSNitro, VerifierGCPCS:
	default:
		return nil, fmt.Errorf("attestation.verifier: unknown verifier %q, want %s", a.Verifier, verifierList)
	}
	if err := a.foreign(); err != nil {
		return nil, err
	}
	f, ok := verifierFactories[a.Verifier]
	if !ok {
		return nil, fmt.Errorf("attestation.verifier: %q is not built into this program (build tag %s)", a.Verifier, peerTags[a.Verifier])
	}
	v, err := f(a, o)
	if err != nil {
		return nil, err
	}
	pins, err := a.setupPins()
	if err != nil {
		return nil, err
	}
	return pins.after(v, o.now), nil
}

// verifierFactories holds the verifiers built into this program. Each
// verifier's file adds its own. A runner built with the tag peerselect has
// only those its peer_* tags name (key generation, runner/keygen); every
// other program has all four.
var verifierFactories = map[string]func(a *Attestation, o *options) (remote.VerifyFunc, error){}

// peerTags names the build tag of each verifier, for the error above.
var peerTags = map[string]string{
	VerifierDev: "peer_dev", VerifierAzureMAA: "peer_azure", VerifierAWSNitro: "peer_aws", VerifierGCPCS: "peer_gcp",
}

// Available reports whether the verifier is built into this program.
func Available(verifier string) bool {
	_, ok := verifierFactories[verifier]
	return ok
}

// checkDocument makes the checks that need no key set or root: id carries a
// document of this platform and format, and its user data is what
// backend.IdentityUserData gives for the identity fields and nonce. A
// verifier calls it first, so a document of another platform is refused
// before the client fetches any key.
func checkDocument(nonce []byte, id *backend.Identity, platform, format, what string) error {
	if id == nil || id.Attestation == nil {
		return errors.New("runnerclient: no attestation")
	}
	a := id.Attestation
	if a.Platform != platform || a.Format != format {
		return fmt.Errorf("runnerclient: platform %q format %q is not %s", a.Platform, a.Format, what)
	}
	if !bytes.Equal(a.UserData, backend.IdentityUserData(nonce, id)) {
		return errors.New("runnerclient: attestation user data does not match the identity fields and nonce")
	}
	return nil
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
// constants of backend/buildflavor for it, so that the key generation
// runners, which link this package, stay byte for byte as they were in
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
