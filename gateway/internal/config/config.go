// Package config loads the gateway YAML configuration.
package config

import (
	"bytes"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	"gopkg.in/yaml.v3"

	"github.com/lidofinance/tee-signer/attestation-verify/runnerclient"
	"github.com/lidofinance/tee-signer/gateway/internal/servertls"
	"github.com/lidofinance/tee-signer/governance/runnerchain"
)

// Fork is one entry of chain.forks: the fork version from epoch on.
type Fork struct {
	Epoch   uint64 `yaml:"epoch"`
	Version string `yaml:"version"`
}

// Signer is one TEE signer of signers.nodes.
type Signer struct {
	// Name names it in the log (default signer-1, signer-2, ...).
	Name string `yaml:"name"`
	// Address is tcp:HOST:PORT of the signer's mutual TLS listener. For an
	// AWS Nitro signer it is the TCP port of the forwarder on the parent
	// instance; the TLS ends inside the enclave.
	Address string `yaml:"address"`
	// TLSKeyPin, optional, is the sha256 of the signer's TLS key, 64 hex
	// digits. The key changes at every start of the signer.
	TLSKeyPin string `yaml:"tls_key_pin"`
	// AllowChainBuild accepts a signer of the non-prod build of this
	// chain: hoodi, devnet or ci-test. Empty: mainnet builds only.
	AllowChainBuild string `yaml:"allow_chain_build"`
	// Attestation says what the signer's attestation must show, with the
	// field names of runnerclient.Attestation.
	Attestation Attestation `yaml:"attestation"`
}

// Attestation is runnerclient.Attestation under its JSON field names:
// verifier, setup_sha256, key_release_sha256, mainnet, maa_host,
// nitro_pcrs and the others. An unknown field is an error.
type Attestation struct{ runnerclient.Attestation }

// UnmarshalYAML reads the YAML mapping through JSON, so the field names
// and their checks are runnerclient's.
func (a *Attestation) UnmarshalYAML(n *yaml.Node) error {
	var m map[string]any
	if err := n.Decode(&m); err != nil {
		return err
	}
	b, err := json.Marshal(m)
	if err != nil {
		return fmt.Errorf("attestation: %w (quote map keys such as the nitro_pcrs indices)", err)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&a.Attestation); err != nil {
		return fmt.Errorf("attestation: %w", err)
	}

	return nil
}

// Config is the gateway configuration file.
type Config struct {
	Listen string `yaml:"listen"`
	// Access is how the API listener is exposed: local, mtls,
	// unsafe_open_tls or unsafe_plain_http. Default: mtls with tls.cert,
	// local without.
	Access string `yaml:"access"`
	// TLS is the server certificate and the accepted clients of the
	// listeners whose access is mtls or unsafe_open_tls.
	TLS struct {
		// Cert is the server certificate chain (PEM, leaf first), Key its key.
		Cert string `yaml:"cert"`
		Key  string `yaml:"key"`
		// ClientCA is a PEM bundle of the CAs whose client certificates are
		// accepted.
		ClientCA string `yaml:"client_ca"`
		// ClientFingerprints are SHA-256 fingerprints of client certificates
		// accepted whatever their issuer.
		ClientFingerprints []string `yaml:"client_fingerprints"`
		// MinVersion is "1.3" (default) or "1.2", which Teku needs.
		MinVersion string `yaml:"min_version"`
		// ReloadInterval is how often the files are read again (default 10s).
		ReloadInterval time.Duration `yaml:"reload_interval"`
	} `yaml:"tls"`
	// Metrics, if set, is the HOST:PORT of the Prometheus endpoint, GET
	// /metrics only. Absent: no endpoint.
	Metrics string `yaml:"metrics"`
	// MetricsAccess is Access for the metrics listener (default local). Its
	// TLS is the tls section.
	MetricsAccess string `yaml:"metrics_access"`
	Chain         struct {
		// Preset is mainnet (all public networks) or minimal (spec tests, Web3Signer examples).
		Preset string `yaml:"preset"`
		// SlotsPerEpoch overrides the preset value when set.
		SlotsPerEpoch      uint64 `yaml:"slots_per_epoch"`
		GenesisForkVersion string `yaml:"genesis_fork_version"`
		// GenesisValidatorsRoot and Forks pin the chain: the gateway computes
		// every domain from them and refuses a request whose fork_info
		// names another chain or another fork.
		GenesisValidatorsRoot string `yaml:"genesis_validators_root"`
		Forks                 []Fork `yaml:"forks"`
		// GloasForkEpoch is the chain's GLOAS_FORK_EPOCH, the epoch of one of
		// forks. Absent: the Gloas types are refused.
		GloasForkEpoch *uint64 `yaml:"gloas_fork_epoch"`
		// SecondsPerSlot is the chain's SECONDS_PER_SLOT (default 12). Only
		// the coalescing below uses it, to turn slots into time.
		SecondsPerSlot uint64 `yaml:"seconds_per_slot"`
	} `yaml:"chain"`
	// Coalesce lets identical requests of the non-slashable types share one
	// call to the signers (internal/coalesce).
	Coalesce struct {
		// Enabled turns it on (default true).
		Enabled *bool `yaml:"enabled"`
		// CacheSlots is how long a signature stays stored after its call
		// succeeded, in slots (default 2). 0 shares calls in flight only.
		CacheSlots *uint64 `yaml:"cache_slots"`
	} `yaml:"coalesce"`
	// Signers are the TEE signers and how the gateway reaches them.
	Signers struct {
		// ClientCert and ClientKey are the PEM files of the client
		// certificate the signers accept (their -tls-client-ca, signing role).
		ClientCert string `yaml:"client_cert"`
		ClientKey  string `yaml:"client_key"`
		// CertReloadInterval is how often the gateway reads ClientCert and
		// ClientKey again for a renewed pair (default 10s).
		CertReloadInterval time.Duration `yaml:"cert_reload_interval"`
		// Timeout bounds one sign request, from the HTTP request to the
		// combined signature, and each key list call (default 5s).
		Timeout time.Duration `yaml:"timeout"`
		// DialTimeout bounds each new connection: TCP, TLS, IDENTITY and the
		// attestation check (default 30s).
		DialTimeout time.Duration `yaml:"dial_timeout"`
		// Connections is the number of connections to each signer (default
		// 2, at most 16).
		Connections int `yaml:"connections"`
		// MaxShareIndex is the highest share index the gateway tries when it
		// matches the share keys to their indices (default: the number of
		// signers).
		MaxShareIndex int      `yaml:"max_share_index"`
		Nodes         []Signer `yaml:"nodes"`
	} `yaml:"signers"`
	Policy struct {
		FeeRecipientAllowlist []string `yaml:"fee_recipient_allowlist"`
	} `yaml:"policy"`
}

// Load reads and checks a config file. Relative paths resolve against the file's directory.
func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	dec := yaml.NewDecoder(strings.NewReader(string(b)))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if c.Listen == "" {
		c.Listen = "127.0.0.1:19000"
	}
	if c.Metrics != "" {
		if _, _, err := net.SplitHostPort(c.Metrics); err != nil {
			return nil, fmt.Errorf("metrics: %w", err)
		}
		if c.Metrics == c.Listen {
			return nil, errors.New("metrics must be another address than listen")
		}
	}
	if err := c.loadAccess(filepath.Dir(path)); err != nil {
		return nil, err
	}
	if c.Chain.Preset == "" {
		c.Chain.Preset = "mainnet"
	}
	if c.Chain.GenesisForkVersion == "" {
		c.Chain.GenesisForkVersion = "0x00000000"
	}
	if c.Chain.SecondsPerSlot == 0 {
		c.Chain.SecondsPerSlot = 12
	}
	if c.Coalesce.Enabled == nil {
		on := true
		c.Coalesce.Enabled = &on
	}
	if c.Coalesce.CacheSlots == nil {
		two := uint64(2)
		c.Coalesce.CacheSlots = &two
	}
	if c.Chain.GenesisValidatorsRoot == "" {
		return nil, errors.New("chain.genesis_validators_root is required: the gateway signs only for the chain it is configured for")
	}
	if _, _, err := c.Schedule(); err != nil {
		return nil, err
	}
	if err := c.loadSigners(filepath.Dir(path)); err != nil {
		return nil, err
	}

	return &c, nil
}

// The values of access and metrics_access.
const (
	// AccessLocal is plain HTTP on a loopback address.
	AccessLocal = "local"
	// AccessMTLS is TLS with client certificates, on any address.
	AccessMTLS = "mtls"
	// AccessUnsafeOpenTLS is TLS without a client certificate check, on
	// any address.
	AccessUnsafeOpenTLS = "unsafe_open_tls"
	// AccessUnsafePlainHTTP is plain HTTP on any address.
	AccessUnsafePlainHTTP = "unsafe_plain_http"
)

// UsesTLS reports whether a listener of access a serves TLS.
func UsesTLS(a string) bool { return a == AccessMTLS || a == AccessUnsafeOpenTLS }

// TLSOn reports whether the tls section is set. Load accepts it only
// when the API listener serves TLS.
func (c *Config) TLSOn() bool { return c.TLS.Cert != "" }

// Loopback reports whether HOST:PORT addr is a loopback address:
// localhost, 127.0.0.0/8 or ::1. A host name other than localhost, or
// no host (every interface), is not.
func Loopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)

	return ip != nil && ip.IsLoopback()
}

// checkAccess checks the access value a of one listener (field names it,
// addrField and addr are its address) against its address and the tls
// section.
func checkAccess(field, a, addrField, addr string, tlsSet, named bool) error {
	switch a {
	case AccessLocal:
		if !Loopback(addr) {
			return fmt.Errorf("%s: local is plain HTTP and needs a loopback %s, not %s; for another address set %s: mtls "+
				"with a tls section", field, addrField, addr, field)
		}
	case AccessMTLS:
		if !tlsSet {
			return fmt.Errorf("%s: mtls needs tls.cert and tls.key", field)
		}
		if !named {
			return fmt.Errorf("%s: mtls needs the clients it accepts: tls.client_ca, tls.client_fingerprints, or both", field)
		}
	case AccessUnsafeOpenTLS:
		if !tlsSet {
			return fmt.Errorf("%s: unsafe_open_tls needs tls.cert and tls.key", field)
		}
	case AccessUnsafePlainHTTP:
	default:
		return fmt.Errorf("%s %q: local, mtls, unsafe_open_tls or unsafe_plain_http", field, a)
	}

	return nil
}

// loadAccess checks access, metrics_access and the tls section, and
// sets their defaults.
func (c *Config) loadAccess(base string) error {
	if _, _, err := net.SplitHostPort(c.Listen); err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	t := &c.TLS
	tlsSet := t.Cert != "" || t.Key != ""
	named := t.ClientCA != "" || len(t.ClientFingerprints) > 0
	if !tlsSet && (named || t.MinVersion != "" || t.ReloadInterval != 0) {
		return errors.New("tls: tls.cert and tls.key are required with any other tls setting")
	}
	if c.Access == "" {
		c.Access = AccessLocal
		if tlsSet {
			c.Access = AccessMTLS
		}
	}
	if err := checkAccess("access", c.Access, "listen", c.Listen, tlsSet, named); err != nil {
		return err
	}
	switch {
	case !UsesTLS(c.Access) && tlsSet:
		return fmt.Errorf("access: %s is plain HTTP; remove the tls section, or set access: mtls", c.Access)
	case c.Access == AccessUnsafeOpenTLS && named:
		return errors.New("access: unsafe_open_tls checks no client certificate; remove tls.client_ca and " +
			"tls.client_fingerprints, or set access: mtls")
	}
	if c.Metrics == "" {
		if c.MetricsAccess != "" {
			return errors.New("metrics_access is set without metrics")
		}
	} else {
		if c.MetricsAccess == "" {
			c.MetricsAccess = AccessLocal
		}
		if err := checkAccess("metrics_access", c.MetricsAccess, "metrics", c.Metrics, tlsSet, named); err != nil {
			return err
		}
	}
	if !tlsSet {
		return nil
	}
	if t.Cert == "" || t.Key == "" {
		return errors.New("tls: tls.cert and tls.key go together")
	}
	seen := map[[32]byte]bool{}
	for i, s := range t.ClientFingerprints {
		fp, err := servertls.ParseFingerprint(s)
		if err != nil {
			return fmt.Errorf("tls.client_fingerprints[%d]: %w", i, err)
		}
		if seen[fp] {
			return fmt.Errorf("tls.client_fingerprints[%d]: %s twice", i, s)
		}
		seen[fp] = true
	}
	switch t.MinVersion {
	case "":
		t.MinVersion = "1.3"
	case "1.2", "1.3":
	default:
		return fmt.Errorf("tls.min_version %q: 1.2 or 1.3", t.MinVersion)
	}
	if t.ReloadInterval == 0 {
		t.ReloadInterval = 10 * time.Second
	}
	if t.ReloadInterval < 0 {
		return errors.New("tls.reload_interval must be positive")
	}
	for _, p := range []*string{&t.Cert, &t.Key, &t.ClientCA} {
		if *p != "" && !filepath.IsAbs(*p) {
			*p = filepath.Join(base, *p)
		}
	}

	return nil
}

// ServerTLS is the servertls setting of the tls section; call it only
// when TLSOn.
func (c *Config) ServerTLS() servertls.Settings {
	t := c.TLS
	s := servertls.Settings{CertFile: t.Cert, KeyFile: t.Key, ClientCAFile: t.ClientCA,
		MinVersion: tls.VersionTLS13}
	if t.MinVersion == "1.2" {
		s.MinVersion = tls.VersionTLS12
	}
	for _, f := range t.ClientFingerprints {
		fp, _ := servertls.ParseFingerprint(f) // checked by Load
		s.ClientFingerprints = append(s.ClientFingerprints, fp)
	}

	return s
}

func (c *Config) loadSigners(base string) error {
	s := &c.Signers
	if len(s.Nodes) == 0 {
		return errors.New("signers.nodes is required")
	}
	if s.ClientCert == "" || s.ClientKey == "" {
		return errors.New("signers.client_cert and signers.client_key are required")
	}
	if s.CertReloadInterval == 0 {
		s.CertReloadInterval = 10 * time.Second
	}
	if s.CertReloadInterval < 0 {
		return errors.New("signers.cert_reload_interval must be positive")
	}
	if s.Timeout == 0 {
		s.Timeout = 5 * time.Second
	}
	if s.DialTimeout == 0 {
		s.DialTimeout = 30 * time.Second
	}
	if s.Timeout < 0 || s.DialTimeout < 0 {
		return errors.New("signers.timeout and signers.dial_timeout must be positive")
	}
	if s.Connections == 0 {
		s.Connections = 2
	}
	if s.Connections < 1 || s.Connections > 16 {
		return errors.New("signers.connections must be 1 to 16")
	}
	if s.MaxShareIndex == 0 {
		s.MaxShareIndex = len(s.Nodes)
	}
	if s.MaxShareIndex < len(s.Nodes) || s.MaxShareIndex > 64 {
		return fmt.Errorf("signers.max_share_index must be %d (the number of signers) to 64", len(s.Nodes))
	}
	for _, p := range []*string{&s.ClientCert, &s.ClientKey} {
		if !filepath.IsAbs(*p) {
			*p = filepath.Join(base, *p)
		}
	}
	names := map[string]bool{}
	for i := range s.Nodes {
		n := &s.Nodes[i]
		if n.Name == "" {
			n.Name = fmt.Sprintf("signer-%d", i+1)
		}
		if names[n.Name] {
			return fmt.Errorf("signers.nodes: name %q twice", n.Name)
		}
		names[n.Name] = true
		if n.Address == "" {
			return fmt.Errorf("signers.nodes[%d] (%s): address is required", i, n.Name)
		}
		if n.Attestation.Verifier == "" {
			return fmt.Errorf("signers.nodes[%d] (%s): attestation.verifier is required", i, n.Name)
		}
		if b := n.AllowChainBuild; b != "" {
			if ch, err := runnerchain.Parse(b); err != nil || ch.Prod() {
				return fmt.Errorf("signers.nodes[%d] (%s): allow_chain_build %q is not a non-prod chain (hoodi, devnet or ci-test)", i, n.Name, b)
			}
		}
		if p := &n.Attestation.GCPJWKSFile; *p != "" && !filepath.IsAbs(*p) {
			*p = filepath.Join(base, *p)
		}
	}

	return nil
}

// Connection is the runnerclient connection of signers.nodes[i].
func (c *Config) Connection(i int) runnerclient.Connection {
	n := c.Signers.Nodes[i]

	return runnerclient.Connection{
		Address: n.Address, ClientCert: c.Signers.ClientCert, ClientKey: c.Signers.ClientKey,
		TLSKeyPin: n.TLSKeyPin, Attestation: n.Attestation.Attestation, AllowChainBuild: n.AllowChainBuild,
	}
}

func parseHex(name, s string, out []byte) error {
	b, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
	if err != nil || len(b) != len(out) {
		return fmt.Errorf("invalid %s %q", name, s)
	}
	copy(out, b)

	return nil
}

// GenesisForkVersion parses chain.genesis_fork_version.
func (c *Config) GenesisForkVersion() (phase0.Version, error) {
	var v phase0.Version

	return v, parseHex("chain.genesis_fork_version", c.Chain.GenesisForkVersion, v[:])
}

// ScheduleEntry is a parsed fork schedule entry.
type ScheduleEntry struct {
	Epoch   phase0.Epoch
	Version phase0.Version
}

// Schedule parses the pinned chain: genesis_validators_root, and the fork
// schedule starting with the genesis fork version at epoch 0, then
// chain.forks in order. Fork epochs must not decrease.
func (c *Config) Schedule() (phase0.Root, []ScheduleEntry, error) {
	var gvr phase0.Root
	if err := parseHex("chain.genesis_validators_root", c.Chain.GenesisValidatorsRoot, gvr[:]); err != nil {
		return gvr, nil, err
	}
	genesis, err := c.GenesisForkVersion()
	if err != nil {
		return gvr, nil, err
	}
	sched := []ScheduleEntry{{Epoch: 0, Version: genesis}}
	for i, f := range c.Chain.Forks {
		e := ScheduleEntry{Epoch: phase0.Epoch(f.Epoch)}
		if err := parseHex(fmt.Sprintf("chain.forks[%d].version", i), f.Version, e.Version[:]); err != nil {
			return gvr, nil, err
		}
		if e.Epoch < sched[len(sched)-1].Epoch {
			return gvr, nil, fmt.Errorf("chain.forks[%d]: epoch %d is before the previous fork's", i, f.Epoch)
		}
		sched = append(sched, e)
	}
	if g := c.Chain.GloasForkEpoch; g != nil {
		found := false
		for _, f := range c.Chain.Forks {
			found = found || f.Epoch == *g
		}
		if !found {
			return gvr, nil, fmt.Errorf("chain.gloas_fork_epoch %d is not the epoch of a fork in chain.forks", *g)
		}
	}

	return gvr, sched, nil
}

// CoalesceKeep is how long a shared signature stays stored:
// coalesce.cache_slots times chain.seconds_per_slot.
func (c *Config) CoalesceKeep() time.Duration {
	return time.Duration(*c.Coalesce.CacheSlots*c.Chain.SecondsPerSlot) * time.Second
}

// GloasEpoch is chain.gloas_fork_epoch, nil when absent.
func (c *Config) GloasEpoch() *phase0.Epoch {
	if c.Chain.GloasForkEpoch == nil {
		return nil
	}
	e := phase0.Epoch(*c.Chain.GloasForkEpoch)

	return &e
}
