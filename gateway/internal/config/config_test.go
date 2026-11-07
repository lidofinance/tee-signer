package config

import (
	"crypto/tls"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/attestantio/go-eth2-client/spec/phase0"
)

const base = `signers:
  client_cert: c.crt
  client_key: c.key
  nodes:
    - {address: "tcp:127.0.0.1:1", attestation: {verifier: dev}}
    - {address: "tcp:127.0.0.1:2", attestation: {verifier: dev}}
    - {address: "tcp:127.0.0.1:3", attestation: {verifier: dev}}
`

func load(t *testing.T, chain string) (*Config, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "gateway.yml")
	if err := os.WriteFile(path, []byte(chain+base), 0o600); err != nil {
		t.Fatal(err)
	}

	return Load(path)
}

func TestChainPinRequiredAndParsed(t *testing.T) {
	if _, err := load(t, "chain:\n  preset: mainnet\n"); err == nil || !strings.Contains(err.Error(), "genesis_validators_root is required") {
		t.Fatalf("no genesis_validators_root: %v", err)
	}
	c, err := load(t, `chain:
  genesis_fork_version: "0x00000000"
  genesis_validators_root: "0x4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95"
  forks:
    - {epoch: 74240, version: "0x01000000"}
    - {epoch: 144896, version: "0x02000000"}
`)
	if err != nil {
		t.Fatal(err)
	}
	gvr, sched, err := c.Schedule()
	if err != nil || gvr[0] != 0x4b || len(sched) != 3 ||
		sched[0] != (ScheduleEntry{0, phase0.Version{}}) || sched[2] != (ScheduleEntry{144896, phase0.Version{2}}) {
		t.Fatalf("schedule %v %v %v", gvr, sched, err)
	}
	for name, chain := range map[string]string{
		"short root":       "chain:\n  genesis_validators_root: \"0x4b36\"\n",
		"bad fork version": "chain:\n  genesis_validators_root: \"0x" + strings.Repeat("00", 32) + "\"\n  forks: [{epoch: 1, version: \"0x01\"}]\n",
		"epochs going back": "chain:\n  genesis_validators_root: \"0x" + strings.Repeat("00", 32) + "\"\n" +
			"  forks: [{epoch: 5, version: \"0x01000000\"}, {epoch: 4, version: \"0x02000000\"}]\n",
	} {
		if _, err := load(t, chain); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// Coalescing is on by default and keeps results for two 12 s slots; the
// config can turn it off, change the slots or the slot time.
func TestCoalesceSettings(t *testing.T) {
	pin := "chain:\n  genesis_validators_root: \"0x" + strings.Repeat("00", 32) + "\"\n"
	c, err := load(t, pin)
	if err != nil {
		t.Fatal(err)
	}
	if !*c.Coalesce.Enabled || c.CoalesceKeep() != 24*time.Second {
		t.Fatalf("defaults: enabled %v, keep %v", *c.Coalesce.Enabled, c.CoalesceKeep())
	}
	c, err = load(t, pin+"  seconds_per_slot: 6\ncoalesce:\n  enabled: false\n  cache_slots: 0\n")
	if err != nil {
		t.Fatal(err)
	}
	if *c.Coalesce.Enabled || c.CoalesceKeep() != 0 {
		t.Fatalf("off: enabled %v, keep %v", *c.Coalesce.Enabled, c.CoalesceKeep())
	}
	c, err = load(t, pin+"  seconds_per_slot: 6\ncoalesce:\n  cache_slots: 3\n")
	if err != nil {
		t.Fatal(err)
	}
	if !*c.Coalesce.Enabled || c.CoalesceKeep() != 18*time.Second {
		t.Fatalf("3 slots of 6 s: enabled %v, keep %v", *c.Coalesce.Enabled, c.CoalesceKeep())
	}
	if _, err := load(t, pin+"coalesce:\n  enable: true\n"); err == nil {
		t.Fatal("a misspelt coalesce key was accepted")
	}
}

const pin = "chain:\n  genesis_validators_root: \"0x" + "4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95" + "\"\n"

func loadRaw(t *testing.T, body string) (*Config, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "gateway.yml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	return Load(path)
}

// allow_chain_build takes a non-prod chain only and reaches the
// connection; the old allow_testnet_build key is refused.
func TestAllowChainBuild(t *testing.T) {
	node := func(extra string) string {
		return pin + `signers:
  client_cert: c.crt
  client_key: c.key
  nodes:
    - {address: "tcp:127.0.0.1:1", attestation: {verifier: dev}` + extra + "}" + `
`
	}
	c, err := loadRaw(t, node(", allow_chain_build: hoodi"))
	if err != nil {
		t.Fatal(err)
	}
	if got := c.Connection(0).AllowChainBuild; got != "hoodi" {
		t.Fatalf("allow_chain_build %q, want hoodi", got)
	}
	for _, extra := range []string{", allow_chain_build: mainnet", ", allow_chain_build: sepolia", ", allow_testnet_build: true"} {
		if _, err := loadRaw(t, node(extra)); err == nil {
			t.Errorf("%s: accepted", extra)
		}
	}
}

// The signers section: defaults, relative paths, the attestation settings
// under runnerclient's names, and the refusals.
func TestSignersSettings(t *testing.T) {
	c, err := load(t, pin)
	if err != nil {
		t.Fatal(err)
	}
	s := c.Signers
	if s.Timeout != 5*time.Second || s.DialTimeout != 30*time.Second || s.Connections != 2 || s.MaxShareIndex != 3 ||
		s.CertReloadInterval != 10*time.Second {
		t.Fatalf("defaults: %+v", s)
	}
	if s.Nodes[2].Name != "signer-3" || !filepath.IsAbs(s.ClientCert) || !filepath.IsAbs(s.ClientKey) {
		t.Fatalf("names and paths: %+v", s)
	}
	conn := c.Connection(1)
	if conn.Address != "tcp:127.0.0.1:2" || conn.ClientCert != s.ClientCert || conn.Attestation.Verifier != "dev" {
		t.Fatalf("connection %+v", conn)
	}

	c, err = loadRaw(t, pin+`signers:
  client_cert: /c.crt
  client_key: /c.key
  timeout: 2s
  cert_reload_interval: 1m
  connections: 4
  max_share_index: 5
  nodes:
    - name: azure
      address: tcp:10.0.0.1:7000
      tls_key_pin: "`+strings.Repeat("ab", 32)+`"
      attestation:
        verifier: azure-maa
        maa_host: example.attest.azure.net
        cce_policy_sha256: "`+strings.Repeat("11", 32)+`"
        setup_sha256: "`+strings.Repeat("22", 32)+`"
        key_release_sha256: "`+strings.Repeat("33", 32)+`"
        mainnet: true
    - name: aws
      address: tcp:10.0.0.2:7000
      attestation:
        verifier: aws-nitro
        nitro_pcrs: {"0": "`+strings.Repeat("44", 48)+`", "1": "`+strings.Repeat("55", 48)+`", "2": "`+strings.Repeat("66", 48)+`"}
`)
	if err != nil {
		t.Fatal(err)
	}
	a := c.Signers.Nodes[0].Attestation.Attestation
	if a.MAAHost != "example.attest.azure.net" || !a.Mainnet || a.KeyReleaseSHA256 != strings.Repeat("33", 32) ||
		c.Signers.Nodes[0].TLSKeyPin != strings.Repeat("ab", 32) || c.Signers.Timeout != 2*time.Second || c.Signers.Connections != 4 ||
		c.Signers.CertReloadInterval != time.Minute {
		t.Fatalf("azure node: %+v", c.Signers)
	}
	if p := c.Signers.Nodes[1].Attestation.NitroPCRs; len(p) != 3 || p["1"] != strings.Repeat("55", 48) {
		t.Fatalf("nitro pcrs %v", p)
	}

	for name, body := range map[string]string{
		"no nodes":              pin + "signers:\n  client_cert: c\n  client_key: k\n",
		"negative reload":       pin + "signers:\n  client_cert: c\n  client_key: k\n  cert_reload_interval: -1s\n  nodes: [{address: tcp:127.0.0.1:1, attestation: {verifier: dev}}]\n",
		"negative timeout":      pin + "signers:\n  client_cert: c\n  client_key: k\n  timeout: -1s\n  nodes: [{address: tcp:127.0.0.1:1, attestation: {verifier: dev}}]\n",
		"negative dial timeout": pin + "signers:\n  client_cert: c\n  client_key: k\n  dial_timeout: -1s\n  nodes: [{address: tcp:127.0.0.1:1, attestation: {verifier: dev}}]\n",
		"no client cert":        pin + "signers:\n  nodes: [{address: \"tcp:1:1\", attestation: {verifier: dev}}]\n",
		"no address":            pin + "signers:\n  client_cert: c\n  client_key: k\n  nodes: [{attestation: {verifier: dev}}]\n",
		"no verifier":           pin + "signers:\n  client_cert: c\n  client_key: k\n  nodes: [{address: \"tcp:1:1\"}]\n",
		"unknown attestation":   pin + "signers:\n  client_cert: c\n  client_key: k\n  nodes: [{address: \"tcp:1:1\", attestation: {verifier: dev, pcr0: x}}]\n",
		"same name twice": pin + "signers:\n  client_cert: c\n  client_key: k\n  nodes: [{name: a, address: \"tcp:1:1\", attestation: {verifier: dev}}," +
			" {name: a, address: \"tcp:1:2\", attestation: {verifier: dev}}]\n",
		"share index below the signers": pin + "signers:\n  client_cert: c\n  client_key: k\n  max_share_index: 1\n" +
			"  nodes: [{address: \"tcp:1:1\", attestation: {verifier: dev}}, {address: \"tcp:1:2\", attestation: {verifier: dev}}]\n",
		"an unknown section": pin + "backend:\n  wallet: W\n",
	} {
		if _, err := loadRaw(t, body); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// metrics is off without the key, and must be HOST:PORT other than listen.
func TestMetricsSetting(t *testing.T) {
	const pin = "chain:\n  genesis_validators_root: \"0x4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95\"\n"
	c, err := load(t, pin)
	if err != nil || c.Metrics != "" {
		t.Fatalf("default: %q %v", c.Metrics, err)
	}
	if c, err = load(t, "metrics: 127.0.0.1:19001\n"+pin); err != nil || c.Metrics != "127.0.0.1:19001" {
		t.Fatalf("set: %v", err)
	}
	for _, bad := range []string{"metrics: 19001\n", "metrics: 127.0.0.1:19000\n"} {
		if _, err := load(t, bad+pin); err == nil || !strings.Contains(err.Error(), "metrics") {
			t.Fatalf("%q: %v", bad, err)
		}
	}
}

// The tls section: defaults, relative paths, fingerprints, and the
// refusals of its own fields.
func TestTLSSettings(t *testing.T) {
	fp := strings.Repeat("ab", 32)
	fpColons := strings.ToUpper(strings.TrimSuffix(strings.Repeat("CD:", 32), ":"))
	c, err := load(t, pin+"listen: 0.0.0.0:19000\ntls:\n  cert: s.pem\n  key: s-key.pem\n  client_ca: ca.pem\n")
	if err != nil {
		t.Fatal(err)
	}
	if !c.TLSOn() || c.Access != AccessMTLS || c.TLS.MinVersion != "1.3" || c.TLS.ReloadInterval != 10*time.Second ||
		!filepath.IsAbs(c.TLS.Cert) || !filepath.IsAbs(c.TLS.Key) || !filepath.IsAbs(c.TLS.ClientCA) {
		t.Fatalf("defaults: %s %+v", c.Access, c.TLS)
	}
	s := c.ServerTLS()
	if s.MinVersion != tls.VersionTLS13 || s.ClientCAFile != c.TLS.ClientCA || len(s.ClientFingerprints) != 0 {
		t.Fatalf("settings: %+v", s)
	}
	c, err = load(t, pin+"listen: \"[::]:19000\"\ntls:\n  cert: /s.pem\n  key: /s-key.pem\n  min_version: \"1.2\"\n  reload_interval: 1m\n"+
		"  client_fingerprints: [\""+fp+"\", \""+fpColons+"\"]\n")
	if err != nil {
		t.Fatal(err)
	}
	s = c.ServerTLS()
	if s.MinVersion != tls.VersionTLS12 || s.ClientCAFile != "" || len(s.ClientFingerprints) != 2 || s.ClientFingerprints[0][0] != 0xab ||
		s.ClientFingerprints[1][31] != 0xcd || c.TLS.ReloadInterval != time.Minute || c.TLS.Cert != "/s.pem" {
		t.Fatalf("fingerprints: %+v %+v", c.TLS, s)
	}

	for name, body := range map[string]string{
		"listen not HOST:PORT":      "listen: 19000\n",
		"key without cert":          "tls:\n  key: k.pem\n  client_ca: ca.pem\n",
		"cert without key":          "tls:\n  cert: s.pem\n  client_ca: ca.pem\n",
		"client_ca without cert":    "tls:\n  client_ca: ca.pem\n",
		"fingerprints without cert": "tls:\n  client_fingerprints: [\"" + fp + "\"]\n",
		"min_version without cert":  "tls:\n  min_version: \"1.3\"\n",
		"reload without cert":       "tls:\n  reload_interval: 1s\n",
		"short fingerprint":         "tls:\n  cert: s.pem\n  key: k.pem\n  client_fingerprints: [\"abcd\"]\n",
		"fingerprint not hex":       "tls:\n  cert: s.pem\n  key: k.pem\n  client_fingerprints: [\"" + strings.Repeat("zz", 32) + "\"]\n",
		"same fingerprint twice": "tls:\n  cert: s.pem\n  key: k.pem\n  client_fingerprints: [\"" + fp + "\", \"" +
			strings.ToUpper(fp) + "\"]\n",
		"min_version 1.1": "tls:\n  cert: s.pem\n  key: k.pem\n  client_ca: ca.pem\n  min_version: \"1.1\"\n",
		"negative reload": "tls:\n  cert: s.pem\n  key: k.pem\n  client_ca: ca.pem\n  reload_interval: -1s\n",
		"unknown tls key": "tls:\n  cert: s.pem\n  key: k.pem\n  client_ca: ca.pem\n  verify_client: false\n",
		// The booleans access replaced: unknown keys.
		"old insecure_no_client_auth":        "tls:\n  cert: s.pem\n  key: k.pem\n  insecure_no_client_auth: true\n",
		"old insecure_plain_http_on_network": "listen: 0.0.0.0:1\ninsecure_plain_http_on_network: true\n",
	} {
		if _, err := load(t, pin+body); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// access and metrics_access: each value with the address and the tls
// section it needs, the defaults, and every refusal on both listeners.
func TestAccess(t *testing.T) {
	const (
		tlsCA   = "tls:\n  cert: s.pem\n  key: k.pem\n  client_ca: ca.pem\n"
		tlsFP   = "tls:\n  cert: s.pem\n  key: k.pem\n  client_fingerprints: [\"" + "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" + "\"]\n"
		tlsOnly = "tls:\n  cert: s.pem\n  key: k.pem\n"
		net     = "listen: 0.0.0.0:19000\n"
		mNet    = "metrics: 0.0.0.0:19001\n"
		mLocal  = "metrics: 127.0.0.1:19001\n"
	)
	for _, tc := range []struct{ name, body, access, metrics string }{
		{"defaults, no metrics", "", AccessLocal, ""},
		{"defaults with metrics", mLocal, AccessLocal, AccessLocal},
		{"local on localhost", "listen: localhost:19000\naccess: local\n", AccessLocal, ""},
		{"local on ::1", "listen: \"[::1]:19000\"\n", AccessLocal, ""},
		{"local on 127.0.0.2", "listen: 127.0.0.2:19000\n", AccessLocal, ""},
		{"tls gives mtls", net + tlsCA, AccessMTLS, ""},
		{"mtls by fingerprints", net + "access: mtls\n" + tlsFP, AccessMTLS, ""},
		{"mtls on loopback", "access: mtls\n" + tlsCA, AccessMTLS, ""},
		{"unsafe_open_tls", net + "access: unsafe_open_tls\n" + tlsOnly, AccessUnsafeOpenTLS, ""},
		{"unsafe_plain_http", net + "access: unsafe_plain_http\n", AccessUnsafePlainHTTP, ""},
		{"unsafe_plain_http on loopback", "access: unsafe_plain_http\n", AccessUnsafePlainHTTP, ""},
		{"metrics local, API mtls", net + tlsCA + mLocal, AccessMTLS, AccessLocal},
		{"metrics mtls", net + tlsCA + mNet + "metrics_access: mtls\n", AccessMTLS, AccessMTLS},
		{"metrics unsafe_open_tls, API mtls", net + tlsCA + mNet + "metrics_access: unsafe_open_tls\n", AccessMTLS, AccessUnsafeOpenTLS},
		{"metrics unsafe_open_tls, API unsafe_open_tls", net + "access: unsafe_open_tls\n" + tlsOnly + mNet +
			"metrics_access: unsafe_open_tls\n", AccessUnsafeOpenTLS, AccessUnsafeOpenTLS},
		{"metrics unsafe_plain_http, API local", mNet + "metrics_access: unsafe_plain_http\n", AccessLocal, AccessUnsafePlainHTTP},
		{"metrics unsafe_plain_http, API mtls", net + tlsCA + mNet + "metrics_access: unsafe_plain_http\n", AccessMTLS, AccessUnsafePlainHTTP},
	} {
		c, err := loadRaw(t, devnetPin+tc.body+devnetBase)
		if err != nil {
			t.Errorf("%s: %v", tc.name, err)
			continue
		}
		if c.Access != tc.access || c.MetricsAccess != tc.metrics || c.TLSOn() != UsesTLS(tc.access) {
			t.Errorf("%s: access %q metrics_access %q tls %v", tc.name, c.Access, c.MetricsAccess, c.TLSOn())
		}
	}

	for _, tc := range []struct{ name, body, want string }{
		{"default local on 0.0.0.0", net, "access: local is plain HTTP and needs a loopback listen"},
		{"local on every interface", "listen: \":19000\"\n", "needs a loopback listen"},
		{"local on [::]", "listen: \"[::]:19000\"\n", "needs a loopback listen"},
		{"local on a LAN address", "listen: 192.168.1.10:19000\n", "needs a loopback listen"},
		{"local on a host name", "listen: gateway.lan:19000\n", "needs a loopback listen"},
		{"local with tls", "access: local\n" + tlsCA, "access: local is plain HTTP"},
		{"unsafe_plain_http with tls", net + "access: unsafe_plain_http\n" + tlsCA, "access: unsafe_plain_http is plain HTTP"},
		{"mtls without tls", net + "access: mtls\n", "access: mtls needs tls.cert and tls.key"},
		{"mtls naming no client", net + tlsOnly, "access: mtls needs the clients"},
		{"unsafe_open_tls without tls", net + "access: unsafe_open_tls\n", "access: unsafe_open_tls needs tls.cert"},
		{"unsafe_open_tls with client_ca", net + "access: unsafe_open_tls\n" + tlsCA, "unsafe_open_tls checks no client certificate"},
		{"unsafe_open_tls with fingerprints", net + "access: unsafe_open_tls\n" + tlsFP, "unsafe_open_tls checks no client certificate"},
		{"unknown access", "access: open\n", "access \"open\""},
		{"access in capitals", "access: MTLS\n" + tlsCA, "access \"MTLS\""},
		{"metrics local on 0.0.0.0", mNet, "metrics_access: local is plain HTTP and needs a loopback metrics"},
		{"metrics local on a LAN address, API mtls", net + tlsCA + "metrics: 10.0.0.5:19001\n", "needs a loopback metrics"},
		{"metrics mtls without tls", mNet + "metrics_access: mtls\n", "metrics_access: mtls needs tls.cert"},
		{"metrics mtls naming no client", net + "access: unsafe_open_tls\n" + tlsOnly + mNet + "metrics_access: mtls\n",
			"metrics_access: mtls needs the clients"},
		{"metrics unsafe_open_tls without tls", mNet + "metrics_access: unsafe_open_tls\n", "metrics_access: unsafe_open_tls needs tls.cert"},
		{"unknown metrics_access", mLocal + "metrics_access: public\n", "metrics_access \"public\""},
		{"metrics_access without metrics", "metrics_access: local\n", "metrics_access is set without metrics"},
	} {
		if _, err := load(t, pin+tc.body); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want %q", tc.name, err, tc.want)
		}
	}
}

// devnetPin pins a devnet chain: the devnet row's fork version and a root
// of no public network.
const devnetPin = "chain:\n  genesis_fork_version: \"0x10000038\"\n  genesis_validators_root: \"0x" +
	"1111111111111111111111111111111111111111111111111111111111111111" + "\"\n"

// devnetBase is base with non-prod signers only.
const devnetBase = `signers:
  client_cert: c.crt
  client_key: c.key
  nodes:
    - {address: "tcp:127.0.0.1:1", allow_chain_build: devnet, attestation: {verifier: dev}}
    - {address: "tcp:127.0.0.1:2", allow_chain_build: devnet, attestation: {verifier: dev}}
`

// With a signer that can sign for mainnet, or on a prod chain, access
// refuses the unsafe values; metrics_access keeps them.
func TestUnsafeAccessOnMainnet(t *testing.T) {
	const (
		openTLS   = "listen: 0.0.0.0:19000\naccess: unsafe_open_tls\ntls:\n  cert: s.pem\n  key: k.pem\n"
		plainHTTP = "listen: 0.0.0.0:19000\naccess: unsafe_plain_http\n"
		plainLoop = "access: unsafe_plain_http\n"
		head      = "signers:\n  client_cert: c.crt\n  client_key: c.key\n  nodes:\n" +
			"    - {address: \"tcp:127.0.0.1:1\", allow_chain_build: devnet, attestation: {verifier: dev}}\n"
		noAllow     = head + "    - {name: prod, address: \"tcp:127.0.0.1:2\", attestation: {verifier: dev}}\n"
		mainnetFlag = head + "    - {name: prod, address: \"tcp:127.0.0.1:2\", allow_chain_build: hoodi, " +
			"attestation: {verifier: dev, mainnet: true}}\n"
	)
	for _, listener := range []string{openTLS, plainHTTP, plainLoop} {
		if _, err := loadRaw(t, devnetPin+listener+devnetBase); err != nil {
			t.Errorf("non-prod signers, %q: %v", listener, err)
		}
		if _, err := loadRaw(t, pin+listener+devnetBase); err == nil || !strings.Contains(err.Error(), "is refused on a prod chain") {
			t.Errorf("non-prod signers on mainnet, %q: %v", listener, err)
		}
		for want, signers := range map[string]string{
			"signers.nodes[1] (prod): it has no allow_chain_build":     noAllow,
			"signers.nodes[1] (prod): attestation.mainnet is true":     mainnetFlag,
			"signers.nodes[0] (signer-1): it has no allow_chain_build": base,
		} {
			_, err := loadRaw(t, pin+listener+signers)
			if err == nil || !strings.Contains(err.Error(), "is refused with a mainnet signer") || !strings.Contains(err.Error(), want) {
				t.Errorf("%q with %q: %v", listener, want, err)
			}
		}
	}
	mtls := "listen: 0.0.0.0:19000\ntls:\n  cert: s.pem\n  key: k.pem\n  client_ca: ca.pem\nmetrics: 0.0.0.0:19001\n"
	for _, m := range []string{AccessUnsafeOpenTLS, AccessUnsafePlainHTTP} {
		if c, err := loadRaw(t, pin+mtls+"metrics_access: "+m+"\n"+noAllow); err != nil || c.MetricsAccess != m {
			t.Errorf("metrics_access %s with a mainnet signer: %v", m, err)
		}
	}
}

func TestLoopback(t *testing.T) {
	for addr, want := range map[string]bool{
		"127.0.0.1:1": true, "127.9.9.9:1": true, "localhost:1": true, "[::1]:1": true,
		"0.0.0.0:1": false, ":1": false, "[::]:1": false, "10.0.0.1:1": false, "gateway.lan:1": false, "127.0.0.1": false,
	} {
		if got := Loopback(addr); got != want {
			t.Errorf("Loopback(%q) = %v", addr, got)
		}
	}
}

// At most 8 signers and share indices up to 8: the search for share
// indices grows fast with both.
func TestSignersLimit(t *testing.T) {
	cfg := func(nodes int, extra string) string {
		s := pin + "signers:\n  client_cert: c\n  client_key: k\n" + extra + "  nodes:\n"
		for i := 1; i <= nodes; i++ {
			s += fmt.Sprintf("    - {address: \"tcp:127.0.0.1:%d\", attestation: {verifier: dev}}\n", i)
		}

		return s
	}
	c, err := loadRaw(t, cfg(8, "  max_share_index: 8\n"))
	if err != nil || len(c.Signers.Nodes) != 8 || c.Signers.MaxShareIndex != 8 {
		t.Fatalf("8 signers, max_share_index 8: %v", err)
	}
	if c, err = loadRaw(t, cfg(8, "")); err != nil || c.Signers.MaxShareIndex != 8 {
		t.Fatalf("8 signers, default max_share_index: %v", err)
	}
	for name, c := range map[string]struct {
		body, want string
	}{
		"9 signers":          {cfg(9, ""), "signers: at most 8"},
		"max_share_index 9":  {cfg(3, "  max_share_index: 9\n"), "must be 3 (the number of signers) to 8"},
		"max_share_index 64": {cfg(3, "  max_share_index: 64\n"), "must be 3 (the number of signers) to 8"},
	} {
		if _, err := loadRaw(t, c.body); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", name, err, c.want)
		}
	}
}
