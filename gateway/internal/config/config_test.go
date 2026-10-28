package config

import (
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
		"no nodes":            pin + "signers:\n  client_cert: c\n  client_key: k\n",
		"negative reload":     pin + "signers:\n  client_cert: c\n  client_key: k\n  cert_reload_interval: -1s\n  nodes: [{address: tcp:127.0.0.1:1, attestation: {verifier: dev}}]\n",
		"no client cert":      pin + "signers:\n  nodes: [{address: \"tcp:1:1\", attestation: {verifier: dev}}]\n",
		"no address":          pin + "signers:\n  client_cert: c\n  client_key: k\n  nodes: [{attestation: {verifier: dev}}]\n",
		"no verifier":         pin + "signers:\n  client_cert: c\n  client_key: k\n  nodes: [{address: \"tcp:1:1\"}]\n",
		"unknown attestation": pin + "signers:\n  client_cert: c\n  client_key: k\n  nodes: [{address: \"tcp:1:1\", attestation: {verifier: dev, pcr0: x}}]\n",
		"same name twice": pin + "signers:\n  client_cert: c\n  client_key: k\n  nodes: [{name: a, address: \"tcp:1:1\", attestation: {verifier: dev}}," +
			" {name: a, address: \"tcp:1:2\", attestation: {verifier: dev}}]\n",
		"share index below the signers": pin + "signers:\n  client_cert: c\n  client_key: k\n  max_share_index: 1\n" +
			"  nodes: [{address: \"tcp:1:1\", attestation: {verifier: dev}}, {address: \"tcp:1:2\", attestation: {verifier: dev}}]\n",
		"the old dirk section": pin + "dirk:\n  wallet: W\n",
	} {
		if _, err := loadRaw(t, body); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
