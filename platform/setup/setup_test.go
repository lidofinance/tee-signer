package setup

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/lidofinance/tee-signer/governance/setupwire"
)

// The sample setups of backend/setupwire, one per platform.
func sample(t *testing.T, platform string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "governance", "setupwire", "testdata", "setup-"+platform+".bin"))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func load(t *testing.T, platform string) *Setup {
	t.Helper()
	s, err := Load(sample(t, platform), platform)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestLoad(t *testing.T) {
	for _, p := range []string{"nitro", "azure", "gcp", "dev"} {
		raw := sample(t, p)
		s, err := Load(raw, p)
		if err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		if h, _ := setupwire.SetupHash(raw); s.SHA256 != h || s.HashHex() == "" || s.Wire.Platform.Platform.String() != p {
			t.Fatalf("%s: hash or platform", p)
		}
		// A setup for another platform is refused, whatever the image.
		for _, other := range []string{"nitro", "azure", "gcp", "dev"} {
			if other == p {
				continue
			}
			if _, err := Load(raw, other); err == nil || !strings.Contains(err.Error(), "this image is "+other) {
				t.Fatalf("%s setup on a %s image: %v", p, other, err)
			}
		}
	}
	raw := sample(t, "nitro")
	for name, bad := range map[string][]byte{
		"empty":         nil,
		"trailing byte": append(slices.Clone(raw), 0),
		"short":         raw[:len(raw)-1],
		"not a setup":   []byte("format = 2\n"),
		"base64":        []byte(base64.StdEncoding.EncodeToString(raw)),
	} {
		if _, err := Load(bad, "nitro"); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
	if _, err := Load(raw, "bogus"); err == nil {
		t.Fatal("unknown image platform accepted")
	}
}

func TestValuesFromTheSetup(t *testing.T) {
	n := load(t, "nitro")
	if n.SlashingLogStore() != "s3:bucket=signer-marks,region=eu-west-1" || n.EncryptedStateStore() != "" || n.SignerID() != "signer-1" ||
		n.MaxKeys() != 1024 {
		t.Fatalf("nitro values: %q %q %q %d", n.SlashingLogStore(), n.EncryptedStateStore(), n.SignerID(), n.MaxKeys())
	}
	a := load(t, "azure")
	if a.SlashingLogStore() != "azblob:account=signermarks,container=marks,subscription=0b2c3d4e-5f60-4718-9a2b-3c4d5e6f7a8b,resource_group=signer-rg" ||
		a.EncryptedStateStore() != a.SlashingLogStore() {
		t.Fatalf("azure stores: %q %q", a.SlashingLogStore(), a.EncryptedStateStore())
	}
	g := load(t, "gcp")
	if g.SlashingLogStore() != "gcs:bucket=signer-marks-gcp" || g.EncryptedStateStore() != "gcs:bucket=signer-state_gcp" {
		t.Fatalf("gcp stores: %q %q", g.SlashingLogStore(), g.EncryptedStateStore())
	}
	d := load(t, "dev")
	if d.SlashingLogStore() != "file:/var/lib/signer/marks" || d.EncryptedStateStore() != "file:/var/lib/signer/state-copy" {
		t.Fatalf("dev stores: %q %q", d.SlashingLogStore(), d.EncryptedStateStore())
	}
	if len(d.Options()) != 0 {
		t.Fatalf("dev options: %v", d.Options())
	}
	// The client CA as PEM, the same certificates in the same order.
	for _, s := range []*Setup{n, a, g, d} {
		rest := s.ClientCAPEM()
		var got [][]byte
		for {
			var blk *pem.Block
			if blk, rest = pem.Decode(rest); blk == nil {
				break
			}
			if _, err := x509.ParseCertificate(blk.Bytes); err != nil || blk.Type != "CERTIFICATE" {
				t.Fatal(err)
			}
			got = append(got, blk.Bytes)
		}
		if len(got) != len(s.Wire.Platform.AllowedClientCA) || !slices.EqualFunc(got, s.Wire.Platform.AllowedClientCA, slices.Equal) {
			t.Fatal("client CA PEM differs from the setup")
		}
	}
	if o := a.Options(); o["maa_endpoint"] != "sharedeus.eus.attest.azure.net" || o["akv_endpoint"] != "signer-kv.vault.azure.net" ||
		o["kid"] != "signer-key" || len(o) != 3 {
		t.Fatalf("azure options %v", o)
	}
	if o := g.Options(); o["kms_key"] == "" || o["wif_provider"] == "" || o["attest_audience"] != "signer-runner-identity" || len(o) != 3 {
		t.Fatalf("gcp options %v", o)
	}
}

// Nitro: the options name the fixed agent and relay, and the routes follow
// from the setup's region and mark bucket over the fixed port map. Nothing
// of the DynamoDB clone guard is left.
func TestNitroOptionsAndRoutes(t *testing.T) {
	n := load(t, "nitro")
	o := n.Options()
	want := map[string]string{"agent": "vsock:3:7101", "region": "eu-west-1",
		"kms_key_id": "arn:aws:kms:eu-west-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab",
		"ntp_relay":  "vsock:3:7102", "record_creds": "record/writer-credentials.kms"}
	for k, v := range want {
		if o[k] != v {
			t.Fatalf("option %s = %q, want %q", k, o[k], v)
		}
	}
	wantProxy := "kms.eu-west-1.amazonaws.com:443=vsock:3:8000,sts.eu-west-1.amazonaws.com:443=vsock:3:8001," +
		"www.cloudflare.com:443=vsock:3:8002,signer-marks.s3.eu-west-1.amazonaws.com:443=vsock:3:8004," +
		"time.cloudflare.com:4460=vsock:3:8005,nts.netnod.se:4460=vsock:3:8006,ptbtime1.ptb.de:4460=vsock:3:8007," +
		"ntppool1.time.nl:4460=vsock:3:8008"
	if o["proxy"] != wantProxy {
		t.Fatalf("proxy\n%s\nwant\n%s", o["proxy"], wantProxy)
	}
	if strings.Contains(o["proxy"], "8003") || strings.Contains(o["proxy"], "dynamodb") || len(o) != 6 {
		t.Fatalf("options %v", o)
	}
	lines, err := NitroProxyLines(n)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(lines, "8000 kms.eu-west-1.amazonaws.com 443\n") ||
		!strings.Contains(lines, "8004 signer-marks.s3.eu-west-1.amazonaws.com 443\n") ||
		strings.Count(lines, "\n") != 8 {
		t.Fatalf("proxy lines:\n%s", lines)
	}
	if _, err := NitroProxyLines(load(t, "gcp")); err == nil {
		t.Fatal("proxy lines of a gcp setup")
	}
	// Every port of the map is distinct, and none is the agent's or the relay's.
	seen := map[uint32]bool{7101: true, 7102: true}
	routes, err := NitroRoutes(&n.Wire.Platform)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range routes {
		if seen[r.Port] {
			t.Fatalf("port %d twice", r.Port)
		}
		seen[r.Port] = true
	}
}

func TestMergeOptions(t *testing.T) {
	got, err := MergeOptions(map[string]string{"region": "r"}, map[string]string{"clock": "nsm"})
	if err != nil || got["region"] != "r" || got["clock"] != "nsm" {
		t.Fatal(got, err)
	}
	if _, err := MergeOptions(map[string]string{"kms_key_id": "a"}, map[string]string{"kms_key_id": "b"}); err == nil ||
		!strings.Contains(err.Error(), "kms_key_id") {
		t.Fatalf("an image option over a setup one: %v", err)
	}
}

func TestEnvChannel(t *testing.T) {
	raw := sample(t, "azure")
	env := map[string]string{}
	ch := Env{Name: EnvVar, Lookup: func(k string) (string, bool) { v, ok := env[k]; return v, ok }}
	if _, err := ch.Read(context.Background()); err == nil || !strings.Contains(err.Error(), "SIGNER_SETUP is not set") {
		t.Fatalf("unset: %v", err)
	}
	env[EnvVar] = base64.StdEncoding.EncodeToString(raw) + "\n"
	got, err := ch.Read(context.Background())
	if err != nil || !slices.Equal(got, raw) {
		t.Fatalf("read: %v", err)
	}
	for name, v := range map[string]string{
		"empty":       "",
		"not base64":  "%%%",
		"url base64":  base64.URLEncoding.EncodeToString([]byte{0xfb, 0xff}),
		"no padding":  base64.RawStdEncoding.EncodeToString(raw[:10]),
		"above limit": strings.Repeat("A", maxBase64+4),
	} {
		env[EnvVar] = v
		if _, err := ch.Read(context.Background()); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
	if ch.String() != "env SIGNER_SETUP" {
		t.Fatal(ch.String())
	}
	// The real environment.
	t.Setenv(EnvVar, base64.StdEncoding.EncodeToString(raw))
	if got, err := (Env{Name: EnvVar}).Read(context.Background()); err != nil || !slices.Equal(got, raw) {
		t.Fatalf("os environment: %v", err)
	}
}

func TestFileChannel(t *testing.T) {
	dir := t.TempDir()
	raw := sample(t, "dev")
	p := filepath.Join(dir, "setup.bin")
	if err := os.WriteFile(p, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := File{Path: p}.Read(context.Background())
	if err != nil || !slices.Equal(got, raw) {
		t.Fatal(err)
	}
	big := filepath.Join(dir, "big.bin")
	if err := os.WriteFile(big, make([]byte, setupwire.MaxSetup+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := (File{Path: big}).Read(context.Background()); err == nil {
		t.Fatal("a file above the setup cap was read")
	}
	if _, err := (File{Path: filepath.Join(dir, "none")}).Read(context.Background()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing file: %v", err)
	}
}

func TestParseSource(t *testing.T) {
	if f, err := ParseSource("platform"); err != nil || f != "" {
		t.Fatal(f, err)
	}
	if f, err := ParseSource("file:/x/setup.bin"); err != nil || f != "/x/setup.bin" {
		t.Fatal(f, err)
	}
	for _, bad := range []string{"", "file:", "env", "Platform", "agent:vsock:3:7101"} {
		if _, err := ParseSource(bad); err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
}

// withPeers is the sample setup of platform p with the peer endpoints e,
// encoded again.
func withPeers(t *testing.T, p string, e ...string) []byte {
	t.Helper()
	s, err := setupwire.DecodeSetup(sample(t, p))
	if err != nil {
		t.Fatal(err)
	}
	s.Platform.KeygenPeerAttestationHosts = e
	b, err := s.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Nitro with keygen_peer_attestation_hosts: each endpoint gets a port of the peer block,
// in the setup's order, in the runner's proxy option and in the parent's
// route lines alike. Nothing else gets a route.
func TestNitroPeerRoutes(t *testing.T) {
	n, err := Load(sample(t, "nitro-peers"), "nitro")
	if err != nil {
		t.Fatal(err)
	}
	peers := ",confidentialcomputing.googleapis.com:443=vsock:3:8010,sharedneu.neu.attest.azure.net:443=vsock:3:8011," +
		"www.googleapis.com:443=vsock:3:8012"
	plain := load(t, "nitro").Options()["proxy"]
	if got := n.Options()["proxy"]; got != plain+peers {
		t.Fatalf("proxy\n%s\nwant\n%s", got, plain+peers)
	}
	lines, err := NitroProxyLines(n)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(lines, "8008 ntppool1.time.nl 4460\n8010 confidentialcomputing.googleapis.com 443\n"+
		"8011 sharedneu.neu.attest.azure.net 443\n8012 www.googleapis.com 443\n") || strings.Count(lines, "\n") != 11 {
		t.Fatalf("proxy lines:\n%s", lines)
	}
	if e, limited := PeerEgress(n.Wire); !limited || len(e) != 3 {
		t.Fatalf("peer egress %v %v", e, limited)
	}

	// The full block: 16 endpoints on 8010 to 8025, apart from every
	// fixed port.
	var e []string
	for i := range NitroPeerPorts {
		e = append(e, fmt.Sprintf("h%02d.example:443", i))
	}
	full, err := Load(withPeers(t, "nitro", e...), "nitro")
	if err != nil {
		t.Fatal(err)
	}
	routes, _ := NitroRoutes(&full.Wire.Platform)
	seen := map[uint32]bool{7101: true, 7102: true}
	for _, r := range routes {
		if seen[r.Port] {
			t.Fatalf("port %d twice", r.Port)
		}
		seen[r.Port] = true
	}
	if last := routes[len(routes)-1]; last.Port != 8025 || last.Host != "h15.example" {
		t.Fatalf("last route %+v", last)
	}
	// More endpoints than the block holds: the host agent and the runner
	// refuse the setup (the codec's cap is the same 16, so only a setup
	// made past the codec gets here).
	p := full.Wire.Platform
	p.KeygenPeerAttestationHosts = append(slices.Clone(e), "h16.example:443")
	if _, err := NitroRoutes(&p); err == nil || !strings.Contains(err.Error(), "17 keygen_peer_attestation_hosts, but the nitro port map has 16 ports for them (8010 to 8025)") {
		t.Fatalf("17 endpoints: %v", err)
	}
	// An endpoint that a fixed route serves is refused, not routed twice.
	if _, err := Load(withPeers(t, "nitro", "www.cloudflare.com:443"), "nitro"); err == nil ||
		!strings.Contains(err.Error(), "www.cloudflare.com:443 is the fixed route of port 8002") {
		t.Fatalf("fixed route as a peer endpoint: %v", err)
	}
	// A Nitro setup without the list: limited egress, no peer endpoint.
	if e, limited := PeerEgress(load(t, "nitro").Wire); !limited || len(e) != 0 {
		t.Fatalf("nitro without peers: %v %v", e, limited)
	}
}

// dev: a setup with keygen_peer_attestation_hosts limits the runner's HTTP client to them
// (option egress); without them, and on Azure and GCP, egress is not
// limited.
func TestDevPeerEgress(t *testing.T) {
	d, err := Load(withPeers(t, "dev", "127.0.0.1:8443", "maa.test:443"), "dev")
	if err != nil {
		t.Fatal(err)
	}
	if o := d.Options(); len(o) != 1 || o["egress"] != "127.0.0.1:8443,maa.test:443" {
		t.Fatalf("dev options %v", o)
	}
	if e, limited := PeerEgress(d.Wire); !limited || len(e) != 2 {
		t.Fatalf("dev with peers: %v %v", e, limited)
	}
	for _, p := range []string{"dev", "azure", "gcp"} {
		if e, limited := PeerEgress(load(t, p).Wire); limited || e != nil {
			t.Fatalf("%s: %v %v", p, e, limited)
		}
	}
	if o := load(t, "dev").Options(); len(o) != 0 {
		t.Fatalf("dev options without peers %v", o)
	}
}
