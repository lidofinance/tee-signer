package setup

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/lidofinance/tee-signer/governance/setupwire"
)

// sample is the sample setup setup-<name> of governance/setupwire. The
// name starts with the platform: nitro, gcp-single, dev-threshold.
func sample(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "governance", "setupwire", "testdata", "setup-"+name+".bin"))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// platformOf is the platform of sample name.
func platformOf(name string) string {
	p, _, _ := strings.Cut(name, "-")
	return p
}

func load(t *testing.T, name string) *Setup {
	t.Helper()
	s, err := Load(sample(t, name), platformOf(name))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestLoad(t *testing.T) {
	for _, name := range []string{"nitro", "azure", "gcp", "gcp-single", "dev-single", "dev-threshold"} {
		p := platformOf(name)
		raw := sample(t, name)
		s, err := Load(raw, p)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if h, _ := setupwire.SetupHash(raw); s.SHA256 != h || s.HashHex() == "" || s.Wire.Platform.Platform.String() != p {
			t.Fatalf("%s: hash or platform", name)
		}
		// A setup for another platform is refused, whatever the image.
		for _, other := range []string{"nitro", "azure", "gcp", "dev"} {
			if other == p {
				continue
			}
			if _, err := Load(raw, other); err == nil || !strings.Contains(err.Error(), "this image is "+other) {
				t.Fatalf("%s setup on a %s image: %v", name, other, err)
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
	d := load(t, "dev-single")
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
	if o := g.Options(); o["kms_key"] == "" || o["wif_provider"] == "" || o["attest_audience"] != "signer-runner-identity" ||
		o["project_number"] != "123456789" || len(o) != 4 {
		t.Fatalf("gcp options %v", o)
	}
	g.Wire.Platform.SealingKeyRelease.ProjectNumber = 0
	if o := g.Options(); len(o) != 3 {
		t.Fatalf("gcp options without project_number %v", o)
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
	if got := o["kms_key_creation_date"]; got != "1793895285" {
		t.Fatalf("kms_key_creation_date = %q", got)
	}
	n.Wire.Platform.SealingKeyRelease.KMSKeyCreationDate = 0
	if _, ok := n.Options()["kms_key_creation_date"]; ok {
		t.Fatal("kms_key_creation_date set for a setup without it")
	}
	wantProxy := "kms.eu-west-1.amazonaws.com:443=vsock:3:8000,sts.eu-west-1.amazonaws.com:443=vsock:3:8001," +
		"www.cloudflare.com:443=vsock:3:8002,signer-marks.s3.eu-west-1.amazonaws.com:443=vsock:3:8004," +
		"time.cloudflare.com:4460=vsock:3:8005,nts.netnod.se:4460=vsock:3:8006,ptbtime1.ptb.de:4460=vsock:3:8007," +
		"ntppool1.time.nl:4460=vsock:3:8008,any.time.nl:4460=vsock:3:8018," +
		"bevtime1.metrologie.at:4460=vsock:3:8009,nts1.ntp.hr:4460=vsock:3:8010,nts.meta.com:4460=vsock:3:8011," +
		"ntp.obspm.fr:4460=vsock:3:8012,ntp0.cam.ac.uk:4460=vsock:3:8013,time1.mbix.ca:4460=vsock:3:8014," +
		"ntp1.wiktel.com:4460=vsock:3:8015,a.st1.ntp.br:4460=vsock:3:8016,time-gps.globalentry.systems:4460=vsock:3:8017"
	if o["proxy"] != wantProxy {
		t.Fatalf("proxy\n%s\nwant\n%s", o["proxy"], wantProxy)
	}
	if strings.Contains(o["proxy"], "8003") || strings.Contains(o["proxy"], "dynamodb") || len(o) != 7 {
		t.Fatalf("options %v", o)
	}
	lines, err := NitroProxyLines(n)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(lines, "8000 kms.eu-west-1.amazonaws.com 443\n") ||
		!strings.Contains(lines, "8004 signer-marks.s3.eu-west-1.amazonaws.com 443\n") ||
		strings.Count(lines, "\n") != 4+len(NitroNTSKE) {
		t.Fatalf("proxy lines:\n%s", lines)
	}
	if _, err := NitroProxyLines(load(t, "gcp")); err == nil {
		t.Fatal("proxy lines of a gcp setup")
	}
	// Every port of the map is distinct, and none is the agent's or the relay's.
	seen := map[uint32]bool{7101: true, 7102: true}
	for _, r := range NitroRoutes(&n.Wire.Platform) {
		if seen[r.Port] {
			t.Fatalf("port %d twice", r.Port)
		}
		seen[r.Port] = true
	}
}

func TestMergeOptions(t *testing.T) {
	got, err := MergeOptions(map[string]string{"region": "r"}, map[string]string{"clock": "system"})
	if err != nil || got["region"] != "r" || got["clock"] != "system" {
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
	raw := sample(t, "dev-single")
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
