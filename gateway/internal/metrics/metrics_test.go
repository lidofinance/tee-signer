package metrics

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/gateway/internal/certreload"
)

func render(t *testing.T, r *Registry) string {
	t.Helper()
	var b strings.Builder
	if _, err := r.WriteTo(&b); err != nil {
		t.Fatal(err)
	}

	return b.String()
}

// The text format: HELP and TYPE once per family, series in the order of
// their label values, escapes in help texts and label values, cumulative
// histogram buckets with +Inf, _sum and _count.
func TestTextFormat(t *testing.T) {
	r := NewRegistry()
	c := r.Counter("c_total", "A counter.\nSecond line with a \\.", "signer", "result")
	g := r.Gauge("g", "A gauge.")
	h := r.Histogram("h_seconds", "A histogram.", []float64{0.1, 1}, "type")
	r.Func("f", "A func.", "gauge", []string{"k"}, func(emit func(float64, ...string)) {
		emit(2, "b")
		emit(1.5e9, "a")
	})
	c.Inc("s2", "ok")
	c.Add(2, "s1", "failed")
	c.Inc("s1", "ok")
	c.Inc("q\"\\\n", "ok")
	g.Set(-3)
	h.Observe(0.05, "A")
	h.Observe(0.5, "A")
	h.Observe(7, "A")
	h.Observe(1, "B")

	want := `# HELP c_total A counter.\nSecond line with a \\.
# TYPE c_total counter
c_total{signer="q\"\\\n",result="ok"} 1
c_total{signer="s1",result="failed"} 2
c_total{signer="s1",result="ok"} 1
c_total{signer="s2",result="ok"} 1
# HELP g A gauge.
# TYPE g gauge
g -3
# HELP h_seconds A histogram.
# TYPE h_seconds histogram
h_seconds_bucket{type="A",le="0.1"} 1
h_seconds_bucket{type="A",le="1"} 2
h_seconds_bucket{type="A",le="+Inf"} 3
h_seconds_sum{type="A"} 7.55
h_seconds_count{type="A"} 3
h_seconds_bucket{type="B",le="0.1"} 0
h_seconds_bucket{type="B",le="1"} 1
h_seconds_bucket{type="B",le="+Inf"} 1
h_seconds_sum{type="B"} 1
h_seconds_count{type="B"} 1
# HELP f A func.
# TYPE f gauge
f{k="a"} 1.5e+09
f{k="b"} 2
`
	if got := render(t, r); got != want {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}
	if v := c.Value("s1", "failed"); v != 2 {
		t.Fatalf("value %v", v)
	}
	if n := h.Count("A"); n != 3 {
		t.Fatalf("count %d", n)
	}
}

func TestHandler(t *testing.T) {
	r := NewRegistry()
	r.Gauge("g", "A gauge.").Set(1)
	srv := httptest.NewServer(r)
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if ct := resp.Header.Get("Content-Type"); ct != ContentType {
		t.Fatalf("content type %q", ct)
	}
}

func mustPanic(t *testing.T, what string, f func()) {
	t.Helper()
	defer func() {
		if recover() == nil {
			t.Errorf("%s: no panic", what)
		}
	}()
	f()
}

func TestMisuse(t *testing.T) {
	r := NewRegistry()
	c := r.Counter("c_total", "A counter.", "a")
	mustPanic(t, "same name twice", func() { r.Gauge("c_total", "Again.") })
	mustPanic(t, "wrong number of label values", func() { c.Inc("x", "y") })
	mustPanic(t, "counter down", func() { c.Add(-1, "x") })
	mustPanic(t, "buckets out of order", func() { r.Histogram("h", "H.", []float64{1, 0.5}) })
}

// writePair writes a self-signed certificate valid from notBefore to
// notAfter and its key, and returns the paths.
func writePair(t *testing.T, notBefore, notAfter time.Time) (certPath, keyPath string) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(5), Subject: pkix.Name{CommonName: "gateway"},
		NotBefore: notBefore, NotAfter: notAfter, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	dir := t.TempDir()
	certPath, keyPath = filepath.Join(dir, "c.pem"), filepath.Join(dir, "k.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}

	return certPath, keyPath
}

// fakeCerts is a CertSource with the pair of a watcher and fixed counts.
type fakeCerts struct {
	w     *certreload.Watcher
	stats certreload.Stats
}

func (f *fakeCerts) Current() *certreload.Pair { return f.w.Current() }
func (f *fakeCerts) Stats() certreload.Stats   { return f.stats }

// The gateway set: every family of a signer exists with 0 before the
// first event, and the certificate families read the source at each
// scrape.
func TestGatewaySeries(t *testing.T) {
	g := New()
	g.Signer("s1")
	out := render(t, g.Registry)
	for _, line := range []string{
		`teesigner_gateway_signer_connections_up{signer="s1"} 0`,
		`teesigner_gateway_signer_dials_total{signer="s1",result="failed"} 0`,
		`teesigner_gateway_signer_rotations_total{signer="s1",result="ok"} 0`,
		`teesigner_gateway_signer_attestation_failures_total{signer="s1",reason="key_pin"} 0`,
		`teesigner_gateway_signer_requests_total{signer="s1",result="timeout"} 0`,
		`teesigner_gateway_signer_keys_refreshed_timestamp_seconds{signer="s1"} 0`,
		`teesigner_gateway_keys 0`,
		`teesigner_gateway_combine_failures_total{reason="below_threshold"} 0`,
		`# TYPE teesigner_gateway_sign_duration_seconds histogram`,
		`# TYPE teesigner_gateway_requests_total counter`,
	} {
		if !strings.Contains(out, line+"\n") {
			t.Errorf("no line %q", line)
		}
	}

	notBefore := time.Now().Add(-time.Hour).Truncate(time.Second)
	notAfter := notBefore.Add(48 * time.Hour)
	certPath, keyPath := writePair(t, notBefore, notAfter)
	w, err := certreload.New(certPath, keyPath, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	since := time.Date(2026, 10, 28, 12, 0, 0, 500_000_000, time.UTC)
	g.Certs(&fakeCerts{w: w, stats: certreload.Stats{Reloaded: 2, Refused: 1, Unchanged: 7, Since: since}})
	out = render(t, g.Registry)
	for _, line := range []string{
		`teesigner_gateway_client_cert_not_after_seconds ` + formatFloat(float64(notAfter.Unix())),
		`teesigner_gateway_client_cert_not_before_seconds ` + formatFloat(float64(notBefore.Unix())),
		`teesigner_gateway_client_cert_reloads_total{result="ok"} 2`,
		`teesigner_gateway_client_cert_reloads_total{result="refused"} 1`,
		`teesigner_gateway_client_cert_reloads_total{result="unchanged"} 7`,
		`teesigner_gateway_client_cert_last_reload_timestamp_seconds ` + formatFloat(float64(since.Unix())+0.5),
	} {
		if !strings.Contains(out, line+"\n") {
			t.Errorf("no line %q in\n%s", line, out)
		}
	}
}
