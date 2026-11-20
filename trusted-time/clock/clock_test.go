package clock

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

type fakeSource struct {
	name string
	t    time.Time
	err  error
}

func (f *fakeSource) Fetch(context.Context) (time.Time, error) { return f.t, f.err }
func (f *fakeSource) Name() string                             { return f.name }

var base = time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)

func TestQuorumMedianAndMinimum(t *testing.T) {
	ctx := context.Background()
	honest := func(s int) *fakeSource { return &fakeSource{name: "h", t: base.Add(time.Duration(s) * time.Second)} }
	liarBack := &fakeSource{name: "back", t: base.Add(-24 * time.Hour)}
	liarFwd := &fakeSource{name: "fwd", t: base.Add(24 * time.Hour)}
	down := &fakeSource{name: "down", err: errors.New("timeout")}

	q := &Quorum{Sources: []Source{honest(0), honest(1), honest(2), liarBack, liarFwd}, Min: 3}
	got, err := q.Fetch(ctx)
	if err != nil || got.Before(base) || got.After(base.Add(2*time.Second)) {
		t.Fatalf("2 liars of 5: got %v %v", got, err)
	}
	q = &Quorum{Sources: []Source{honest(0), liarBack, liarBack, down, down}, Min: 3}
	if got, err = q.Fetch(ctx); err != nil || !got.Equal(liarBack.t) {
		// 3 answers, 2 of them lies: the median is a lie. This is the
		// documented limit: liars must stay below Min.
		t.Fatalf("expected the liars to win with 2 of 3 answers, got %v %v", got, err)
	}
	q = &Quorum{Sources: []Source{honest(0), down, down}, Min: 2}
	if _, err = q.Fetch(ctx); err == nil || !strings.Contains(err.Error(), "1 of 3") {
		t.Fatalf("want quorum failure, got %v", err)
	}
}

func TestHTTPSDate(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Date", "Mon, 12 Oct 2026 12:00:00 GMT")
	}))
	defer srv.Close()
	h := &HTTPSDate{URL: srv.URL, Client: srv.Client()}
	got, err := h.Fetch(context.Background())
	if err != nil || !got.Equal(base) {
		t.Fatalf("%v %v", got, err)
	}
	if _, err := (&HTTPSDate{URL: "http://example.invalid"}).Fetch(context.Background()); err == nil {
		t.Fatal("plain http accepted")
	}
}

// The quorum counts each source: answers, failures, the last error, and how
// far its reading was from the quorum's answer. A failed round still counts.
func TestQuorumSourceStats(t *testing.T) {
	ctx := context.Background()
	a := &fakeSource{name: "a", t: base}
	b := &fakeSource{name: "b", t: base.Add(2 * time.Second)}
	c := &fakeSource{name: "c", err: errors.New("timeout")}
	q := &Quorum{Sources: []Source{a, b, c}, Min: 2}
	if st := q.SourceStats(); len(st) != 3 || st[0].Name != "a" || st[0].Queries != 0 || st[0].LastAnswerAge != -1 {
		t.Fatalf("before any round: %+v", st)
	}
	if got, err := q.Fetch(ctx); err != nil || !got.Equal(base) {
		t.Fatalf("%v %v", got, err)
	}
	st := q.SourceStats()
	if st[0].Answers != 1 || st[0].LastDiff != 0 || st[0].LastAnswerAge < 0 || st[0].LastError != "" {
		t.Fatalf("a: %+v", st[0])
	}
	if st[1].Answers != 1 || st[1].LastDiff != 2*time.Second {
		t.Fatalf("b: %+v", st[1])
	}
	if st[2].Queries != 1 || st[2].Failures != 1 || st[2].Answers != 0 || st[2].LastAnswerAge != -1 || st[2].LastError == "" {
		t.Fatalf("c: %+v", st[2])
	}
	// A round without a quorum: b's answer counts, its last diff stays.
	a.err, b.t = errors.New("down"), base.Add(5*time.Second)
	if _, err := q.Fetch(ctx); err == nil {
		t.Fatal("quorum with one answer")
	}
	st = q.SourceStats()
	if st[0].Failures != 1 || st[1].Answers != 2 || st[1].LastDiff != 2*time.Second || st[2].Failures != 2 {
		t.Fatalf("after a failed round: %+v", st)
	}
	an := &Anchored{Src: q, Interval: time.Second}
	if got := an.SourceStats(); len(got) != 3 || got[1].Answers != 2 {
		t.Fatalf("anchored: %+v", got)
	}
	if got := (&Anchored{Src: a, Interval: time.Second}).SourceStats(); got != nil {
		t.Fatalf("a source without stats: %+v", got)
	}
}

// selfSigned is a certificate for names that no client trusts.
func selfSigned(t *testing.T, names ...string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "coarse"}, DNSNames: names,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// A coarse source's LastError goes into
// HEALTH (coarse[].last_error), so its length must be bounded whatever the
// host or the path sends: one oversized certificate name or Date header
// must not push the runner's HEALTH answer over the 1 MiB frame. The cap
// is the one HEALTH already applies to each NTS server's last_error
// (ntsHealthErrMax in nts.go, 256 octets plus "...").
func TestQuorumSourceStatsBoundsLastError(t *testing.T) {
	const want = 256 + len("...")
	ok := func() Source { return &fakeSource{name: "ok", t: base} }
	for _, tc := range []struct {
		name   string
		source func(t *testing.T) Source
	}{
		// A party on the path of one coarse host answers the TLS handshake
		// with its own certificate: no trusted key, one 175,000-octet name.
		// Go checks the name first and quotes the certificate's names.
		{"certificate name", func(t *testing.T) Source {
			srv := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
			srv.TLS = &tls.Config{Certificates: []tls.Certificate{selfSigned(t, strings.Repeat("\x01", 175_000))}}
			srv.Config.ErrorLog = log.New(io.Discard, "", 0)
			srv.StartTLS()
			t.Cleanup(srv.Close)
			c := &http.Client{Transport: &http.Transport{
				TLSClientConfig: &tls.Config{RootCAs: x509.NewCertPool()},
				DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
					var d net.Dialer
					return d.DialContext(ctx, network, srv.Listener.Addr().String())
				},
			}}
			return &HTTPSDate{URL: "https://coarse.test", Client: c}
		}},
		// The coarse host itself, with a valid certificate, sends a Date
		// header that does not parse; the error quotes it.
		{"date header", func(t *testing.T) Source {
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Date", strings.Repeat("A", 400_000))
			}))
			t.Cleanup(srv.Close)
			return &HTTPSDate{URL: srv.URL, Client: srv.Client()}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			q := &Quorum{Sources: []Source{ok(), ok(), tc.source(t)}, Min: 2}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if _, err := q.Fetch(ctx); err != nil {
				t.Fatalf("quorum of the two good sources: %.200v", err)
			}
			got := q.SourceStats()[2].LastError
			if got == "" {
				t.Fatal("the failing source has no last error")
			}
			if len(got) > want || !utf8.ValidString(got) {
				js, _ := json.Marshal(got)
				t.Fatalf("LastError is %d octets (%d in JSON), want at most %d of valid UTF-8; starts %.60q",
					len(got), len(js), want, got)
			}
		})
	}
}
