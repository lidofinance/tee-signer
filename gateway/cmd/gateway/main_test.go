package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/gateway/internal/config"
	"github.com/lidofinance/tee-signer/gateway/internal/servertls"
)

type pair struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func issue(t *testing.T, serial int64, tmpl *x509.Certificate, parent *pair) *pair {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl.SerialNumber = big.NewInt(serial)
	tmpl.NotBefore, tmpl.NotAfter = time.Now().Add(-time.Hour), time.Now().Add(time.Hour)
	signer, signerCert := k, tmpl
	if parent != nil {
		signer, signerCert = parent.key, parent.cert
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, signerCert, &k.PublicKey, signer)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)

	return &pair{c, k}
}

// The listener of each access value, with the handler of the metrics
// listener: who gets /metrics, over which protocol.
func TestListenerAccess(t *testing.T) {
	dir := t.TempDir()
	ca := issue(t, 1, &x509.Certificate{Subject: pkix.Name{CommonName: "CA"}, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign}, nil)
	server := issue(t, 2, &x509.Certificate{Subject: pkix.Name{CommonName: "gateway"}, IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}, ca)
	client := issue(t, 3, &x509.Certificate{Subject: pkix.Name{CommonName: "prometheus"},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}, ca)
	keyDER, _ := x509.MarshalPKCS8PrivateKey(server.key)
	files := map[string][]byte{
		"server.pem":     pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.cert.Raw}),
		"server-key.pem": pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
		"ca.pem":         pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.cert.Raw}),
	}
	for name, b := range files {
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	log := slog.New(slog.DiscardHandler)
	st, err := servertls.New(servertls.Settings{CertFile: filepath.Join(dir, "server.pem"), KeyFile: filepath.Join(dir, "server-key.pem"),
		ClientCAFile: filepath.Join(dir, "ca.pem"), MinVersion: tls.VersionTLS13}, log)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca.cert)
	httpsClient := func(withCert bool) *http.Client {
		cfg := &tls.Config{RootCAs: roots}
		if withCert {
			cfg.Certificates = []tls.Certificate{{Certificate: [][]byte{client.cert.Raw}, PrivateKey: client.key}}
		}
		return &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}, Timeout: 5 * time.Second}
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "up 1\n") })
	get := func(cl *http.Client, url string) bool {
		resp, err := cl.Get(url)
		if err != nil {
			return false
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode == http.StatusOK && string(b) == "up 1\n"
	}

	plain := &http.Client{Timeout: 5 * time.Second}
	for _, tc := range []struct {
		access                      string
		plain, httpsNoCert, httpsCA bool
	}{
		{config.AccessLocal, true, false, false},
		{config.AccessUnsafePlainHTTP, true, false, false},
		{config.AccessMTLS, false, false, true},
		{config.AccessUnsafeOpenTLS, false, true, true},
	} {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		srv := httpServer(context.Background(), tc.access, st, mux, log)
		if srv.ReadHeaderTimeout != 10*time.Second || srv.IdleTimeout != 120*time.Second {
			t.Errorf("%s: timeouts %v, %v", tc.access, srv.ReadHeaderTimeout, srv.IdleTimeout)
		}
		go func() { _ = serve(srv, ln) }()
		addr := ln.Addr().String()
		for name, got := range map[string][2]bool{
			"plain HTTP":                  {get(plain, "http://"+addr+"/metrics"), tc.plain},
			"HTTPS without a certificate": {get(httpsClient(false), "https://"+addr+"/metrics"), tc.httpsNoCert},
			"HTTPS with a CA's client":    {get(httpsClient(true), "https://"+addr+"/metrics"), tc.httpsCA},
		} {
			if got[0] != got[1] {
				t.Errorf("%s, %s: served %v, want %v", tc.access, name, got[0], got[1])
			}
		}
		srv.Close()
	}
}

// syncBuffer is a log sink the test reads while the server writes.
type syncBuffer struct {
	mu sync.Mutex
	b  strings.Builder
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// When a reload changes the client CA, an mtls listener retires its open
// connections: a request in flight completes, its connection closes, and
// the next request needs a new connection that passes the new check. Over
// HTTP/1.1 (Connection: close) and HTTP/2 (GOAWAY).
func TestRetireOnClientCAChange(t *testing.T) {
	for _, h2 := range []bool{false, true} {
		t.Run(map[bool]string{false: "http1.1", true: "h2"}[h2], func(t *testing.T) {
			dir := t.TempDir()
			serverCA := issue(t, 1, &x509.Certificate{Subject: pkix.Name{CommonName: "server CA"}, IsCA: true,
				BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}, nil)
			server := issue(t, 2, &x509.Certificate{Subject: pkix.Name{CommonName: "gateway"},
				IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}, serverCA)
			caA := issue(t, 3, &x509.Certificate{Subject: pkix.Name{CommonName: "client CA A"}, IsCA: true,
				BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}, nil)
			caB := issue(t, 4, &x509.Certificate{Subject: pkix.Name{CommonName: "client CA B"}, IsCA: true,
				BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}, nil)
			client := func(ca *pair, serial int64) *pair {
				return issue(t, serial, &x509.Certificate{Subject: pkix.Name{CommonName: "client"},
					ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}, ca)
			}
			certPEM := func(p *pair) []byte { return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: p.cert.Raw}) }
			keyDER, _ := x509.MarshalPKCS8PrivateKey(server.key)
			write := func(name string, b []byte) {
				if err := os.WriteFile(filepath.Join(dir, name), b, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			write("server.pem", certPEM(server))
			write("server-key.pem", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
			write("ca.pem", certPEM(caA))
			logs := &syncBuffer{}
			log := slog.New(slog.NewTextHandler(logs, nil))
			st, err := servertls.New(servertls.Settings{CertFile: filepath.Join(dir, "server.pem"),
				KeyFile: filepath.Join(dir, "server-key.pem"), ClientCAFile: filepath.Join(dir, "ca.pem"),
				MinVersion: tls.VersionTLS13}, log)
			if err != nil {
				t.Fatal(err)
			}

			started, release := make(chan struct{}), make(chan struct{})
			mux := http.NewServeMux()
			mux.HandleFunc("GET /fast", func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "OK") })
			mux.HandleFunc("GET /slow", func(w http.ResponseWriter, _ *http.Request) {
				close(started)
				<-release
				_, _ = io.WriteString(w, "OK")
			})
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			srv := httpServer(ctx, config.AccessMTLS, st, mux, log)
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			go func() { _ = serve(srv, ln) }()
			defer srv.Close()
			url := "https://" + ln.Addr().String()

			roots := x509.NewCertPool()
			roots.AddCert(serverCA.cert)
			httpClient := func(c *pair) *http.Client {
				cfg := &tls.Config{RootCAs: roots, Certificates: []tls.Certificate{{Certificate: [][]byte{c.cert.Raw}, PrivateKey: c.key}}}
				return &http.Client{Transport: &http.Transport{TLSClientConfig: cfg, ForceAttemptHTTP2: h2}, Timeout: 10 * time.Second}
			}
			get := func(cl *http.Client, path string) (*http.Response, error) {
				resp, err := cl.Get(url + path)
				if err == nil {
					_, _ = io.ReadAll(resp.Body)
					resp.Body.Close()
				}
				return resp, err
			}
			clientA := httpClient(client(caA, 5))
			defer clientA.CloseIdleConnections()
			if resp, err := get(clientA, "/fast"); err != nil || resp.StatusCode != http.StatusOK || resp.Close || (resp.ProtoMajor == 2) != h2 {
				t.Fatalf("before the reload: %v %v", resp, err)
			}

			// A request in flight on that connection while the CA changes.
			type result struct {
				resp *http.Response
				err  error
			}
			inFlight := make(chan result, 1)
			go func() {
				resp, err := get(clientA, "/slow")
				inFlight <- result{resp, err}
			}()
			<-started
			write("ca.pem", certPEM(caB))
			if !st.Poll() {
				t.Fatalf("new client CA not reloaded:\n%s", logs)
			}
			for deadline := time.Now().Add(5 * time.Second); !strings.Contains(logs.String(), "client CA changed"); {
				if time.Now().After(deadline) {
					t.Fatalf("connections not retired:\n%s", logs)
				}
				time.Sleep(10 * time.Millisecond)
			}
			close(release)
			r := <-inFlight
			if r.err != nil || r.resp.StatusCode != http.StatusOK || (!h2 && !r.resp.Close) {
				t.Fatalf("request in flight: %v %v", r.resp, r.err)
			}

			// The next request needs a new connection: CA A's client is out,
			// CA B's client is in.
			if resp, err := get(clientA, "/fast"); err == nil {
				t.Fatalf("client of the removed CA after the reload: %d", resp.StatusCode)
			}
			clientB := httpClient(client(caB, 6))
			defer clientB.CloseIdleConnections()
			if resp, err := get(clientB, "/fast"); err != nil || resp.StatusCode != http.StatusOK {
				t.Fatalf("client of the new CA: %v %v", resp, err)
			}
		})
	}
}
