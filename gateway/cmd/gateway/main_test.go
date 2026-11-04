package main

import (
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
		srv := httpServer(tc.access, st, mux, log)
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
