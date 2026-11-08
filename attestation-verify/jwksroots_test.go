package attest

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/platform/cloudroots"
)

// A key set on a Google or MAA host is fetched over TLS that trusts that
// cloud's roots only, even when the caller's client trusts another CA.
func TestJWKSFetchPinsIssuerRoots(t *testing.T) {
	// A self-signed certificate for the issuer hosts and example.com,
	// which the caller's client trusts. Every name dials the test server.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test"},
		DNSNames:  []string{"www.googleapis.com", "sharedweu.weu.attest.azure.net", "example.com"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write(jwksFor(t, "kid-a", testRSA(t, 1), false))
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	srv.StartTLS()
	defer srv.Close()
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: pool},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, srv.Listener.Addr().String())
		},
	}}
	for _, u := range []string{
		"https://www.googleapis.com/service_accounts/v1/metadata/jwk/x",
		"https://sharedweu.weu.attest.azure.net/certs",
	} {
		_, err := FetchJWKS(context.Background(), client, u)
		if err == nil || !strings.Contains(err.Error(), "certificate signed by unknown authority") {
			t.Errorf("%s: got %v, want an unknown authority error", u, err)
		}
	}
	// Another host keeps the caller's roots.
	if _, err := FetchJWKS(context.Background(), client, "https://example.com/keys"); err != nil {
		t.Errorf("example.com: %v", err)
	}

	for host, want := range map[string]*struct{ p cloudroots.Provider }{
		"confidentialcomputing.googleapis.com": {cloudroots.Google},
		"SharedEUS.eus.attest.azure.net":       {cloudroots.Azure},
		"googleapis.com.example":               nil,
		"attest.azure.net":                     nil,
	} {
		got := issuerRoots(host)
		if (want == nil) != (got == nil) || (want != nil && !got.Equal(cloudroots.Pool(want.p))) {
			t.Errorf("%s: wrong roots", host)
		}
	}
}
