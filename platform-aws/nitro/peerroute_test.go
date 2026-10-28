//go:build !peerselect || peer_azure || peer_gcp

package nitro

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/attestation-verify"
	"github.com/lidofinance/tee-signer/platform/setup"
	"github.com/lidofinance/tee-signer/signer-protocol/transport"
)

// fakeKeySet is an HTTPS server for the MAA host of a peer: its
// openid-configuration and its key set at /certs, under a certificate for
// that host name from a test CA. It listens on 127.0.0.1, so only a route
// that forwards to it reaches it.
func fakeKeySet(t *testing.T, host string) (addr string, roots *x509.CertPool) {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"}, IsCA: true,
		BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caDER)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: host}, DNSNames: []string{host},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	issuer := "https://" + host
	jwks := fmt.Sprintf(`{"keys":[{"kid":"peer-key","kty":"RSA","n":%q,"e":"AQAB"}]}`,
		base64.RawURLEncoding.EncodeToString(sig.N.Bytes()))
	l, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{leafDER}, PrivateKey: key}}})
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			fmt.Fprintf(w, `{"issuer":%q,"jwks_uri":%q}`, issuer, issuer+"/certs")
		case "/certs":
			io.WriteString(w, jwks)
		default:
			http.NotFound(w, r)
		}
	})}
	go srv.Serve(l)
	t.Cleanup(func() { srv.Close() })
	roots = x509.NewCertPool()
	roots.AddCert(ca)
	return l.Addr().String(), roots
}

// fakeVsockProxy plays vsock-proxy on the parent for one route: it takes
// the enclave's connection and copies bytes to and from the host. TLS ends
// in the enclave (here: the client), so the proxy sees only ciphertext.
func fakeVsockProxy(t *testing.T, to string) transport.Addr {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				up, err := net.Dial("tcp", to)
				if err != nil {
					return
				}
				defer up.Close()
				go io.Copy(up, c)
				io.Copy(c, up)
			}()
		}
	}()
	a, err := transport.Parse("tcp:" + l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func loadNitroSetup(t *testing.T, name string) *setup.Setup {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "governance", "setupwire", "testdata", name+".bin"))
	if err != nil {
		t.Fatal(err)
	}
	st, err := setup.Load(raw, "nitro")
	if err != nil {
		t.Fatal(err)
	}
	return st
}

// The enclave's HTTP client reaches a peer's MAA key set only through the
// route of a listed peer endpoint. The routes come from the setup as the
// runner gets them (the proxy option); the vsock port of the MAA host's
// route is played by a TCP forwarder to a fake MAA server with a
// certificate for sharedneu.neu.attest.azure.net. Without the endpoint in
// the setup, the fetch fails.
func TestPeerKeySetThroughRoute(t *testing.T) {
	const host = "sharedneu.neu.attest.azure.net"
	maa, roots := fakeKeySet(t, host)
	fetch := func(st *setup.Setup) error {
		routes, err := ParseRoutes(st.Options()["proxy"])
		if err != nil {
			t.Fatal(err)
		}
		// The parent's vsock-proxy for the route: only a route that the
		// setup lists gets one.
		if a, ok := routes[host+":443"]; ok {
			if a.String() != "vsock:3:8011" {
				t.Fatalf("route of %s: %s, want vsock:3:8011", host, a)
			}
			routes[host+":443"] = fakeVsockProxy(t, maa)
		}
		c := ProxyClient(routes)
		c.Transport.(*http.Transport).TLSClientConfig = &tls.Config{RootCAs: roots}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		ks, err := attest.DiscoverJWKS(ctx, c, "https://"+host)
		if err == nil && len(ks.KeyIDs()) != 1 {
			t.Fatalf("key set %v", ks.KeyIDs())
		}
		return err
	}
	if err := fetch(loadNitroSetup(t, "setup-nitro-peers")); err != nil {
		t.Fatalf("listed endpoint: %v", err)
	}
	err := fetch(loadNitroSetup(t, "setup-nitro"))
	if err == nil || !strings.Contains(err.Error(), "nitro: no vsock-proxy route for sharedneu.neu.attest.azure.net:443") {
		t.Fatalf("setup without the endpoint: %v", err)
	}
	// Another MAA host, not listed: no route either.
	routes, _ := ParseRoutes(loadNitroSetup(t, "setup-nitro-peers").Options()["proxy"])
	_, err = attest.DiscoverJWKS(context.Background(), ProxyClient(routes), "https://sharedweu.weu.attest.azure.net")
	if err == nil || !strings.Contains(err.Error(), "no vsock-proxy route for sharedweu.weu.attest.azure.net:443") {
		t.Fatalf("unlisted host: %v", err)
	}
}
