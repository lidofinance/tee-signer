//go:build !peerselect || peer_azure || peer_gcp

package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lidofinance/tee-signer/attestation-verify"
	"github.com/lidofinance/tee-signer/governance/setupwire"
	"github.com/lidofinance/tee-signer/platform/dev"
	"github.com/lidofinance/tee-signer/platform/setup"
)

// keySetServer is a fake MAA host on 127.0.0.1: its openid-configuration
// and one RSA key at /certs.
func keySetServer(t *testing.T) *httptest.Server {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var srv *httptest.Server
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			fmt.Fprintf(w, `{"issuer":%q,"jwks_uri":%q}`, srv.URL, srv.URL+"/certs")
		case "/certs":
			fmt.Fprintf(w, `{"keys":[{"kid":"k1","kty":"RSA","n":%q,"e":"AQAB"}]}`, base64.RawURLEncoding.EncodeToString(k.N.Bytes()))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// A Nitro-like dev runner: its setup lists one peer endpoint, so the start
// gives the dev platform option egress, and the platform's HTTP client
// (the one the DKG peer verifiers get, dkg_hooks.go) fetches the key set
// of the listed MAA host and reaches no other host. PeerEgress reports the
// limit that the DKG orders check (keygen TestOrderPeerEgress).
func TestDevRunnerPeerEgress(t *testing.T) {
	listed, other := keySetServer(t), keySetServer(t)
	s, err := setupwire.DecodeSetup(sampleSetup(t, "dev"))
	if err != nil {
		t.Fatal(err)
	}
	s.Platform.EncryptedStateStore = nil
	s.Platform.KeygenPeerAttestationHosts = []string{strings.TrimPrefix(listed.URL, "https://")}
	raw, err := s.Encode()
	if err != nil {
		t.Fatal(err)
	}
	var events []string
	ch := &fakeChannel{raw: raw, events: &events}
	withChannel("dev", ch, func() {
		a := &startArgs{platformName: "dev", setupSrc: "platform", given: map[string]string{"setup": "platform"}, stateDir: t.TempDir()}
		st, plat, _, err := startPlatform(context.Background(), a, dev.New, quietLog)
		if err != nil {
			t.Fatal(err)
		}
		if e, limited := setup.PeerEgress(st.setup.Wire); !limited || len(e) != 1 {
			t.Fatalf("peer egress %v %v", e, limited)
		}
		if plat.HTTPClient == nil {
			t.Fatal("no egress client")
		}
		plat.HTTPClient.Transport.(*http.Transport).TLSClientConfig = listed.Client().Transport.(*http.Transport).TLSClientConfig
		ks, err := attest.DiscoverJWKS(context.Background(), plat.HTTPClient, listed.URL)
		if err != nil || len(ks.KeyIDs()) != 1 {
			t.Fatalf("listed key set: %v", err)
		}
		_, err = attest.DiscoverJWKS(context.Background(), plat.HTTPClient, other.URL)
		if err == nil || !strings.Contains(err.Error(), "dev: no route for "+strings.TrimPrefix(other.URL, "https://")) {
			t.Fatalf("unlisted key set: %v", err)
		}
	})
}
