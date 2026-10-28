package attest

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

// Tests that reproduce findings of the security review in issue #4 on
// lidofinance/threshold-signer-poc. Each asserts the behaviour the finding
// asks for, so each fails until its fix lands.

// hostsTransport serves each request from the handler of its host name,
// in process: a stand-in for DNS and a WebPKI certificate an attacker
// controls.
type hostsTransport map[string]http.Handler

func (h hostsTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	w := httptest.NewRecorder()
	if s, ok := h[r.URL.Hostname()]; ok {
		s.ServeHTTP(w, r)
	} else {
		w.WriteHeader(http.StatusNotFound)
	}
	return w.Result(), nil
}

// Issue #4 F3: the MAA key set comes from the issuer's discovery document,
// and DiscoverJWKS follows any jwks_uri it names. Whoever answers for the
// issuer's name (DNS plus a WebPKI certificate) can point jwks_uri at a host
// of their own and get a token signed with their key accepted. Only a
// jwks_uri on the issuer's host (or a pinned key set) may be used.
func TestReview4F3JWKSURIOnAnotherHost(t *testing.T) {
	now := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	iss, err := url.Parse(maaIssuer)
	if err != nil {
		t.Fatal(err)
	}
	evil := testRSA(t, 1)
	const evilHost = "keys.attacker.example"
	discovery, _ := json.Marshal(map[string]string{"issuer": maaIssuer, "jwks_uri": "https://" + evilHost + "/certs"})
	client := &http.Client{Transport: hostsTransport{
		iss.Hostname(): http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(discovery) }),
		evilHost:       http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(jwksFor(t, "evil-kid", evil, false)) }),
	}}

	ks, err := DiscoverJWKS(context.Background(), client, maaIssuer)
	if err != nil {
		t.Logf("refused: %v", err)
		return
	}
	t.Errorf("DiscoverJWKS took a key set from jwks_uri on %s, issuer host %s (kids %v)", evilHost, iss.Hostname(), ks.KeyIDs())
	tok := signJWT(t, evil, "evil-kid", aciClaims(now), nil)
	if _, err := VerifyMAA(tok, MAAOptions{Issuer: maaIssuer, Keys: ks, Now: now, ComplianceStatus: ComplianceACI,
		HostData: []string{maaHostData}, RuntimeData: maaRuntime}); err == nil {
		t.Errorf("VerifyMAA accepted a token signed by the key from %s", evilHost)
	} else {
		t.Logf("VerifyMAA with that key set: %v", err)
	}
}
