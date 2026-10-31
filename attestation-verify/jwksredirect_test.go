package attest

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"testing"
)

// checkJWKSURI keeps the key set on the issuer's host. A redirect from
// that host to another one would undo it, so the fetch refuses a redirect
// off the host of the URL it asked for.
func TestJWKSRedirectToAnotherHostRefused(t *testing.T) {
	iss, err := url.Parse(maaIssuer)
	if err != nil {
		t.Fatal(err)
	}
	const otherHost = "keys.other.example"
	discovery, _ := json.Marshal(map[string]string{"issuer": maaIssuer, "jwks_uri": maaIssuer + "/certs"})
	keys := jwksFor(t, "kid-b", testRSA(t, 1), false)
	client := &http.Client{Transport: hostsTransport{
		iss.Hostname(): http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/.well-known/openid-configuration":
				w.Write(discovery)
			case "/certs":
				http.Redirect(w, r, "https://"+otherHost+"/certs", http.StatusFound)
			default:
				http.NotFound(w, r)
			}
		}),
		otherHost: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(keys) }),
	}}
	if ks, err := DiscoverJWKS(context.Background(), client, maaIssuer); err == nil {
		t.Fatalf("DiscoverJWKS took a key set through a redirect to %s (kids %v)", otherHost, ks.KeyIDs())
	}
	if client.CheckRedirect != nil {
		t.Fatal("the fetch changed the caller's client")
	}

	// A redirect on the same host is still followed.
	same := &http.Client{Transport: hostsTransport{
		iss.Hostname(): http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/keys" {
				http.Redirect(w, r, "/moved", http.StatusFound)
				return
			}
			w.Write(keys)
		}),
	}}
	if _, err := FetchJWKS(context.Background(), same, maaIssuer+"/keys"); err != nil {
		t.Fatalf("same-host redirect: %v", err)
	}
}
