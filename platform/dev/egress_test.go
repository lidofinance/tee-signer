package dev

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lidofinance/tee-signer/platform"
)

// With option egress (a dev setup's peer_attestation_hosts) the HTTP client reaches
// the listed host:ports and no other; without it the platform keeps no
// client of its own, as before.
func TestEgress(t *testing.T) {
	ok := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "listed") }))
	defer ok.Close()
	other := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "other") }))
	defer other.Close()
	listed := strings.TrimPrefix(ok.URL, "https://")
	p, err := New(platform.Options{StateDir: t.TempDir(), Params: map[string]string{"egress": "maa.test:443," + listed}})
	if err != nil {
		t.Fatal(err)
	}
	if p.HTTPClient == nil {
		t.Fatal("no HTTP client with egress")
	}
	p.HTTPClient.Transport.(*http.Transport).TLSClientConfig = ok.Client().Transport.(*http.Transport).TLSClientConfig
	get := func(url string) (string, error) {
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
		res, err := p.HTTPClient.Do(req)
		if err != nil {
			return "", err
		}
		defer res.Body.Close()
		b, err := io.ReadAll(res.Body)
		return string(b), err
	}
	if got, err := get(ok.URL); err != nil || got != "listed" {
		t.Fatalf("listed endpoint: %q %v", got, err)
	}
	want := fmt.Sprintf("dev: no route for %s: not one of the setup's peer_attestation_hosts", strings.TrimPrefix(other.URL, "https://"))
	if _, err := get(other.URL); err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("other endpoint: %v", err)
	}
	plain, err := New(platform.Options{StateDir: t.TempDir()})
	if err != nil || plain.HTTPClient != nil {
		t.Fatalf("without egress: client %v, %v", plain.HTTPClient, err)
	}
}
