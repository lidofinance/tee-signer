//go:build nts

package main

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lidofinance/tee-signer/platform/cloudroots"
	"github.com/lidofinance/tee-signer/trusted-time/clock"
	"github.com/lidofinance/tee-signer/trusted-time/nts"
)

// The coarse check trusts the platform's pinned roots plus the NTS
// operators' roots, and nothing else; the platform's client keeps its own.
func TestCoarseClientRoots(t *testing.T) {
	if c, err := coarseClient(nil); c != nil || err != nil {
		t.Fatalf("nil client: %v, %v", c, err)
	}
	plain := &http.Client{}
	if c, _ := coarseClient(plain); c != plain {
		t.Fatal("a client without pinned roots changed")
	}

	tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: cloudroots.Pool(cloudroots.AWS)}}
	c, err := coarseClient(&http.Client{Transport: tr})
	if err != nil {
		t.Fatal(err)
	}
	if !c.Transport.(*http.Transport).TLSClientConfig.RootCAs.Equal(coarseRoots(t)) {
		t.Error("coarse roots are not the platform's plus the NTS operators'")
	}
	if !tr.TLSClientConfig.RootCAs.Equal(cloudroots.Pool(cloudroots.AWS)) {
		t.Error("the platform's client changed")
	}
	refusesTestCA(t, c)
}

// newNTSClock gives each HTTPS-date source of the coarse clock the client
// coarseClient makes from the platform's client.
func TestNTSClockUsesCoarseClient(t *testing.T) {
	t.Setenv("RUNNER_NTS_COARSE_URLS", "https://a.example/,https://b.example/,https://c.example/")
	t.Setenv("RUNNER_NTS_MAX_BOUND", "")
	tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: cloudroots.Pool(cloudroots.AWS)}}
	_, coarse, err := newNTSClock(&http.Client{Transport: tr}, nil, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	want := coarseRoots(t)
	for _, s := range coarse.Src.(*clock.Quorum).Sources {
		c := s.(*clock.HTTPSDate).Client
		if !c.Transport.(*http.Transport).TLSClientConfig.RootCAs.Equal(want) {
			t.Fatal("coarse source roots are not the platform's plus the NTS operators'")
		}
		refusesTestCA(t, c)
	}
}

// coarseRoots is the AWS pool plus the NTS operators' roots.
func coarseRoots(t *testing.T) *x509.CertPool {
	want := cloudroots.Pool(cloudroots.AWS)
	for _, s := range nts.PublicServers {
		if err := nts.AddRoots(want, s.Roots); err != nil {
			t.Fatal(err)
		}
	}
	return want
}

// refusesTestCA checks that c refuses a server whose CA is a test CA.
func refusesTestCA(t *testing.T, c *http.Client) {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	_, err := c.Get(srv.URL)
	if err == nil || !strings.Contains(err.Error(), "certificate signed by unknown authority") {
		t.Fatalf("got %v, want an unknown authority error", err)
	}
}
