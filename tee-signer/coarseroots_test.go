//go:build nts

package main

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lidofinance/tee-signer/platform/cloudroots"
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
	want := cloudroots.Pool(cloudroots.AWS)
	for _, s := range nts.PublicServers {
		if err := nts.AddRoots(want, s.Roots); err != nil {
			t.Fatal(err)
		}
	}
	if !c.Transport.(*http.Transport).TLSClientConfig.RootCAs.Equal(want) {
		t.Error("coarse roots are not the platform's plus the NTS operators'")
	}
	if !tr.TLSClientConfig.RootCAs.Equal(cloudroots.Pool(cloudroots.AWS)) {
		t.Error("the platform's client changed")
	}

	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	_, err = c.Get(srv.URL)
	if err == nil || !strings.Contains(err.Error(), "certificate signed by unknown authority") {
		t.Fatalf("got %v, want an unknown authority error", err)
	}
}
