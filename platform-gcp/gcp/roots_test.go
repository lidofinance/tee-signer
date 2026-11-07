package gcp

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lidofinance/tee-signer/platform/cloudroots"
)

// The client for Google's APIs (and the mark log, through the platform's
// HTTPClient) trusts Google's roots only.
func TestGoogleClientRefusesOtherCA(t *testing.T) {
	c := googleClient()
	if !c.Transport.(*http.Transport).TLSClientConfig.RootCAs.Equal(cloudroots.Pool(cloudroots.Google)) {
		t.Fatal("the client's roots are not Google's")
	}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	_, err := c.Get(srv.URL)
	if err == nil || !strings.Contains(err.Error(), "certificate signed by unknown authority") {
		t.Fatalf("got %v, want an unknown authority error", err)
	}
}
