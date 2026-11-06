package nitro

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lidofinance/tee-signer/platform/cloudroots"
	"github.com/lidofinance/tee-signer/signer-protocol/transport"
)

// The proxy client trusts AWS's roots only: a server whose certificate
// another CA issued is refused, though the route reaches it.
func TestProxyClientRefusesOtherCA(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	a, err := transport.Parse("tcp:" + srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	c := ProxyClient(map[string]transport.Addr{"example.com:443": a})
	if !c.Transport.(*http.Transport).TLSClientConfig.RootCAs.Equal(cloudroots.Pool(cloudroots.AWS)) {
		t.Fatal("the client's roots are not AWS's")
	}
	_, err = c.Get("https://example.com/")
	if err == nil || !strings.Contains(err.Error(), "certificate signed by unknown authority") {
		t.Fatalf("got %v, want an unknown authority error", err)
	}
}
