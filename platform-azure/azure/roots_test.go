package azure

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/platform/cloudroots"
)

// The Azure clients (MAA, Key Vault, the mark log through the platform's
// HTTPClient) trust Azure's roots only.
func TestNewClientRefusesOtherCA(t *testing.T) {
	c := newClient(5 * time.Second)
	if !c.Transport.(*http.Transport).TLSClientConfig.RootCAs.Equal(cloudroots.Pool(cloudroots.Azure)) {
		t.Fatal("the client's roots are not Azure's")
	}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	_, err := c.Get(srv.URL)
	if err == nil || !strings.Contains(err.Error(), "certificate signed by unknown authority") {
		t.Fatalf("got %v, want an unknown authority error", err)
	}
}

// A Key Vault without Roots checks the release JWS against Azure's roots,
// not the system ones.
func TestVerifyJWSNilRootsIsAzure(t *testing.T) {
	if !(&KeyVault{}).roots().Equal(cloudroots.Pool(cloudroots.Azure)) {
		t.Fatal("nil Roots is not Azure's roots")
	}
	fx := newTLSFixture(t)
	jws := signJWS(t, fx, "PS256", []byte(`{"a":1}`))
	_, err := (&KeyVault{Endpoint: "vault.test"}).verifyJWS(jws)
	if err == nil || !strings.Contains(err.Error(), "certificate signed by unknown authority") {
		t.Fatalf("got %v, want an unknown authority error", err)
	}
}

// HttpDo falls back to
// http.DefaultClient for a nil client, which trusts the system roots and
// follows proxy variables, the two things newClient avoids. A caller that
// forgets the client must get an error, not the weaker client. The server
// here is plain HTTP on loopback, which http.DefaultClient reaches.
func TestHTTPDoRefusesANilClient(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.Write([]byte("{}"))
	}))
	defer srv.Close()
	_, err := httpGetWithRetry(context.Background(), nil, srv.URL, nil, nil)
	if err == nil || hits.Load() != 0 {
		t.Fatalf("a nil client sent %d request(s) through http.DefaultClient (err %v), want an error and no request", hits.Load(), err)
	}
}
