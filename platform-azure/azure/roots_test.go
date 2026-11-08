package azure

import (
	"net/http"
	"net/http/httptest"
	"strings"
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
