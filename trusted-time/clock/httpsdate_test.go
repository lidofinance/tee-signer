package clock

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TIME-SOURCE-01: an HTTPS time source that redirects to plain HTTP gives
// no reading. Before the fix the client followed the redirect and took
// the Date of the unauthenticated answer.
func TestHTTPSDateRefusesRedirectToHTTP(t *testing.T) {
	future := time.Now().Add(30 * 24 * time.Hour).UTC().Truncate(time.Second)
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Date", future.Format(http.TimeFormat))
	}))
	defer plain.Close()
	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, plain.URL+"/", http.StatusFound)
	}))
	defer tlsSrv.Close()

	h := &HTTPSDate{URL: tlsSrv.URL + "/", Client: tlsSrv.Client()}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	got, err := h.Fetch(ctx)
	if err == nil {
		t.Fatalf("a redirect to http gave the reading %v (the plain server's Date is %v)", got, future)
	}
}

// A redirect from HTTPS to HTTPS still gives the reading of the final,
// authenticated answer.
func TestHTTPSDateFollowsRedirectToHTTPS(t *testing.T) {
	var final *httptest.Server
	final = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer final.Close()
	first := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, final.URL+"/", http.StatusFound)
	}))
	first.TLS = final.TLS
	first.StartTLS()
	defer first.Close()
	h := &HTTPSDate{URL: first.URL + "/", Client: final.Client()}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	got, err := h.Fetch(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if d := time.Since(got); d < -2*time.Second || d > 2*time.Second {
		t.Fatalf("reading %v, %v off the system clock", got, d)
	}
}
