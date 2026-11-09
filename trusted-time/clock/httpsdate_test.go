package clock

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func fetchDate(t *testing.T, srv *httptest.Server) (time.Time, error) {
	t.Helper()
	h := &HTTPSDate{URL: srv.URL + "/", Client: srv.Client()}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return h.Fetch(ctx)
}

// TIME-SOURCE-01: an HTTPS time source that redirects to plain HTTP gives
// the Date of its own TLS answer, never the Date of the plain HTTP one.
func TestHTTPSDateIgnoresRedirectToHTTP(t *testing.T) {
	future := time.Now().Add(30 * 24 * time.Hour).UTC().Truncate(time.Second)
	var plainHits atomic.Int32
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		plainHits.Add(1)
		w.Header().Set("Date", future.Format(http.TimeFormat))
	}))
	defer plain.Close()
	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, plain.URL+"/", http.StatusFound)
	}))
	defer tlsSrv.Close()

	got, err := fetchDate(t, tlsSrv)
	if err != nil {
		t.Fatal(err)
	}
	if got.Equal(future) || plainHits.Load() != 0 {
		t.Fatalf("reading %v, %d requests to the plain server", got, plainHits.Load())
	}
}

// TIME-SOURCE-02: a 302 to another host gives the 302's own Date, and the
// client makes no second request (on Nitro the target has no route).
func TestHTTPSDateUsesRedirectDate(t *testing.T) {
	want := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	var targetHits atomic.Int32
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetHits.Add(1)
	}))
	defer target.Close()
	var hits atomic.Int32
	first := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Date", want.Format(http.TimeFormat))
		w.Header().Set("Location", target.URL+"/iam")
		w.WriteHeader(http.StatusFound)
	}))
	defer first.Close()

	got, err := fetchDate(t, first)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Equal(want) {
		t.Fatalf("reading %v, want the 302's Date %v", got, want)
	}
	if hits.Load() != 1 || targetHits.Load() != 0 {
		t.Fatalf("%d requests to the source, %d to the redirect target; want 1 and 0", hits.Load(), targetHits.Load())
	}
}

// Any status gives a reading when it carries a Date.
func TestHTTPSDateNotFound(t *testing.T) {
	want := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Date", want.Format(http.TimeFormat))
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	got, err := fetchDate(t, srv)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Equal(want) {
		t.Fatalf("reading %v, want %v", got, want)
	}
}

// A response without a Date gives no reading and says why.
func TestHTTPSDateNoDate(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header()["Date"] = nil // net/http adds a Date unless the key is set to nil
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()
	_, err := fetchDate(t, srv)
	if err == nil || !strings.Contains(err.Error(), "no Date header (status 302)") {
		t.Fatalf("err %v, want a missing Date error", err)
	}
}
