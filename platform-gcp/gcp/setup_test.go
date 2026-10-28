package gcp

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// The setup from a fake metadata server: the request carries
// Metadata-Flavor, the answer must too; 5xx is tried again, 404 is not.
func TestMetadataSetup(t *testing.T) {
	setupBytes := []byte("S\x02 setup bytes")
	var (
		status    atomic.Int32
		flavor    atomic.Bool
		body      atomic.Value
		requests  atomic.Int32
		failFirst atomic.Int32
	)
	status.Store(http.StatusOK)
	flavor.Store(true)
	body.Store(base64.StdEncoding.EncodeToString(setupBytes) + "\n")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.URL.Path != "/computeMetadata/v1/instance/attributes/signer-setup" || r.Header.Get("Metadata-Flavor") != "Google" {
			http.Error(w, "bad request", http.StatusForbidden)
			return
		}
		if failFirst.Load() > 0 {
			failFirst.Add(-1)
			http.Error(w, "busy", http.StatusServiceUnavailable)
			return
		}
		if flavor.Load() {
			w.Header().Set("Metadata-Flavor", "Google")
		}
		w.WriteHeader(int(status.Load()))
		_, _ = w.Write([]byte(body.Load().(string)))
	}))
	defer srv.Close()
	m := MetadataSetup{URL: srv.URL + "/computeMetadata/v1/instance/attributes/signer-setup", HTTP: srv.Client(), Retry: 10 * time.Millisecond}
	ctx := context.Background()

	got, err := m.Read(ctx)
	if err != nil || !slices.Equal(got, setupBytes) {
		t.Fatalf("read: %q %v", got, err)
	}
	// Two 503s, then the answer.
	failFirst.Store(2)
	requests.Store(0)
	if got, err := m.Read(ctx); err != nil || !slices.Equal(got, setupBytes) || requests.Load() != 3 {
		t.Fatalf("after 503s: %v, %d requests", err, requests.Load())
	}
	// No attribute: an error at once.
	status.Store(http.StatusNotFound)
	requests.Store(0)
	if _, err := m.Read(ctx); err == nil || !strings.Contains(err.Error(), "no metadata attribute signer-setup") || requests.Load() != 1 {
		t.Fatalf("404: %v, %d requests", err, requests.Load())
	}
	status.Store(http.StatusOK)
	// An answer without the flavor header is not the metadata server's.
	flavor.Store(false)
	if _, err := m.Read(ctx); err == nil || !strings.Contains(err.Error(), "Metadata-Flavor") {
		t.Fatalf("no flavor header: %v", err)
	}
	flavor.Store(true)
	for name, b := range map[string]string{
		"not base64": "S\x02 raw bytes",
		"empty":      "",
		"too long":   strings.Repeat("A", maxAttribute+1),
	} {
		body.Store(b)
		if _, err := m.Read(ctx); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
	// A server that never answers: the read ends with its context.
	dead := MetadataSetup{URL: "http://127.0.0.1:1/x", Retry: 10 * time.Millisecond}
	dctx, cancel := context.WithTimeout(ctx, 300*time.Millisecond)
	defer cancel()
	if _, err := dead.Read(dctx); err == nil || !strings.Contains(err.Error(), "no setup from the metadata server") {
		t.Fatalf("no server: %v", err)
	}
	if m.String() != "metadata attribute signer-setup" || MetadataSetupURL != "http://metadata.google.internal/computeMetadata/v1/instance/attributes/signer-setup" {
		t.Fatal("names")
	}
}
