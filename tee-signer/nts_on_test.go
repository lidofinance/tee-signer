//go:build nts

package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/trusted-time/nts"
)

// -nts-clock-check calls Refresh once. That call must contact every server
// at once: the random start wait of a running signer (up to 5 s) would
// slow the check down, five runs by about 12 s.
func TestNTSClockCheckContactsServersAtOnce(t *testing.T) {
	var urls []string
	pool := x509.NewCertPool()
	for range 3 {
		s := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
		t.Cleanup(s.Close)
		urls = append(urls, s.URL+"/")
		pool.AddCert(s.Certificate())
	}
	t.Setenv("RUNNER_NTS_COARSE_URLS", strings.Join(urls, ","))
	allowCoarseTestURLs(t)
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}
	start := time.Now()
	for run := range 5 {
		var mu sync.Mutex
		var addrs []string
		dial := func(_ context.Context, _, addr string) (net.Conn, error) {
			mu.Lock()
			addrs = append(addrs, addr)
			mu.Unlock()
			return nil, errors.New("test dialer")
		}
		if code := ntsClockCheckWith(client, dial, slog.New(slog.DiscardHandler)); code != 1 {
			t.Fatalf("run %d: exit code %d with every NTS-KE failing, want 1", run, code)
		}
		if len(addrs) != len(nts.PublicServers) {
			t.Fatalf("run %d: the check contacted %v, want each of the %d servers once", run, addrs, len(nts.PublicServers))
		}
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("five checks took %v: the check waits before it contacts the servers", d)
	}
	// It runs the runner's schedule (the shift schedule's 1 s query
	// timeout), with no seed and no start wait.
	n, _, err := ntsCheckClock(client, nil, slog.New(slog.DiscardHandler))
	if err != nil || !n.Shifts || n.ScheduleSeed != nil || n.StartDelay >= 0 {
		t.Fatalf("check clock: err %v, shifts %v, seed %v, start delay %v", err, n.Shifts, n.ScheduleSeed, n.StartDelay)
	}
}
