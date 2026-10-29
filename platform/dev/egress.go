package dev

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"slices"
	"strings"
	"time"
)

// EgressClient is the dev platform's HTTP client when the setup lists
// peer_attestation_hosts (platform option egress, host:port comma-separated): it
// dials those host:ports directly and refuses every other one, as a Nitro
// enclave reaches only the routes of its setup. Local runners and tests
// use it to see that the handover verifier works with no other network.
func EgressClient(endpoints []string) *http.Client {
	allowed := slices.Clone(endpoints)
	var d net.Dialer
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if !slices.Contains(allowed, addr) {
				return nil, fmt.Errorf("dev: no route for %s: not one of the setup's peer_attestation_hosts (%s)", addr, strings.Join(allowed, ", "))
			}
			return d.DialContext(ctx, network, addr)
		},
		Proxy:               nil,
		ForceAttemptHTTP2:   true,
		TLSHandshakeTimeout: 10 * time.Second,
	}
	return &http.Client{Transport: tr, Timeout: 30 * time.Second}
}
