//go:build nts && debugimport

package main

import (
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/lidofinance/tee-signer/trusted-time/clock"
)

// ntsServers: in a debug build (the runner/e2e tests), two variables replace
// the public operators with test servers (runner/nts/ntstest):
//
//	RUNNER_NTS_TEST_SERVERS=op=host[@ke-host:port],...  operator, TLS name and NTS-KE address
//	RUNNER_NTS_TEST_ROOTS=file.pem                      the roots of all of them
//
// Release builds have neither (nts_servers_release.go).
func ntsServers() ([]clock.NTSServer, error) {
	spec := os.Getenv("RUNNER_NTS_TEST_SERVERS")
	if spec == "" {
		return publicNTSServers()
	}
	pem, err := os.ReadFile(os.Getenv("RUNNER_NTS_TEST_ROOTS"))
	if err != nil {
		return nil, fmt.Errorf("RUNNER_NTS_TEST_ROOTS: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, errors.New("RUNNER_NTS_TEST_ROOTS: no certificate")
	}
	var out []clock.NTSServer
	for _, part := range strings.Split(spec, ",") {
		op, rest, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok || op == "" || rest == "" {
			return nil, fmt.Errorf("RUNNER_NTS_TEST_SERVERS: %q: want op=host[@ke-host:port]", part)
		}
		host, ke, _ := strings.Cut(rest, "@")
		out = append(out, clock.NTSServer{Host: host, Operator: op, Roots: pool, KEAddr: ke})
	}
	return out, nil
}
