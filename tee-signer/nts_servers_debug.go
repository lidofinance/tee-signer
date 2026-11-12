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

// clockProtocolEnvAllowed: a debug build (the tests) takes
// RUNNER_CLOCK_PROTOCOL on every platform.
const clockProtocolEnvAllowed = true

// coarseTestURLs: a debug build also takes coarse URLs outside the
// catalog (the tests' HTTPS-date servers), with the platform's roots.
var coarseTestURLs = true

// ntsServers: in a debug build (the tests/e2e tests), two variables replace
// the public operators with test servers (trusted-time/nts/ntstest):
//
//	RUNNER_NTS_TEST_SERVERS=op=host[@ke-host:port][#ntp-host:port],...  operator, TLS name, NTS-KE address
//	                                                                     and plain NTP address (-clock-protocol ntp)
//	RUNNER_NTS_TEST_ROOTS=file.pem                                      the roots of all of them
//
// Release builds have neither (nts_servers_release.go). The test servers
// replace the confirmed entries too.
func ntsServers(confirmed []string, from string) ([]clock.NTSServer, error) {
	spec := os.Getenv("RUNNER_NTS_TEST_SERVERS")
	if spec == "" {
		return publicNTSServersFor(confirmed, from)
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
			return nil, fmt.Errorf("RUNNER_NTS_TEST_SERVERS: %q: want op=host[@ke-host:port][#ntp-host:port]", part)
		}
		rest, ntp, _ := strings.Cut(rest, "#")
		host, ke, _ := strings.Cut(rest, "@")
		out = append(out, clock.NTSServer{Host: host, Operator: op, Roots: pool, KEAddr: ke, NTPAddr: ntp})
	}
	return out, nil
}
