//go:build nts && !debugimport

package main

import "github.com/lidofinance/tee-signer/trusted-time/clock"

// ntsServers: a release build always uses the catalog's default public
// servers plus the confirmed entries, with their pinned roots. Only a debug
// build can name others (nts_servers_debug.go).
func ntsServers(confirmed []string, from string) ([]clock.NTSServer, error) {
	return publicNTSServersFor(confirmed, from)
}

// clockProtocolEnvAllowed: a release build takes RUNNER_CLOCK_PROTOCOL on
// the dev platform only (clockProtocol).
const clockProtocolEnvAllowed = false

// coarseTestURLs: a release build takes only coarse URLs of the catalog on
// a platform with pinned roots.
var coarseTestURLs = false // tests of package main set it
