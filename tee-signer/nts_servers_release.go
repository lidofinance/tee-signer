//go:build nts && !debugimport

package main

import "github.com/lidofinance/tee-signer/trusted-time/clock"

// ntsServers: a release build always uses the catalog's default public
// servers with their pinned roots. Only a debug build can name others
// (nts_servers_debug.go).
func ntsServers() ([]clock.NTSServer, error) { return publicNTSServers() }

// coarseTestURLs: a release build takes only coarse URLs of the catalog on
// a platform with pinned roots.
var coarseTestURLs = false // tests of package main set it
