//go:build nts && !debugimport

package main

import "github.com/lidofinance/tee-signer/trusted-time/clock"

// ntsServers: a release build always uses the four public operators with
// their pinned roots. Only a debug build can name others
// (nts_servers_debug.go).
func ntsServers() ([]clock.NTSServer, error) { return publicNTSServers() }
