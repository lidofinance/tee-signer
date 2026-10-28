//go:build debugimport

// Debug build: no handover side (tee-signer/server builds them with
// !debugimport), so no image takes a debug build.

package main

import "github.com/lidofinance/tee-signer/tee-signer/server"

func enableHandover(*server.Server) error { return nil }
