//go:build debugimport

// Debug build only (go build -tags debugimport): the -allow-import flag
// for plaintext IMPORT_SHARE, on the dev platform. Release builds and the
// cloud images have neither the flag nor the handler (nodebugimport.go,
// server/plainimport.go).

package main

import (
	"flag"
	"fmt"

	"github.com/lidofinance/tee-signer/tee-signer/server"
)

var allowImport = flag.Bool("allow-import", false, "accept plaintext IMPORT_SHARE (debug build, dev platform only)")

// checkPlainImport refuses -allow-import on any platform but dev.
func checkPlainImport(platformName string) error {
	if platformName != "dev" && *allowImport {
		return fmt.Errorf("-allow-import (plaintext shares) is for the dev platform only; %s takes IMPORT_SHARE_SEALED", platformName)
	}
	return nil
}

// plainVsockAllowed says whether a vsock listener without -tls-client-ca is
// accepted: in the debug build on the dev platform, so the vsock loopback
// test can run without a certificate.
func plainVsockAllowed(platformName string) bool { return platformName == "dev" }

// unixOffDevAllowed: a debug build may listen on a unix socket on any
// platform, for the e2e tests that run cloud platforms with fake hardware.
// No cloud image is a debug build.
func unixOffDevAllowed() bool { return true }

func applyPlainImport(srv *server.Server) { srv.AllowImport = *allowImport }

func plainImportStatus() string {
	if *allowImport {
		return "on (debug build)"
	}
	return "off (debug build)"
}
