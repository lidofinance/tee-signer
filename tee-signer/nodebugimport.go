//go:build !debugimport

// Release build: no -allow-import flag and no plaintext share import.
// debugimport.go is the debug-build counterpart.

package main

import (
	"errors"

	"github.com/lidofinance/tee-signer/tee-signer/server"
)

func checkPlainImport(string) error { return nil }

// The core sets its restart floor on every load in every build. A release
// build keeps -restart-floor for the command lines of existing images, and
// refuses it off: the runner's own floor copy stays on.
const restartFloorUsage = "must be true in a release build: the runner's own restart floor copy (the core always sets its floor)"

func checkRestartFloor(on bool) error {
	if !on {
		return errors.New("-restart-floor=false is for debug builds; the core sets its restart floor on every load in any case")
	}
	return nil
}

// plainVsockAllowed is false in a release build: vsock is served with
// mutual TLS only, because the host side of vsock is not trusted.
func plainVsockAllowed(string) bool { return false }

// unixOffDevAllowed is false in a release build: off the dev platform no
// listener without TLS, whose client would be a local admin.
func unixOffDevAllowed() bool { return false }

// untrustedClockAllowed is false in a release build: off the dev platform
// the clock must be one the host cannot set (checkClock).
func untrustedClockAllowed() bool { return false }

func applyPlainImport(*server.Server) {}

func plainImportStatus() string { return "not built in" }

// flagPathAllowed is false in a release build: off the dev platform the
// values come from the signer's setup (checkFlagPath).
func flagPathAllowed() bool { return false }
