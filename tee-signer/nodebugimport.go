//go:build !debugimport

// Release build: no -allow-import flag and no plaintext share import.
// debugimport.go is the debug-build counterpart.

package main

import "github.com/lidofinance/tee-signer/tee-signer/server"

func checkPlainImport(string) error { return nil }

// plainVsockAllowed is false in a release build: vsock is served with
// mutual TLS only, because the host side of vsock is not trusted.
func plainVsockAllowed(string) bool { return false }

// unixOffDevAllowed is false in a release build: off the dev platform no
// listener without TLS, whose client would be a local admin.
func unixOffDevAllowed() bool { return false }

func applyPlainImport(*server.Server) {}

func plainImportStatus() string { return "not built in" }
