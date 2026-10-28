//go:build platform_dev

package main

import (
	"github.com/lidofinance/tee-signer/platform/dev"
	"github.com/lidofinance/tee-signer/platform/setup"
)

// The dev platform: no hardware, no cloud SDK. It protects nothing. The
// setup comes in SIGNER_SETUP, or from a file (-setup file:PATH).
func init() {
	register("dev", dev.New)
	registerSetup("dev", func() setup.Channel { return setup.Env{Name: setup.EnvVar} })
}
