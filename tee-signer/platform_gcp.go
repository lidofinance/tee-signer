//go:build platform_gcp

package main

import (
	"github.com/lidofinance/tee-signer/platform-gcp/gcp"
	_ "github.com/lidofinance/tee-signer/platform-gcp/gcslog" // the Cloud Storage mark log
	"github.com/lidofinance/tee-signer/platform/setup"
)

// Google Confidential Space. The setup comes from the instance metadata
// attribute signer-setup, which no launch policy has to allow.
func init() {
	register("gcp", gcp.New)
	registerSetup("gcp", func() setup.Channel { return gcp.MetadataSetup{URL: gcp.MetadataSetupURL} })
}
