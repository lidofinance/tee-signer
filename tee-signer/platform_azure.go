//go:build platform_azure

package main

import (
	_ "github.com/lidofinance/tee-signer/platform-azure/azlog" // the Blob Storage mark log
	"github.com/lidofinance/tee-signer/platform-azure/azure"
	"github.com/lidofinance/tee-signer/platform/setup"
)

// Azure confidential containers (SEV-SNP, MAA, Key Vault). The setup comes
// in SIGNER_SETUP, a wildcard environment rule of the CCE policy.
func init() {
	register("azure", azure.New)
	registerSetup("azure", func() setup.Channel { return setup.Env{Name: setup.EnvVar} })
}
