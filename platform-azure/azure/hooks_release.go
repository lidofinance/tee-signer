//go:build !debugimport

package azure

import "github.com/lidofinance/tee-signer/platform"

// Release build: the runner reads the real SEV-SNP device and calls the
// real metadata service. There are no test options.
var debugOptions []string

func hardwareFor(platform.Options) (ReportSource, string, error) {
	return newDeviceReports(), "", nil
}
