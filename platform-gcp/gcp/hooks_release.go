//go:build !debugimport

package gcp

import "github.com/lidofinance/tee-signer/platform"

// Release build: the runner calls Google's endpoints. There are no test
// options.
func debugEndpoints(platform.Options, *KMS) {}
