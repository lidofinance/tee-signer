//go:build !debugimport

package nitro

import "github.com/lidofinance/tee-signer/platform"

// Release build: the platform always opens /dev/nsm, calls KMS and uses the
// host agent. It has no test options, so the measured command line of an
// enclave image cannot carry one.
func debugPlatform(platform.Options) (*platform.Platform, bool, error) { return nil, false, nil }
