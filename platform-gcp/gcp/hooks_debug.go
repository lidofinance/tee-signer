//go:build debugimport

package gcp

// Debug build only (-tags platform_gcp,debugimport, the
// runner-gcp-debugimport binary): one option that lets a test run the GCP
// runner on a machine without Google.
//
//	test_google_url=<URL>  STS, IAM credentials and Cloud KMS at this base
//	                       URL instead of Google's (runner/e2e fakes them)
//
// The launcher socket is the release option socket. Release builds have no
// such option (hooks_release.go), so a measured image cannot carry it.

import "github.com/lidofinance/tee-signer/platform"

func debugEndpoints(o platform.Options, k *KMS) {
	if u := o.Param("test_google_url", ""); u != "" {
		k.STSURL, k.IAMURL, k.KMSURL = u, u, u
	}
}
