//go:build !verifierselect

package runnerclient

// The platform and format names of the documents the tests build: the
// same strings package verify checks.
const (
	nitroPlatform = "nitro"
	nitroFormat   = "aws-nitro-cose-sign1"
	gcpPlatform   = "gcp"
	gcpFormat     = "gcp-confidential-space-jwt"
)
