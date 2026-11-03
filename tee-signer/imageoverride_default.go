//go:build !nonprod

package main

// A mainnet build has no -allow-unlisted-image: the image check
// (imagecheck.go) always holds. imageoverride_nonprod.go is the non-prod
// build's counterpart.
func imageOverride() bool { return false }
