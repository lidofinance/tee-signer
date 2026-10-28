//go:build !testnet

package main

// A default build has no -allow-unlisted-image: the image check
// (imagecheck.go) always holds. imageoverride_testnet.go is the testnet
// build's counterpart.
func imageOverride() bool { return false }
