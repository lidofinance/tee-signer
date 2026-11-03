//go:build nonprod

package main

import "flag"

// A non-prod build may serve an image the allowed list in force does not
// name, for research on a devnet where the approvers cannot sign a locked
// update. Only this explicit flag turns it on; the image's command carries
// it, so its measurement does too. The runner logs it at start and HEALTH
// reports state "override". A mainnet build has no such flag
// (imageoverride_default.go, server.ErrOverrideInMainnetBuild).
var allowUnlistedImage = flag.Bool("allow-unlisted-image", false,
	"serve even when allowed_image_measurements in force does not name this image (non-prod build only; logged, HEALTH image state override)")

func imageOverride() bool { return *allowUnlistedImage }
