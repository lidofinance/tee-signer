package server

import (
	"bytes"
	"slices"

	"github.com/lidofinance/tee-signer/governance/setupwire"
	"github.com/lidofinance/tee-signer/platform"
)

// UnlistedKeyRuleImages compares the images the key rule releases the
// sealing key to (platform.KeyRule.Images) with allowed_image_measurements
// in force, the list the image check reads (lockedInForce). It returns the
// ids that no entry of the list has as platform.RuleImageID, and the
// locked version of the list. On a prod chain the start withholds the
// shares when any is unlisted (tee-signer keyruleimages.go,
// ImageGate.WithholdKeyRule); off prod it warns.
func (u *Updates) UnlistedKeyRuleImages(ids [][]byte) (unlisted [][]byte, version uint64, err error) {
	l, v, err := u.lockedInForce()
	if err != nil {
		return nil, 0, err
	}
	return unlistedKeyRuleImages(l, ids), v, nil
}

// unlistedKeyRuleImages is the ids that no entry of l's allowed list has
// as platform.RuleImageID.
func unlistedKeyRuleImages(l *setupwire.Locked, ids [][]byte) (unlisted [][]byte) {
	for _, id := range ids {
		listed := slices.ContainsFunc(l.AllowedImageMeasurements, func(a setupwire.Image) bool {
			return bytes.Equal(platform.RuleImageID(a), id)
		})
		if !listed {
			unlisted = append(unlisted, id)
		}
	}
	return unlisted
}
