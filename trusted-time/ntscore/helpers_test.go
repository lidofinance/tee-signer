//go:build nts

package ntscore

import "time"

// maxSampleBound is MaxSampleBoundNs as a Duration.
const maxSampleBound = time.Duration(MaxSampleBoundNs)

func allZero(b []byte) bool {
	var acc byte
	for _, x := range b {
		acc |= x
	}
	return acc == 0
}
