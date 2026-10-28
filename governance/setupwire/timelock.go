package setupwire

import (
	"fmt"
	"math"
	"math/bits"
	"slices"
)

// Arithmetic of section 6, steps 3 and 7, and of activation. Times are Unix
// seconds; the caller passes trusted time from the NTS clock. Every sum
// saturates at the largest uint64 instead of wrapping, so a huge time lock
// or activate_at cannot wrap around and pass a check.

// MaxVersionStep is how far a version may jump past the group's highest.
const MaxVersionStep = 1 << 32

// SatAdd returns a + b, or math.MaxUint64 when the sum does not fit.
func SatAdd(a, b uint64) uint64 {
	s, carry := bits.Add64(a, b, 0)
	if carry != 0 {
		return math.MaxUint64
	}
	return s
}

// CheckVersion is step 3: version must be above the active and the
// pending version of its group and at most MaxVersionStep above the higher
// of the two. pending is 0 when the group has no pending update.
func CheckVersion(version, active, pending uint64) error {
	top := max(active, pending)
	if version <= top {
		return fmt.Errorf("update: version %d, want above %d", version, top)
	}
	if version-top > MaxVersionStep {
		return fmt.Errorf("update: version %d is more than 2^32 above %d", version, top)
	}
	return nil
}

// GainsImage reports whether next lists an image that active does not.
func GainsImage(active, next []Image) bool {
	for _, n := range next {
		if !slices.ContainsFunc(active, func(a Image) bool { return compareImages(a, n) == 0 }) {
			return true
		}
	}
	return false
}

// Wait is W of step 7 for update u under the active locked group: 0 for
// an open update; for a locked one the active change delay, or the images
// minimum when that is larger and allowed_image_measurements gains an
// entry. A change delay of zero does not shorten the images minimum
// (decision 10).
func Wait(active *Locked, u *UpdateBody) uint64 {
	if u.Group != GroupLocked {
		return 0
	}
	w := active.ChangeDelay()
	if u.Locked != nil && GainsImage(active.AllowedImageMeasurements, u.Locked.AllowedImageMeasurements) {
		w = max(w, ImagesMinTimeLock)
	}
	return w
}

// LatestActivateAt is the latest activate_at an update with wait w may
// name at trusted time now: now + w + ActivationHorizon, saturated.
func LatestActivateAt(now, w uint64) uint64 {
	return SatAdd(SatAdd(now, w), ActivationHorizon)
}

// CheckActivateAt is the horizon part of step 7. An activate_at in the past
// is fine: EffectiveActivation still makes the update wait w.
func CheckActivateAt(activateAt, now, w uint64) error {
	if limit := LatestActivateAt(now, w); activateAt > limit {
		return fmt.Errorf("update: activate_at %d is past %d (now + wait %d + horizon %d)", activateAt, limit, w, uint64(ActivationHorizon))
	}
	return nil
}

// EffectiveActivation is the later of activate_at and arrival + w: a
// signer that gets the update late still waits the full w.
func EffectiveActivation(activateAt, arrival, w uint64) uint64 {
	return max(activateAt, SatAdd(arrival, w))
}
