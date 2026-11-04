package setupwire

import (
	"fmt"
	"math"
	"math/bits"
	"slices"

	"github.com/lidofinance/tee-signer/signer-protocol"
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

// MinChangeDelay is the floor of change_delay_seconds on the chain with
// this genesis fork version: the build's default time lock on a prod
// chain (ProdChain), none elsewhere. Without the floor, a locked group
// with change_delay_seconds = 0 put a rotation, new fee recipients, new
// slot times or an emptied image list in force the moment k approvers
// signed; only image additions kept the images minimum.
func MinChangeDelay(genesisForkVersion backend.Version) uint64 {
	if ProdChain(genesisForkVersion) {
		return DefaultTimeLock
	}
	return 0
}

// CheckChangeDelay refuses a change_delay_seconds below the floor of the
// chain (MinChangeDelay). An absent value is the default, which is never
// below the floor. It is the check of a new value only: the tools apply
// it to a setup they make (setup-tool encode; signer-admin setup and
// draft through runnerchain.Limits.CheckTimeLock) and the runner to a
// locked update it has not seen (Updates.Accept, after the again paths).
// A pinned setup or a stored update with a value below the floor is not
// refused, so a cluster from before the floor keeps starting and can
// restore a lost body; ChangeDelayOn and Wait raise its wait to the floor.
func (l *Locked) CheckChangeDelay(genesisForkVersion backend.Version) error {
	floor := MinChangeDelay(genesisForkVersion)
	if l.ChangeDelaySeconds != nil && *l.ChangeDelaySeconds < floor {
		return fmt.Errorf("locked: change_delay_seconds %d on a prod chain (mainnet, or a chain without a row in the chain table), at least %d", *l.ChangeDelaySeconds, floor)
	}
	return nil
}

// ChangeDelayOn is the change delay in force on the chain: ChangeDelay, or
// the chain's floor (MinChangeDelay) when that is larger, so a stored
// value below the floor cannot shorten a wait.
func (l *Locked) ChangeDelayOn(genesisForkVersion backend.Version) uint64 {
	return max(l.ChangeDelay(), MinChangeDelay(genesisForkVersion))
}

// Wait is W of step 7 for update u under the active locked group of a
// setup of the chain with this genesis fork version: 0 for an open
// update; for a locked one the active change delay (ChangeDelayOn, never
// below the chain's floor), or the images minimum when that is larger and
// allowed_image_measurements gains an entry. A change delay of zero does
// not shorten the images minimum (decision 10).
func Wait(genesisForkVersion backend.Version, active *Locked, u *UpdateBody) uint64 {
	if u.Group != GroupLocked {
		return 0
	}
	w := active.ChangeDelayOn(genesisForkVersion)
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
