// Package flavor is what clients and tools know of the runner's two build
// flavours (backend/buildflavor): default, the build for real keys, and
// testnet (go build -tags testnet), the same code with governance times in
// minutes for research on devnets and test networks. It says how a runner
// shows its flavour, gives the governance times of each flavour, and holds
// the chains a testnet build may run on (chains.go).
//
// A runner shows its flavour in two places, both set by its code:
//
//   - HEALTH's version: VersionSuffix at its end in a testnet build. People,
//     the dashboard and the tools read it here.
//   - the subject common name of the TLS certificate it makes at start:
//     TestnetCertName in a testnet build, DefaultCertName otherwise. Only
//     the runner holds the certificate's key, and the attested identity
//     binds that key, so attest/runnerclient checks the flavour here, in
//     the handshake, before it sends anything.
//
// Neither changes the wire protocol. IDENTITY and ATTEST do not carry the
// flavour: they have no field for it. The measurement (PCRs, CCE policy,
// image digest) differs anyway, since the constants are in the image.
//
// Clients compute waits with Limits of the runner's flavour, not with the
// constants of their own build.
package flavor

import (
	"fmt"
	"strings"

	"github.com/lidofinance/tee-signer/governance/setupwire"
	"github.com/lidofinance/tee-signer/signer-protocol/buildflavor"
)

// Flavor is a build flavour of the runner.
type Flavor string

const (
	Default Flavor = "default"
	Testnet Flavor = "testnet"
)

// Build is the flavour of this binary.
const Build = Flavor(buildflavor.Name)

// The marks of the flavour in a runner's HEALTH version and TLS certificate.
const (
	VersionSuffix   = buildflavor.TestnetVersionSuffix
	DefaultCertName = buildflavor.DefaultCertName
	TestnetCertName = buildflavor.TestnetCertName
)

// FromVersion is the flavour of a runner whose HEALTH reports version v.
func FromVersion(v string) Flavor {
	if strings.HasSuffix(v, VersionSuffix) {
		return Testnet
	}
	return Default
}

// FromCertName is the flavour of a runner whose TLS certificate has the
// subject common name cn. Any name but TestnetCertName is the default
// flavour.
func FromCertName(cn string) Flavor {
	if cn == TestnetCertName {
		return Testnet
	}
	return Default
}

// Limits are the governance times of a flavour, in seconds: the values of
// setupwire's DefaultTimeLock, MaxTimeLock, ActivationHorizon and
// ImagesMinTimeLock in a build of that flavour.
type Limits struct {
	DefaultTimeLock   uint64 // when the setup names no change delay
	MaxTimeLock       uint64
	ActivationHorizon uint64 // past the required wait
	ImagesMinTimeLock uint64 // allowed-images updates and DKG orders
}

// Limits returns the governance times of f.
func (f Flavor) Limits() Limits {
	if f == Testnet {
		return Limits{buildflavor.TestnetFlavorTimeLock, buildflavor.TestnetFlavorMaxTimeLock,
			buildflavor.TestnetFlavorActivationHorizon, buildflavor.TestnetFlavorImagesMinTimeLock}
	}
	return Limits{buildflavor.DefaultFlavorTimeLock, buildflavor.DefaultFlavorMaxTimeLock,
		buildflavor.DefaultFlavorActivationHorizon, buildflavor.DefaultFlavorImagesMinTimeLock}
}

// TimeLock is setupwire's Locked.ChangeDelay under l.
func (l Limits) TimeLock(lk *setupwire.Locked) uint64 {
	if lk.ChangeDelaySeconds == nil {
		return l.DefaultTimeLock
	}
	return *lk.ChangeDelaySeconds
}

// CheckTimeLock is the time lock cap of setupwire's Locked.Check under l.
func (l Limits) CheckTimeLock(lk *setupwire.Locked) error {
	if lk.ChangeDelaySeconds != nil && *lk.ChangeDelaySeconds > l.MaxTimeLock {
		return fmt.Errorf("locked: change_delay_seconds %d, at most %d in a %s build", *lk.ChangeDelaySeconds, l.MaxTimeLock, l.flavor())
	}
	return nil
}

// Wait is setupwire.Wait under l: 0 for an open update; for a locked one
// the active time lock, or the images minimum when that is larger and the
// allowed list gains an entry.
func (l Limits) Wait(active *setupwire.Locked, u *setupwire.UpdateBody) uint64 {
	if u.Group != setupwire.GroupLocked {
		return 0
	}
	w := l.TimeLock(active)
	if u.Locked != nil && setupwire.GainsImage(active.AllowedImageMeasurements, u.Locked.AllowedImageMeasurements) {
		w = max(w, l.ImagesMinTimeLock)
	}
	return w
}

// OrderWait is dkgorder.Wait under l: the time lock in force, at least the
// images minimum. On the dev platform a runner waits the time lock alone
// (runner/keygen); dev says so.
func (l Limits) OrderWait(active *setupwire.Locked, dev bool) uint64 {
	if dev {
		return l.TimeLock(active)
	}
	return max(l.TimeLock(active), l.ImagesMinTimeLock)
}

// LatestActivateAt is setupwire.LatestActivateAt under l.
func (l Limits) LatestActivateAt(now, w uint64) uint64 {
	return setupwire.SatAdd(setupwire.SatAdd(now, w), l.ActivationHorizon)
}

// CheckActivateAt is setupwire.CheckActivateAt under l.
func (l Limits) CheckActivateAt(activateAt, now, w uint64) error {
	if limit := l.LatestActivateAt(now, w); activateAt > limit {
		return fmt.Errorf("update: activate_at %d is past %d (now + wait %d + horizon %d)", activateAt, limit, w, l.ActivationHorizon)
	}
	return nil
}

func (l Limits) flavor() Flavor {
	if l == Testnet.Limits() {
		return Testnet
	}
	return Default
}
