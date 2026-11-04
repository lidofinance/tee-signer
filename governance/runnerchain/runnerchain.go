// Package runnerchain is what clients and tools know of the chain a runner
// is built for (signer-protocol/buildchain): mainnet, the build for real
// keys, or hoodi, devnet or ci-test, the same code with governance times in
// minutes for research and tests. It says how a runner shows its chain,
// gives the governance times of each build, and holds the chains each
// non-prod build may run on (chains.go).
//
// A runner shows the chain of its build in two places, both set by its
// code:
//
//   - HEALTH's version: "+" and the chain at its end in a non-prod build.
//     People, the dashboard and the tools read it here.
//   - the subject common name of the TLS certificate it makes at start:
//     CertName of its chain. Only the runner holds the certificate's key,
//     and the attested identity binds that key, so attestation-verify/runnerclient
//     checks the build here, in the handshake, before it sends anything.
//
// Neither changes the wire protocol. IDENTITY and ATTEST do not carry the
// build's chain: they have no field for it. The measurement (PCRs, CCE
// policy, image digest) differs anyway, since the constants are in the
// image.
//
// Clients compute waits with Limits of the runner's build, not with the
// constants of their own build.
package runnerchain

import (
	"fmt"
	"strings"

	"github.com/lidofinance/tee-signer/governance/setupwire"
	"github.com/lidofinance/tee-signer/signer-protocol/buildchain"
)

// Chain is the chain a runner is built for.
type Chain string

const (
	Mainnet Chain = buildchain.Mainnet
	Hoodi   Chain = buildchain.Hoodi
	Devnet  Chain = buildchain.Devnet
	CITest  Chain = buildchain.CITest
)

// Build is the chain of this binary's build.
const Build = Chain(buildchain.Name)

// Chains are the chains a runner can be built for: the rows of the chain
// table (governance/setupwire chains.go), mainnet first.
var Chains = func() []Chain {
	var out []Chain
	for _, r := range setupwire.ChainRows() {
		out = append(out, Chain(r.Name))
	}
	return out
}()

// MainnetCertName is the certificate name of a mainnet runner.
const MainnetCertName = buildchain.MainnetCertName

// Parse is the chain named s, or an error.
func Parse(s string) (Chain, error) {
	for _, c := range Chains {
		if string(c) == s {
			return c, nil
		}
	}
	return "", fmt.Errorf("chain %q: want one of %s", s, names())
}

func names() string {
	var s []string
	for _, c := range Chains {
		s = append(s, string(c))
	}
	return strings.Join(s, ", ")
}

// Prod is c's prod property in the chain table: the build of c has the
// long governance times, and setups of c get the strict checks. A chain
// the table does not have counts as prod, the safe side for times and
// checks.
func (c Chain) Prod() bool {
	r, ok := setupwire.ChainRowByName(string(c))
	return !ok || r.Prod
}

// VersionSuffix is the end of HEALTH's version in a runner of c: "+" and
// the chain (semver build metadata), nothing for mainnet.
func (c Chain) VersionSuffix() string {
	if c.Prod() {
		return ""
	}
	return "+" + string(c)
}

// CertName is the subject common name of the TLS certificate of a runner
// of c.
func (c Chain) CertName() string {
	if c.Prod() {
		return MainnetCertName
	}
	return MainnetCertName + " " + string(c)
}

// FromVersion is the chain of a runner whose HEALTH reports version v: the
// build metadata after "+", or mainnet without it. A name this package does
// not know comes back as it is.
func FromVersion(v string) Chain {
	if i := strings.LastIndexByte(v, '+'); i >= 0 {
		return Chain(v[i+1:])
	}
	return Mainnet
}

// FromCertName is the chain of a runner whose TLS certificate has the
// subject common name cn. ok is false for a name no build makes.
func FromCertName(cn string) (c Chain, ok bool) {
	for _, c := range Chains {
		if c.CertName() == cn {
			return c, true
		}
	}
	return "", false
}

// Limits are the governance times of a build, in seconds: the values of
// setupwire's DefaultTimeLock, MaxTimeLock, ActivationHorizon and
// ImagesMinTimeLock in that build.
type Limits struct {
	DefaultTimeLock   uint64 // when the setup names no change delay
	MaxTimeLock       uint64
	ActivationHorizon uint64 // past the required wait
	ImagesMinTimeLock uint64 // allowed-images updates
}

var (
	mainnetLimits = Limits{buildchain.MainnetTimeLock, buildchain.MainnetMaxTimeLock,
		buildchain.MainnetActivationHorizon, buildchain.MainnetImagesMinTimeLock}
	shortLimits = Limits{buildchain.ShortTimeLock, buildchain.ShortMaxTimeLock,
		buildchain.ShortActivationHorizon, buildchain.ShortImagesMinTimeLock}
)

// Limits returns the governance times of the build of c. A chain this
// package does not know gets the mainnet times.
func (c Chain) Limits() Limits {
	if !c.Prod() {
		return shortLimits
	}
	return mainnetLimits
}

// MinTimeLock is setupwire.MinChangeDelay under l: the floor of the time
// lock on a prod chain, l's default; none on another chain.
func (l Limits) MinTimeLock(c *setupwire.Chain) uint64 {
	if c.Prod() {
		return l.DefaultTimeLock
	}
	return 0
}

// TimeLock is setupwire's Locked.ChangeDelayOn under l: the group's time
// lock, never below the chain's floor.
func (l Limits) TimeLock(c *setupwire.Chain, lk *setupwire.Locked) uint64 {
	w := l.DefaultTimeLock
	if lk.ChangeDelaySeconds != nil {
		w = *lk.ChangeDelaySeconds
	}
	return max(w, l.MinTimeLock(c))
}

// CheckTimeLock is the time lock cap of setupwire's Locked.Check and the
// floor of Locked.CheckChangeDelay under l.
func (l Limits) CheckTimeLock(c *setupwire.Chain, lk *setupwire.Locked) error {
	if lk.ChangeDelaySeconds == nil {
		return nil
	}
	if *lk.ChangeDelaySeconds > l.MaxTimeLock {
		return fmt.Errorf("locked: change_delay_seconds %d, at most %d in a %s build", *lk.ChangeDelaySeconds, l.MaxTimeLock, l.kind())
	}
	if floor := l.MinTimeLock(c); *lk.ChangeDelaySeconds < floor {
		return fmt.Errorf("locked: change_delay_seconds %d on a prod chain (mainnet, or genesis values no row of the chain table matches), at least %d in a %s build", *lk.ChangeDelaySeconds, floor, l.kind())
	}
	return nil
}

// Wait is setupwire.Wait under l: 0 for an open update; for a locked one
// the active time lock (never below the chain's floor), or the images
// minimum when that is larger and the allowed list gains an entry.
func (l Limits) Wait(c *setupwire.Chain, active *setupwire.Locked, u *setupwire.UpdateBody) uint64 {
	if u.Group != setupwire.GroupLocked {
		return 0
	}
	w := l.TimeLock(c, active)
	if u.Locked != nil && setupwire.GainsImage(active.AllowedImageMeasurements, u.Locked.AllowedImageMeasurements) {
		w = max(w, l.ImagesMinTimeLock)
	}
	return w
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

// kind names the builds with these times in messages.
func (l Limits) kind() string {
	if l == shortLimits {
		return "non-prod"
	}
	return "mainnet"
}
