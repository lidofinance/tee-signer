package server

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sync"

	"github.com/lidofinance/tee-signer/governance/setupwire"
	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/buildflavor"
)

// The image check (docs/protocol.md, "Image check"). The key rule of the
// cloud decides which image gets the sealing key; the approvers decide
// which images may run, in allowed_image_measurements of the locked group.
// The runner holds itself to their list: it reads its own image from the
// evidence its key release used (platform.Platform.SelfImage) and compares
// it with the list in force, the newest mark log record's locked group with
// every pending update past its effective time made active (Updates). An
// image the list does not name signs, hands over and imports nothing. It
// stays up and answers HEALTH, PUBLIC_KEYS, ATTEST, IDENTITY and
// CONFIG_UPDATE, so a watchdog sees why and the approvers can list it.
//
// The check runs at start before the shares load (main.go leaves them
// sealed in the store when it fails) and again on every request, so a
// locked update that drops the image stops the runner at the update's
// effective time.

// ImageGateOptions configure NewImageGate.
type ImageGateOptions struct {
	// Platform is the platform's name and SelfImage its SelfImage hook. A
	// nil hook is accepted on dev only, which has no image kind.
	Platform  string
	SelfImage func(ctx context.Context) (setupwire.Image, error)
	// Override serves an image the list does not name. Only a testnet
	// build takes it (-allow-unlisted-image); NewImageGate refuses it in a
	// default build.
	Override bool
	Log      *slog.Logger
}

// ImageGate is the image check of one runner process.
type ImageGate struct {
	self     *setupwire.Image // nil: dev, or unknown (selfErr set)
	selfErr  error
	override bool
	log      *slog.Logger

	mu       sync.Mutex
	withheld bool   // the start left the shares sealed (Withhold)
	logged   string // the last verdict written to the log
}

// ErrOverrideInDefaultBuild is NewImageGate's answer to an override in a
// default build.
var ErrOverrideInDefaultBuild = errors.New("image check: a default build has no override; only a testnet build serves an image the allowed list does not name")

// NewImageGate reads the runner's own image once. A platform that cannot
// say which image it is gives a gate that refuses (state unknown), not an
// error: the runner stays up and HEALTH says why.
func NewImageGate(ctx context.Context, o ImageGateOptions) (*ImageGate, error) {
	if o.Override && buildflavor.Name != "testnet" {
		return nil, ErrOverrideInDefaultBuild
	}
	g := &ImageGate{override: o.Override, log: o.Log}
	if g.log == nil {
		g.log = slog.Default()
	}
	switch {
	case o.SelfImage != nil:
		im, err := o.SelfImage(ctx)
		if err != nil {
			g.selfErr = err
		} else {
			g.self = &im
		}
	case o.Platform != "dev":
		g.selfErr = fmt.Errorf("platform %s gives no image of its own", o.Platform)
	}
	return g, nil
}

// Withhold records that the start loaded no share because the check
// refused. The runner then refuses until a restart, also once the list
// names its image.
func (g *ImageGate) Withhold() {
	g.mu.Lock()
	g.withheld = true
	g.mu.Unlock()
}

// Check is nil when the runner may serve a request that signs, hands over
// or imports, and a NOT_READY refusal that says why otherwise.
func (g *ImageGate) Check(u *Updates) error {
	_, err := g.verdict(u)
	return err
}

// Status is the check as HEALTH reports it, and whether it refuses.
func (g *ImageGate) Status(u *Updates) (*backend.ImageCheck, bool) {
	c, err := g.verdict(u)
	return &c, err != nil
}

// verdict evaluates the check now and logs it when it changed.
func (g *ImageGate) verdict(u *Updates) (backend.ImageCheck, error) {
	c, refuse := g.evaluate(u)
	key := fmt.Sprintf("%s %d", c.State, c.LockedVersion)
	g.mu.Lock()
	changed := key != g.logged
	g.logged = key
	g.mu.Unlock()
	if changed {
		attrs := []any{"state", c.State, "kind", c.Kind, "measurement", c.Measurement, "locked_version", c.LockedVersion, "why", c.Why}
		switch c.State {
		case backend.ImageAllowed:
			g.log.Info("image check: this image is on allowed_image_measurements in force", attrs...)
		case backend.ImageNotApplicable:
			g.log.Info("image check: not applicable", attrs...)
		case backend.ImageOverride:
			g.log.Warn("image check: this image is NOT on allowed_image_measurements in force; served anyway under the testnet build's override", attrs...)
		default:
			g.log.Error("image check failed: this runner signs, hands over and imports nothing", attrs...)
		}
	}
	if refuse != "" {
		return c, backend.Refused(backend.StatusNotReady, "image check: %s", refuse)
	}
	return c, nil
}

// evaluate is the check against the list in force now: the state, and the
// reason to refuse ("" to serve).
func (g *ImageGate) evaluate(u *Updates) (backend.ImageCheck, string) {
	var c backend.ImageCheck
	if g.self != nil {
		c.Kind, c.Measurement = g.self.Kind.String(), hex.EncodeToString(g.self.Measurement)
	}
	switch {
	case g.selfErr != nil:
		c.State, c.Why = backend.ImageUnknown, "this runner cannot tell its own image: "+g.selfErr.Error()
		return c, c.Why
	case g.self == nil:
		c.State, c.Why = backend.ImageNotApplicable, "the dev platform has no image kind"
		return c, ""
	case u == nil:
		c.State, c.Why = backend.ImageNotApplicable, "no setup, so no allowed-images list"
		return c, ""
	}
	l, v, err := u.lockedInForce()
	if err != nil {
		c.State, c.Why = backend.ImageUnknown, "the allowed list in force is unknown: "+err.Error()
		return c, c.Why
	}
	c.LockedVersion = v
	n := 0
	listed := slices.ContainsFunc(l.AllowedImageMeasurements, func(a setupwire.Image) bool {
		if a.Kind != g.self.Kind {
			return false
		}
		n++
		return bytes.Equal(a.Measurement, g.self.Measurement)
	})
	g.mu.Lock()
	withheld := g.withheld
	g.mu.Unlock()
	switch {
	case listed && withheld:
		c.State = backend.ImageRestartNeeded
		c.Why = fmt.Sprintf("locked version %d lists this image, but it was not allowed at start and the shares stayed sealed: restart the runner", v)
		return c, c.Why
	case listed:
		c.State = backend.ImageAllowed
		return c, ""
	case g.override:
		c.State = backend.ImageOverride
		c.Why = fmt.Sprintf("not on allowed_image_measurements of locked version %d; served under the testnet build's override", v)
		return c, ""
	}
	c.State = backend.ImageNotAllowed
	c.Why = fmt.Sprintf("this %s image is not on allowed_image_measurements of locked version %d in force (it lists %d %s images): it signs, hands over and imports nothing until a locked update lists it",
		g.self.Kind, v, n, g.self.Kind)
	return c, c.Why
}
