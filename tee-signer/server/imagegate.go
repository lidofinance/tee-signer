package server

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"

	"github.com/lidofinance/tee-signer/governance/setupwire"
	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/buildchain"
)

// The image check (docs/protocol.md, "Image check"). The key rule of the
// cloud decides which image gets the sealing key; the approvers decide
// which images may run, in allowed_image_measurements of the locked group.
// The runner holds itself to their list: it reads its own image from the
// evidence its key release used (platform.Platform.SelfImage) and compares
// it with the list in force, the newest mark log record's locked group with
// every pending update past its effective time made active (Updates). An
// image the list does not name signs and imports nothing. It
// stays up and answers HEALTH, PUBLIC_KEYS, ATTEST, IDENTITY and
// CONFIG_UPDATE, so a watchdog sees why and the approvers can list it.
//
// The check runs at start before the shares load (main.go leaves them
// sealed in the store when it fails) and again on every request, so a
// locked update that drops the image stops the runner at the update's
// effective time.
//
// The image rule of the key rule lock (AWS, tee-signer/keyruleimages.go)
// uses the same gate: a start on a prod chain whose key rule releases the
// sealing key to an image the list does not name leaves the shares sealed
// too (WithholdKeyRule), and the gate reports it as ImageKeyRuleUnlisted
// until a locked update lists the image, then asks for a restart.

// ImageGateOptions configure NewImageGate.
type ImageGateOptions struct {
	// Platform is the platform's name and SelfImage its SelfImage hook. A
	// nil hook is accepted on dev only, which has no image kind.
	Platform  string
	SelfImage func(ctx context.Context) (setupwire.Image, error)
	// Override serves an image the list does not name. Only a non-prod
	// build takes it (-allow-unlisted-image); NewImageGate refuses it in a
	// mainnet build.
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
	withheld bool     // the start left the shares sealed (Withhold, WithholdKeyRule)
	ruleIDs  [][]byte // the key rule's images the start compared (WithholdKeyRule)
	logged   string   // the last verdict written to the log
}

// ErrOverrideInMainnetBuild is NewImageGate's answer to an override in a
// mainnet build.
var ErrOverrideInMainnetBuild = errors.New("image check: a mainnet build has no override; only a non-prod build serves an image the allowed list does not name")

// NewImageGate reads the runner's own image once. A platform that cannot
// say which image it is gives a gate that refuses (state unknown), not an
// error: the runner stays up and HEALTH says why.
func NewImageGate(ctx context.Context, o ImageGateOptions) (*ImageGate, error) {
	if o.Override && buildchain.Prod {
		return nil, ErrOverrideInMainnetBuild
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

// WithholdKeyRule records that the start loaded no share because the
// image rule of the key rule lock refused (tee-signer keyruleimages.go):
// the key rule releases the sealing key to ids, and the list in force
// did not name every one of them, or could not be read. The gate then
// compares ids with the list on every verdict: it refuses with
// ImageKeyRuleUnlisted while one is unlisted, and asks for a restart once
// the list names them all, as after Withhold.
func (g *ImageGate) WithholdKeyRule(ids [][]byte) {
	g.mu.Lock()
	g.withheld, g.ruleIDs = true, ids
	g.mu.Unlock()
}

// Check is nil when the runner may serve a request that signs
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
			g.log.Warn("image check: this image is NOT on allowed_image_measurements in force; served anyway under the non-prod build's override", attrs...)
		case backend.ImageKeyRuleUnlisted:
			g.log.Error("image check failed: the key rule releases the sealing key to an image allowed_image_measurements in force does not name; this runner signs and imports nothing", attrs...)
		default:
			g.log.Error("image check failed: this runner signs and imports nothing", attrs...)
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
	g.mu.Lock()
	withheld, ruleIDs := g.withheld, g.ruleIDs
	g.mu.Unlock()
	switch {
	case g.selfErr != nil:
		c.State, c.Why = backend.ImageUnknown, "this runner cannot tell its own image: "+g.selfErr.Error()
		return c, c.Why
	case g.self == nil:
		c.State, c.Why = backend.ImageNotApplicable, "the dev platform has no image kind"
		return c, ""
	case u == nil && ruleIDs != nil:
		c.State, c.Why = backend.ImageUnknown, "no mark log, so no allowed list in force to compare the key rule's images with: the start left the shares sealed"
		return c, c.Why
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
	unlisted := unlistedKeyRuleImages(l, ruleIDs)
	switch {
	case !listed && !g.override:
		c.State = backend.ImageNotAllowed
		c.Why = fmt.Sprintf("this %s image is not on allowed_image_measurements of locked version %d in force (it lists %d %s images): it signs and imports nothing until a locked update lists it",
			g.self.Kind, v, n, g.self.Kind)
		return c, c.Why
	case len(unlisted) > 0:
		c.State = backend.ImageKeyRuleUnlisted
		c.Why = fmt.Sprintf("the key rule releases the sealing key to %d image(s) that allowed_image_measurements of locked version %d in force does not name (PCR0 %s): "+
			"an enclave of such an image opens every sealed share without the image check, so the start left the shares sealed; "+
			"this runner signs and imports nothing until a locked update lists the image(s) and it restarts, or the shares move to a key whose policy names listed images only",
			len(unlisted), v, hexList(unlisted))
		return c, c.Why
	case listed && withheld:
		c.State = backend.ImageRestartNeeded
		c.Why = fmt.Sprintf("locked version %d lists this image, but it was not allowed at start and the shares stayed sealed: restart the runner", v)
		if ruleIDs != nil {
			c.Why = fmt.Sprintf("locked version %d lists every image the key rule releases the sealing key to, but the start left the shares sealed: restart the runner", v)
		}
		return c, c.Why
	case listed:
		c.State = backend.ImageAllowed
		return c, ""
	}
	c.State = backend.ImageOverride
	c.Why = fmt.Sprintf("not on allowed_image_measurements of locked version %d; served under the non-prod build's override", v)
	return c, ""
}

// hexList is ids in hex, comma-separated.
func hexList(ids [][]byte) string {
	s := make([]string, len(ids))
	for i, id := range ids {
		s[i] = hex.EncodeToString(id)
	}
	return strings.Join(s, ",")
}
