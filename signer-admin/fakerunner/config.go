package fakerunner

import (
	"fmt"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/governance/flavor"
	"github.com/lidofinance/tee-signer/governance/setupwire"
	cloud "github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/wire"
	wireadmin "github.com/lidofinance/tee-signer/signer-protocol/wire/admin"
)

// configModel plays the config updates of a runner with a setup
// (runner/server/config.go of the cloud repo, setup-phase.md section 6) on
// this machine's clock: the checks in the runner's order, the waits,
// supersede and the rotation rule. It does not run the fork rule or the
// core's value checks; the dev runner test of signer-admin covers the real
// runner.
type configModel struct {
	setup *setupwire.Setup
	hash  [32]byte
	// groups by setupwire.Group: index 1 locked, 2 open.
	groups [3]groupModel
	// limits are the governance times of the build flavour it plays.
	limits flavor.Limits
}

type groupModel struct {
	version uint64
	hash    [32]byte
	body    *setupwire.UpdateBody // nil at version 0
	pending *pendingModel
}

type pendingModel struct {
	version uint64
	hash    [32]byte
	at      uint64
	update  *setupwire.Update
}

func newConfigModel(raw []byte) (*configModel, error) {
	s, err := setupwire.DecodeSetup(raw)
	if err != nil {
		return nil, err
	}
	h, err := s.Hash()
	if err != nil {
		return nil, err
	}
	c := &configModel{setup: s, hash: h, limits: flavor.Default.Limits()}
	for _, g := range []setupwire.Group{setupwire.GroupLocked, setupwire.GroupOpen} {
		if c.groups[g].hash, err = s.GroupHash(g); err != nil {
			return nil, err
		}
	}
	return c, nil
}

func (c *configModel) locked() *setupwire.Locked {
	if b := c.groups[setupwire.GroupLocked].body; b != nil {
		return b.Locked
	}
	return &c.setup.Locked
}

func (c *configModel) activate(g setupwire.Group) {
	gm := &c.groups[g]
	p := gm.pending
	gm.version, gm.hash, gm.body, gm.pending = p.version, p.hash, &p.update.Body, nil
}

// reconcile brings every pending update due at now into force: open first
// when it is due strictly earlier, then locked (a rotation drops the
// pending open update, which the old set signed), then open.
func (c *configModel) reconcile(now uint64) {
	lp, op := c.groups[setupwire.GroupLocked].pending, c.groups[setupwire.GroupOpen].pending
	if op != nil && op.at <= now && (lp == nil || op.at < lp.at) {
		c.activate(setupwire.GroupOpen)
	}
	if lp != nil && lp.at <= now {
		rotation := len(lp.update.NewSet) > 0
		c.activate(setupwire.GroupLocked)
		if rotation {
			c.groups[setupwire.GroupOpen].pending = nil
		}
	}
	if op := c.groups[setupwire.GroupOpen].pending; op != nil && op.at <= now {
		c.activate(setupwire.GroupOpen)
	}
}

func (c *configModel) state(now uint64) cloud.SetupState {
	c.reconcile(now)
	s := cloud.SetupState{SetupHash: c.hash, ApproverSetHash: c.locked().Approvers.Hash()}
	for g, dst := range map[setupwire.Group]*cloud.ConfigGroup{setupwire.GroupLocked: &s.Locked, setupwire.GroupOpen: &s.Open} {
		gm := &c.groups[g]
		*dst = cloud.ConfigGroup{Version: gm.version, Hash: gm.hash}
		if p := gm.pending; p != nil {
			dst.Pending = cloud.PendingUpdate{Version: p.version, Hash: p.hash, EffectiveAt: p.at}
		}
	}
	return s
}

func badRequest(format string, args ...any) error {
	return cloud.Refused(cloud.StatusBadRequest, "config update: "+format, args...)
}

// accept is Updates.Accept of the runner, without the fork rule and the
// core's checks.
func (c *configModel) accept(raw []byte, now uint64) (uint8, error) {
	u, err := setupwire.DecodeUpdate(raw)
	if err != nil {
		return 0, badRequest("%v", err)
	}
	b := &u.Body
	if err := b.Matches(c.setup); err != nil {
		return 0, badRequest("%v", err)
	}
	hash, err := b.Hash()
	if err != nil {
		return 0, badRequest("%v", err)
	}
	c.reconcile(now)
	gm := &c.groups[b.Group]
	if p := gm.pending; p != nil && p.version == b.Version && p.hash == hash {
		if err := u.Verify(&c.locked().Approvers); err != nil {
			return 0, badRequest("%v", err)
		}
		return wireadmin.ConfigKnown, nil
	}
	if gm.version == b.Version && gm.hash == hash {
		return wireadmin.ConfigKnown, nil
	}
	var pending uint64
	if gm.pending != nil {
		pending = gm.pending.version
	}
	if err := setupwire.CheckVersion(b.Version, gm.version, pending); err != nil {
		return 0, badRequest("%s %v", b.Group, err)
	}
	if b.PrevHash != gm.hash {
		return 0, badRequest("prev_hash %x is not the %s update in force (version %d, %x)", b.PrevHash[:8], b.Group, gm.version, gm.hash[:8])
	}
	if err := u.Verify(&c.locked().Approvers); err != nil {
		return 0, badRequest("%v", err)
	}
	wait := c.limits.Wait(c.locked(), b)
	if err := c.limits.CheckActivateAt(b.ActivateAt, now, wait); err != nil {
		return 0, badRequest("%v", err)
	}
	gm.pending = &pendingModel{version: b.Version, hash: hash, at: setupwire.EffectiveActivation(b.ActivateAt, now, wait), update: u}
	c.reconcile(now)
	return wireadmin.ConfigAccepted, nil
}

func unixNow() uint64 { return uint64(max(time.Now().Unix(), 0)) }

// StartSetup starts a runner with the setup raw (a binary setup). Its
// IDENTITY and HEALTH report the setup state, and it takes CONFIG_UPDATE
// as a runner with that setup does, with its clock trusted.
func StartSetup(t testing.TB, raw []byte) *Runner {
	t.Helper()
	return StartSetupAs(t, raw, flavor.Default)
}

// StartSetupAs is StartSetup for a runner of build flavour f: its
// certificate's name, its HEALTH version and its waits are that flavour's.
func StartSetupAs(t testing.TB, raw []byte, f flavor.Flavor) *Runner {
	t.Helper()
	m, err := newConfigModel(raw)
	if err != nil {
		t.Fatal(fmt.Errorf("fakerunner: %w", err))
	}
	m.limits = f.Limits()
	r := start(t, cloud.SetupState{}, f)
	r.mu.Lock()
	r.config = m
	r.mu.Unlock()
	return r
}

// configUpdate answers CONFIG_UPDATE.
func (r *Runner) configUpdate(p []byte) []byte {
	raw, err := wireadmin.DecodeConfigUpdate(p)
	if err != nil {
		return wire.EncodeError(cloud.Refused(cloud.StatusBadRequest, "%v", err))
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.config == nil {
		return wire.EncodeError(cloud.Refused(cloud.StatusUnsupported, "this runner has no setup, so it takes no config update"))
	}
	now := unixNow()
	outcome, err := r.config.accept(raw, now)
	if err != nil {
		return wire.EncodeError(err)
	}
	s := r.config.state(now)
	return wire.EncodeOK(wireadmin.EncodeConfigUpdateResponse(outcome, &s))
}
