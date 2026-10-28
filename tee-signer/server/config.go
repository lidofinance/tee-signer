package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"slices"
	"time"

	"github.com/lidofinance/tee-signer/devkit/lockorder"
	"github.com/lidofinance/tee-signer/governance/setupwire"
	"github.com/lidofinance/tee-signer/platform"
	"github.com/lidofinance/tee-signer/signer-core/core"
	"github.com/lidofinance/tee-signer/signer-protocol"
	wireadmin "github.com/lidofinance/tee-signer/signer-protocol/wire/admin"
	"github.com/lidofinance/tee-signer/slashing-log"
)

// Config updates (research/setup-phase.md in the threshold-signer-poc repo, "Design
// v2", sections 6 to 9, review items G and J). A runner with a setup holds
// two config groups, locked and open. Version 0 of each is the setup's;
// every later version is an approver-signed CONFIG_UPDATE. Every mark log
// record carries the state (per group the active update and the pending
// one), and the log holds the bodies of those updates.
//
// The effective config follows from the newest record and the clock, not
// from a record that says an update is active. Once a pending update's
// effective time has passed, its values apply to every request, whether or
// not the record that shows it lands. A rotation that comes into force
// drops the pending open update, which the old set signed.
//
// The locked values the core signs by (allowed_fee_recipients, the builder
// gas limits, builder_registration_max_future_seconds,
// exit_allowed_validators, allow_unverified_nonslashable_signing) switch at
// the effective time (core.Signer.SetPolicy), and so do the slot time
// changes (core.Signer.SetSlotTimes). The slot time rule takes an update
// only if its slot times agree with those in force on every epoch up to
// epoch(T) + max_sign_epochs_ahead_of_clock + 1, T its effective time, so
// the switch at T changes no clock the signer used before T. An open update
// (forks, Gloas) goes into the core when it arrives. The fork rule
// (core.Signer.SetSchedule) takes it only if the old and the new schedule
// agree on every epoch the signer may sign before the effective time, so
// applying it at once signs the same as applying it then. A switch at the
// effective time could instead meet the rule one epoch late and be refused.
//
// The fork rule counts epochs under the full slot schedule: the slot times
// in force and those of a pending locked update, whichever gives the later
// epoch. In the other order, a locked update with new slot times is refused
// when a pending open update would no longer keep clear of the epochs the
// signer may reach before its effective time under them.

// UpdateLog is what config updates need of the mark log
// (*markstore.MarkLog).
type UpdateLog interface {
	State() markstore.ConfigState
	Body(g setupwire.Group, v uint64) ([]byte, [32]byte, error)
	PutBody(ctx context.Context, raw []byte) (setupwire.Group, uint64, [32]byte, error)
	SetState(ctx context.Context, st markstore.ConfigState) error
}

// UpdatesOptions configure NewUpdates.
type UpdatesOptions struct {
	Setup     *setupwire.Setup
	SetupHash [32]byte
	Log       UpdateLog
	// Clock is the platform's clock. It decides which updates are in force.
	// An update is taken only while the clock is trusted and answers (the
	// NTS clock with a quorum), unless AnyClock is set: the dev platform,
	// which protects nothing.
	Clock    platform.Clock
	AnyClock bool
	Logger   *slog.Logger
}

// logTimeout bounds the log writes of one CONFIG_UPDATE.
const logTimeout = time.Minute

// updateRef names the update a group's values come from: its version and
// hash (version 0: the setup's group).
type updateRef struct {
	version uint64
	hash    [32]byte
}

// unknownRef is a ref no group has: the core holds values of no known
// update (placeholders, while a body is unreadable).
var unknownRef = updateRef{version: math.MaxUint64}

func refOf(g markstore.GroupState) updateRef { return updateRef{g.Version, g.Hash} }

// bodyID names a decoded update body.
type bodyID struct {
	g setupwire.Group
	updateRef
}

// view is the config in force at one time.
type view struct {
	// state is the log's state with every pending update whose effective
	// time has passed made active, and what a rotation dropped gone.
	state markstore.ConfigState
	// locked and open are the active values; nil when the body is
	// unreadable.
	locked *setupwire.Locked
	open   *setupwire.Open
	// lockedAt is the effective time of the locked update that came into
	// force in this view, 0 when none did.
	lockedAt uint64
	// pendingSlots are the slot time changes of the pending locked update
	// when its body is readable and they differ from those in force: the
	// fork rule counts epochs under them too.
	pendingSlots [][]core.SlotTimeChange
	// newest is the open schedule the core holds: the pending update's when
	// its body is readable, else the active one's. newestAt is its
	// effective time, 0 for the active values.
	newest    *setupwire.Open
	newestRef updateRef
	newestAt  uint64
	// missing: a body the active values need is unreadable.
	missing error
}

// Updates holds a runner's config groups: it takes CONFIG_UPDATE, gives the
// core the values in force and reports the effective state.
type Updates struct {
	opt UpdatesOptions

	// writeMu orders the log writes: an accepted update and the record that
	// shows an update in force.
	writeMu lockorder.Mutex[updatesWriteMuName]

	mu     lockorder.Mutex[updatesMuName]
	signer *core.Signer
	bodies map[bodyID]*setupwire.Update
	logSt  markstore.ConfigState // the log's state the view comes from
	view   view
	// next is the earliest effective time of a pending update in the view.
	next uint64
	// lastNow is the latest time a view was computed at. A view is never
	// computed at an earlier time, so updates in force stay in force when
	// a later reading is behind (SG-ACTIVATE-02).
	lastNow uint64
	// coreLocked and coreOpen name the updates whose values the core holds.
	coreLocked, coreOpen updateRef
	// stuck: the core refused values of the log; nothing is signed until a
	// restart builds the core from the log.
	stuck error

	// sourceOrders are the handover orders that name this runner as their
	// source (handover_source.go), by hash, with their not_after: one of
	// them in the order slot is no import (importslot.go), and it leaves
	// the slot at its not_after (compute). handedOver reports the
	// tombstone, after which the order stays.
	srcMu        lockorder.Mutex[updatesSrcMuName]
	sourceOrders map[[32]byte]uint64
	handedOver   func() bool
}

// NewUpdates returns the config updates of a runner with a setup. Call
// StartConfig before the core exists, then Attach.
func NewUpdates(o UpdatesOptions) (*Updates, error) {
	if o.Setup == nil || o.Log == nil || o.Clock == nil {
		return nil, errors.New("config updates: setup, mark log and clock are required")
	}
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	return &Updates{opt: o, bodies: map[bodyID]*setupwire.Update{}, coreLocked: unknownRef, coreOpen: unknownRef}, nil
}

// policyOf is the core's signing policy of a locked group.
func policyOf(l *setupwire.Locked) core.Policy {
	return core.Policy{
		ExitAllowlist:                append([]uint64(nil), l.ExitAllowedValidators...),
		FeeRecipients:                append([]backend.Address(nil), l.AllowedFeeRecipients...),
		BuilderRequestAuthRoots:      append([]backend.Root(nil), l.AllowedBuilderRequestAuthDataRoots...),
		GasLimitMin:                  l.BuilderGasLimitMin,
		GasLimitMax:                  l.BuilderGasLimitMax,
		RegistrationMaxFutureSeconds: l.BuilderRegistrationMaxFutureSeconds,
		AllowUnverifiedNonslashable:  l.AllowUnverifiedNonslashableSigning,
	}
}

// slotTimesOf is the core's slot time changes of a locked group.
func slotTimesOf(l *setupwire.Locked) []core.SlotTimeChange {
	var out []core.SlotTimeChange
	for _, c := range l.SlotTimeChanges {
		out = append(out, core.SlotTimeChange{Epoch: c.Epoch, SecondsPerSlot: c.SecondsPerSlot})
	}
	return out
}

// scheduleOf is the core's fork schedule of an open group.
func scheduleOf(o *setupwire.Open) core.Schedule {
	s := core.Schedule{}
	for _, f := range o.ForkSchedule {
		s.Forks = append(s.Forks, core.Fork{Epoch: f.Epoch, Version: f.Version})
	}
	if o.GloasForkEpoch != nil {
		e := *o.GloasForkEpoch
		s.GloasForkEpoch = &e
	}
	return s
}

func unix(t time.Time) uint64 { return uint64(max(t.Unix(), 0)) }

// StartConfig returns base (the setup's chain config) with the values in
// force at start: the locked values of the active update, and the newest
// open schedule whose body is readable. A value whose body is unreadable
// keeps base's; the runner then signs nothing until the body is back. A
// pending update whose effective time passed while the runner was down is in
// force at once.
func (u *Updates) StartConfig(base core.Config) (core.Config, error) {
	var now uint64
	if t, err := u.opt.Clock.Now(); err == nil {
		now = unix(t)
	} else {
		u.opt.Logger.Warn("config: no clock at start; the updates due by now come into force once it answers", "err", err)
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	u.reconcileLocked(now)
	v := &u.view
	cfg := base
	if v.locked != nil {
		cfg = cfg.WithPolicy(policyOf(v.locked)).WithSlotTimes(slotTimesOf(v.locked))
		u.coreLocked = refOf(v.state.Locked)
	}
	if v.newest != nil {
		cfg, u.coreOpen = cfg.WithSchedule(scheduleOf(v.newest)), v.newestRef
	}
	if v.missing != nil {
		u.opt.Logger.Error("config: an update body is unreadable; the runner signs nothing until it is back (send the update again)", "err", v.missing)
	}
	u.opt.Logger.Info("config at start", "locked", v.state.Locked.Version, "open", v.state.Open.Version,
		"locked_pending", pendingVersion(v.state.Locked), "open_pending", pendingVersion(v.state.Open),
		"in_force_without_record", !v.state.Equal(u.logSt))
	return cfg, cfg.Validate()
}

// Attach gives the updates the core built from StartConfig's config.
func (u *Updates) Attach(s *core.Signer) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.signer = s
}

func pendingVersion(g markstore.GroupState) uint64 {
	if g.Pending == nil {
		return 0
	}
	return g.Pending.Version
}

// body returns the decoded update of group g at ref, from the cache or the
// log. An unreadable body is markstore.ErrBodyMissing.
func (u *Updates) body(g setupwire.Group, r updateRef) (*setupwire.Update, error) {
	id := bodyID{g, r}
	if b := u.bodies[id]; b != nil {
		return b, nil
	}
	raw, h, err := u.opt.Log.Body(g, r.version)
	if err != nil {
		return nil, err
	}
	upd, err := setupwire.DecodeUpdate(raw)
	if err == nil {
		h, err = upd.Body.Hash()
	}
	if err != nil || h != r.hash || upd.Body.Group != g {
		return nil, fmt.Errorf("%w: the stored %s version %d is not the update the log names", markstore.ErrBodyMissing, g, r.version)
	}
	u.bodies[id] = upd
	return upd, nil
}

func (u *Updates) lockedValues(g markstore.GroupState) (*setupwire.Locked, error) {
	if g.Version == 0 {
		return &u.opt.Setup.Locked, nil
	}
	b, err := u.body(setupwire.GroupLocked, refOf(g))
	if err != nil {
		return nil, err
	}
	return b.Body.Locked, nil
}

func (u *Updates) openValues(g markstore.GroupState) (*setupwire.Open, error) {
	if g.Version == 0 {
		return &u.opt.Setup.Open, nil
	}
	b, err := u.body(setupwire.GroupOpen, refOf(g))
	if err != nil {
		return nil, err
	}
	return b.Body.Open, nil
}

// isRotation reports whether the pending update of locked group g changes
// the approver set of g's active update. It reads both from their hashed
// bodies. An unreadable body is an error, and the update then counts as a
// rotation.
func (u *Updates) isRotation(g markstore.GroupState) (bool, error) {
	p := g.Pending
	b, err := u.body(setupwire.GroupLocked, updateRef{p.Version, p.Hash})
	if err != nil {
		return true, fmt.Errorf("the locked update %d coming into force: %w", p.Version, err)
	}
	old, err := u.lockedValues(g)
	if err != nil {
		return true, fmt.Errorf("the approver set before locked update %d: %w", p.Version, err)
	}
	return b.Body.IsRotation(&old.Approvers), nil
}

func activate(g *markstore.GroupState) {
	g.Version, g.Hash, g.Pending = g.Pending.Version, g.Pending.Hash, nil
}

// compute is the view of state st at time now. Pending updates come into
// force in the order of their effective times; at a tie the locked one
// goes first, so a rotation drops an open update due at the same second. A
// locked update is a rotation when its body gives the approvers another
// set than the one in force before it (setupwire.UpdateBody.IsRotation,
// the rule Verify applied at its arrival). The decision reads only the
// hashed body: the new-set signatures of a stored copy lie outside the
// hash, and the store is untrusted (SG-RECOVERY-01). When either body is
// unreadable the update counts as a rotation, and the view is missing, so
// the runner signs nothing and writes no state until the body is back.
func (u *Updates) compute(st markstore.ConfigState, now uint64) view {
	v := view{state: st.Clone()}
	var errs []error
	lp, op := v.state.Locked.Pending, v.state.Open.Pending
	if op != nil && op.EffectiveAt <= now && (lp == nil || op.EffectiveAt < lp.EffectiveAt) {
		activate(&v.state.Open)
	}
	if lp != nil && lp.EffectiveAt <= now {
		rotation, err := u.isRotation(v.state.Locked)
		if err != nil {
			errs = append(errs, err)
		}
		v.lockedAt = lp.EffectiveAt
		activate(&v.state.Locked)
		if rotation {
			// The new set replaces the old one: what the old set signed and
			// is still pending goes (section 8, step 4). A handover import
			// in progress stays in the slot (importslot.go): its source wrote
			// its tombstone, and the runner signs nothing until every share
			// is in.
			v.state.Open.Pending = nil
			if o := v.state.Order; o == nil || o.Kind != markstore.OrderHandover {
				v.state.Order = nil
			}
		}
	}
	if op := v.state.Open.Pending; op != nil && op.EffectiveAt <= now {
		activate(&v.state.Open)
	}
	// A source order past its not_after leaves the slot: no handover can
	// start under it, and IDENTITY would show it instead of a DKG order
	// that waits. Sync writes the cleared slot to the log.
	if na, ok := u.expiringSourceOrder(v.state.Order); ok && now >= na {
		v.state.Order = nil
	}
	var err error
	if v.locked, err = u.lockedValues(v.state.Locked); err != nil {
		errs = append(errs, err)
	}
	if v.open, err = u.openValues(v.state.Open); err != nil {
		errs = append(errs, err)
	} else {
		v.newest, v.newestRef = v.open, refOf(v.state.Open)
	}
	if p := v.state.Open.Pending; p != nil {
		r := updateRef{p.Version, p.Hash}
		if b, err := u.body(setupwire.GroupOpen, r); err == nil {
			v.newest, v.newestRef, v.newestAt = b.Body.Open, r, p.EffectiveAt
		}
	}
	if p := v.state.Locked.Pending; p != nil && v.locked != nil {
		if b, err := u.body(setupwire.GroupLocked, updateRef{p.Version, p.Hash}); err == nil {
			if st := slotTimesOf(b.Body.Locked); !slices.Equal(st, slotTimesOf(v.locked)) {
				v.pendingSlots = [][]core.SlotTimeChange{st}
			}
		}
	}
	v.missing = errors.Join(errs...)
	return v
}

// nextDue is the earliest effective time of a pending update in st.
func nextDue(st markstore.ConfigState) uint64 {
	n := uint64(math.MaxUint64)
	for _, g := range []markstore.GroupState{st.Locked, st.Open} {
		if g.Pending != nil {
			n = min(n, g.Pending.EffectiveAt)
		}
	}
	return n
}

// reconcileLocked computes the view at now from the log's state and gives
// the core the values in force: the locked values of the active update,
// the newest readable open schedule.
func (u *Updates) reconcileLocked(now uint64) {
	now = max(now, u.lastNow)
	u.lastNow = now
	u.logSt = u.opt.Log.State()
	u.view = u.compute(u.logSt, now)
	u.next = nextDue(u.view.state)
	if na, ok := u.expiringSourceOrder(u.view.state.Order); ok {
		u.next = min(u.next, na)
	}
	u.pruneLocked()
	if u.signer == nil || u.stuck != nil {
		return
	}
	v := &u.view
	if r := refOf(v.state.Locked); v.locked != nil && r != u.coreLocked {
		if st := slotTimesOf(v.locked); !slices.Equal(st, u.signer.Config().SlotTimeChanges) {
			if err := u.signer.SetSlotTimes(st, v.lockedAt); err != nil {
				u.stuck = fmt.Errorf("the core refused the slot time changes of locked version %d: %w", r.version, err)
				u.opt.Logger.Error("config: "+u.stuck.Error()+"; nothing is signed until a restart", "version", r.version)
				return
			}
			u.opt.Logger.Info("config: slot time changes in force", "version", r.version, "changes", len(st))
		}
		if err := u.signer.SetPolicy(policyOf(v.locked)); err != nil {
			u.stuck = fmt.Errorf("the core refused the values of locked version %d: %w", r.version, err)
			u.opt.Logger.Error("config: "+u.stuck.Error()+"; nothing is signed until a restart", "version", r.version)
			return
		}
		u.coreLocked = r
		u.opt.Logger.Info("config: locked values in force", "version", r.version, "hash", fmt.Sprintf("%x", r.hash[:8]),
			"in_record", r == refOf(u.logSt.Locked))
	}
	if v.newest != nil && v.newestRef != u.coreOpen {
		if err := u.signer.SetSchedule(scheduleOf(v.newest), v.newestAt, v.pendingSlots...); err != nil {
			u.stuck = fmt.Errorf("the core refused the fork schedule of open version %d: %w", v.newestRef.version, err)
			u.opt.Logger.Error("config: "+u.stuck.Error()+"; nothing is signed until a restart", "version", v.newestRef.version)
			return
		}
		u.coreOpen = v.newestRef
		u.opt.Logger.Info("config: fork schedule in the core", "open_version", v.newestRef.version, "effective_at", v.newestAt)
	}
}

// pruneLocked drops decoded bodies that neither the log's state nor the
// view names.
func (u *Updates) pruneLocked() {
	keep := map[bodyID]bool{}
	for _, st := range []*markstore.ConfigState{&u.logSt, &u.view.state} {
		for _, g := range []setupwire.Group{setupwire.GroupLocked, setupwire.GroupOpen} {
			gs, _ := st.Group(g)
			keep[bodyID{g, refOf(*gs)}] = true
			if p := gs.Pending; p != nil {
				keep[bodyID{g, updateRef{p.Version, p.Hash}}] = true
			}
		}
	}
	for id := range u.bodies {
		if !keep[id] {
			delete(u.bodies, id)
		}
	}
}

// blockedLocked is why the runner signs nothing now, or nil.
func (u *Updates) blockedLocked() error {
	if u.stuck != nil {
		return backend.Refused(backend.StatusStorage, "config: %v; restart the runner, it builds the core from the log", u.stuck)
	}
	if u.view.missing != nil {
		return backend.Refused(backend.StatusStorage, "config: the values in force are unknown, so nothing is signed: %v (send that update again to restore its body)", u.view.missing)
	}
	return nil
}

// beforeSign brings the core to the config in force now and says whether
// the runner may sign: not while a body the values in force need is
// unreadable, and not after the core refused values of the log. The guard
// names the core's config generation now and the time the next update
// comes into force; the request signs with core.Signer.SignGuarded, which
// refuses once either moved (SG-ACTIVATE-01). Lock order: Updates.mu, then
// the core's lock, as in reconcileLocked.
func (u *Updates) beforeSign() (core.Guard, error) {
	t, err := u.opt.Clock.Now()
	if err != nil {
		return core.Guard{}, backend.Refused(backend.StatusClock, "config: clock: %v", err)
	}
	now := unix(t)
	u.mu.Lock()
	defer u.mu.Unlock()
	if now >= u.next {
		u.reconcileLocked(now)
	}
	g := core.Guard{Until: u.next}
	if u.signer != nil {
		g.Generation = u.signer.Generation()
	}
	return g, u.blockedLocked()
}

// signErr is beforeSign's refusal as of the last reading, for HEALTH.
func (u *Updates) signErr() error {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.blockedLocked()
}

// SetupState is the setup state that IDENTITY, ATTEST and HEALTH carry
// (section 4): setup_hash, per group the update in force and the pending
// one, and the hash of the approver set in force (zero when its body is
// unreadable). An update past its effective time shows as active before a
// record says so.
func (u *Updates) SetupState() backend.SetupState {
	t, err := u.opt.Clock.Now()
	u.mu.Lock()
	defer u.mu.Unlock()
	if now := unix(t); err == nil && now >= u.next {
		u.reconcileLocked(now)
	}
	return u.stateLocked()
}

func (u *Updates) stateLocked() backend.SetupState {
	v := &u.view
	s := backend.SetupState{SetupHash: u.opt.SetupHash, Locked: groupOf(v.state.Locked), Open: groupOf(v.state.Open)}
	if v.locked != nil {
		s.ApproverSetHash = v.locked.Approvers.Hash()
	}
	if o := v.state.Order; o != nil {
		s.Order = backend.Order{Kind: uint8(o.Kind), Hash: o.Hash, ActAt: o.ActAt}
	}
	return s
}

func groupOf(g markstore.GroupState) backend.ConfigGroup {
	c := backend.ConfigGroup{Version: g.Version, Hash: g.Hash}
	if p := g.Pending; p != nil {
		c.Pending = backend.PendingUpdate{Version: p.Version, Hash: p.Hash, EffectiveAt: p.EffectiveAt}
	}
	return c
}

// reconcile brings the core to the config in force now.
func (u *Updates) reconcile() {
	t, err := u.opt.Clock.Now()
	if err != nil {
		return
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	if now := unix(t); now >= u.next {
		u.reconcileLocked(now)
	}
}

// Sync brings the core to the config in force now and, once every body it
// needs is readable, writes a record that shows it: the updates that came
// into force and what a rotation dropped.
func (u *Updates) Sync(ctx context.Context) error {
	t, err := u.opt.Clock.Now()
	if err != nil {
		return fmt.Errorf("config: clock: %w", err)
	}
	now := unix(t)
	u.writeMu.Lock()
	defer u.writeMu.Unlock()
	u.mu.Lock()
	// Only this runner's writes change the log's state, and each one
	// reconciles, so logSt is current; the view changes only when an update
	// comes due.
	if now >= u.next {
		u.reconcileLocked(now)
	}
	st, old := u.view.state.Clone(), u.logSt
	write := u.view.missing == nil && !st.Equal(old)
	u.mu.Unlock()
	if !write {
		return nil
	}
	if err := u.opt.Log.SetState(ctx, st); err != nil {
		return fmt.Errorf("config: the record that shows the config in force: %w", err)
	}
	u.opt.Logger.Info("config: record shows the config in force", "locked", st.Locked.Version, "open", st.Open.Version,
		"locked_pending", pendingVersion(st.Locked), "open_pending", pendingVersion(st.Open),
		"dropped_open", old.Open.Pending != nil && st.Open.Pending == nil && st.Open.Version != old.Open.Pending.Version)
	u.mu.Lock()
	u.reconcileLocked(now)
	u.mu.Unlock()
	return nil
}

// Run calls Sync every interval until ctx ends. After a failed write it
// waits half a minute before it writes again, and keeps the core in step
// meanwhile.
func (u *Updates) Run(ctx context.Context, every time.Duration) {
	tick := time.NewTicker(every)
	defer tick.Stop()
	var wait time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		if time.Now().Before(wait) {
			u.reconcile()
			continue
		}
		sctx, cancel := context.WithTimeout(ctx, logTimeout)
		err := u.Sync(sctx)
		cancel()
		if err != nil {
			u.opt.Logger.Warn("config: sync failed; it will try again", "err", err)
			wait = time.Now().Add(30 * time.Second)
		}
	}
}

// SetupWire is the runner's setup.
func (u *Updates) SetupWire() *setupwire.Setup { return u.opt.Setup }

// LockedInForce is the locked group in force now. DKG orders take the
// approvers, the time lock, the allowed images, the withdrawal credentials
// and the deposit amounts from it.
// A failed clock read is a refusal: the view of the last read may be from
// before a rotation that is in force by now (SSI-AUTH-01).
func (u *Updates) LockedInForce() (*setupwire.Locked, error) {
	t, err := u.opt.Clock.Now()
	if err != nil {
		return nil, backend.Refused(backend.StatusClock, "config: no time to tell the approvers in force: %v", err)
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	if now := unix(t); now >= u.next {
		u.reconcileLocked(now)
	}
	if u.view.locked == nil {
		return nil, backend.Refused(backend.StatusStorage, "config: the locked values in force are unknown: %v", u.view.missing)
	}
	return u.view.locked, nil
}

// lockedInForce is the locked group in force and its version, for the image
// check (imagegate.go), which reports its allowed list in HEALTH too: on a
// failed clock read it keeps the last view.
func (u *Updates) lockedInForce() (*setupwire.Locked, uint64, error) {
	t, err := u.opt.Clock.Now()
	u.mu.Lock()
	defer u.mu.Unlock()
	if now := unix(t); err == nil && now >= u.next {
		u.reconcileLocked(now)
	}
	if u.view.locked == nil {
		return nil, 0, backend.Refused(backend.StatusStorage, "config: the locked values in force are unknown: %v", u.view.missing)
	}
	return u.view.locked, u.view.state.Locked.Version, nil
}

// lockedNow reads the trusted time once and returns the locked group in
// force at that time, with the time. A check that verifies signatures
// against the approvers and then tests expiry or a day uses both from this
// one read, so the two cannot come from different clocks (SSI-AUTH-01).
func (u *Updates) lockedNow() (*setupwire.Locked, uint64, error) {
	now, err := u.trustedNow()
	if err != nil {
		return nil, 0, err
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	if now >= u.next {
		u.reconcileLocked(now)
	}
	if u.view.locked == nil {
		return nil, 0, backend.Refused(backend.StatusStorage, "config: the locked values in force are unknown: %v", u.view.missing)
	}
	return u.view.locked, now, nil
}

// trustedNow is the time an update is checked against (section 6, step 6).
func (u *Updates) trustedNow() (uint64, error) {
	if !u.opt.Clock.Trusted() && !u.opt.AnyClock {
		return 0, backend.Refused(backend.StatusClock, "config update: the clock %s is not trusted; an update needs the NTS clock", u.opt.Clock.Source())
	}
	t, err := u.opt.Clock.Now()
	if err != nil {
		return 0, backend.Refused(backend.StatusClock, "config update: no trusted time (the NTS clock needs a quorum): %v", err)
	}
	return unix(t), nil
}

// refusedAs keeps the status of err, a *backend.RefusedError from the core,
// and puts what in front of its detail.
func refusedAs(err error, what string) error {
	var r *backend.RefusedError
	if errors.As(err, &r) {
		return &backend.RefusedError{Code: r.Code, Detail: what + ": " + r.Detail}
	}
	return backend.Refused(backend.StatusInternal, "%s: %v", what, err)
}

// Accept takes a signed CONFIG_UPDATE (section 6). The checks, in order:
// the strict decoder with the value rules (counts within caps, approver
// keys, approvals_needed > n/2, change delay cap, withdrawal credentials,
// gas limits, slot time changes); the cluster and the chain; the trusted clock; no handover
// import in progress (importslot.go); version and prev_hash against
// the group's state in force; k signatures of the approvers in force, and
// for a rotation every key of the new set; activate_at within the wait plus
// the activation horizon; the core's checks of the values, for an open
// update the fork rule, for a locked one the slot time rule. Then it writes the body, then a record with the
// update pending, and answers with the effective state. The wait is the
// active time lock for locked (at least the images minimum when the allowed
// list gains an entry), 0 for open; the update is in force at the later of
// activate_at and its arrival plus the wait. A higher version replaces the
// group's pending update with a wait of its own. The same update again
// writes its body again if no readable copy is left and answers
// wireadmin.ConfigKnown.
func (u *Updates) Accept(ctx context.Context, raw []byte) (uint8, backend.SetupState, error) {
	var none backend.SetupState
	upd, err := setupwire.DecodeUpdate(raw)
	if err != nil {
		return 0, none, backend.Refused(backend.StatusBadRequest, "config update: %v", err)
	}
	b := &upd.Body
	if err := b.Matches(u.opt.Setup); err != nil {
		return 0, none, backend.Refused(backend.StatusBadRequest, "config update: %v", err)
	}
	hash, err := b.Hash()
	if err != nil {
		return 0, none, backend.Refused(backend.StatusBadRequest, "config update: %v", err)
	}
	// The time is read once writeMu is held: a time read before the wait
	// could be from before a rotation that came into force meanwhile, and
	// the old set's signatures would still count (SG-ACTIVATE-02).
	u.writeMu.Lock()
	defer u.writeMu.Unlock()
	now, err := u.trustedNow()
	if err != nil {
		return 0, none, err
	}
	if o := u.ImportOrder(); o != nil {
		// The import's config is version 0 until every share is in
		// (importslot.go); setImportOrder writes the slot under writeMu too.
		return 0, none, backend.Refused(backend.StatusNotReady,
			"config update: a handover import (order %x) is in progress; no update is taken until every handed-over share is in", o.Hash[:8])
	}
	u.mu.Lock()
	u.reconcileLocked(now)
	now = u.lastNow
	v, stuck, signer := u.view, u.stuck, u.signer
	u.mu.Unlock()
	if signer == nil {
		return 0, none, backend.Refused(backend.StatusNotReady, "config update: the runner is not serving yet")
	}
	gs, _ := v.state.Group(b.Group)
	ref := updateRef{b.Version, hash}
	if p := gs.Pending; p != nil && ref == (updateRef{p.Version, p.Hash}) {
		// The pending update again: its signatures are checked as at its
		// arrival (the set in force is the same, or the update is gone).
		if v.locked == nil {
			return 0, none, backend.Refused(backend.StatusStorage, "config update: the approver set in force is unknown: %v", v.missing)
		}
		if err := upd.Verify(&v.locked.Approvers); err != nil {
			return 0, none, backend.Refused(backend.StatusBadRequest, "config update: %v", err)
		}
		return u.again(ctx, raw, upd, ref, now)
	}
	if ref == refOf(*gs) {
		// The update in force again. The record that named it was written
		// after every check, so its hash is enough.
		return u.again(ctx, raw, upd, ref, now)
	}
	if err := setupwire.CheckVersion(b.Version, gs.Version, pendingVersion(*gs)); err != nil {
		return 0, none, backend.Refused(backend.StatusBadRequest, "config update: %s %v", b.Group, err)
	}
	if b.PrevHash != gs.Hash {
		return 0, none, backend.Refused(backend.StatusBadRequest, "config update: prev_hash %x is not the %s update in force (version %d, %x)",
			b.PrevHash[:8], b.Group, gs.Version, gs.Hash[:8])
	}
	if v.locked == nil {
		return 0, none, backend.Refused(backend.StatusStorage, "config update: the approver set in force is unknown: %v", v.missing)
	}
	if b.Group == setupwire.GroupOpen && v.open == nil {
		return 0, none, backend.Refused(backend.StatusStorage, "config update: the open values in force are unknown, so the fork rule has nothing to check against: %v", v.missing)
	}
	if err := upd.Verify(&v.locked.Approvers); err != nil {
		return 0, none, backend.Refused(backend.StatusBadRequest, "config update: %v", err)
	}
	wait := setupwire.Wait(v.locked, b)
	if err := setupwire.CheckActivateAt(b.ActivateAt, now, wait); err != nil {
		return 0, none, backend.Refused(backend.StatusBadRequest, "config update: %v", err)
	}
	at := setupwire.EffectiveActivation(b.ActivateAt, now, wait)
	switch b.Group {
	case setupwire.GroupLocked:
		if err := signer.CheckPolicy(policyOf(b.Locked)); err != nil {
			return 0, none, refusedAs(err, fmt.Sprintf("config update: locked version %d", b.Version))
		}
		st := slotTimesOf(b.Locked)
		if err := signer.CheckSlotTimes(st, at); err != nil {
			return 0, none, refusedAs(err, fmt.Sprintf("config update: the slot time rule refuses locked version %d in force at %d", b.Version, at))
		}
		// A pending open update must stay clear of the epochs the signer may
		// reach before its effective time under the new slot times too: the
		// fork rule, checked as a return to the open values in force with the
		// new changes pending (the rule is symmetric).
		if p := v.state.Open.Pending; p != nil && !slices.Equal(st, slotTimesOf(v.locked)) {
			if v.open == nil {
				return 0, none, backend.Refused(backend.StatusStorage, "config update: the open values in force are unknown, so the pending fork has nothing to be checked against: %v", v.missing)
			}
			if v.newestRef == (updateRef{p.Version, p.Hash}) {
				if err := signer.CheckSchedule(scheduleOf(v.open), v.newestAt, st); err != nil {
					return 0, none, refusedAs(err, fmt.Sprintf("config update: the fork rule under the new slot times of locked version %d refuses the pending open version %d in force at %d",
						b.Version, p.Version, v.newestAt))
				}
			}
		}
	case setupwire.GroupOpen:
		if stuck != nil {
			return 0, none, backend.Refused(backend.StatusStorage, "config update: %v; restart the runner first", stuck)
		}
		// The epochs count under the slot times in force and under those of a
		// pending locked update.
		if err := signer.CheckSchedule(scheduleOf(b.Open), at, v.pendingSlots...); err != nil {
			return 0, none, refusedAs(err, fmt.Sprintf("config update: the fork rule refuses open version %d in force at %d", b.Version, at))
		}
	}

	next := v.state.Clone()
	ng, _ := next.Group(b.Group)
	replaced := ng.Pending
	ng.Pending = &markstore.Pending{Version: b.Version, Hash: hash, EffectiveAt: at}
	wctx, cancel := context.WithTimeout(ctx, logTimeout)
	defer cancel()
	if _, _, _, err := u.opt.Log.PutBody(wctx, raw); err != nil {
		return 0, none, backend.Refused(backend.StatusStorage, "config update: body not written to the mark log: %v", err)
	}
	if err := u.opt.Log.SetState(wctx, next); err != nil {
		return 0, none, backend.Refused(backend.StatusStorage, "config update: record not written to the mark log: %v", err)
	}
	u.mu.Lock()
	u.bodies[bodyID{b.Group, ref}] = upd
	u.reconcileLocked(now)
	st := u.stateLocked()
	u.mu.Unlock()
	args := []any{"group", b.Group.String(), "version", b.Version, "hash", fmt.Sprintf("%x", hash[:8]),
		"wait_s", wait, "effective_at", at, "rotation", b.IsRotation(&v.locked.Approvers)}
	if replaced != nil {
		args = append(args, "replaces", replaced.Version)
	}
	u.opt.Logger.Info("config update accepted", args...)
	return wireadmin.ConfigAccepted, st, nil
}

// again stores the body of an update the state names already, if no
// readable copy is left, and answers wireadmin.ConfigKnown. A decoded
// update already in the cache stays: the update in force comes here
// without a signature check, so its copy must not replace the envelope
// verified at arrival (SG-RECOVERY-01). Decisions read only the hashed
// body anyway.
func (u *Updates) again(ctx context.Context, raw []byte, upd *setupwire.Update, ref updateRef, now uint64) (uint8, backend.SetupState, error) {
	wctx, cancel := context.WithTimeout(ctx, logTimeout)
	defer cancel()
	if _, _, _, err := u.opt.Log.PutBody(wctx, raw); err != nil {
		return 0, backend.SetupState{}, backend.Refused(backend.StatusStorage, "config update: body not written to the mark log: %v", err)
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	if id := (bodyID{upd.Body.Group, ref}); u.bodies[id] == nil {
		u.bodies[id] = upd
	}
	u.reconcileLocked(now)
	return wireadmin.ConfigKnown, u.stateLocked(), nil
}
