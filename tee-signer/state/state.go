// Package state implements the core's storage and clock hooks for the
// runner, with two restart protections that can be used alone or together:
//
//   - Persisted marks: the core's commit-ahead watermarks are sealed and
//     written to the platform store. Safe only if the store cannot be
//     rolled back, which no cloud platform here provides.
//   - Restart floor: when a validator is loaded, the clock epoch E is read
//     and everything at or below E+margin is refused: block slots up to the
//     last slot of epoch E+margin, attestation targets <= E+margin, sources
//     < E+margin. The margin is max_epochs_ahead + 1 (2 with the default
//     policy): max_epochs_ahead covers messages signed ahead of the clock,
//     and the +1 absorbs a restart reading that is up to one epoch behind
//     the last pre-restart reading (two time servers that disagree by a
//     second across an epoch boundary). It needs no storage, but it is
//     only as good as the clock (see README.md).
//
// Mark log (Mode.MarkLog, package markstore): the core keeps one device
// mark for every validator, and every raise of it is a record in a locked,
// append-only log outside the host's reach, written before the core signs
// past the old mark. At start the runner reads the newest record and the
// core restores from it. The log is authoritative for the source bound, so
// the restart floor then bounds targets and blocks only; that removes the
// floor's stall while the chain does not finalize. The log also does the
// clone guard's job (a second instance's write conflicts), so -record is
// not used with it.
//
// A third, optional floor comes from the clone guard (package record):
// the epoch the record's previous owner may have signed up to. Every floor
// bounds sources as well as targets.
//
// Repeat roots (Mode.RepeatRoots, the core's persist_repeat_root): the roots
// of each validator's last attestation and block, sealed and bound to the
// pubkey, written on every vote. They let an exact repeat sign after a
// restart. They are no restart protection: the floors above still refuse
// everything else, and a rolled-back record only holds an older root this
// validator already signed.
package state

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"sync"
	"time"

	"github.com/lidofinance/tee-signer/platform"
	"github.com/lidofinance/tee-signer/signer-core/core"
	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/slashing-log"
)

// Mode selects the restart protections.
type Mode struct {
	Floor   bool
	Persist bool
	// FloorMargin is added to the clock epoch. It must be at least
	// max_epochs_ahead + 1 (DefaultFloorMargin).
	FloorMargin uint64
	// RepeatRoots stores repeat roots in the platform store (needs store
	// and sealer). Set it together with core.Config.PersistRepeatRoot.
	RepeatRoots bool
	// MarkLog keeps the core's device mark in a mark log (UseMarkLog). Set
	// it together with core.Config.DeviceMark. Not with Persist.
	MarkLog bool

	// noSourceFloor drops the source bound from the floor (targets and
	// blocks only). Tests use it to show why the source bound is needed.
	noSourceFloor bool
	// shortMargin allows FloorMargin = max_epochs_ahead, the margin before
	// the review. Tests use it to show the sub-second skew gap.
	shortMargin bool
}

// DefaultFloorMargin is max_epochs_ahead + 1.
func DefaultFloorMargin(cfg core.Config) uint64 { return satAdd(cfg.MaxEpochsAhead, 1) }

// Guard is the clone guard (package record): an external single-writer
// record per node.
type Guard interface {
	// Floor is the epoch the record's previous owner may have signed up to.
	Floor() (uint64, bool)
	// Cover must succeed before anything for epoch e is signed.
	Cover(ctx context.Context, e uint64) error
	Status() string
}

// guardTimeout bounds one record write; the core waits for it.
const guardTimeout = 10 * time.Second

func (m Mode) String() string {
	switch {
	case m.MarkLog && m.Floor:
		return "marklog+floor(target,block)"
	case m.MarkLog:
		return "marklog"
	case m.Floor && m.Persist:
		return "floor+persisted"
	case m.Floor:
		return "floor"
	case m.Persist:
		return "persisted"
	}
	return "none"
}

// Hooks implements core.Hooks.
type Hooks struct {
	cfg core.Config
	// epochAt is the clock epoch the restart floor starts from: cfg's
	// until UseClock gives it the signer's, which follows the slot time
	// changes in force.
	epochAt func(uint64) uint64
	mode    Mode
	clock   platform.Clock
	store   platform.Store
	sealer  platform.Sealer
	log     *slog.Logger
	guard   Guard
	marks   MarkLog
	// mark is the newest mark the log held at start; found says one existed.
	mark      backend.Watermark
	markFound bool

	mu     sync.Mutex
	floors map[backend.Pubkey]uint64
	expect map[backend.Pubkey]bool
	// The source gate (SourceFloor, decideGate): while on, a validator
	// without vote history of its own (history) signs no vote with a source
	// below gateFloor. decided: the gate was read from the log or set.
	gateDecided bool
	gateOn      bool
	gateFloor   uint64
	history     map[backend.Pubkey]bool
}

var _ core.Hooks = (*Hooks)(nil)

// New checks the mode against the config. Persist needs store and sealer.
func New(cfg core.Config, mode Mode, clk platform.Clock, store platform.Store,
	sealer platform.Sealer, log *slog.Logger) (*Hooks, error) {
	if !mode.Floor && !mode.Persist && !mode.MarkLog {
		return nil, errors.New("state: no restart protection: enable the floor, persisted marks, a mark log, or a mix")
	}
	if mode.MarkLog && mode.Persist {
		return nil, errors.New("state: the mark log and persisted marks exclude each other: the log holds the mark")
	}
	minMargin := DefaultFloorMargin(cfg)
	if mode.shortMargin {
		minMargin = cfg.MaxEpochsAhead
	}
	if mode.Floor && mode.FloorMargin < minMargin {
		return nil, fmt.Errorf("state: floor margin %d is below max_epochs_ahead + 1 = %d; a vote signed ahead of one clock "+
			"reading escapes a floor taken from a restart reading one second earlier",
			mode.FloorMargin, minMargin)
	}
	if mode.Persist && (store == nil || sealer == nil) {
		return nil, errors.New("state: persisted marks need a store and a sealer")
	}
	if mode.RepeatRoots && (store == nil || sealer == nil) {
		return nil, errors.New("state: persisted repeat roots need a store and a sealer")
	}
	if clk == nil {
		return nil, errors.New("state: nil clock")
	}
	if log == nil {
		log = slog.Default()
	}
	h := &Hooks{cfg: cfg, mode: mode, clock: clk, store: store, sealer: sealer, log: log,
		floors: map[backend.Pubkey]uint64{}, expect: map[backend.Pubkey]bool{}, history: map[backend.Pubkey]bool{}}
	h.epochAt = h.cfg.EpochAt
	return h, nil
}

// UseClock makes the restart floor take its clock epoch from epochAt (the
// signer's core.Signer.EpochAt, which follows the slot time changes in
// force) in place of the start config's. Call it before the first validator
// loads.
func (h *Hooks) UseClock(epochAt func(uint64) uint64) { h.epochAt = epochAt }

// Mode returns the active protections.
func (h *Hooks) Mode() Mode { return h.mode }

// UseGuard adds the clone guard. Call it after the guard has claimed its
// record and before any validator is loaded.
func (h *Hooks) UseGuard(g Guard) { h.guard = g }

// MarkLog is the mark log as the hooks use it (markstore.MarkLog).
type MarkLog interface {
	// Append must return nil only once a record with wm is durable.
	Append(ctx context.Context, wm backend.Watermark) error
	// Raise makes the log's mark at least wm (one record if it is not yet).
	Raise(ctx context.Context, wm backend.Watermark) error
	// HandedOver reports a log that ends with a tombstone.
	HandedOver() (backend.Watermark, bool)
	// HandOverTo ends a log with a setup with a tombstone that names the
	// target's setup_hash; again for the same target it returns the same
	// mark, for another it refuses.
	HandOverTo(ctx context.Context, target [32]byte) (backend.Watermark, error)
	// HandedOverTo is the setup_hash the tombstone names, if any.
	HandedOverTo() ([32]byte, bool)
	// Exits is the day's exits the newest record carries;
	// RecordExits writes a record that carries d (exit approvals).
	Exits() *markstore.ExitDay
	RecordExits(ctx context.Context, d *markstore.ExitDay) error
	// Lost is the error the log latched: markstore.ErrLost after another
	// instance wrote it, markstore.ErrHandedOver after a handover.
	Lost() error
	// SourceGate is the source gate the log holds; SetSourceGate sets the
	// one the next record carries.
	SourceGate() (uint64, bool)
	SetSourceGate(floor uint64, on bool)
	Status() string
}

// UseMarkLog adds the mark log after it has claimed the log, with the mark
// the claim read. Call it before any validator is loaded.
func (h *Hooks) UseMarkLog(m MarkLog, mark backend.Watermark, found bool) {
	h.marks, h.mark, h.markFound = m, mark, found
}

// ErrNoMarkLog: the runner runs without a mark log.
var ErrNoMarkLog = errors.New("state: no mark log")

// RaiseMark makes the mark log's mark at least wm before a share with
// interchange maxima is stored, so neither this process nor a restart signs
// under them. Without a mark log it does nothing (the per-validator marks
// take the maxima in the core).
func (h *Hooks) RaiseMark(ctx context.Context, wm backend.Watermark) error {
	if h.marks == nil {
		return nil
	}
	// The gate first, so the raise's record carries it: a restart right
	// after must not read the raised mark as history of every validator.
	if err := h.decideGate(); err != nil {
		return err
	}
	return h.marks.Raise(ctx, wm)
}

// SourceFloor is the source gate for pk (issue #5 R2, RBRLOG-02,
// SSI-HISTORY-01): while the gate holds and pk has no vote history of its
// own in the core (NoteHistory), a vote with a source below the floor epoch
// is refused, so a share imported with no history cannot surround a vote
// cast before the log was lost. The core's device mark keeps the log's
// source meanwhile, so a validator's own history can set a lower bound.
func (h *Hooks) SourceFloor(pk backend.Pubkey) (uint64, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.gateFloor, h.gateOn && !h.history[pk]
}

// NoteHistory exempts pk from the source gate: its vote history is in the
// core (an import with attestation maxima that the core took, or, after a
// restart, a stored share whose import carried them; the log's mark, which
// the core starts from, holds them since the import raised it).
func (h *Hooks) NoteHistory(pk backend.Pubkey) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.history[pk] = true
}

// decideGate sets the source gate once, from the log as the claim read it
// (h.mark): the gate a record carries, kept until the log's source reaches
// its floor; else a new gate at the restart floor epoch when the log holds
// no vote. Only with the restart floor and the mark log on.
func (h *Hooks) decideGate() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.gateDecided || !h.mode.Floor || !h.mode.MarkLog || h.marks == nil {
		return nil
	}
	floor, on := h.marks.SourceGate()
	switch {
	case on && h.mark.HasAttestation && h.mark.SourceEpoch >= floor:
		h.marks.SetSourceGate(0, false)
		h.log.Info("source gate dropped: the log's source reached its floor", "floor_epoch", floor, "log_source", h.mark.SourceEpoch)
		on = false
	case on:
	case !h.mark.HasAttestation:
		now, err := h.clock.Now()
		if err != nil {
			return fmt.Errorf("source gate needs the clock: %w", err)
		}
		floor, on = satAdd(h.epochAt(uint64(now.Unix())), h.mode.FloorMargin), true
		h.marks.SetSourceGate(floor, true)
	}
	h.gateDecided, h.gateOn, h.gateFloor = true, on, floor
	if on {
		h.log.Info("source gate: votes with a source below the floor epoch are refused for validators without their own history",
			"floor_epoch", floor, "log_source", h.mark.SourceEpoch, "log_has_vote", h.mark.HasAttestation)
	}
	return nil
}

// HandOverTo ends the mark log for a handover to the runner of target's
// setup (handover, one target per tombstone) and returns the mark the
// target must start above.
func (h *Hooks) HandOverTo(ctx context.Context, target [32]byte) (backend.Watermark, error) {
	if h.marks == nil {
		return backend.Watermark{}, ErrNoMarkLog
	}
	return h.marks.HandOverTo(ctx, target)
}

// HandedOverTo is the setup_hash the mark log's tombstone names, if it
// ends with one that names a target.
func (h *Hooks) HandedOverTo() ([32]byte, bool) {
	if h.marks == nil {
		return [32]byte{}, false
	}
	return h.marks.HandedOverTo()
}

// Exits is the day's exits in the mark log; ErrNoMarkLog without one.
func (h *Hooks) Exits() (*markstore.ExitDay, error) {
	if h.marks == nil {
		return nil, ErrNoMarkLog
	}
	return h.marks.Exits(), nil
}

// RecordExits writes the day's exits to the mark log before an exit is
// signed; ErrNoMarkLog without one.
func (h *Hooks) RecordExits(ctx context.Context, d *markstore.ExitDay) error {
	if h.marks == nil {
		return ErrNoMarkLog
	}
	return h.marks.RecordExits(ctx, d)
}

// MarkLogLost is markstore.ErrLost once another runner instance took the
// mark log over (RBRLOG-03), nil otherwise; a handover is not a loss.
func (h *Hooks) MarkLogLost() error {
	if h.marks == nil {
		return nil
	}
	if err := h.marks.Lost(); errors.Is(err, markstore.ErrLost) {
		return err
	}
	return nil
}

// HandedOver reports a mark log that ends with a handover's tombstone.
func (h *Hooks) HandedOver() bool {
	if h.marks == nil {
		return false
	}
	_, ok := h.marks.HandedOver()
	return ok
}

// GuardStatus describes the clone guard or the mark log, or "none".
func (h *Hooks) GuardStatus() string {
	if h.marks != nil {
		return h.marks.Status()
	}
	if h.guard == nil {
		return "none"
	}
	return h.guard.Status()
}

// ExpectRecord tells LoadWatermark that pk was restored from storage, so a
// missing watermark record means someone deleted it.
func (h *Hooks) ExpectRecord(pk backend.Pubkey) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.expect[pk] = true
}

// Floor returns the floor epoch applied to pk at load time.
func (h *Hooks) Floor(pk backend.Pubkey) (uint64, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	f, ok := h.floors[pk]
	return f, ok
}

func satAdd(a, b uint64) uint64 {
	if a > math.MaxUint64-b {
		return math.MaxUint64
	}
	return a + b
}

// FloorWatermark is the watermark that refuses everything at or below
// epoch f: blocks up to the last slot of f, targets <= f, sources < f.
func FloorWatermark(cfg core.Config, f uint64) backend.Watermark {
	lastSlot := satAdd(f, 1)
	if lastSlot > math.MaxUint64/cfg.SlotsPerEpoch {
		lastSlot = math.MaxUint64
	} else {
		lastSlot = lastSlot*cfg.SlotsPerEpoch - 1
	}
	return backend.Watermark{
		HasBlock: true, BlockSlot: lastSlot,
		HasAttestation: true, SourceEpoch: f, TargetEpoch: f,
	}
}

// Merge raises a to at least b, field by field (like the core's wm_merge).
func Merge(a, b backend.Watermark) backend.Watermark {
	if b.HasBlock {
		if !a.HasBlock || b.BlockSlot > a.BlockSlot {
			a.BlockSlot = b.BlockSlot
		}
		a.HasBlock = true
	}
	if b.HasAttestation {
		if !a.HasAttestation {
			a.SourceEpoch, a.TargetEpoch = b.SourceEpoch, b.TargetEpoch
		} else {
			a.SourceEpoch = max(a.SourceEpoch, b.SourceEpoch)
			a.TargetEpoch = max(a.TargetEpoch, b.TargetEpoch)
		}
		a.HasAttestation = true
	}
	return a
}

func wmKey(pk backend.Pubkey) string { return "wm/" + hex.EncodeToString(pk[:]) }
func wmAAD(pk backend.Pubkey) []byte { return append([]byte("signer-watermark-v1|"), pk[:]...) }

// LoadWatermark merges the persisted record (if enabled) with the restart
// floor (if enabled).
func (h *Hooks) LoadWatermark(pk backend.Pubkey) (backend.Watermark, bool, error) {
	var wm backend.Watermark
	found := false
	if h.mode.Persist {
		blob, err := h.store.Get(wmKey(pk))
		switch {
		case errors.Is(err, platform.ErrNotFound):
			h.mu.Lock()
			expected := h.expect[pk]
			h.mu.Unlock()
			if expected {
				return wm, false, fmt.Errorf("watermark record for stored share %v is missing", pk)
			}
		case err != nil:
			return wm, false, err
		default:
			rec, err := h.sealer.Unseal(blob, wmAAD(pk))
			if err != nil {
				return wm, false, fmt.Errorf("unseal watermark: %w", err)
			}
			if wm, err = backend.DecodeWatermark(rec); err != nil {
				return wm, false, err
			}
			found = true
		}
	}
	floor, hasFloor := uint64(0), false
	if h.mode.Floor {
		now, err := h.clock.Now()
		if err != nil {
			return wm, false, fmt.Errorf("restart floor needs the clock: %w", err)
		}
		e := h.epochAt(uint64(now.Unix()))
		f := satAdd(e, h.mode.FloorMargin)
		fw := FloorWatermark(h.cfg, f)
		if h.mode.noSourceFloor {
			fw.SourceEpoch = 0
		}
		wm = Merge(wm, fw)
		found = true
		floor, hasFloor = f, true
		h.log.Info("restart floor", "pubkey", pk.String()[:18], "clock", now.UTC().Format("2006-01-02T15:04:05Z"),
			"clock_source", h.clock.Source(), "clock_epoch", e, "floor_margin", h.mode.FloorMargin, "floor_epoch", f,
			"refuse_target_lte", wm.TargetEpoch, "refuse_source_lt", wm.SourceEpoch, "refuse_block_slot_lte", wm.BlockSlot)
	}
	if h.guard != nil {
		if r, ok := h.guard.Floor(); ok {
			wm = Merge(wm, FloorWatermark(h.cfg, r))
			found = true
			if !hasFloor || r > floor {
				floor, hasFloor = r, true
			}
			h.log.Info("record floor", "pubkey", pk.String()[:18], "record_epoch", r,
				"refuse_target_lte", wm.TargetEpoch, "refuse_source_lt", wm.SourceEpoch, "refuse_block_slot_lte", wm.BlockSlot)
		}
	}
	if hasFloor {
		h.mu.Lock()
		h.floors[pk] = floor
		h.mu.Unlock()
	}
	return wm, found, nil
}

var _ core.DeviceMarkHooks = (*Hooks)(nil)

// LoadDeviceMark is the mark the log held at start, merged with the
// restart floor's target and block bounds (if the floor is on). The floor
// leaves the source bound of a log with a vote alone: the log's mark
// carries the highest source signed, so a restart while the chain does not
// finalize signs again at the first vote above the target bound. A log
// with no vote keeps source 0 in the core and gates sources in SourceFloor
// instead, so an import with vote history can still set the bound.
func (h *Hooks) LoadDeviceMark() (backend.Watermark, bool, error) {
	if !h.mode.MarkLog || h.marks == nil {
		return backend.Watermark{}, false, errors.New("state: no mark log")
	}
	wm, found := h.mark, h.markFound
	if h.mode.Floor {
		if err := h.decideGate(); err != nil {
			return wm, false, err
		}
		now, err := h.clock.Now()
		if err != nil {
			return wm, false, fmt.Errorf("restart floor needs the clock: %w", err)
		}
		e := h.epochAt(uint64(now.Unix()))
		f := satAdd(e, h.mode.FloorMargin)
		fw := FloorWatermark(h.cfg, f)
		// The log's mark is authoritative for sources. A log with no vote
		// yet (fresh, or lost and set up again) gets the floor's source
		// bound through the source gate (SourceFloor), not in the core:
		// the core cannot lower a bound, and an import with history may
		// need a lower one.
		fw.SourceEpoch = 0
		if wm.HasAttestation {
			fw.SourceEpoch = wm.SourceEpoch
		}
		wm, found = Merge(wm, fw), true
		h.log.Info("restart from the mark log", "clock_epoch", e, "floor_epoch", f,
			"log_source", h.mark.SourceEpoch, "log_target", h.mark.TargetEpoch, "log_block_slot", h.mark.BlockSlot,
			"refuse_target_lte", wm.TargetEpoch, "refuse_source_lt", wm.SourceEpoch, "refuse_block_slot_lte", wm.BlockSlot)
	}
	return wm, found, nil
}

// StoreDeviceMark writes a record with the new mark to the log before the
// core signs past the old one. It fails, and the core refuses, when the log
// cannot be written (store down, or another instance took the log over).
func (h *Hooks) StoreDeviceMark(wm backend.Watermark) error {
	if h.marks == nil {
		return errors.New("state: no mark log")
	}
	ctx, cancel := context.WithTimeout(context.Background(), guardTimeout)
	defer cancel()
	return h.marks.Append(ctx, wm)
}

// markEpoch is the highest epoch a watermark reaches.
func (h *Hooks) markEpoch(wm backend.Watermark) uint64 {
	var e uint64
	if wm.HasAttestation {
		e = max(wm.SourceEpoch, wm.TargetEpoch)
	}
	if wm.HasBlock {
		e = max(e, wm.BlockSlot/h.cfg.SlotsPerEpoch)
	}
	return e
}

// StoreWatermark runs before the core signs past its commit-ahead mark.
// With a clone guard it first makes the record cover the new mark, so the
// runner refuses to sign if it cannot advance the record. Then it persists
// the mark, or does nothing more in floor-only mode: there the in-memory
// state is authoritative while the process lives, and the floor covers
// restarts.
func (h *Hooks) StoreWatermark(pk backend.Pubkey, wm backend.Watermark) error {
	if h.guard != nil {
		ctx, cancel := context.WithTimeout(context.Background(), guardTimeout)
		err := h.guard.Cover(ctx, h.markEpoch(wm))
		cancel()
		if err != nil {
			return err
		}
	}
	if !h.mode.Persist {
		return nil
	}
	blob, err := h.sealer.Seal(backend.EncodeWatermark(wm), wmAAD(pk))
	if err != nil {
		return err
	}
	return h.store.Put(wmKey(pk), blob)
}

func rrKey(pk backend.Pubkey) string { return "rr/" + hex.EncodeToString(pk[:]) }

// rrAAD binds a sealed record to its validator: an attestation root moved to
// another validator of the same committee would be a vote it never cast.
func rrAAD(pk backend.Pubkey) []byte { return append([]byte("signer-repeat-roots-v1|"), pk[:]...) }

var _ core.RepeatRootHooks = (*Hooks)(nil)

// LoadRepeatRoots reads and unseals pk's repeat roots. A missing record is
// "nothing signed yet": deleting it costs at most a refused retry.
func (h *Hooks) LoadRepeatRoots(pk backend.Pubkey) ([]byte, bool, error) {
	if !h.mode.RepeatRoots {
		return nil, false, errors.New("state: repeat roots are not enabled")
	}
	blob, err := h.store.Get(rrKey(pk))
	if errors.Is(err, platform.ErrNotFound) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	rec, err := h.sealer.Unseal(blob, rrAAD(pk))
	if err != nil {
		return nil, false, fmt.Errorf("unseal repeat roots: %w", err)
	}
	return rec, true, nil
}

// StoreRepeatRoots seals and writes pk's repeat roots, before the core signs.
// A failure does not stop the signature; it is logged here.
func (h *Hooks) StoreRepeatRoots(pk backend.Pubkey, rec []byte) error {
	if !h.mode.RepeatRoots {
		return errors.New("state: repeat roots are not enabled")
	}
	blob, err := h.sealer.Seal(rec, rrAAD(pk))
	if err == nil {
		err = h.store.Put(rrKey(pk), blob)
	}
	if err != nil {
		h.log.Warn("repeat roots not stored; a repeat after a restart will be refused",
			"pubkey", pk.String()[:18], "err", err)
	}
	return err
}

func (h *Hooks) Now() (uint64, error) {
	t, err := h.clock.Now()
	if err != nil {
		return 0, err
	}
	if t.Unix() <= 0 {
		return 0, errors.New("clock before 1970")
	}
	return uint64(t.Unix()), nil
}
