// Package core is the cgo binding to the portable C signer core
// (signer-core, see core/README.md). It needs the static libraries that
// scripts/build-core.sh puts in build/<arch>/lib.
//
// The runner and the software backend both sign through this package, so
// slashing protection and policy are the same C code in both.
package core

/*
#cgo CFLAGS: -I${SRCDIR}/../include -I${SRCDIR}/../third_party/blst/bindings
#cgo linux,amd64 LDFLAGS: -L${SRCDIR}/../../build/x86_64/lib -lsigner_core -lblst
#cgo linux,arm64 LDFLAGS: -L${SRCDIR}/../../build/aarch64/lib -lsigner_core -lblst
#include <stdlib.h>
#include <string.h>
#include "signer_core.h"

void scgo_make_ops(sc_host_ops *ops, uintptr_t handle);
int scgo_p2_lincomb(const uint8_t *points, const uint8_t *scalars, size_t n, uint8_t out[96]);
int scgo_p1_lincomb(const uint8_t *points, const uint8_t *scalars, size_t n, uint8_t out[48]);
*/
import "C"

import (
	"errors"
	"fmt"
	"math"
	"runtime/cgo"
	"sync"
	"sync/atomic"
	"unsafe"

	"github.com/lidofinance/tee-signer/signer-protocol"
)

const (
	maxForks            = C.SC_MAX_FORKS
	maxExitAllowlist    = C.SC_MAX_EXIT_ALLOWLIST
	maxFeeRecipients    = C.SC_MAX_FEE_RECIPIENTS
	maxBuilderAuthRoots = C.SC_MAX_BUILDER_AUTH_ROOTS
	maxSlotTimes        = C.SC_MAX_SLOT_TIMES
)

// Hooks are the host callbacks of the core: durable watermark storage and
// the trusted clock. The runner composes them from platform hooks and the
// restart rule (runner/state).
type Hooks interface {
	// LoadWatermark returns the watermark to start a validator from.
	// found=false means "never signed anything".
	LoadWatermark(pubkey backend.Pubkey) (wm backend.Watermark, found bool, err error)
	// StoreWatermark must return nil only once wm is durable.
	StoreWatermark(pubkey backend.Pubkey, wm backend.Watermark) error
	// Now is the trusted wall clock in unix seconds.
	Now() (uint64, error)
}

// RepeatRootHooks store the roots of each validator's last attestation and
// block (the core's sc_repeat_roots, in its 72-byte encoding). Hooks must
// implement them when Config.PersistRepeatRoot is set; the core then writes
// the record before every new attestation or block and loads it with the
// validator, so an exact repeat after a restart signs. The store must bind
// each record to its pubkey: validators of one committee sign the same
// attestation root, so a record moved to another validator would let that
// validator sign a vote it never cast.
type RepeatRootHooks interface {
	// LoadRepeatRoots returns the stored record; found=false: none.
	LoadRepeatRoots(pubkey backend.Pubkey) (rec []byte, found bool, err error)
	// StoreRepeatRoots must return nil only once rec is durable.
	StoreRepeatRoots(pubkey backend.Pubkey, rec []byte) error
}

// DeviceMarkHooks keep one mark for every validator of the signer (the
// core's SC_MARKS_PER_DEVICE). Hooks must implement them when
// Config.DeviceMark is set. LoadDeviceMark returns the mark to start from;
// found=false means nothing was ever signed. StoreDeviceMark must return nil
// only once the mark is durable: the core signs past the old mark only after
// it returns.
type DeviceMarkHooks interface {
	LoadDeviceMark() (wm backend.Watermark, found bool, err error)
	StoreDeviceMark(wm backend.Watermark) error
}

// hookState is what the C ctx pointer refers to (through a cgo.Handle).
type hookState struct {
	hooks   Hooks
	lastErr error // last hook error, read by the caller under Signer.mu
}

// SlashingState is the per-validator state of the core.
type SlashingState struct {
	RAM       backend.Watermark `json:"ram"`       // exact highest values signed in this run
	Committed backend.Watermark `json:"committed"` // durable upper bound
}

// Stats are the core's counters.
type Stats struct {
	Signatures       uint64 `json:"signatures"`
	HashCacheHits    uint64 `json:"hash_cache_hits"`
	HashCacheMisses  uint64 `json:"hash_cache_misses"`
	WatermarkWrites  uint64 `json:"watermark_writes"`
	ExactRepeats     uint64 `json:"exact_repeats"`
	RepeatRootWrites uint64 `json:"repeat_root_writes"`
	// UnverifiedSignatures counts bare roots of types 2 to 6 signed
	// through allow_unverified_nonslashable.
	UnverifiedSignatures uint64 `json:"unverified_signatures"`
}

// Signer wraps one sc_signer. All methods are safe for concurrent use; calls
// into C are serialized because the core is not thread safe.
type Signer struct {
	mu  sync.Mutex
	cfg Config
	// clock is a copy of cfg for EpochAt and SlotAt, which take no lock:
	// the restart floor asks for the epoch from inside the core's calls.
	clock  atomic.Pointer[Config]
	mem    unsafe.Pointer
	s      *C.sc_signer
	handle cgo.Handle
	state  *hookState
	keys   []backend.ValidatorKey
	// unready holds loaded keys whose interchange maxima the core did not
	// take (AddValidator): they sign nothing until an Import succeeds.
	unready map[backend.Pubkey]error
	// unverified counts signatures made through allow_unverified_nonslashable.
	unverified uint64
	// gen counts the changes of the config: every policy, fork schedule or
	// slot time change the signer takes (Generation, SignGuarded).
	gen uint64
}

// Guard is what a caller checked the config against before a request:
// the signer's Generation then, and Until, the time from which other
// values come into force (math.MaxUint64: none pending). SignGuarded signs
// only while both still hold.
type Guard struct {
	Generation uint64
	Until      uint64
}

// ErrConfigMoved is SignGuarded's refusal: the config changed, or the time
// of a pending change came, after the caller checked it. The caller brings
// the config up to date and sends the request again.
var ErrConfigMoved = errors.New("core: the config changed after the request checked it")

var ErrClosed = errors.New("core: signer closed")

// NewSigner allocates a signer for up to maxValidators validators with a
// hash_to_G2 cache of cacheEntries (0 disables it).
func NewSigner(cfg Config, maxValidators, cacheEntries uint32, hooks Hooks) (*Signer, error) {
	if hooks == nil {
		return nil, errors.New("core: nil hooks")
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if _, ok := hooks.(DeviceMarkHooks); cfg.DeviceMark && !ok {
		return nil, errors.New("core: a device mark needs hooks that keep one")
	}
	if _, ok := hooks.(RepeatRootHooks); cfg.PersistRepeatRoot && !ok {
		return nil, errors.New("core: persist_repeat_root needs hooks that store repeat roots")
	}
	need := C.sc_signer_mem_size(C.uint32_t(maxValidators), C.uint32_t(cacheEntries))
	if need == 0 {
		return nil, errors.New("core: bad signer size")
	}
	cc := (*C.sc_config)(C.calloc(1, C.size_t(unsafe.Sizeof(C.sc_config{}))))
	if cc == nil {
		return nil, errors.New("core: out of memory")
	}
	defer C.free(unsafe.Pointer(cc))
	fillConfig(cc, &cfg)

	mem := C.malloc(need) // malloc alignment covers the core's 8-byte requirement
	if mem == nil {
		return nil, errors.New("core: out of memory")
	}
	st := &hookState{hooks: hooks}
	h := cgo.NewHandle(st)
	var ops C.sc_host_ops
	C.scgo_make_ops(&ops, C.uintptr_t(h))
	var s *C.sc_signer
	var times C.sc_slot_times
	fillSlotTimes(&times, cfg.SlotTimeChanges)
	if rc := C.sc_signer_init_ext(mem, need, C.uint32_t(maxValidators), C.uint32_t(cacheEntries), cc, &times, &ops, &s); rc != C.SC_OK {
		C.free(mem)
		h.Delete()
		return nil, fmt.Errorf("core: sc_signer_init: %v", backend.Status(rc))
	}
	sg := &Signer{cfg: cfg, mem: mem, s: s, handle: h, state: st}
	sg.setClock()
	return sg, nil
}

func fillConfig(cc *C.sc_config, c *Config) {
	copyBytes(unsafe.Pointer(&cc.genesis_validators_root[0]), c.GenesisValidatorsRoot[:])
	copyBytes(unsafe.Pointer(&cc.genesis_fork_version[0]), c.GenesisForkVersion[:])
	for i, f := range c.Forks {
		cc.forks[i].epoch = C.uint64_t(f.Epoch)
		copyBytes(unsafe.Pointer(&cc.forks[i].version[0]), f.Version[:])
	}
	cc.fork_count = C.uint32_t(len(c.Forks))
	copyBytes(unsafe.Pointer(&cc.voluntary_exit_fork_version[0]), c.VoluntaryExitForkVersion[:])
	cc.genesis_time = C.uint64_t(c.GenesisTime)
	cc.seconds_per_slot = C.uint64_t(c.SecondsPerSlot)
	cc.slots_per_epoch = C.uint64_t(c.SlotsPerEpoch)
	cc.max_epochs_ahead = C.uint64_t(c.MaxEpochsAhead)
	for i, idx := range c.ExitAllowlist {
		cc.exit_allowlist[i] = C.uint64_t(idx)
	}
	cc.exit_allowlist_count = C.uint32_t(len(c.ExitAllowlist))
	for i, a := range c.FeeRecipients {
		copyBytes(unsafe.Pointer(&cc.fee_recipients[i][0]), a[:])
	}
	cc.fee_recipient_count = C.uint32_t(len(c.FeeRecipients))
	for i, r := range c.BuilderRequestAuthRoots {
		copyBytes(unsafe.Pointer(&cc.builder_auth_roots[i][0]), r[:])
	}
	cc.builder_auth_root_count = C.uint32_t(len(c.BuilderRequestAuthRoots))
	cc.gas_limit_min = C.uint64_t(c.GasLimitMin)
	cc.gas_limit_max = C.uint64_t(c.GasLimitMax)
	cc.registration_max_future_seconds = C.uint64_t(c.RegistrationMaxFutureSeconds)
	cc.commit_ahead.block_slots = C.uint64_t(c.CommitAhead.BlockSlots)
	cc.commit_ahead.source_epochs = C.uint64_t(c.CommitAhead.SourceEpochs)
	cc.commit_ahead.target_epochs = C.uint64_t(c.CommitAhead.TargetEpochs)
	// One mark per validator: the runner's restart floor and clone record work
	// per validator, and cloud storage has no wear limit. With a mark store
	// (the locked log of runner/markstore) one mark per device: one log
	// record covers every validator.
	cc.mark_scope = C.SC_MARKS_PER_VALIDATOR
	if c.DeviceMark {
		cc.mark_scope = C.SC_MARKS_PER_DEVICE
	}
	cc.persist_repeat_root = 0
	if c.PersistRepeatRoot {
		cc.persist_repeat_root = 1
	}
	if c.GloasForkEpoch != nil {
		cc.gloas_scheduled = 1
		cc.gloas_fork_epoch = C.uint64_t(*c.GloasForkEpoch)
	}
}

// setClock publishes cfg's clock to EpochAt and SlotAt. Call it with mu
// held, after cfg changed.
func (s *Signer) setClock() {
	c := s.cfg.WithSlotTimes(s.cfg.SlotTimeChanges)
	s.clock.Store(&c)
}

// fillSlotTimes copies slot time changes into the core's form; the caller
// checked their count.
func fillSlotTimes(ct *C.sc_slot_times, changes []SlotTimeChange) {
	for i, ch := range changes {
		ct.changes[i].epoch = C.uint64_t(ch.Epoch)
		ct.changes[i].seconds_per_slot = C.uint64_t(ch.SecondsPerSlot)
	}
	ct.count = C.uint32_t(len(changes))
}

func copyBytes(dst unsafe.Pointer, src []byte) {
	if len(src) > 0 {
		C.memcpy(dst, unsafe.Pointer(&src[0]), C.size_t(len(src)))
	}
}

func u8(p []byte) *C.uint8_t { return (*C.uint8_t)(unsafe.Pointer(&p[0])) }

// Config returns the signer's configuration, with the fork schedule in force.
func (s *Signer) Config() Config {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cfg
}

// CheckSchedule reports whether SetSchedule would take next now. It changes
// nothing (sc_signer_check_schedule_under).
func (s *Signer) CheckSchedule(next Schedule, activateAt uint64, pending ...[]SlotTimeChange) error {
	return s.schedule(next, activateAt, pending, false)
}

// SetSchedule replaces the signer's fork schedule with next, which takes
// effect at activateAt (unix seconds, 0 for now), through the core's fork
// rule (sc_signer_set_schedule_under): every epoch up to epoch(max(activateAt,
// now)) + MaxEpochsAhead + 1 must keep its fork version and Gloas state, or
// the result is a *backend.RefusedError with StatusSchedule and nothing
// changes. The epoch is the largest under the slot time changes in force and
// under each list of pending: changes the host accepted that are not yet in
// force. A new schedule applied before activateAt signs the same as one
// applied at it. The domain check of typed requests follows the new schedule
// at once.
func (s *Signer) SetSchedule(next Schedule, activateAt uint64, pending ...[]SlotTimeChange) error {
	return s.schedule(next, activateAt, pending, true)
}

func (s *Signer) schedule(next Schedule, activateAt uint64, pending [][]SlotTimeChange, apply bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.s == nil {
		return ErrClosed
	}
	merged := s.cfg.WithSchedule(next)
	if err := merged.Validate(); err != nil {
		return backend.Refused(backend.StatusArg, "fork schedule: %v", err)
	}
	var cs C.sc_schedule
	for i, f := range merged.Forks {
		cs.forks[i].epoch = C.uint64_t(f.Epoch)
		copyBytes(unsafe.Pointer(&cs.forks[i].version[0]), f.Version[:])
	}
	cs.fork_count = C.uint32_t(len(merged.Forks))
	if merged.GloasForkEpoch != nil {
		cs.gloas_scheduled = 1
		cs.gloas_fork_epoch = C.uint64_t(*merged.GloasForkEpoch)
	}
	var pend []C.sc_slot_times
	for _, p := range pending {
		if err := checkSlotTimes(&s.cfg, p); err != nil {
			return backend.Refused(backend.StatusArg, "fork schedule: pending %v", err)
		}
		var ct C.sc_slot_times
		fillSlotTimes(&ct, p)
		pend = append(pend, ct)
	}
	var pp *C.sc_slot_times
	if len(pend) > 0 {
		pp = &pend[0]
	}
	s.state.lastErr = nil
	var rc C.int
	if apply {
		rc = C.sc_signer_set_schedule_under(s.s, &cs, C.uint64_t(activateAt), pp, C.uint32_t(len(pend)))
	} else {
		rc = C.sc_signer_check_schedule_under(s.s, &cs, C.uint64_t(activateAt), pp, C.uint32_t(len(pend)))
	}
	if err := s.refusal(rc, "fork schedule"); err != nil {
		return err
	}
	if apply {
		s.cfg = merged
		s.gen++
	}
	return nil
}

// CheckSlotTimes reports whether SetSlotTimes would take next now. It
// changes nothing (sc_signer_check_slot_times).
func (s *Signer) CheckSlotTimes(next []SlotTimeChange, activateAt uint64) error {
	return s.slotTimes(next, activateAt, false)
}

// SetSlotTimes replaces the signer's slot time changes with next, in force
// from activateAt (unix seconds, 0 for now), through the core's rule
// (sc_signer_set_slot_times): every epoch up to epoch(max(activateAt, now))
// + MaxEpochsAhead + 1 must keep its slot time, or the result is a
// *backend.RefusedError with StatusSchedule and nothing changes. The clock
// horizon follows the new slot times at once; before activateAt both give
// the same clock for every epoch the signer may sign.
func (s *Signer) SetSlotTimes(next []SlotTimeChange, activateAt uint64) error {
	return s.slotTimes(next, activateAt, true)
}

func (s *Signer) slotTimes(next []SlotTimeChange, activateAt uint64, apply bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.s == nil {
		return ErrClosed
	}
	merged := s.cfg.WithSlotTimes(next)
	if err := merged.Validate(); err != nil {
		return backend.Refused(backend.StatusArg, "slot time changes: %v", err)
	}
	var ct C.sc_slot_times
	fillSlotTimes(&ct, merged.SlotTimeChanges)
	s.state.lastErr = nil
	var rc C.int
	if apply {
		rc = C.sc_signer_set_slot_times(s.s, &ct, C.uint64_t(activateAt))
	} else {
		rc = C.sc_signer_check_slot_times(s.s, &ct, C.uint64_t(activateAt))
	}
	if err := s.refusal(rc, "slot time changes"); err != nil {
		return err
	}
	if apply {
		s.cfg = merged
		s.setClock()
		s.gen++
	}
	return nil
}

// EpochAt is the epoch at unix time t under the slot time changes in force:
// Config.EpochAt of the signer's config, which a test checks against the
// core's sc_epoch_at. It takes no lock, so a hook may call it from inside
// the core.
func (s *Signer) EpochAt(t uint64) uint64 { return s.clock.Load().EpochAt(t) }

// SlotAt is the slot at unix time t under the slot time changes in force.
func (s *Signer) SlotAt(t uint64) uint64 { return s.clock.Load().SlotAt(t) }

// coreEpochAt is the epoch the core itself gives at unix time t
// (sc_epoch_at with the slot times it holds).
func (s *Signer) coreEpochAt(t uint64) uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.s == nil {
		return s.cfg.EpochAt(t)
	}
	cc := (*C.sc_config)(C.calloc(1, C.size_t(unsafe.Sizeof(C.sc_config{}))))
	if cc == nil {
		return s.cfg.EpochAt(t)
	}
	defer C.free(unsafe.Pointer(cc))
	fillConfig(cc, &s.cfg)
	var ct C.sc_slot_times
	C.sc_signer_get_slot_times(s.s, &ct)
	return uint64(C.sc_epoch_at(cc, &ct, C.uint64_t(t)))
}

// CheckPolicy reports whether SetPolicy would take p. It changes nothing.
func (s *Signer) CheckPolicy(p Policy) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.s == nil {
		return ErrClosed
	}
	merged := s.cfg.WithPolicy(p)
	if err := merged.Validate(); err != nil {
		return backend.Refused(backend.StatusArg, "policy: %v", err)
	}
	return nil
}

// SetPolicy replaces the signer's signing policy with p
// (sc_signer_set_policy): exit allowlist, fee recipients, gas limit range,
// registration_max_future_seconds, and allow_unverified_nonslashable, which
// only this binding reads. The chain, the clock horizon, the slashing
// settings and the fork schedule stay, and so do the loaded validators and
// their slashing state. A policy that fails the checks of NewSigner is a
// *backend.RefusedError with StatusArg, and nothing changes. The next
// request signs under the new policy.
func (s *Signer) SetPolicy(p Policy) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.s == nil {
		return ErrClosed
	}
	merged := s.cfg.WithPolicy(p)
	if err := merged.Validate(); err != nil {
		return backend.Refused(backend.StatusArg, "policy: %v", err)
	}
	cc := (*C.sc_config)(C.calloc(1, C.size_t(unsafe.Sizeof(C.sc_config{}))))
	if cc == nil {
		return errors.New("core: out of memory")
	}
	defer C.free(unsafe.Pointer(cc))
	fillConfig(cc, &merged)
	s.state.lastErr = nil
	if err := s.refusal(C.sc_signer_set_policy(s.s, cc), "policy"); err != nil {
		return err
	}
	s.cfg = merged
	s.gen++
	return nil
}

// Generation is the number of config changes the signer took so far.
func (s *Signer) Generation() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.gen
}

// checkDomain refuses a typed request whose domain differs from the one
// this signer's chain config and fork schedule give its message, before the
// core signs anything, as the OP-TEE TA does (check_domain in the PoC repo's
// ta/trusted-app/signer_ta.c). A caller on another fork, or a signer that
// missed a fork update, then gets StatusDomainMismatch instead of a
// signature that is invalid on chain.
func (s *Signer) checkDomain(req backend.SignRequest) error {
	want, err := s.cfg.MessageDomain(req.Message)
	if err != nil {
		var r *backend.RefusedError
		if errors.As(err, &r) {
			return err
		}
		return backend.Refused(backend.StatusBadRequest, "%v", err)
	}
	if req.Domain != want {
		return backend.Refused(backend.StatusDomainMismatch, "%v: domain %v, this signer's fork schedule wants %v",
			req.Message.Kind(), req.Domain, want)
	}
	return nil
}

// refusal turns a core status into an error, adding the hook error if a
// hook caused it.
func (s *Signer) refusal(rc C.int, what string) error {
	if rc == C.SC_OK {
		return nil
	}
	detail := what
	if s.state.lastErr != nil {
		detail += ": " + s.state.lastErr.Error()
	}
	return &backend.RefusedError{Code: backend.Status(rc), Detail: detail}
}

// AddValidator loads a share. pubkey is the validator's on-chain key,
// secret the share (big endian). The core calls Hooks.LoadWatermark here.
// If interchange is set, the EIP-3076 maxima are imported before the lock
// is released, so no request can be signed between the two steps. If the
// import fails the validator stays loaded but the error is returned, and
// the key signs nothing until an Import of its maxima succeeds
// (SSI-HISTORY-02): its RAM bounds are from before its history.
func (s *Signer) AddValidator(pubkey backend.Pubkey, secret [32]byte, index uint64,
	interchange *backend.Watermark) (backend.ValidatorKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.s == nil {
		return backend.ValidatorKey{}, ErrClosed
	}
	s.state.lastErr = nil
	sec := (*[32]byte)(C.malloc(32))
	defer func() {
		C.memset(unsafe.Pointer(sec), 0, 32)
		C.free(unsafe.Pointer(sec))
	}()
	*sec = secret
	var share [48]byte
	rc := C.sc_signer_add_validator(s.s, u8(pubkey[:]), (*C.uint8_t)(unsafe.Pointer(sec)), C.uint64_t(index), u8(share[:]))
	if err := s.refusal(rc, "add validator"); err != nil {
		return backend.ValidatorKey{}, err
	}
	k := backend.ValidatorKey{Pubkey: pubkey, SharePubkey: share, Index: index}
	s.keys = append(s.keys, k)
	if interchange != nil {
		cw := toC(*interchange)
		gvr := s.cfg.GenesisValidatorsRoot
		if err := s.refusal(C.sc_signer_import(s.s, u8(pubkey[:]), u8(gvr[:]), &cw), "import"); err != nil {
			if s.unready == nil {
				s.unready = map[backend.Pubkey]error{}
			}
			s.unready[pubkey] = err
			return k, err
		}
	}
	return k, nil
}

// Keys lists the loaded validators in load order.
func (s *Signer) Keys() []backend.ValidatorKey {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]backend.ValidatorKey(nil), s.keys...)
}

// Import raises a validator's watermark to EIP-3076 maxima.
func (s *Signer) Import(pubkey backend.Pubkey, wm backend.Watermark) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.s == nil {
		return ErrClosed
	}
	s.state.lastErr = nil
	cw := toC(wm)
	gvr := s.cfg.GenesisValidatorsRoot
	if err := s.refusal(C.sc_signer_import(s.s, u8(pubkey[:]), u8(gvr[:]), &cw), "import"); err != nil {
		return err
	}
	delete(s.unready, pubkey)
	return nil
}

// State returns a validator's slashing state.
func (s *Signer) State(pubkey backend.Pubkey) (SlashingState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.s == nil {
		return SlashingState{}, ErrClosed
	}
	var st C.sc_slashing_state
	if rc := C.sc_signer_get_state(s.s, u8(pubkey[:]), &st); rc != C.SC_OK {
		return SlashingState{}, &backend.RefusedError{Code: backend.Status(rc)}
	}
	return SlashingState{RAM: fromC(st.ram), Committed: fromC(st.committed)}, nil
}

// Stats returns the core's counters.
func (s *Signer) Stats() Stats {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.s == nil {
		return Stats{}
	}
	return s.statsLocked()
}

func (s *Signer) statsLocked() Stats {
	var st C.sc_signer_stats
	C.sc_signer_get_stats(s.s, &st)
	return Stats{uint64(st.signatures), uint64(st.hash_cache_hits), uint64(st.hash_cache_misses),
		uint64(st.watermark_writes), uint64(st.exact_repeats), uint64(st.repeat_root_writes), s.unverified}
}

// Sign signs one message through slashing protection and policy.
func (s *Signer) Sign(req backend.SignRequest) (backend.Signature, error) {
	sig, _, err := s.SignDetailed(req)
	return sig, err
}

// SignDetailed is Sign, and also reports whether the request was an exact
// repeat of the validator's last signed attestation or block. The C core
// decides that (sc_repeat_roots): the same signing root as the last one, so
// the same deterministic BLS signature, signed again without the slashing
// check; policy checks still run. Anything else at that target or slot is
// refused there. With Config.PersistRepeatRoot the roots survive a restart
// through RepeatRootHooks; without it they live in this process only.
func (s *Signer) SignDetailed(req backend.SignRequest) (backend.Signature, bool, error) {
	return s.signGuarded(req, nil)
}

// SignGuarded is SignDetailed for a caller that brought the config up to
// date first and took g then. Under the signer's lock, before anything is
// signed, it returns ErrConfigMoved if the config changed since
// (g.Generation) or the trusted clock reached g.Until, when another config
// comes into force. A request that waited for the lock across that time so
// never signs under the values it replaced (SG-ACTIVATE-01). The clock is
// the hooks' Now, which the core reads under the same lock.
func (s *Signer) SignGuarded(req backend.SignRequest, g Guard) (backend.Signature, bool, error) {
	return s.signGuarded(req, &g)
}

func (s *Signer) signGuarded(req backend.SignRequest, g *Guard) (backend.Signature, bool, error) {
	var sig backend.Signature
	if req.Message == nil {
		return sig, false, backend.Refused(backend.StatusBadRequest, "no message")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.s == nil {
		return sig, false, ErrClosed
	}
	if g != nil {
		if s.gen != g.Generation {
			return sig, false, ErrConfigMoved
		}
		if g.Until != math.MaxUint64 {
			now, err := s.state.hooks.Now()
			if err != nil {
				return sig, false, backend.Refused(backend.StatusClock, "config guard: %v", err)
			}
			if now >= g.Until {
				return sig, false, ErrConfigMoved
			}
		}
	}
	before := s.statsLocked().ExactRepeats
	sig, err := s.signLocked(req)
	if err != nil {
		return sig, false, err
	}
	return sig, s.statsLocked().ExactRepeats > before, nil
}

func (s *Signer) signLocked(req backend.SignRequest) (backend.Signature, error) {
	var sig backend.Signature
	s.state.lastErr = nil
	if err, ok := s.unready[req.Pubkey]; ok {
		return sig, backend.Refused(backend.StatusStorage, "the import of this key's slashing history failed (%v): it signs nothing until the history is in", err)
	}
	if _, root := req.Message.(*backend.RootMessage); !root {
		if err := s.checkDomain(req); err != nil {
			return sig, err
		}
	}
	pk := u8(req.Pubkey[:])
	out := u8(sig[:])
	var rc C.int
	switch m := req.Message.(type) {
	case *backend.AttestationData:
		if err := s.checkSource(m); err != nil {
			return sig, err
		}
		var d C.sc_attestation_data
		d.slot = C.uint64_t(m.Slot)
		d.index = C.uint64_t(m.Index)
		copyBytes(unsafe.Pointer(&d.beacon_block_root[0]), m.BeaconBlockRoot[:])
		d.source.epoch = C.uint64_t(m.Source.Epoch)
		copyBytes(unsafe.Pointer(&d.source.root[0]), m.Source.Root[:])
		d.target.epoch = C.uint64_t(m.Target.Epoch)
		copyBytes(unsafe.Pointer(&d.target.root[0]), m.Target.Root[:])
		rc = C.sc_sign_attestation(s.s, pk, &d, out)
	case *backend.BeaconBlockHeader:
		var b C.sc_beacon_block_header
		b.slot = C.uint64_t(m.Slot)
		b.proposer_index = C.uint64_t(m.ProposerIndex)
		copyBytes(unsafe.Pointer(&b.parent_root[0]), m.ParentRoot[:])
		copyBytes(unsafe.Pointer(&b.state_root[0]), m.StateRoot[:])
		copyBytes(unsafe.Pointer(&b.body_root[0]), m.BodyRoot[:])
		rc = C.sc_sign_block(s.s, pk, &b, out)
	case *backend.VoluntaryExit:
		e := C.sc_voluntary_exit{epoch: C.uint64_t(m.Epoch), validator_index: C.uint64_t(m.ValidatorIndex)}
		rc = C.sc_sign_voluntary_exit(s.s, pk, &e, out)
	case *backend.ValidatorRegistration:
		var r C.sc_validator_registration
		copyBytes(unsafe.Pointer(&r.fee_recipient[0]), m.FeeRecipient[:])
		r.gas_limit = C.uint64_t(m.GasLimit)
		r.timestamp = C.uint64_t(m.Timestamp)
		copyBytes(unsafe.Pointer(&r.pubkey[0]), m.Pubkey[:])
		rc = C.sc_sign_validator_registration(s.s, pk, &r, out)
	case *backend.PayloadAttestationData:
		var d C.sc_payload_attestation_data
		copyBytes(unsafe.Pointer(&d.beacon_block_root[0]), m.BeaconBlockRoot[:])
		d.slot = C.uint64_t(m.Slot)
		if m.PayloadPresent {
			d.payload_present = 1
		}
		if m.BlobDataAvailable {
			d.blob_data_available = 1
		}
		rc = C.sc_sign_payload_attestation(s.s, pk, &d, out)
	case *backend.PayloadEnvelope:
		enc, err := backend.EncodeSSZ(m)
		if err != nil {
			return sig, backend.Refused(backend.StatusBadRequest, "%v", err)
		}
		var e C.sc_payload_envelope
		if C.sc_decode_payload_envelope(u8(enc), C.size_t(len(enc)), &e) != C.SC_OK {
			return sig, backend.Refused(backend.StatusBadRequest, "payload envelope layout")
		}
		rc = C.sc_sign_payload_envelope(s.s, pk, &e, out)
	case *backend.ProposerPreferences:
		var p C.sc_proposer_preferences
		copyBytes(unsafe.Pointer(&p.dependent_root[0]), m.DependentRoot[:])
		p.proposal_slot = C.uint64_t(m.ProposalSlot)
		p.validator_index = C.uint64_t(m.ValidatorIndex)
		copyBytes(unsafe.Pointer(&p.fee_recipient[0]), m.FeeRecipient[:])
		p.target_gas_limit = C.uint64_t(m.TargetGasLimit)
		rc = C.sc_sign_proposer_preferences(s.s, pk, &p, out)
	case *backend.BuilderRequestAuth:
		if len(m.Data) > backend.MaxBuilderRequestAuthData {
			return sig, backend.Refused(backend.StatusBadRequest, "builder request auth: %d data bytes", len(m.Data))
		}
		var r C.sc_builder_request_auth
		if len(m.Data) > 0 {
			data := C.CBytes(m.Data)
			defer C.free(data)
			r.data = (*C.uint8_t)(data)
		}
		r.data_len = C.size_t(len(m.Data))
		r.slot = C.uint64_t(m.Slot)
		rc = C.sc_sign_builder_request_auth(s.s, pk, &r, out)
	case *backend.SelectionProof:
		rc = C.sc_sign_selection_proof(s.s, pk, C.uint64_t(m.Slot), out, nil)
	case *backend.AggregateAndProof:
		if len(m.SSZ) == 0 {
			return sig, backend.Refused(backend.StatusBadRequest, "empty aggregate")
		}
		scratch := C.malloc(C.SC_TYPED_SCRATCH_LEN)
		defer C.free(scratch)
		ssz := C.CBytes(m.SSZ)
		defer C.free(ssz)
		rc = C.sc_sign_aggregate_and_proof(s.s, pk, (*C.uint8_t)(ssz), C.size_t(len(m.SSZ)),
			C.int(m.Form), s.preset(), (*C.uint8_t)(scratch), out, nil)
	case *backend.SyncCommitteeMessage:
		rc = C.sc_sign_sync_committee_message(s.s, pk, C.uint64_t(m.Slot), u8(m.BeaconBlockRoot[:]), out, nil)
	case *backend.SyncSelectionProof:
		rc = C.sc_sign_sync_selection_proof(s.s, pk, C.uint64_t(m.Slot), C.uint64_t(m.SubcommitteeIndex),
			s.preset(), out, nil)
	case *backend.ContributionAndProof:
		if len(m.SSZ) == 0 {
			return sig, backend.Refused(backend.StatusBadRequest, "empty contribution")
		}
		ssz := C.CBytes(m.SSZ)
		defer C.free(ssz)
		rc = C.sc_sign_contribution_and_proof(s.s, pk, (*C.uint8_t)(ssz), C.size_t(len(m.SSZ)),
			s.preset(), out, nil)
	case *backend.RootMessage:
		dt, ok := m.Type.DomainType()
		if !ok {
			return sig, backend.Refused(backend.StatusUnsupported, "root message type %d", m.Type)
		}
		if m.Type.Unverified() && !s.cfg.AllowUnverifiedNonslashable {
			return sig, backend.Refused(backend.StatusPolicyDomain,
				"root type %d is signed unverified; allow_unverified_nonslashable is off", m.Type)
		}
		// A root message carries its own domain; SignRequest.Domain is not used.
		if want := s.cfg.Domain(dt, m.Epoch); want != m.Domain {
			return sig, backend.Refused(backend.StatusDomainMismatch, "domain %v, this chain wants %v", m.Domain, want)
		}
		rc = C.sc_sign_root(s.s, pk, u8(dt[:]), C.uint64_t(m.Epoch), u8(m.ObjectRoot[:]), out)
		if rc == C.SC_OK && m.Type.Unverified() {
			s.unverified++
		}
	default:
		return sig, backend.Refused(backend.StatusUnsupported, "message type %T", req.Message)
	}
	return sig, s.refusal(rc, req.Message.Kind().String())
}

// checkSource refuses, with a device mark, a vote whose source no honest
// validator can have: at or above its target, or at or above the clock
// epoch (the chain justifies an epoch only after it ends). The core raises
// the source bound to the source of every vote it signs, and a device mark
// shares that bound across every key, so such a vote would stop every
// key's honest votes until the chain justifies that epoch. Per-validator
// marks keep the core's own checks: there a vote moves its own key's bound
// only. Source 0 raises nothing and stays allowed (the genesis vote has
// source = target = 0).
func (s *Signer) checkSource(m *backend.AttestationData) error {
	src := m.Source.Epoch
	if !s.cfg.DeviceMark || src == 0 {
		return nil
	}
	if src >= m.Target.Epoch {
		return backend.Refused(backend.StatusSlashSourceGtTarget, "attestation source %d, target %d", src, m.Target.Epoch)
	}
	now, err := s.state.hooks.Now()
	if err != nil {
		return backend.Refused(backend.StatusClock, "attestation source check: %v", err)
	}
	if e := s.EpochAt(now); src >= e {
		return backend.Refused(backend.StatusPolicyFuture, "attestation source %d at or above the clock epoch %d", src, e)
	}
	return nil
}

// preset is the core's preset struct for Config.PresetName.
func (s *Signer) preset() *C.sc_preset {
	return cPreset(s.cfg.PresetName())
}

// CoverEpoch makes the device mark cover attestation targets and blocks of
// epoch ahead of the votes (sc_signer_cover_epoch), so the store write
// happens before the epoch starts. Device marks only.
func (s *Signer) CoverEpoch(epoch uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.s == nil {
		return ErrClosed
	}
	s.state.lastErr = nil
	return s.refusal(C.sc_signer_cover_epoch(s.s, C.uint64_t(epoch)), "cover epoch")
}

// Close wipes all secrets and frees the signer.
func (s *Signer) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.s == nil {
		return
	}
	C.sc_signer_wipe(s.s)
	C.free(s.mem)
	s.handle.Delete()
	s.s, s.mem = nil, nil
}

func toC(w backend.Watermark) C.sc_watermark {
	var c C.sc_watermark
	c.block_slot = C.uint64_t(w.BlockSlot)
	c.source_epoch = C.uint64_t(w.SourceEpoch)
	c.target_epoch = C.uint64_t(w.TargetEpoch)
	if w.HasBlock {
		c.flags |= C.SC_WM_HAS_BLOCK
	}
	if w.HasAttestation {
		c.flags |= C.SC_WM_HAS_ATTESTATION
	}
	return c
}

func fromC(c C.sc_watermark) backend.Watermark {
	return backend.Watermark{
		BlockSlot:      uint64(c.block_slot),
		SourceEpoch:    uint64(c.source_epoch),
		TargetEpoch:    uint64(c.target_epoch),
		HasBlock:       c.flags&C.SC_WM_HAS_BLOCK != 0,
		HasAttestation: c.flags&C.SC_WM_HAS_ATTESTATION != 0,
	}
}

// EncodeWatermark is the core's fixed 32-byte storage record.
func EncodeWatermark(w backend.Watermark) []byte {
	cw := toC(w)
	out := make([]byte, C.SC_WATERMARK_ENCODED_LEN)
	C.sc_watermark_encode(&cw, u8(out))
	return out
}

// DecodeWatermark parses a record from EncodeWatermark.
func DecodeWatermark(b []byte) (backend.Watermark, error) {
	if len(b) == 0 {
		return backend.Watermark{}, errors.New("core: empty watermark record")
	}
	var cw C.sc_watermark
	if rc := C.sc_watermark_decode(u8(b), C.size_t(len(b)), &cw); rc != C.SC_OK {
		return backend.Watermark{}, fmt.Errorf("core: watermark record: %v", backend.Status(rc))
	}
	return fromC(cw), nil
}

// StatusName returns the core's name for a status code (sc_status_name).
func StatusName(code int) string { return C.GoString(C.sc_status_name(C.int(code))) }
