package server

import (
	"context"
	"time"

	"github.com/lidofinance/tee-signer/governance/exitapproval"
	"github.com/lidofinance/tee-signer/governance/setupwire"
	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/slashing-log"
)

// The exit rules of the OP-TEE trusted app, on a runner with a setup
// (issue #4 F4; signer_ta.c do_approve_exit and exit_allowed): a voluntary
// exit is signed only if an exit approval of exit_approvals_needed
// approvers in force names its key, index and epoch, and the day's stake
// cap (exit_stake_cap_per_day) has room for the stake it counts. The
// allowlist (exit_allowed_validators) stays the core's check.
//
// Approvals live in memory: a restart drops them, as in the TA. The day's
// exits (their stake and their approvals' nonces) go into the mark log, in
// a record written before the exit is signed, where the TA keeps them in
// its rollback-protected state: the log has the guarantees of the device
// mark (conditional create, version and link checks, the delete-marker
// check on S3), so a rollback of the host's local state does not free the
// day's cap. A runner without a mark log signs no exit.

const (
	maxPendingExits = 8
	daySeconds      = 86400
)

type exitState struct {
	mu      namedMutex[exitsMuName]
	pending []heldExit
}

// heldExit is a held approval with what it was checked against: the hash of
// the approver set in force and exit_approvals_needed. It counts only while
// both are still in force (VSEXIT-01); the TA clears its held approvals on
// every locked activation to the same end.
type heldExit struct {
	exitapproval.Approval
	set    [32]byte
	needed uint8
}

// valid reports whether h counts under locked l at now.
func (h *heldExit) valid(l *setupwire.Locked, now uint64) bool {
	return h.NotAfter > now && h.set == l.Approvers.Hash() && h.needed == l.ExitApprovalsNeeded
}

// exitDay is the day's exits in the mark log as of now: empty on a new
// day; a refusal while the log holds a later day.
func (s *Server) exitDay(now uint64) (*markstore.ExitDay, error) {
	cur, err := s.Hooks.Exits()
	if err != nil {
		return nil, backend.Refused(backend.StatusStorage, "exits need the mark log: %v", err)
	}
	d := &markstore.ExitDay{Day: now / daySeconds}
	switch {
	case cur != nil && cur.Day > d.Day:
		// A later day's ledger (carried in by a handover from a clock past
		// midnight) stays until this clock gets there (SHH-02).
		return nil, backend.Refused(backend.StatusPolicyExit, "the exit ledger is of day %d, the clock's day is %d", cur.Day, d.Day)
	case cur != nil && cur.Day == d.Day:
		d = cur
	}
	return d, nil
}

// exitStake is the stake an approved exit counts against the cap:
// max_effective_balance, always (VSEXIT-02, OPTEE-DEPOSIT-02). The runner cannot check the balance an approval
// states, and a validator with 0x01 credentials may have switched to
// compounding since, so neither the stated balance, exit_stake_counting
// nor the setup's credentials prefix lowers the charge. An approval that
// states nothing, or more than max_effective_balance, is refused.
func exitStake(l *setupwire.Locked, a *exitapproval.Approval) (uint64, error) {
	most := l.MaxEffectiveBalance
	if a.EffectiveBalance == 0 || a.EffectiveBalance > most {
		return 0, backend.Refused(backend.StatusPolicyExit,
			"exit approval for validator %d: effective balance %d Gwei, allowed 1 to %d", a.ValidatorIndex, a.EffectiveBalance, most)
	}
	return most, nil
}

// approveExit answers APPROVE_EXIT: it checks a signed approval and holds
// it until an exit matches it or it expires.
func (s *Server) approveExit(p []byte) ([]byte, error) {
	if s.Updates == nil {
		return nil, backend.Refused(backend.StatusUnsupported, "this runner has no setup, so it has no exit approvers")
	}
	sa, err := exitapproval.Decode(p)
	if err != nil {
		return nil, backend.Refused(backend.StatusBadRequest, "%v", err)
	}
	a := &sa.Approval
	locked, now, err := s.Updates.lockedNow()
	if err != nil {
		return nil, err
	}
	switch {
	case a.GenesisValidatorsRoot != s.Updates.SetupWire().Chain.GenesisValidatorsRoot:
		return nil, backend.Refused(backend.StatusPolicyExit, "exit approval for another chain")
	case a.Pubkey == (backend.Pubkey{}) || a.Nonce == ([32]byte{}):
		return nil, backend.Refused(backend.StatusBadRequest, "exit approval: zero pubkey or nonce")
	case a.NotAfter <= now || a.NotAfter-now > exitapproval.MaxLifetime:
		return nil, backend.Refused(backend.StatusPolicyExit, "exit approval for validator %d: expired or valid too long (not after %d, now %d)",
			a.ValidatorIndex, a.NotAfter, now)
	}
	if err := sa.Verify(&locked.Approvers, locked.ExitApprovalsNeeded); err != nil {
		return nil, backend.Refused(backend.StatusForbidden, "%v", err)
	}
	if _, err := exitStake(locked, a); err != nil {
		return nil, err
	}
	s.exits.mu.Lock()
	defer s.exits.mu.Unlock()
	d, err := s.exitDay(now)
	if err != nil {
		return nil, err
	}
	for _, e := range d.Exits {
		if e.Nonce == a.Nonce {
			return nil, backend.Refused(backend.StatusPolicyExit, "exit approval for validator %d: its nonce was used today", a.ValidatorIndex)
		}
	}
	held := heldExit{Approval: *a, set: locked.Approvers.Hash(), needed: locked.ExitApprovalsNeeded}
	free := -1
	for i := range s.exits.pending {
		if s.exits.pending[i] == held {
			return nil, nil
		}
		if free < 0 && !s.exits.pending[i].valid(locked, now) {
			free = i
		}
	}
	switch {
	case free >= 0:
		s.exits.pending[free] = held
	case len(s.exits.pending) < maxPendingExits:
		s.exits.pending = append(s.exits.pending, held)
	default:
		return nil, backend.Refused(backend.StatusNoMem, "%d exit approvals held, none expired", maxPendingExits)
	}
	s.Log.Info("exit approval held", "validator_index", a.ValidatorIndex, "exit_epoch", a.ExitEpoch,
		"effective_balance", a.EffectiveBalance, "signatures", len(sa.Approvals), "not_after", a.NotAfter)
	return nil, nil
}

// exitAllowed is the exit rule before a voluntary exit is signed: an
// approval held for this key, index and epoch, and room under the day's
// cap. An exit of the same key, index and epoch recorded earlier the same
// day signs again without counting; a new one is recorded before it is
// signed.
func (s *Server) exitAllowed(pk backend.Pubkey, e *backend.VoluntaryExit) error {
	locked, now, err := s.Updates.lockedNow()
	if err != nil {
		return err
	}
	s.exits.mu.Lock()
	defer s.exits.mu.Unlock()
	var a *exitapproval.Approval
	for i := range s.exits.pending {
		p := &s.exits.pending[i]
		if p.valid(locked, now) && p.Pubkey == pk && p.ValidatorIndex == e.ValidatorIndex && p.ExitEpoch == e.Epoch {
			a = &p.Approval
			break
		}
	}
	if a == nil {
		return backend.Refused(backend.StatusPolicyExit,
			"no exit approval held for validator %d at epoch %d (exit_approvals_needed %d)", e.ValidatorIndex, e.Epoch, locked.ExitApprovalsNeeded)
	}
	loaded := false
	for _, k := range s.Signer.Keys() {
		loaded = loaded || k.Pubkey == pk
	}
	if !loaded {
		// Recorded only for a key this runner holds, so an empty handover
		// target has no ledger entry before its import (SHH-01).
		return backend.Refused(backend.StatusUnknownValidator, "no share of validator %s is loaded", pk.String()[:18])
	}
	d, err := s.exitDay(now)
	if err != nil {
		return err
	}
	for _, x := range d.Exits {
		// A repeat is the same key, index and epoch (OPTEE-EXIT-01): an
		// approval that pairs another key with that index and epoch counts
		// its own stake. Entries carried in from a handover have no key and
		// match nothing.
		if x.Pubkey == pk && x.ValidatorIndex == e.ValidatorIndex && x.ExitEpoch == e.Epoch {
			return nil
		}
	}
	stake, err := exitStake(locked, a)
	if err != nil {
		return err
	}
	limit := locked.ExitStakeCapPerDay
	if stake > limit || d.Stake > limit-stake || len(d.Exits) >= markstore.MaxExitsPerDay {
		return backend.Refused(backend.StatusPolicyExit,
			"exit of validator %d counts %d Gwei, %d Gwei in %d exit(s) today, the cap is %d Gwei a day",
			e.ValidatorIndex, stake, d.Stake, len(d.Exits), limit)
	}
	d.Exits = append(d.Exits, markstore.ExitEntry{Pubkey: pk, ValidatorIndex: e.ValidatorIndex, ExitEpoch: e.Epoch, Stake: stake, Nonce: a.Nonce})
	d.Stake += stake
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := s.Hooks.RecordExits(ctx, d); err != nil {
		return backend.Refused(backend.StatusStorage, "exit record in the mark log: %v", err)
	}
	return nil
}
