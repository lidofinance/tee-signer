package setupwire

import (
	"errors"
	"fmt"
	"math"
	"math/bits"
)

// Slot time changes (research/attestation-prover.md, "Signer changes",
// item 5). The chain part names the genesis slot time; the locked group
// lists later changes, each from the first slot of an epoch on. Time maps
// to slots piece by piece: piece i starts at the first slot of its epoch
// and runs with its seconds per slot until the next piece starts. The C
// core (sc_slot_at, sc_epoch_at) does the same arithmetic.
//
// The rule for an update (CheckSlotTimeRule, the fork rule of section 7
// applied to slot times): every epoch whose slot time differs between the
// slot times in force and the new ones is at least epoch(T) +
// max_sign_epochs_ahead_of_clock + 2, with T the update's effective
// activation time. Before T the signer signs no epoch past epoch(T) +
// max_sign_epochs_ahead_of_clock, so both slot times give the same clock
// for every epoch it may sign before T.

// SlotClock maps unix time to slots and epochs under a chain's genesis slot
// time and its slot time changes.
type SlotClock struct {
	GenesisTime    uint64
	SecondsPerSlot uint64 // at genesis
	SlotsPerEpoch  uint64
	Changes        []SlotTimeChange // as CheckSlotTimes accepts them
}

// NewSlotClock is the clock of chain with changes.
func NewSlotClock(c *Chain, changes []SlotTimeChange) SlotClock {
	return SlotClock{GenesisTime: c.GenesisTime, SecondsPerSlot: c.SecondsPerSlot, SlotsPerEpoch: c.SlotsPerEpoch, Changes: changes}
}

// piece is one stretch of constant slot time: from startSlot (whose first
// second is start) on, slots of secs seconds.
type piece struct {
	startSlot, start, secs uint64
}

// pieces lists the stretches; ok is false when a start time or slot does
// not fit 64 bits.
func (c SlotClock) pieces() ([]piece, bool) {
	ps := []piece{{0, c.GenesisTime, c.SecondsPerSlot}}
	for _, ch := range c.Changes {
		prev := ps[len(ps)-1]
		hi, slot := bits.Mul64(ch.Epoch, c.SlotsPerEpoch)
		if hi != 0 || slot < prev.startSlot {
			return nil, false
		}
		hi, dur := bits.Mul64(slot-prev.startSlot, prev.secs)
		if hi != 0 {
			return nil, false
		}
		start, carry := bits.Add64(prev.start, dur, 0)
		if carry != 0 {
			return nil, false
		}
		ps = append(ps, piece{slot, start, ch.SecondsPerSlot})
	}
	return ps, true
}

// SlotAt is the slot at unix time t: 0 before genesis, and the last slot
// that fits 64 bits past the end of time.
func (c SlotClock) SlotAt(t uint64) uint64 {
	if t <= c.GenesisTime || c.SecondsPerSlot == 0 {
		return 0
	}
	ps, ok := c.pieces()
	if !ok {
		// CheckSlotTimes refuses such changes; keep the genesis slot time.
		ps = []piece{{0, c.GenesisTime, c.SecondsPerSlot}}
	}
	p := ps[0]
	for _, q := range ps[1:] {
		if t < q.start {
			break
		}
		p = q
	}
	n := (t - p.start) / p.secs
	if s, carry := bits.Add64(p.startSlot, n, 0); carry == 0 {
		return s
	}
	return math.MaxUint64
}

// EpochAt is the epoch at unix time t (0 before genesis).
func (c SlotClock) EpochAt(t uint64) uint64 {
	if c.SlotsPerEpoch == 0 {
		return 0
	}
	return c.SlotAt(t) / c.SlotsPerEpoch
}

// CheckSlotTimes is the rule for a list of slot time changes against the
// chain, beyond Locked.Check: the first change starts another slot time
// than the genesis one, an epoch of any slot time fits 64 bits, and the
// start of every change is a time that fits 64 bits.
func CheckSlotTimes(c *Chain, changes []SlotTimeChange) error {
	if len(changes) == 0 {
		return nil
	}
	if changes[0].SecondsPerSlot == c.SecondsPerSlot {
		return fmt.Errorf("slot_time_changes: epoch %d keeps the genesis slot time (%d s)", changes[0].Epoch, c.SecondsPerSlot)
	}
	for _, ch := range changes {
		if hi, _ := bits.Mul64(ch.SecondsPerSlot, c.SlotsPerEpoch); hi != 0 {
			return fmt.Errorf("slot_time_changes: epoch %d: seconds per slot * slots_per_epoch overflows 64 bits", ch.Epoch)
		}
	}
	if _, ok := NewSlotClock(c, changes).pieces(); !ok {
		return errors.New("slot_time_changes: the start time of a change does not fit 64 bits")
	}
	return nil
}

// secondsAt is the slot time of epoch e.
func secondsAt(genesis uint64, changes []SlotTimeChange, e uint64) uint64 {
	s := genesis
	for _, ch := range changes {
		if ch.Epoch > e {
			break
		}
		s = ch.SecondsPerSlot
	}
	return s
}

// FirstSlotTimeDifference is the first epoch at which active and next give
// another slot time, and false when they give the same one at every epoch.
func FirstSlotTimeDifference(genesisSeconds uint64, active, next []SlotTimeChange) (uint64, bool) {
	first, found := uint64(0), false
	for _, list := range [][]SlotTimeChange{active, next} {
		for _, ch := range list {
			if secondsAt(genesisSeconds, active, ch.Epoch) != secondsAt(genesisSeconds, next, ch.Epoch) && (!found || ch.Epoch < first) {
				first, found = ch.Epoch, true
			}
		}
	}
	return first, found
}

// CheckSlotTimeRule is the rule for an update that replaces the slot time
// changes active (in force) with next, in force from the effective
// activation time t, for a signer with maxAhead =
// max_sign_epochs_ahead_of_clock: the first epoch whose slot time differs
// is at least epoch(t) + maxAhead + 2 (sums saturate). epoch(t) is taken
// under active; both lists agree on every epoch up to that one.
func CheckSlotTimeRule(c *Chain, maxAhead uint64, active, next []SlotTimeChange, t uint64) error {
	e, differ := FirstSlotTimeDifference(c.SecondsPerSlot, active, next)
	if !differ {
		return nil
	}
	min := SatAdd(SatAdd(NewSlotClock(c, active).EpochAt(t), maxAhead), 2)
	if e < min {
		return fmt.Errorf("slot_time_changes: the slot time changes at epoch %d, but an update in force at %d may change it from epoch %d on "+
			"(epoch(T) + max_sign_epochs_ahead_of_clock + 2)", e, t, min)
	}
	return nil
}

// SlotStart is the unix time at which slot begins, the inverse of SlotAt:
// the T of a beacon block root that the attestation prover asks with
// (research/attestation-prover.md, "The proof"). ok is false when the time
// does not fit 64 bits or the slot times are ones CheckSlotTimes refuses.
func (c SlotClock) SlotStart(slot uint64) (uint64, bool) {
	if c.SecondsPerSlot == 0 {
		return 0, false
	}
	ps, ok := c.pieces()
	if !ok {
		return 0, false
	}
	p := ps[0]
	for _, q := range ps[1:] {
		if slot < q.startSlot {
			break
		}
		p = q
	}
	hi, d := bits.Mul64(slot-p.startSlot, p.secs)
	if hi != 0 {
		return 0, false
	}
	t, carry := bits.Add64(p.start, d, 0)
	return t, carry == 0
}
