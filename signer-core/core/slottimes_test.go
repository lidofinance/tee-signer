package core

import (
	"math/rand/v2"
	"strings"
	"testing"

	"github.com/lidofinance/tee-signer/governance/setupwire"
	"github.com/lidofinance/tee-signer/signer-protocol"
)

// The Go clock (Config.EpochAt), the C core's (Signer.EpochAt, sc_epoch_at)
// and setupwire's SlotClock give the same epoch at every time, piece by
// piece: 12 s slots, 6 s from epoch 30, 4 s from epoch 40.
func TestSlotTimesClock(t *testing.T) {
	cfg := DevConfig(genesis, 12, 32)
	cfg.SlotTimeChanges = []SlotTimeChange{{30, 6}, {40, 4}}
	h := NewMemHooks()
	h.Clock = clockAtEpoch(0)
	s, err := NewSigner(cfg, 4, 0, h)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	sw := setupwire.SlotClock{GenesisTime: cfg.GenesisTime, SecondsPerSlot: cfg.SecondsPerSlot, SlotsPerEpoch: cfg.SlotsPerEpoch,
		Changes: []setupwire.SlotTimeChange{{Epoch: 30, SecondsPerSlot: 6}, {Epoch: 40, SecondsPerSlot: 4}}}
	start30 := uint64(genesis + 30*32*12)
	start40 := start30 + 10*32*6
	times := []uint64{0, genesis, genesis + 1, start30 - 1, start30, start30 + 5, start30 + 6, start40 - 1, start40, start40 + 3, start40 + 4}
	r := rand.New(rand.NewPCG(1, 2))
	for range 2000 {
		times = append(times, genesis+r.Uint64N(200*32*12))
	}
	for _, at := range times {
		g, c, w := cfg.EpochAt(at), s.coreEpochAt(at), sw.EpochAt(at)
		if g != c || g != w {
			t.Fatalf("t=%d: Go %d, core %d, setupwire %d", at, g, c, w)
		}
		if cfg.SlotAt(at) != sw.SlotAt(at) {
			t.Fatalf("t=%d: slot %d, setupwire %d", at, cfg.SlotAt(at), sw.SlotAt(at))
		}
	}
	if cfg.EpochAt(start40) != 40 || cfg.EpochAt(start40-1) != 39 || cfg.SecondsPerSlotAt(35) != 6 || cfg.SecondsPerSlotAt(29) != 12 {
		t.Fatal("piece boundaries")
	}
	plain := DevConfig(genesis, 12, 32)
	if plain.EpochAt(start40) != (start40-genesis)/(12*32) {
		t.Fatal("without changes the clock is the plain one")
	}
}

// The clock horizon follows the slot times the signer holds: at the start of
// epoch 45 under the changes (epoch 36 under 12 s slots) it signs up to
// epoch 46 (MaxEpochsAhead 1).
func TestSlotTimesHorizon(t *testing.T) {
	cfg := DevConfig(genesis, 12, 32)
	cfg.SlotTimeChanges = []SlotTimeChange{{30, 6}, {40, 4}}
	at := uint64(genesis+30*32*12+10*32*6+5*32*4) + 3
	h := NewMemHooks()
	h.Clock = func() (uint64, error) { return at, nil }
	s, pk, _ := newTestSignerWith(t, h, cfg)
	if s.EpochAt(at) != 45 || cfg.EpochAt(at) != 45 {
		t.Fatalf("epoch %d", s.EpochAt(at))
	}
	_, err := s.Sign(signReq(s, pk, att(44, 47)))
	wantStatus(t, err, backend.StatusPolicyFuture)
	mustSign(t, s, pk, att(44, 46))
	h2 := NewMemHooks()
	h2.Clock = h.Clock
	p, ppk, _ := newTestSignerWith(t, h2, DevConfig(genesis, 12, 32))
	_, err = p.Sign(signReq(p, ppk, att(44, 46)))
	wantStatus(t, err, backend.StatusPolicyFuture)
}

// SetSlotTimes keeps every epoch up to epoch(max(activateAt, now)) +
// MaxEpochsAhead + 1: with the clock in epoch 20, a change at epoch 22 is
// too soon and one at 23 passes; in force from epoch 50, 53 passes and 52
// does not. Config shows the slot times in force.
func TestSetSlotTimes(t *testing.T) {
	h := NewMemHooks()
	s, pk, cfg := newTestSigner(t, h) // clock in epoch 20, MaxEpochsAhead 1
	at50 := uint64(genesis + 50*32*12)
	for _, c := range []struct {
		changes    []SlotTimeChange
		activateAt uint64
		ok         bool
	}{
		{[]SlotTimeChange{{22, 6}}, 0, false},
		{[]SlotTimeChange{{23, 6}}, 0, true},
		{[]SlotTimeChange{{52, 6}}, at50, false},
		{[]SlotTimeChange{{53, 6}}, at50, true},
	} {
		err := s.CheckSlotTimes(c.changes, c.activateAt)
		if (err == nil) != c.ok {
			t.Fatalf("%+v at %d: %v, want ok=%v", c.changes, c.activateAt, err, c.ok)
		}
		if !c.ok {
			wantStatus(t, err, backend.StatusSchedule)
		}
	}
	if len(s.Config().SlotTimeChanges) != 0 {
		t.Fatal("a check changed the slot times")
	}
	err := s.SetSlotTimes([]SlotTimeChange{{23, 12}}, 0)
	if err == nil || !strings.Contains(err.Error(), "keeps the slot time") {
		t.Fatalf("a change to the genesis slot time: %v", err)
	}
	wantStatus(t, err, backend.StatusArg)
	if err := s.SetSlotTimes([]SlotTimeChange{{23, 6}}, 0); err != nil {
		t.Fatal(err)
	}
	if got := s.Config().SlotTimeChanges; len(got) != 1 || got[0] != (SlotTimeChange{23, 6}) {
		t.Fatalf("config shows %+v", got)
	}
	// The clock moves to epoch 22: the change at 23 is within reach and
	// stays; a later one on top still passes.
	h.Clock = clockAtEpoch(22)
	wantStatus(t, s.SetSlotTimes(nil, 0), backend.StatusSchedule)
	if err := s.SetSlotTimes([]SlotTimeChange{{23, 6}, {30, 4}}, 0); err != nil {
		t.Fatal(err)
	}
	mustSign(t, s, pk, att(21, 23))
	// The lock-free clock follows the core's after the change.
	for e := uint64(0); e < 60; e++ {
		at := genesis + e*32*12 + 7
		if s.EpochAt(at) != s.coreEpochAt(at) {
			t.Fatalf("t=%d: EpochAt %d, core %d", at, s.EpochAt(at), s.coreEpochAt(at))
		}
	}
	if s.EpochAt(genesis+23*32*12+7*32*6) != 30 || cfg.EpochAt(genesis+23*32*12+7*32*6) == 30 {
		t.Fatal("the signer's clock does not follow the new slot times")
	}
}

func TestSlotTimesValidate(t *testing.T) {
	for _, c := range []struct {
		changes []SlotTimeChange
		want    string
	}{
		{[]SlotTimeChange{{0, 6}}, "non-zero"},
		{[]SlotTimeChange{{5, 0}}, "non-zero"},
		{[]SlotTimeChange{{9, 6}, {5, 4}}, "ascending"},
		{[]SlotTimeChange{{5, 6}, {9, 6}}, "keeps the slot time"},
		{[]SlotTimeChange{{5, 1 << 62}}, "overflows"},
		{[]SlotTimeChange{{1 << 62, 6}}, "does not fit"},
		{make([]SlotTimeChange, maxSlotTimes+1), "at most"},
	} {
		cfg := DevConfig(genesis, 12, 32)
		cfg.SlotTimeChanges = c.changes
		if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%+v: %v, want %q", c.changes, err, c.want)
		}
		if _, err := NewSigner(cfg, 4, 0, NewMemHooks()); err == nil {
			t.Errorf("%+v: NewSigner took it", c.changes)
		}
	}
}

// The fork rule counts epochs under pending slot time changes too. With the
// clock in epoch 20 (12 s slots, MaxEpochsAhead 1), a fork in force at the
// start of epoch 40 may touch epoch 43 under the plain clock; with 4 s slots
// pending from epoch 22 the clock reaches epoch 76 by then, so the first
// epoch is 79. The other order: with that fork in the core, 3 s slots from
// epoch 22 would bring it within reach, which a check of a return to the
// schedule before the fork refuses.
func TestSchedulePendingSlotTimes(t *testing.T) {
	s, _, cfg := newTestSigner(t, NewMemHooks())
	at := uint64(genesis + 40*32*12)
	pend := []SlotTimeChange{{22, 4}}
	base := cfg.Schedule()
	with := func(epoch uint64) Schedule {
		n := cfg.Schedule()
		n.Forks = append(n.Forks, Fork{Epoch: epoch, Version: nextVersion})
		return n
	}
	if err := s.CheckSchedule(with(50), at); err != nil {
		t.Fatalf("plain clock: %v", err)
	}
	wantStatus(t, s.CheckSchedule(with(50), at, pend), backend.StatusSchedule)
	wantStatus(t, s.CheckSchedule(with(78), at, pend), backend.StatusSchedule)
	wantStatus(t, s.CheckSchedule(with(79), at, []SlotTimeChange{{22, 12}}), backend.StatusArg)
	if err := s.SetSchedule(with(79), at, pend); err != nil {
		t.Fatal(err)
	}
	if err := s.CheckSchedule(base, at, pend); err != nil {
		t.Fatalf("4 s slots keep the fork clear: %v", err)
	}
	wantStatus(t, s.CheckSchedule(base, at, []SlotTimeChange{{22, 3}}), backend.StatusSchedule)
	if c := s.Config(); c.ForkVersionAt(79) != nextVersion {
		t.Fatal("the schedule is not in the core")
	}
}
