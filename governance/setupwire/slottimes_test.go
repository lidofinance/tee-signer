package setupwire

import (
	"math"
	"strings"
	"testing"
)

// Time maps to slots piece by piece: 6 s slots up to epoch 10, then 4 s,
// then 3 s from epoch 20 (8 slots an epoch).
func TestSlotClock(t *testing.T) {
	c := sampleChain() // genesis 1_760_000_000, 6 s, 8 slots
	changes := []SlotTimeChange{{Epoch: 10, SecondsPerSlot: 4}, {Epoch: 20, SecondsPerSlot: 3}}
	clk := NewSlotClock(&c, changes)
	g := c.GenesisTime
	start10 := g + 80*6       // slot 80
	start20 := start10 + 80*4 // slot 160
	for _, tc := range []struct {
		t, slot uint64
	}{
		{0, 0}, {g, 0}, {g + 5, 0}, {g + 6, 1}, {start10 - 1, 79}, {start10, 80}, {start10 + 3, 80}, {start10 + 4, 81},
		{start20 - 1, 159}, {start20, 160}, {start20 + 2, 160}, {start20 + 3, 161}, {start20 + 3*800, 960},
	} {
		if got := clk.SlotAt(tc.t); got != tc.slot {
			t.Errorf("SlotAt(genesis%+d) = %d, want %d", int64(tc.t)-int64(g), got, tc.slot)
		}
		if got := clk.EpochAt(tc.t); got != tc.slot/8 {
			t.Errorf("EpochAt(genesis%+d) = %d, want %d", int64(tc.t)-int64(g), got, tc.slot/8)
		}
	}
	// No changes: the plain formula.
	plain := NewSlotClock(&c, nil)
	for _, d := range []uint64{0, 1, 47, 48, 1 << 30} {
		if got, want := plain.EpochAt(g+d), d/48; got != want {
			t.Errorf("no changes: EpochAt(genesis+%d) = %d, want %d", d, got, want)
		}
	}
	// The end of time saturates instead of wrapping.
	if got := NewSlotClock(&Chain{GenesisTime: 0, SecondsPerSlot: 1, SlotsPerEpoch: 1}, nil).SlotAt(math.MaxUint64); got != math.MaxUint64 {
		t.Errorf("SlotAt(max) = %d", got)
	}
}

func TestSlotTimeRule(t *testing.T) {
	c := sampleChain()
	const ahead = 2
	for _, tc := range []struct {
		name         string
		active, next []SlotTimeChange
		ok           bool
	}{
		{"same", nil, nil, true},
		{"new change at 104", nil, []SlotTimeChange{{104, 4}}, true},
		{"new change at 103", nil, []SlotTimeChange{{103, 4}}, false},
		{"started change kept", []SlotTimeChange{{50, 4}}, []SlotTimeChange{{50, 4}, {200, 3}}, true},
		{"started change moved", []SlotTimeChange{{50, 4}}, []SlotTimeChange{{60, 4}}, false},
		{"future change removed", []SlotTimeChange{{150, 4}}, nil, true},
		{"near change removed", []SlotTimeChange{{103, 4}}, nil, false},
		{"near change kept, later one added", []SlotTimeChange{{103, 4}}, []SlotTimeChange{{103, 4}, {104, 3}}, true},
		{"seconds of a near change changed", []SlotTimeChange{{103, 4}}, []SlotTimeChange{{103, 3}}, false},
	} {
		// epoch(T) is taken under the active slot times: under 4 s slots
		// from epoch 50, epoch 100 starts earlier.
		a := epochStartWith(&c, tc.active, 100) + 10
		if NewSlotClock(&c, tc.active).EpochAt(a) != 100 {
			t.Fatalf("%s: T is not in epoch 100", tc.name)
		}
		err := CheckSlotTimeRule(&c, ahead, tc.active, tc.next, a)
		if (err == nil) != tc.ok {
			t.Errorf("%s: %v, want ok=%v", tc.name, err, tc.ok)
		}
		if err != nil && !strings.Contains(err.Error(), "epoch(T) + max_sign_epochs_ahead_of_clock + 2") {
			t.Errorf("%s: message %v", tc.name, err)
		}
	}
	if e, d := FirstSlotTimeDifference(6, []SlotTimeChange{{5, 4}, {9, 3}}, []SlotTimeChange{{5, 4}, {8, 3}}); !d || e != 8 {
		t.Fatalf("first difference %d %v", e, d)
	}
	if _, d := FirstSlotTimeDifference(6, []SlotTimeChange{{5, 4}}, []SlotTimeChange{{5, 4}}); d {
		t.Fatal("difference in equal lists")
	}
}

// epochStartWith is the first second of epoch e under changes.
func epochStartWith(c *Chain, changes []SlotTimeChange, e uint64) uint64 {
	clk := NewSlotClock(c, changes)
	ps, _ := clk.pieces()
	p := ps[0]
	for _, q := range ps[1:] {
		if q.startSlot <= e*c.SlotsPerEpoch {
			p = q
		}
	}
	return p.start + (e*c.SlotsPerEpoch-p.startSlot)*p.secs
}

// SlotStart is the first second of a slot under the same pieces, so
// SlotAt(SlotStart(s)) is s and the second before belongs to s - 1.
func TestSlotStart(t *testing.T) {
	c := sampleChain() // genesis 1_760_000_000, 6 s, 8 slots
	clk := NewSlotClock(&c, []SlotTimeChange{{Epoch: 10, SecondsPerSlot: 4}, {Epoch: 20, SecondsPerSlot: 3}})
	g := c.GenesisTime
	for _, tc := range []struct{ slot, start uint64 }{
		{0, g}, {1, g + 6}, {79, g + 79*6}, {80, g + 80*6}, {81, g + 80*6 + 4}, {160, g + 80*6 + 80*4}, {161, g + 80*6 + 80*4 + 3},
	} {
		got, ok := clk.SlotStart(tc.slot)
		if !ok || got != tc.start {
			t.Errorf("SlotStart(%d) = %d %v, want %d", tc.slot, got, ok, tc.start)
		}
		if clk.SlotAt(got) != tc.slot || (tc.slot > 0 && clk.SlotAt(got-1) != tc.slot-1) {
			t.Errorf("slot %d: SlotAt does not invert SlotStart", tc.slot)
		}
	}
	if _, ok := NewSlotClock(&c, nil).SlotStart(math.MaxUint64); ok {
		t.Error("a start past 2^64 was given")
	}
	if _, ok := NewSlotClock(&Chain{}, nil).SlotStart(1); ok {
		t.Error("a chain without a slot time gave a start")
	}
}
