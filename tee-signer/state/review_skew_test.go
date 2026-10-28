package state

import "testing"

// Review finding: the floor margin equals max_epochs_ahead exactly, so the
// rule needs a clock that never steps back across a restart, not even by
// one second. An anchored quorum clock is monotonic inside one process but
// not across restarts: the restart reading comes from different servers,
// whose Date headers differ by their mutual skew. If the last vote was
// signed just after an epoch boundary and the restart reading lands just
// before it, the floor is one epoch too low and the target signed before
// the restart can be signed again.
func TestFloorBrokenBySubSecondSkewAtRestart(t *testing.T) {
	n := newNode(t, Mode{Floor: true, FloorMargin: 1, shortMargin: true}) // the runner now refuses margin 1
	n.clk.set(at(100, 5))
	if err := n.start(t); err != nil {
		t.Fatal(err)
	}
	// Reading from a server 300 ms fast: epoch 105 began 0.3 s ago.
	n.clk.set(at(105, 0))
	if err := n.attest(104, 106, 1); err != nil { // target E+1 = 106, allowed
		t.Fatal(err)
	}
	// Host restarts the runner at once; the restart reading comes from a
	// server 700 ms slow, so it is one second earlier: still epoch 104.
	n.clk.set(at(105, -1))
	if err := n.start(t); err != nil {
		t.Fatal(err)
	}
	if f, _ := n.hooks.Floor(n.pk); f != 105 {
		t.Fatalf("floor %d, want 105", f)
	}
	n.clk.set(at(106, 5))
	if err := n.attest(105, 106, 2); err != nil {
		t.Fatalf("expected a double vote for target 106 (documents the margin gap), got %v", err)
	}
}

// With one extra epoch of margin the same skew is harmless: the floor is
// 106 and the second vote is refused. Cost: one more refused epoch per
// restart.
func TestFloorMarginPlusOneAbsorbsSkew(t *testing.T) {
	n := newNode(t, Mode{Floor: true, FloorMargin: 2})
	n.clk.set(at(100, 5))
	if err := n.start(t); err != nil {
		t.Fatal(err)
	}
	n.clk.set(at(105, 0))
	if err := n.attest(104, 106, 1); err != nil {
		t.Fatal(err)
	}
	n.clk.set(at(105, -1))
	if err := n.start(t); err != nil {
		t.Fatal(err)
	}
	if f, _ := n.hooks.Floor(n.pk); f != 106 {
		t.Fatalf("floor %d, want 106", f)
	}
	n.clk.set(at(106, 5))
	wantSlashing(t, n.attest(105, 106, 2)) // the core reports the source bound first
	n.clk.set(at(107, 5))
	if err := n.attest(106, 107, 1); err != nil {
		t.Fatalf("E+3 after restart: %v", err)
	}
}
