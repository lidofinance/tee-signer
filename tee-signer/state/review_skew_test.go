package state

import (
	"testing"

	"github.com/lidofinance/tee-signer/signer-protocol"
)

// Review finding: the floor margin equals max_epochs_ahead exactly, so the
// rule needs a clock that never steps back across a restart, not even by
// one second. An anchored quorum clock is monotonic inside one process but
// not across restarts: the restart reading comes from different servers,
// whose Date headers differ by their mutual skew. If the last vote was
// signed just after an epoch boundary for target E+1 and the restart
// reading lands just before it, the floor is one epoch too low and the
// target signed before the restart can be signed again.
//
// The core's slot rule closes that gap: the vote for E+1 is refused, and a
// vote for an epoch that starts within the rule's 2 s margin is at or below
// the floor of a reading taken just before it. The runner still refuses
// margin 1; lowering it is a separate change.
func TestFloorSubSecondSkewAtRestart(t *testing.T) {
	n := newNode(t, Mode{Floor: true, FloorMargin: 1, shortMargin: true}) // the runner refuses margin 1
	n.clk.set(at(100, 5))
	if err := n.start(t); err != nil {
		t.Fatal(err)
	}
	// Reading from a server 300 ms fast: epoch 105 began 0.3 s ago.
	n.clk.set(at(105, 0))
	wantStatus(t, n.attest(104, 106, 1), backend.StatusPolicyFuture) // E+1: slot not started
	// The earliest vote for epoch 105: 2 s before it starts.
	n.clk.set(at(105, -2))
	if err := n.attest(104, 105, 1); err != nil {
		t.Fatal(err)
	}
	// Host restarts the runner at once; the restart reading comes from a
	// slower server, one second earlier: still epoch 104.
	n.clk.set(at(105, -3))
	if err := n.start(t); err != nil {
		t.Fatal(err)
	}
	if f, _ := n.hooks.Floor(n.pk); f != 105 {
		t.Fatalf("floor %d, want 105", f)
	}
	n.clk.set(at(105, 5))
	wantSlashing(t, n.attest(104, 105, 2))
}

// With one extra epoch of margin (the default) the floor sits one epoch
// higher still. Cost: one more refused epoch per restart.
func TestFloorMarginPlusOneAbsorbsSkew(t *testing.T) {
	n := newNode(t, Mode{Floor: true, FloorMargin: 2})
	n.clk.set(at(100, 5))
	if err := n.start(t); err != nil {
		t.Fatal(err)
	}
	n.clk.set(at(106, 0))
	if err := n.attest(105, 106, 1); err != nil {
		t.Fatal(err)
	}
	n.clk.set(at(106, -1))
	if err := n.start(t); err != nil {
		t.Fatal(err)
	}
	if f, _ := n.hooks.Floor(n.pk); f != 107 {
		t.Fatalf("floor %d, want 107", f)
	}
	n.clk.set(at(107, 5))
	wantSlashing(t, n.attest(106, 107, 2)) // the core reports the source bound first
	n.clk.set(at(108, 5))
	if err := n.attest(107, 108, 1); err != nil {
		t.Fatalf("E+3 after restart: %v", err)
	}
}
