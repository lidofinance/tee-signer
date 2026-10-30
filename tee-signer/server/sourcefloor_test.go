//go:build !debugimport

package server

import (
	"testing"

	"github.com/lidofinance/tee-signer/signer-protocol"
)

// floorOf is the restart floor epoch a runner started now takes.
func (e *tgtEnv) floorOf() uint64 {
	return e.signer.EpochAt(e.now()) + e.setup.Safety.MaxSignEpochsAheadOfClock + 1
}

// wantSlashSource fails unless err is a StatusSlashSource refusal.
func wantSlashSource(t *testing.T, err error, what string) {
	t.Helper()
	if err == nil {
		t.Errorf("%s: signed, want %v", what, backend.StatusSlashSource)
	} else if backend.StatusOf(err) != backend.StatusSlashSource {
		t.Errorf("%s: %v, want %v", what, err, backend.StatusSlashSource)
	}
}

// RBRLOG-02: a fresh (or lost and recreated) log with the floor on gates
// vote sources below the floor epoch. The first cover write records
// HasAttestation with source 0, and a restart took that as vote history
// and dropped the gate. The gate must survive the restart.
func TestRBRLOG02SourceFloorSurvivesCoverAndRestart(t *testing.T) {
	e := newTgtEnv(t, "dev", nil)
	floor := e.floorOf()
	sk, pk := newKey(t)
	if err := e.importSealed(pk, sk, 5, nil); err != nil { // no history
		t.Fatal(err)
	}
	if err := e.signer.CoverEpoch(floor + 1); err != nil {
		t.Fatal(err)
	}
	if m, _ := e.marks.Mark(); !m.HasAttestation || m.SourceEpoch != 0 {
		t.Fatalf("the cover write left mark %+v, want HasAttestation with source 0", m)
	}
	e.clock.add(5 * testEpoch) // past the target bound the cover wrote
	e.restart()
	f2 := e.floorOf()
	e.clock.add((f2 - e.signer.EpochAt(e.now())) * testEpoch)
	wantSlashSource(t, e.signMsg(pk, vote(floor-1, f2+1)),
		"vote below the floor after a cover write and a restart")
	// A vote at the floor signs, and once its source is in the log a
	// restart needs the gate no more.
	if err := e.signMsg(pk, vote(floor, f2+1)); err != nil {
		t.Fatalf("vote at the floor: %v", err)
	}
	e.restart()
	if m, _ := e.marks.Mark(); m.SourceEpoch < floor {
		t.Fatalf("log source %d after a vote at the floor %d", m.SourceEpoch, floor)
	}
}

// SSI-HISTORY-01: one import with vote history lifted the source gate for
// every validator. Validator A, imported without history, must stay gated
// while B's history lets B vote below the floor, also after a restart.
func TestSSIHISTORY01HistoryLiftsTheGateForItsKeyOnly(t *testing.T) {
	e := newTgtEnv(t, "dev", nil)
	start := e.signer.EpochAt(e.now())
	floor := e.floorOf()
	ska, pka := newKey(t)
	if err := e.importSealed(pka, ska, 5, nil); err != nil {
		t.Fatal(err)
	}
	skb, pkb := newKey(t)
	hist := &backend.Watermark{HasAttestation: true, SourceEpoch: start - 3, TargetEpoch: start - 2, HasBlock: true, BlockSlot: (start - 2) * 8}
	if err := e.importSealed(pkb, skb, 6, hist); err != nil {
		t.Fatal(err)
	}
	check := func(when string) {
		t.Helper()
		wantSlashSource(t, e.signMsg(pka, vote(start-3, floor+1)), when+": A (no history) below the floor")
		if err := e.signMsg(pkb, vote(start-3, floor+1)); err != nil {
			t.Errorf("%s: B at its own history's source %d: %v", when, start-3, err)
		}
	}
	e.clock.add((floor - start) * testEpoch)
	check("same process")

	f2 := e.floorOf()
	e.restart()
	e.clock.add((f2 - e.signer.EpochAt(e.now())) * testEpoch)
	wantSlashSource(t, e.signMsg(pka, vote(start-3, f2+1)), "after a restart: A (no history) below the floor")
	if err := e.signMsg(pkb, vote(start-3, f2+1)); err != nil {
		t.Errorf("after a restart: B at its own history's source %d: %v", start-3, err)
	}
}

// SLBOUND-01: the source gate is set once, when the log starts. A validator
// imported later without vote history may have voted elsewhere since, with
// sources above that gate. Its import sets a source floor of its own at the
// import's clock epoch, kept in its sealed share record, so neither this
// process nor a restart signs it a vote that surrounds those votes, also
// after the log's gate has dropped.
func TestSLBOUND01LateImportGetsItsOwnSourceFloor(t *testing.T) {
	e := newTgtEnv(t, "dev", nil)
	gate := e.floorOf()
	ska, pka := newKey(t)
	if err := e.importSealed(pka, ska, 5, nil); err != nil {
		t.Fatal(err)
	}
	// The runner sits idle while B votes elsewhere, then B comes in
	// without its history.
	e.clock.add(20 * testEpoch)
	late := e.floorOf()
	skb, pkb := newKey(t)
	if err := e.importSealed(pkb, skb, 6, nil); err != nil {
		t.Fatal(err)
	}
	e.clock.add((late - e.signer.EpochAt(e.now())) * testEpoch)
	wantSlashSource(t, e.signMsg(pkb, vote(gate, late+1)), "same process: B at the log's gate, below its import")
	// A's vote at the gate puts the gate's floor into the log's source, so
	// a restart drops the gate.
	if err := e.signMsg(pka, vote(gate, late+1)); err != nil {
		t.Fatalf("A at the gate: %v", err)
	}
	e.clock.add(5 * testEpoch)
	e.restart()
	if _, on := e.marks.SourceGate(); on {
		t.Fatal("the gate is still on after the log's source reached it")
	}
	f2 := e.floorOf()
	e.clock.add((f2 - e.signer.EpochAt(e.now())) * testEpoch)
	wantSlashSource(t, e.signMsg(pkb, vote(gate, f2+1)), "after a restart: B below its import floor")
	if err := e.signMsg(pkb, vote(late, f2+1)); err != nil {
		t.Fatalf("after a restart: B at its import floor %d: %v", late, err)
	}
}
