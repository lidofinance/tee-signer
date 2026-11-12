//go:build !debugimport

package server

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/lidofinance/tee-signer/signer-core/core"
	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/tee-signer/state"
)

// wantFloor fails unless err is a floor refusal (StatusFloor) whose detail
// starts with "floor epoch f (which floor)".
func wantFloor(t *testing.T, err error, f uint64, which, what string) {
	t.Helper()
	wantFloorCode(t, err, backend.StatusFloor, f, which, what)
}

// wantFloorCode fails unless err is a refusal with code (StatusFloor or
// StatusFloorUnproven) whose detail starts with "floor epoch f (which
// floor)", or with "floor epoch " when which is "".
func wantFloorCode(t *testing.T, err error, code backend.Status, f uint64, which, what string) {
	t.Helper()
	var r *backend.RefusedError
	want := "floor epoch "
	if which != "" {
		want = fmt.Sprintf("floor epoch %d (%s floor): ", f, which)
	}
	if !errors.As(err, &r) || r.Code != code {
		t.Errorf("%s: %v, want %v", what, err, code)
	} else if !strings.HasPrefix(r.Detail, want) {
		t.Errorf("%s: detail %q, want it to start with %q", what, r.Detail, want)
	}
}

// wantConflict fails unless err is a slashing refusal, not a floor one,
// whose detail names no floor: no "floor epoch", no
// "(at or below W floor epoch N)" suffix, no "source floor".
func wantConflict(t *testing.T, err error, what string) {
	t.Helper()
	var r *backend.RefusedError
	switch {
	case !errors.As(err, &r) || !r.Code.IsSlashing():
		t.Errorf("%s: %v, want a slashing refusal", what, err)
	case strings.Contains(r.Detail, "floor epoch") || strings.Contains(r.Detail, "(at or below ") ||
		strings.Contains(r.Detail, "source floor"):
		t.Errorf("%s: detail %q names a floor", what, r.Detail)
	}
}

// The core reads the clock for its restart floor when it loads a key. An
// epoch that starts between the import floor's clock reading and the
// core's gives the core a floor one epoch higher; a message that floor
// alone refuses is still a floor refusal, and above it the key signs.
func TestFloorStatusEpochStartsDuringImport(t *testing.T) {
	e := newTgtEnv(t, "dev", nil)
	f := e.floorOf()
	// A first key: the device mark and its floor come in with it.
	skA, pkA := newKey(t)
	if err := e.importSealed(pkA, skA, 4, nil); err != nil {
		t.Fatal(err)
	}
	sk, pk := newKey(t)
	// The share write comes after the import floor and before the core's
	// load: the next epoch starts there.
	e.store.mu.Lock()
	e.store.failPut = func(string) bool { e.clock.add(testEpoch); return false }
	e.store.mu.Unlock()
	err := e.importSealed(pk, sk, 5, nil)
	e.store.mu.Lock()
	e.store.failPut = nil
	e.store.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	e.clock.add((f + 1 - e.signer.EpochAt(e.now())) * testEpoch) // the slots of f+1 have started
	wantFloor(t, e.signMsg(pk, vote(f, f+1)), f+1, "import", "a vote at the core's floor")
	wantFloor(t, e.signMsg(pk, &backend.BeaconBlockHeader{Slot: (f + 1) * 8, ProposerIndex: 5, BodyRoot: backend.Root{0xb0}}),
		f+1, "import", "a block at the core's floor")
	e.clock.add(testEpoch)
	if err := e.signMsg(pk, vote(f+1, f+2)); err != nil {
		t.Fatalf("a vote above the core's floor: %v", err)
	}
}

// After an import without history only the floors refuse the key's
// messages at or below them. Once the key votes, a vote that surrounds
// that vote is a slashing refusal, though the source floor refuses it too.
func TestFloorStatusAfterImport(t *testing.T) {
	e := newTgtEnv(t, "dev", nil)
	now, f := e.signer.EpochAt(e.now()), e.floorOf()
	sk, pk := newKey(t)
	if err := e.importSealed(pk, sk, 5, nil); err != nil {
		t.Fatal(err)
	}
	wantFloor(t, e.signMsg(pk, vote(now-1, now)), f, "source", "a vote below the source floor")
	wantFloor(t, e.signMsg(pk, &backend.BeaconBlockHeader{Slot: now * 8, ProposerIndex: 5, BodyRoot: backend.Root{0xb0}}),
		f, "import", "a block below the import floor")
	e.clock.add((f - now) * testEpoch) // the slots of f have started
	wantFloor(t, e.signMsg(pk, vote(f, f)), f, "import", "a vote at the import floor")
	e.clock.add(testEpoch)
	if err := e.signMsg(pk, vote(f, f+1)); err != nil {
		t.Fatalf("a vote above the floor: %v", err)
	}
	// Above the floor a refusal is the core's, as before FLOOR.
	double := vote(f, f+1)
	double.BeaconBlockRoot = backend.Root{0xdd}
	wantConflict(t, e.signMsg(pk, double), "a double vote above the floor")
	e.clock.add(testEpoch)
	// The source floor refuses it before the core, with the code and detail
	// the core gives a source refusal.
	err := e.signMsg(pk, vote(f-1, f+2))
	wantConflict(t, err, "a vote below the source floor that surrounds the key's vote")
	if r := (*backend.RefusedError)(nil); errors.As(err, &r) && (r.Code != backend.StatusSlashSource || r.Detail != "attestation") {
		t.Errorf("source floor conflict %v, want %v with detail %q", err, backend.StatusSlashSource, "attestation")
	}
	wantConflict(t, e.signMsg(pk, vote(f, f)), "a vote at the floor after the key voted")
}

// A key imported with history: a message its history refuses keeps its
// slashing code at or below the import floor; one only the floor refuses
// is a floor refusal. After a restart the runner holds the history only in
// the mark log's mark, one for all keys: the same conflict is then
// FLOOR_UNPROVEN, still refused.
func TestFloorStatusKeepsHistoryConflicts(t *testing.T) {
	e := newTgtEnv(t, "dev", nil)
	now, f := e.signer.EpochAt(e.now()), e.floorOf()
	hist := &backend.Watermark{HasAttestation: true, SourceEpoch: now - 3, TargetEpoch: now - 2, HasBlock: true, BlockSlot: (now - 2) * 8}
	sk, pk := newKey(t)
	if err := e.importSealed(pk, sk, 5, hist); err != nil {
		t.Fatal(err)
	}
	double := vote(now-3, now-2)
	double.BeaconBlockRoot = backend.Root{0xdd}
	wantConflict(t, e.signMsg(pk, double), "a double vote at the history's target")
	wantConflict(t, e.signMsg(pk, vote(now-4, now-1)), "a vote that surrounds the history")
	err := e.signMsg(pk, &backend.BeaconBlockHeader{Slot: (now - 2) * 8, ProposerIndex: 5, BodyRoot: backend.Root{0xb1}})
	wantConflict(t, err, "a second block at the history's slot")
	// The core's detail as it is, with nothing about the floor added.
	if r := (*backend.RefusedError)(nil); errors.As(err, &r) && r.Detail != "block" {
		t.Errorf("block refusal detail %q, want %q", r.Detail, "block")
	}
	wantFloor(t, e.signMsg(pk, vote(now-2, now)), f, "import", "a vote above the history, below the floor")
	wantFloor(t, e.signMsg(pk, &backend.BeaconBlockHeader{Slot: now * 8, ProposerIndex: 5, BodyRoot: backend.Root{0xb2}}),
		f, "import", "a block above the history, below the floor")
	e.restart()
	f2 := e.floorOf()
	if rec := e.hooks.Recorded(pk); rec.HasAttestation || rec.HasBlock {
		t.Fatalf("own record %+v after the restart, want none (no persisted marks)", rec)
	}
	wantFloorCode(t, e.signMsg(pk, double), backend.StatusFloorUnproven, 0, "", "after a restart: a double vote at the history's target")
	wantFloorCode(t, e.signMsg(pk, &backend.BeaconBlockHeader{Slot: (now - 2) * 8, ProposerIndex: 5, BodyRoot: backend.Root{0xb1}}),
		backend.StatusFloorUnproven, f2, "restart", "after a restart: a second block at the history's slot")
}

// After a restart with the mark log the runner holds one mark for all
// keys and no vote of a key's own. A vote the mark refuses is
// FLOOR_UNPROVEN, both for the key that signed that target (its double
// vote) and for a key that did not vote then; a vote above the mark, below
// the floor, is FLOOR. All stay refused.
func TestFloorStatusAfterRestart(t *testing.T) {
	e := newTgtEnv(t, "dev", nil)
	now, f := e.signer.EpochAt(e.now()), e.floorOf()
	sk, pk := newKey(t)
	if err := e.importSealed(pk, sk, 5, nil); err != nil {
		t.Fatal(err)
	}
	skB, pkB := newKey(t)
	if err := e.importSealed(pkB, skB, 6, nil); err != nil {
		t.Fatal(err)
	}
	e.clock.add((f + 1 - now) * testEpoch)
	if err := e.signMsg(pk, vote(f, f+1)); err != nil {
		t.Fatal(err)
	}
	e.restart()
	f2 := e.floorOf()
	rec, found := e.hooks.Unproven(pkB)
	if !found || !rec.HasAttestation || rec.TargetEpoch < f+1 || rec.TargetEpoch >= f2 {
		t.Fatalf("mark log mark %+v (found %v) after the restart, want a target from %d to below the floor %d", rec, found, f+1, f2)
	}
	for _, k := range []backend.Pubkey{pk, pkB} {
		if own := e.hooks.Recorded(k); own.HasAttestation {
			t.Fatalf("own record %+v after the restart, want none", own)
		}
	}
	double := vote(f, f+1)
	double.BeaconBlockRoot = backend.Root{0xdd}
	wantFloorCode(t, e.signMsg(pk, double), backend.StatusFloorUnproven, 0, "",
		"after a restart: a double vote of the key's own vote, known only to the mark log")
	wantFloorCode(t, e.signMsg(pkB, vote(f, f+1)), backend.StatusFloorUnproven, 0, "",
		"after a restart: another key's vote for a target the mark log holds")
	e.clock.add((rec.TargetEpoch + 1 - e.signer.EpochAt(e.now())) * testEpoch)
	wantFloor(t, e.signMsg(pk, vote(rec.SourceEpoch, rec.TargetEpoch+1)), f2, "restart",
		"after a restart: a vote above the log's mark, below the restart floor")
}

// A vote the core signed while its SIGN has not returned yet is no vote
// since the load for the server, but the server counts it as in the core:
// a vote that surrounds it is no floor refusal.
func TestFloorStatusVoteInTheCore(t *testing.T) {
	e := newTgtEnv(t, "dev", nil)
	now, f := e.signer.EpochAt(e.now()), e.floorOf()
	sk, pk := newKey(t)
	if err := e.importSealed(pk, sk, 5, nil); err != nil {
		t.Fatal(err)
	}
	e.clock.add((f + 2 - now) * testEpoch)
	// What sign does before the core takes the vote; its deferred count
	// down has not run yet.
	e.srv.blockedMu.Lock()
	if e.srv.voting == nil {
		e.srv.voting, e.srv.voted = map[backend.Pubkey]int{}, map[backend.Pubkey]bool{}
	}
	e.srv.voting[pk]++
	e.srv.blockedMu.Unlock()
	in := vote(f, f+2)
	cfg := e.signer.Config()
	d, err := cfg.MessageDomain(in)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.signer.SignDetailed(backend.SignRequest{Pubkey: pk, Message: in, Domain: d}); err != nil {
		t.Fatalf("the vote in the core: %v", err)
	}
	e.clock.add(testEpoch)
	wantConflict(t, e.signMsg(pk, vote(f-1, f+3)), "a vote below the source floor that surrounds the vote in the core")
}

// With persisted marks (no mark log) the stored mark is the core's
// commit-ahead mark: it has headroom above what the key signed, and any
// earlier floor. It proves no message: after a quick restart a double vote
// of a signed vote and an honest vote the key never signed, both under
// the stored mark, are FLOOR_UNPROVEN, refused; not a slashing code.
func TestFloorStatusPersistedRecord(t *testing.T) {
	e := newTgtEnv(t, "dev", nil)
	cfg := baseConfig(e.setup)
	sk, pk := newKey(t)
	start := func() *Server {
		t.Helper()
		h, err := state.New(cfg, state.Mode{Floor: true, Persist: true, FloorMargin: state.DefaultFloorMargin(cfg)}, e.clock, e.store, e.sealer, quiet)
		if err != nil {
			t.Fatal(err)
		}
		c, err := core.NewSigner(cfg, 4, 0, h)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(c.Close)
		h.UseClock(c.EpochAt)
		if _, err := c.AddValidator(pk, sk, 5, nil); err != nil {
			t.Fatal(err)
		}
		return &Server{Signer: c, Hooks: h, Log: quiet}
	}
	sign := func(s *Server, m backend.Message) error {
		c := s.Signer.Config()
		d, err := c.MessageDomain(m)
		if err != nil {
			t.Fatal(err)
		}
		_, err = s.sign(backend.SignRequest{Pubkey: pk, Message: m, Domain: d})
		return err
	}
	now, f := e.signer.EpochAt(e.now()), e.floorOf()
	s := start()
	e.clock.add((f + 1 - now) * testEpoch)
	if err := sign(s, vote(f, f+1)); err != nil {
		t.Fatalf("a vote above the floor: %v", err)
	}
	s.Signer.Close()
	s = start()
	if rec := s.Hooks.Recorded(pk); rec.HasAttestation {
		t.Errorf("recorded %+v after the restart, want nothing proven", rec)
	}
	stored, found := s.Hooks.Unproven(pk)
	if !found || !stored.HasAttestation || stored.TargetEpoch < f+2 {
		t.Fatalf("stored mark %+v (found %v), want a target from %d (headroom above the vote at %d)", stored, found, f+2, f+1)
	}
	double := vote(f, f+1)
	double.BeaconBlockRoot = backend.Root{0xdd}
	wantFloorCode(t, sign(s, double), backend.StatusFloorUnproven, 0, "", "after a restart: a double vote of a stored vote")
	// The slots of those votes have started; the restart floor still
	// refuses them.
	e.clock.add((stored.TargetEpoch - s.Signer.EpochAt(e.now())) * testEpoch)
	for tg := f + 2; tg <= stored.TargetEpoch; tg++ {
		wantFloorCode(t, sign(s, vote(tg-1, tg)), backend.StatusFloorUnproven, 0, "",
			fmt.Sprintf("after a restart: honest vote (%d, %d) the key never signed, under the stored mark", tg-1, tg))
	}
}
