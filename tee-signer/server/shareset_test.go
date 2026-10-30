//go:build !debugimport

package server

import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/lidofinance/tee-signer/signer-protocol"
)

// deleteShare removes pk's stored record, as a host can.
func (e *tgtEnv) deleteShare(pk backend.Pubkey) {
	e.store.mu.Lock()
	delete(e.store.m, shareKey(pk))
	e.store.mu.Unlock()
}

// putRaw puts a stored record back, as a host can.
func (e *tgtEnv) putRaw(pk backend.Pubkey, blob []byte) {
	e.store.mu.Lock()
	e.store.m[shareKey(pk)] = blob
	e.store.mu.Unlock()
}

// Replay: the host keeps the record of an earlier import of K with vote
// history. K leaves this runner, votes elsewhere and comes back without
// history (floor F2). The host puts the old record back: K must not load
// with that history.
func TestShareRecordReplayRefused(t *testing.T) {
	e := newTgtEnv(t, "dev", nil)
	start := e.signer.EpochAt(e.now())
	sk, pk := newKey(t)
	hist := &backend.Watermark{HasAttestation: true, SourceEpoch: start - 3, TargetEpoch: start - 2}
	if err := e.importSealed(pk, sk, 5, hist); err != nil {
		t.Fatal(err)
	}
	old, err := e.store.Get(shareKey(pk))
	if err != nil || !e.recordOf(pk).History {
		t.Fatalf("no record with history: %v", err)
	}
	// K leaves, votes elsewhere for 20 epochs, comes back without history.
	e.deleteShare(pk)
	e.restart()
	e.clock.add(20 * testEpoch)
	f2 := e.floorOf()
	if err := e.importSealed(pk, sk, 5, nil); err != nil {
		t.Fatal(err)
	}
	// The host replays the old record.
	e.putRaw(pk, old)
	e.restart()
	f3 := e.floorOf()
	e.clock.add((max(f2, f3) + 1 - e.signer.EpochAt(e.now())) * testEpoch)
	en := e.signer.EpochAt(e.now())
	wantSlashSource(t, e.signMsg(pk, vote(f2-1, en+1)), "the replayed record: a vote below the re-import's floor")
}

// promotedPair imports A without history and B with vote history: B's
// record is the last share write.
func promotedPair(t *testing.T, e *tgtEnv) (a, b backend.Pubkey, floor uint64) {
	t.Helper()
	floor = e.floorOf()
	start := e.signer.EpochAt(e.now())
	ska, pka := newKey(t)
	skb, pkb := newKey(t)
	if err := e.importSealed(pka, ska, 5, nil); err != nil {
		t.Fatal(err)
	}
	hist := &backend.Watermark{HasAttestation: true, SourceEpoch: start - 3, TargetEpoch: start - 2}
	if err := e.importSealed(pkb, skb, 6, hist); err != nil {
		t.Fatal(err)
	}
	e.clock.add((floor + 1 - e.signer.EpochAt(e.now())) * testEpoch)
	if !e.recordOf(pkb).History {
		t.Fatal("B has no history")
	}
	return pka, pkb, floor
}

// A restart right after a share write finds the newest log record's
// pending set (the write landed) and loads it as it is: B keeps its
// history, nothing is rewritten.
func TestShareSetPendingVouches(t *testing.T) {
	e := newTgtEnv(t, "dev", nil)
	pka, pkb, floor := promotedPair(t, e)
	// B's record sealed again is the last share write: no mark record
	// follows it, so the newest record keeps its pending root. (An import
	// writes a mark record after its share.)
	rb := e.recordOf(pkb)
	var sk [32]byte
	if err := e.srv.readShare(pkb, func(_ *shareRecord, sec *[32]byte) error { sk = *sec; return nil }); err != nil {
		t.Fatal(err)
	}
	rb.Secret = sk[:]
	blob, err := e.srv.sealRecord(rb)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.srv.putShare(pkb, blob); err != nil {
		t.Fatal(err)
	}
	puts := e.store.putsOf(shareKey(pka)) + e.store.putsOf(shareKey(pkb))
	recs := e.records()
	if sh := recs[len(recs)-1].Shares; sh == nil || sh.Pending == nil {
		t.Fatalf("the newest record's share set %+v, want a pending root", sh)
	}
	e.restart()
	if r := e.recordOf(pkb); !r.History {
		t.Fatal("B lost its history: the start did not take the pending set")
	}
	if r := e.recordOf(pka); r.History || r.SourceFloor != floor {
		t.Fatalf("A: history %t floor %d, want its import floor %d", r.History, r.SourceFloor, floor)
	}
	if n := e.store.putsOf(shareKey(pka)) + e.store.putsOf(shareKey(pkb)); n != puts {
		t.Fatalf("%d records rewritten at a start the log vouches for", n-puts)
	}
	// And again: the set is now the current one.
	e.restart()
	if !e.recordOf(pkb).History {
		t.Fatal("B lost its history at the second restart")
	}
}

// A write cut between the log record and the store write: the log vouches
// for the set before and after, the store holds the one before. The start
// loads it as it is: the key that was being imported is not there, and
// nothing is reset.
func TestShareSetCutWriteLoadsTheSetBefore(t *testing.T) {
	e := newTgtEnv(t, "dev", nil)
	pka, pkb, floor := promotedPair(t, e)
	skc, pkc := newKey(t)
	e.store.mu.Lock()
	e.store.failPut = func(k string) bool { return k == shareKey(pkc) }
	e.store.mu.Unlock()
	if err := e.importSealed(pkc, skc, 7, nil); err == nil {
		t.Fatal("an import whose store write failed succeeded")
	}
	e.store.mu.Lock()
	e.store.failPut = nil
	e.store.mu.Unlock()
	puts := e.store.putsOf(shareKey(pkb))
	e.restart()
	if r := e.recordOf(pka); r.History || r.SourceFloor != floor {
		t.Fatalf("A after the cut write: history %t floor %d", r.History, r.SourceFloor)
	}
	if !e.recordOf(pkb).History || e.store.putsOf(shareKey(pkb)) != puts {
		t.Fatal("B was reset after a cut write")
	}
	if _, err := e.signer.State(pkc); err == nil {
		t.Fatal("the key of the cut write loaded")
	}
}

// A record the host hid makes the set one the log does not vouch for:
// every key left loads without history and with a fresh floor.
func TestShareSetHiddenRecordResets(t *testing.T) {
	e := newTgtEnv(t, "dev", nil)
	pka, pkb, floor := promotedPair(t, e)
	blob, _ := e.store.Get(shareKey(pka))
	e.deleteShare(pka)
	e.restart()
	if r := e.recordOf(pkb); r.History || r.SourceFloor <= floor {
		t.Fatalf("B after a hidden record: history %t floor %d", r.History, r.SourceFloor)
	}
	// The record comes back: again not the vouched set.
	e.putRaw(pka, blob)
	e.restart()
	ra, rb := e.recordOf(pka), e.recordOf(pkb)
	if ra.History || ra.SourceFloor <= floor {
		t.Fatalf("A back: history %t floor %d", ra.History, ra.SourceFloor)
	}
	// The reset converges: a start with no change rewrites nothing.
	puts := e.store.putsOf(shareKey(pka)) + e.store.putsOf(shareKey(pkb))
	e.clock.add(3 * testEpoch)
	e.restart()
	if n := e.store.putsOf(shareKey(pka)) + e.store.putsOf(shareKey(pkb)); n != puts {
		t.Fatalf("%d records rewritten at a start after a reset", n-puts)
	}
	if e.recordOf(pka).SourceFloor != ra.SourceFloor || e.recordOf(pkb).SourceFloor != rb.SourceFloor {
		t.Fatal("the floors moved at a start after a reset")
	}
}

// A reset whose rewrite of one record fails leaves that record out of the
// set the log vouches for: the next start resets again and does not load
// the replayed history. The host hides A (a reset) and fails B's rewrite.
func TestResetRewriteFailureNotVouched(t *testing.T) {
	e := newTgtEnv(t, "dev", nil)
	pka, pkb, floor := promotedPair(t, e)
	e.deleteShare(pka)
	e.store.mu.Lock()
	e.store.failPut = func(k string) bool { return k == shareKey(pkb) }
	e.store.mu.Unlock()
	e.restart()
	e.store.mu.Lock()
	e.store.failPut = nil
	e.store.mu.Unlock()
	e.restart()
	if r := e.recordOf(pkb); r.History || r.SourceFloor <= floor {
		t.Fatalf("B after a reset whose rewrite failed: history %t floor %d", r.History, r.SourceFloor)
	}
	f := e.floorOf()
	e.clock.add((f + 1 - e.signer.EpochAt(e.now())) * testEpoch)
	en := e.signer.EpochAt(e.now())
	wantSlashSource(t, e.signMsg(pkb, vote(floor+1, en+1)), "B below the reset floor")
}

// A share write goes to the mark log first: with the log unwritable the
// store is not written.
func TestShareWriteLogBeforeStore(t *testing.T) {
	e := newTgtEnv(t, "dev", nil)
	sk, pk := newKey(t)
	if err := e.importSealed(pk, sk, 5, nil); err != nil {
		t.Fatal(err)
	}
	blob, err := e.store.Get(shareKey(pk))
	if err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() == 0 {
		t.Skip("the test makes the mark log unwritable with a directory mode, which root ignores")
	}
	puts := e.store.putsOf(shareKey(pk))
	marks := filepath.Join(e.dir, "marks")
	setMode := func(m os.FileMode) {
		filepath.WalkDir(marks, func(p string, d fs.DirEntry, err error) error { //nolint:errcheck // test cleanup
			if err == nil && d.IsDir() {
				os.Chmod(p, m) //nolint:errcheck // checked by the write below
			}
			return nil
		})
	}
	setMode(0o500)
	t.Cleanup(func() { setMode(0o700) })
	if err := e.srv.putShare(pk, blob); err == nil {
		t.Fatal("a share write with the mark log unwritable succeeded")
	}
	if e.store.putsOf(shareKey(pk)) != puts {
		t.Fatal("the store was written before the mark log")
	}
}

// rawRecordOf reads pk's stored record without the runner's hash check.
func (e *tgtEnv) rawRecordOf(pk backend.Pubkey) shareRecord {
	e.t.Helper()
	blob, err := e.store.Get(shareKey(pk))
	if err != nil {
		e.t.Fatal(err)
	}
	plain, err := e.sealer.Unseal(blob, e.srv.shareAAD(pk))
	if err != nil {
		e.t.Fatal(err)
	}
	var rec shareRecord
	if err := json.Unmarshal(plain, &rec); err != nil {
		e.t.Fatal(err)
	}
	return rec
}

// A stored blob that does not unseal (sealed under another setup or log,
// corrupt, or not a record) is no part of the share set: the start that
// first sees it does not reset for it, and later starts rewrite nothing.
func TestUnreadableRecordDoesNotReset(t *testing.T) {
	e := newTgtEnv(t, "dev", nil)
	e.looseLoad = true
	pka, pkb, _ := promotedPair(t, e)
	_, pkc := newKey(t)
	e.putRaw(pkc, []byte("not a sealed record"))
	puts := e.store.putsOf(shareKey(pka)) + e.store.putsOf(shareKey(pkb))
	fa, fb := e.rawRecordOf(pka).SourceFloor, e.rawRecordOf(pkb).SourceFloor
	for i := range 3 {
		e.clock.add(3 * testEpoch)
		e.restart()
		n := e.store.putsOf(shareKey(pka)) + e.store.putsOf(shareKey(pkb))
		if n != puts || e.rawRecordOf(pka).SourceFloor != fa || e.rawRecordOf(pkb).SourceFloor != fb {
			t.Fatalf("start %d with an unreadable blob stored: %d records rewritten, floors %d %d", i+1, n-puts,
				e.rawRecordOf(pka).SourceFloor, e.rawRecordOf(pkb).SourceFloor)
		}
	}
	if !e.rawRecordOf(pkb).History {
		t.Fatal("B lost its history for an unreadable blob of another key")
	}
}

// A record whose write-back the store refuses at every start: every start
// resets, the key loads with the fresh floor, and the runner refuses to
// read the stale record (no promotion, no handover from it).
func TestRewriteAlwaysFailsKeepsResetting(t *testing.T) {
	e := newTgtEnv(t, "dev", nil)
	pka, pkb, floor := promotedPair(t, e)
	e.deleteShare(pka)
	e.store.mu.Lock()
	e.store.failPut = func(k string) bool { return k == shareKey(pkb) }
	e.store.mu.Unlock()
	for i := range 3 {
		e.clock.add(3 * testEpoch)
		e.restart()
		if !e.rawRecordOf(pkb).History {
			t.Fatal("B's record was written back")
		}
		if f, on := e.hooks.SourceFloor(pkb); !on || f <= floor {
			t.Fatalf("start %d: B loaded with floor %d (on %t)", i+1, f, on)
		}
	}
	if err := e.srv.readShare(pkb, func(*shareRecord, *[32]byte) error { return nil }); err == nil {
		t.Fatal("the stale record of B read without refusal")
	}
}
