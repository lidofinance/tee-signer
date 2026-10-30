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

// HSH-01 review (replay): the host keeps the record of an earlier import
// of K that had earned history. K leaves this runner, votes elsewhere and
// comes back without history (floor F2). The host puts the old record
// back: K must not load with that history.
func TestShareRecordReplayRefused(t *testing.T) {
	e := newTgtEnv(t, "dev", nil)
	floor := e.floorOf()
	sk, pk := newKey(t)
	if err := e.importSealed(pk, sk, 5, nil); err != nil {
		t.Fatal(err)
	}
	e.clock.add((floor + 1 - e.signer.EpochAt(e.now())) * testEpoch)
	if err := e.signMsg(pk, vote(floor, floor+1)); err != nil {
		t.Fatal(err)
	}
	e.srv.promotions.Wait()
	old, err := e.store.Get(shareKey(pk))
	if err != nil || !e.recordOf(pk).History {
		t.Fatalf("no promoted record: %v", err)
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

// promotedPair imports A and B without history and lets B earn history:
// B's record is the last share write.
func promotedPair(t *testing.T, e *tgtEnv) (a, b backend.Pubkey, floor uint64) {
	t.Helper()
	floor = e.floorOf()
	ska, pka := newKey(t)
	skb, pkb := newKey(t)
	for i, k := range []struct {
		sk [32]byte
		pk backend.Pubkey
	}{{ska, pka}, {skb, pkb}} {
		if err := e.importSealed(k.pk, k.sk, uint64(5+i), nil); err != nil {
			t.Fatal(err)
		}
	}
	e.clock.add((floor + 1 - e.signer.EpochAt(e.now())) * testEpoch)
	if err := e.signMsg(pkb, vote(floor, floor+1)); err != nil {
		t.Fatal(err)
	}
	e.srv.promotions.Wait()
	if !e.recordOf(pkb).History {
		t.Fatal("B did not earn history")
	}
	return pka, pkb, floor
}

// A restart right after a share write finds the newest log record's
// pending set (the write landed) and loads it as it is: B keeps its
// history, nothing is rewritten.
func TestShareSetPendingVouches(t *testing.T) {
	e := newTgtEnv(t, "dev", nil)
	pka, pkb, floor := promotedPair(t, e)
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
// loads it as it is, so the key that was being promoted has no history,
// and nothing is reset.
func TestShareSetCutWriteLoadsTheSetBefore(t *testing.T) {
	e := newTgtEnv(t, "dev", nil)
	pka, pkb, floor := promotedPair(t, e)
	e.store.mu.Lock()
	e.store.failPut = func(k string) bool { return k == shareKey(pka) }
	e.store.mu.Unlock()
	if err := e.signMsg(pka, vote(floor, floor+2)); err != nil {
		t.Fatal(err)
	}
	e.srv.promotions.Wait()
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

// At most maxPromotions promotion writes run at once; a vote over it
// leaves its key for a later vote.
func TestPromoteInFlightBound(t *testing.T) {
	e := newTgtEnv(t, "dev", nil)
	floor := e.floorOf()
	var pks []backend.Pubkey
	for i := range maxPromotions + 1 {
		sk, pk := newKey(t)
		if err := e.importSealed(pk, sk, uint64(20+i), nil); err != nil {
			t.Fatal(err)
		}
		pks = append(pks, pk)
	}
	e.clock.add((floor + 1 - e.signer.EpochAt(e.now())) * testEpoch)
	release := make(chan struct{})
	e.store.mu.Lock()
	e.store.failPut = func(string) bool { <-release; return false }
	e.store.mu.Unlock()
	for _, pk := range pks {
		if err := e.signMsg(pk, vote(floor, floor+1)); err != nil {
			t.Fatal(err)
		}
	}
	close(release)
	e.srv.promotions.Wait()
	e.store.mu.Lock()
	e.store.failPut = nil
	e.store.mu.Unlock()
	n := 0
	for _, pk := range pks {
		if e.recordOf(pk).History {
			n++
		}
	}
	if n != maxPromotions {
		t.Fatalf("%d keys promoted with %d votes at once, want %d", n, len(pks), maxPromotions)
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
