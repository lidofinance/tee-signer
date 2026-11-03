//go:build !debugimport

package server

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
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

// recordOf is pk's stored share record on e, read as the host sees it.
func (e *tgtEnv) recordOf(pk backend.Pubkey) shareRecord {
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

// secretOf is pk's secret share from its stored record.
func (e *tgtEnv) secretOf(pk backend.Pubkey) (sk [32]byte) {
	copy(sk[:], e.recordOf(pk).Secret)
	return sk
}

// setMarksMode sets the mode of the mark log's directories; 0o500 makes
// every log write fail.
func (e *tgtEnv) setMarksMode(m os.FileMode) {
	filepath.WalkDir(filepath.Join(e.dir, "marks"), func(p string, d fs.DirEntry, err error) error { //nolint:errcheck // test helper
		if err == nil && d.IsDir() {
			os.Chmod(p, m) //nolint:errcheck // checked by the test
		}
		return nil
	})
}

// historyPair imports A without vote history and then B with it, and
// moves the clock past A's source floor: B's record is the last share
// write, and a start that resets gives B a floor above A's.
func historyPair(t *testing.T, e *tgtEnv) (a, b backend.Pubkey, floor uint64) {
	t.Helper()
	floor = e.floorOf()
	start := e.signer.EpochAt(e.now())
	ska, pka := newKey(t)
	if err := e.importSealed(pka, ska, 5, nil); err != nil {
		t.Fatal(err)
	}
	skb, pkb := newKey(t)
	hist := &backend.Watermark{HasAttestation: true, SourceEpoch: start - 3, TargetEpoch: start - 2}
	if err := e.importSealed(pkb, skb, 6, hist); err != nil {
		t.Fatal(err)
	}
	if !e.recordOf(pkb).History || e.recordOf(pka).History {
		t.Fatal("B has no history, or A has")
	}
	e.clock.add((floor + 1 - e.signer.EpochAt(e.now())) * testEpoch)
	return pka, pkb, floor
}

// The host keeps the record of an earlier import of K that had history.
// K leaves this runner, votes elsewhere and comes back without history.
// The host puts the old record back: K must not load with that history.
func TestShareRecordReplayRefused(t *testing.T) {
	e := newTgtEnv(t, "dev", nil)
	_, pk, _ := historyPair(t, e)
	sk := e.secretOf(pk)
	old, err := e.store.Get(shareKey(pk))
	if err != nil {
		t.Fatal(err)
	}
	// K leaves, votes elsewhere for 20 epochs, comes back without history.
	e.deleteShare(pk)
	e.restart()
	e.clock.add(20 * testEpoch)
	f2 := e.floorOf()
	if err := e.importSealed(pk, sk, 6, nil); err != nil {
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

// A restart right after a share write finds a set the newest log record
// vouches for and loads it as it is: B keeps its history, A its floor, and
// nothing is rewritten.
func TestShareSetLoadsTheVouchedSet(t *testing.T) {
	e := newTgtEnv(t, "dev", nil)
	pka, pkb, floor := historyPair(t, e)
	puts := e.store.putsOf(shareKey(pka)) + e.store.putsOf(shareKey(pkb))
	recs := e.records()
	if recs[len(recs)-1].Shares == nil {
		t.Fatal("the newest record carries no share set")
	}
	for range 2 {
		e.restart()
		if !e.recordOf(pkb).History {
			t.Fatal("B lost its history at a start the log vouches for")
		}
		if r := e.recordOf(pka); r.History || r.SourceFloor != floor {
			t.Fatalf("A: history %t floor %d, want its import floor %d", r.History, r.SourceFloor, floor)
		}
		if n := e.store.putsOf(shareKey(pka)) + e.store.putsOf(shareKey(pkb)); n != puts {
			t.Fatalf("%d records rewritten at a start the log vouches for", n-puts)
		}
	}
}

// A write cut between the log record and the store write: the log vouches
// for the set before and after, the store holds the one before. The start
// loads it as it is, and nothing is reset.
func TestShareSetCutWriteLoadsTheSetBefore(t *testing.T) {
	e := newTgtEnv(t, "dev", nil)
	pka, pkb, floor := historyPair(t, e)
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
	if sh := e.records()[len(e.records())-1].Shares; sh == nil || sh.Pending == nil {
		t.Fatalf("the newest record's share set %+v, want the cut write's pending root", sh)
	}
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
	pka, pkb, floor := historyPair(t, e)
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
	pka, pkb, floor := historyPair(t, e)
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
	if os.Geteuid() == 0 {
		t.Skip("the test makes the mark log unwritable with a directory mode, which root ignores")
	}
	e := newTgtEnv(t, "dev", nil)
	sk, pk := newKey(t)
	if err := e.importSealed(pk, sk, 5, nil); err != nil {
		t.Fatal(err)
	}
	blob, err := e.store.Get(shareKey(pk))
	if err != nil {
		t.Fatal(err)
	}
	puts := e.store.putsOf(shareKey(pk))
	e.setMarksMode(0o500)
	t.Cleanup(func() { e.setMarksMode(0o700) })
	if err := e.srv.putShare(pk, blob); err == nil {
		t.Fatal("a share write with the mark log unwritable succeeded")
	}
	if e.store.putsOf(shareKey(pk)) != puts {
		t.Fatal("the store was written before the mark log")
	}
}

// A stored blob that does not unseal (sealed under another setup or log,
// corrupt, or not a record) is no part of the share set: the start that
// first sees it does not reset for it, and later starts rewrite nothing.
func TestUnreadableRecordDoesNotReset(t *testing.T) {
	e := newTgtEnv(t, "dev", nil)
	e.looseLoad = true
	pka, pkb, _ := historyPair(t, e)
	_, pkc := newKey(t)
	e.putRaw(pkc, []byte("not a sealed record"))
	puts := e.store.putsOf(shareKey(pka)) + e.store.putsOf(shareKey(pkb))
	fa, fb := e.recordOf(pka).SourceFloor, e.recordOf(pkb).SourceFloor
	for i := range 3 {
		e.clock.add(3 * testEpoch)
		e.restart()
		n := e.store.putsOf(shareKey(pka)) + e.store.putsOf(shareKey(pkb))
		if n != puts || e.recordOf(pka).SourceFloor != fa || e.recordOf(pkb).SourceFloor != fb {
			t.Fatalf("start %d with an unreadable blob stored: %d records rewritten, floors %d %d", i+1, n-puts,
				e.recordOf(pka).SourceFloor, e.recordOf(pkb).SourceFloor)
		}
	}
	if !e.recordOf(pkb).History {
		t.Fatal("B lost its history for an unreadable blob of another key")
	}
}

// A record whose write-back the store refuses at every start: every start
// resets, and the key loads with the fresh floor.
func TestRewriteAlwaysFailsKeepsResetting(t *testing.T) {
	e := newTgtEnv(t, "dev", nil)
	pka, pkb, floor := historyPair(t, e)
	e.deleteShare(pka)
	e.store.mu.Lock()
	e.store.failPut = func(k string) bool { return k == shareKey(pkb) }
	e.store.mu.Unlock()
	for i := range 3 {
		e.clock.add(3 * testEpoch)
		e.restart()
		if !e.recordOf(pkb).History {
			t.Fatal("B's record was written back")
		}
		if f, on := e.hooks.SourceFloor(pkb); !on || f <= floor {
			t.Fatalf("start %d: B loaded with floor %d (on %t)", i+1, f, on)
		}
	}
}

// A share write that did not reach the store leaves its set out of the
// commitment the next log record carries. The host kept the blob and
// stores it after that record: the start finds a set the log does not
// vouch for and resets, so B loses its history.
func TestShareWriteNotLandedNotVouched(t *testing.T) {
	e := newTgtEnv(t, "dev", nil)
	_, pkb, _ := historyPair(t, e)
	skc, pkc := newKey(t)
	e.store.mu.Lock()
	e.store.failPut = func(k string) bool { return k == shareKey(pkc) }
	e.store.mu.Unlock()
	if err := e.importSealed(pkc, skc, 7, nil); err == nil {
		t.Fatal("an import whose store write failed succeeded")
	}
	e.store.mu.Lock()
	e.store.failPut = nil
	blob := e.store.dropped[shareKey(pkc)]
	e.store.mu.Unlock()
	if blob == nil {
		t.Fatal("the test store kept no blob")
	}
	n := len(e.records())
	e.clock.add(4 * testEpoch)
	en := e.signer.EpochAt(e.now())
	if err := e.signMsg(pkb, vote(en-1, en)); err != nil {
		t.Fatal(err)
	}
	recs := e.records()
	if len(recs) == n {
		t.Fatal("the vote wrote no log record")
	}
	if sh := recs[len(recs)-1].Shares; sh == nil || sh.Pending != nil {
		t.Fatalf("the log record after a failed write carries share set %+v, want no pending root", sh)
	}
	e.putRaw(pkc, blob)
	e.restart()
	if e.recordOf(pkb).History {
		t.Fatal("B kept its history: the log vouched for the set with the record that was never written")
	}
}

// A share write whose store reply was lost but which landed: the runner
// reads it back and keeps the set after, so the import stands and the
// next start finds the stored set vouched, with no reset.
func TestShareWriteLostReplyLanded(t *testing.T) {
	e := newTgtEnv(t, "dev", nil)
	pka, pkb, _ := historyPair(t, e)
	skc, pkc := newKey(t)
	e.store.mu.Lock()
	e.store.landPut = func(k string) bool { return k == shareKey(pkc) }
	e.store.mu.Unlock()
	if err := e.importSealed(pkc, skc, 7, nil); err != nil {
		t.Fatalf("an import whose write landed with its reply lost: %v", err)
	}
	e.store.mu.Lock()
	e.store.landPut = nil
	e.store.mu.Unlock()
	skd, pkd := newKey(t)
	if err := e.importSealed(pkd, skd, 8, nil); err != nil {
		t.Fatal(err)
	}
	puts := e.store.putsOf(shareKey(pka)) + e.store.putsOf(shareKey(pkb))
	e.restart()
	if n := e.store.putsOf(shareKey(pka)) + e.store.putsOf(shareKey(pkb)); n != puts {
		t.Fatalf("%d records rewritten: the start reset after a write whose reply was lost", n-puts)
	}
	if !e.recordOf(pkb).History {
		t.Fatal("B lost its history")
	}
}

// A start that resets but cannot write the log record that vouches for
// the rewritten records loads no key and rewrites nothing: the log still
// vouches for the old set, so a key that loaded now could later load
// again from a replayed old record, with its history and no floor.
func TestResetLogWriteFailsLoadsNoKey(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("the test makes the mark log unwritable with a directory mode, which root ignores")
	}
	e := newTgtEnv(t, "dev", nil)
	e.looseLoad = true
	pka, pkb, _ := historyPair(t, e)
	e.deleteShare(pkb) // the start resets
	puts := e.store.putsOf(shareKey(pka))
	e.beforeLoad = func() { e.setMarksMode(0o500) }
	e.afterLoad = func() { e.setMarksMode(0o700) }
	t.Cleanup(func() { e.setMarksMode(0o700) })
	e.restart()
	e.beforeLoad, e.afterLoad = nil, nil
	if n := len(e.signer.Keys()); n != 0 || e.loadErr == nil {
		t.Fatalf("a reset whose log record failed: %d keys loaded, err %v", n, e.loadErr)
	}
	if e.store.putsOf(shareKey(pka)) != puts {
		t.Fatal("a record was rewritten before the log vouched for it")
	}
}

// B's record (with history) is stored and vouched for but B does not load
// at a start that resets without a clock. B is imported again without
// history and that store write fails: the next start must not load the
// old record with its history.
func TestFailedReimportDoesNotVouchOldRecord(t *testing.T) {
	e := newTgtEnv(t, "dev", nil)
	e.looseLoad = true
	pka, pkb, floor := historyPair(t, e)
	skb := e.secretOf(pkb)
	a, _ := e.store.Get(shareKey(pka))
	e.deleteShare(pka) // the start resets, and the reset needs the clock
	e.beforeLoad = func() { e.clock.set(func(c *fakeClock) { c.err = errors.New("no clock") }) }
	e.afterLoad = func() { e.clock.set(func(c *fakeClock) { c.err = nil }) }
	e.restart()
	e.beforeLoad, e.afterLoad = nil, nil
	if n := len(e.signer.Keys()); n != 0 {
		t.Fatalf("%d keys loaded with no clock", n)
	}
	e.putRaw(pka, a)
	e.clock.add(20 * testEpoch) // B votes elsewhere
	f2 := e.floorOf()
	e.store.mu.Lock()
	e.store.failPut = func(k string) bool { return k == shareKey(pkb) }
	e.store.mu.Unlock()
	if err := e.importSealed(pkb, skb, 6, nil); err == nil {
		t.Fatal("an import whose store write failed succeeded")
	}
	e.store.mu.Lock()
	e.store.failPut = nil
	e.store.mu.Unlock()
	e.restart()
	f := e.floorOf()
	e.clock.add((f + 1 - e.signer.EpochAt(e.now())) * testEpoch)
	en := e.signer.EpochAt(e.now())
	wantSlashSource(t, e.signMsg(pkb, vote(floor+1, en+1)), "B below its import floor "+strconv.FormatUint(f2, 10))
}
