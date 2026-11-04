//go:build !debugimport

package server

import (
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
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

// wantNoLoad checks that a start loaded no key because the stored records
// are not the set the mark log vouches for, and that the error and HEALTH
// name each of pks.
func wantNoLoad(e *tgtEnv, pks ...backend.Pubkey) {
	e.t.Helper()
	if n := len(e.signer.Keys()); n != 0 || e.loadErr == nil || !strings.Contains(e.loadErr.Error(), "not the set the mark log vouches for") {
		e.t.Fatalf("%d keys loaded, err %v", n, e.loadErr)
	}
	h, err := e.srv.health()
	if err != nil || h.Ready || !strings.Contains(h.LoadFailed, "not the set the mark log vouches for") {
		e.t.Fatalf("health: %+v %v", h, err)
	}
	for _, pk := range pks {
		if !strings.Contains(e.loadErr.Error(), shareKey(pk)) || !strings.Contains(h.LoadFailed, shareKey(pk)) {
			e.t.Fatalf("%s not named: %v", shareKey(pk), e.loadErr)
		}
	}
}

// The host keeps the record of an earlier import of K that had history.
// The operator removes every share, and K comes back without history. The
// host puts the old record back: no key loads.
func TestShareRecordReplayRefused(t *testing.T) {
	e := newTgtEnv(t, "dev", nil)
	e.looseLoad = true
	pka, pk, _ := historyPair(t, e)
	sk := e.secretOf(pk)
	old, err := e.store.Get(shareKey(pk))
	if err != nil {
		t.Fatal(err)
	}
	e.deleteShare(pka)
	e.deleteShare(pk)
	e.restart()
	if n := len(e.signer.Keys()); n != 0 || e.loadErr != nil {
		t.Fatalf("an empty store: %d keys loaded, err %v", n, e.loadErr)
	}
	// Every record hidden or removed: not ready until an import.
	if h, err := e.srv.health(); err != nil || h.Ready || !strings.Contains(h.LoadFailed, "no readable share record") {
		t.Fatalf("an empty store under a vouched set: health %+v %v", h, err)
	}
	if err := e.importSealed(pk, sk, 6, nil); err != nil {
		t.Fatal(err)
	}
	if h, err := e.srv.health(); err != nil || !h.Ready || h.LoadFailed != "" {
		t.Fatalf("after the import: health %+v %v", h, err)
	}
	e.putRaw(pk, old)
	e.restart()
	wantNoLoad(e, pk)
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
// for the set before and after, the store holds the one before. Here the
// store write fails and so does the log record that would drop the set
// after. The runner takes no further share write. The start loads the
// stored set as it is, and nothing is reset.
func TestShareSetCutWriteLoadsTheSetBefore(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("the test makes the mark log unwritable with a directory mode, which root ignores")
	}
	e := newTgtEnv(t, "dev", nil)
	pka, pkb, floor := historyPair(t, e)
	skc, pkc := newKey(t)
	t.Cleanup(func() { e.setMarksMode(0o700) })
	e.store.mu.Lock()
	e.store.failPut = func(k string) bool {
		if k != shareKey(pkc) {
			return false
		}
		e.setMarksMode(0o500)
		return true
	}
	e.store.mu.Unlock()
	if err := e.importSealed(pkc, skc, 7, nil); err == nil {
		t.Fatal("an import whose store write failed succeeded")
	}
	e.store.mu.Lock()
	e.store.failPut = nil
	e.store.mu.Unlock()
	e.setMarksMode(0o700)
	if sh := e.records()[len(e.records())-1].Shares; sh == nil || sh.Pending == nil {
		t.Fatalf("the newest record's share set %+v, want the cut write's pending root", sh)
	}
	skd, pkd := newKey(t)
	if err := e.importSealed(pkd, skd, 8, nil); err == nil {
		t.Fatal("a share write went on while the log vouches for a failed one")
	}
	puts := e.store.putsOf(shareKey(pkb))
	e.restart()
	if r := e.recordOf(pka); r.History || r.SourceFloor != floor {
		t.Fatalf("A after the cut write: history %t floor %d", r.History, r.SourceFloor)
	}
	if !e.recordOf(pkb).History || e.store.putsOf(shareKey(pkb)) != puts {
		t.Fatal("B was reset after a cut write")
	}
	if err := e.importSealed(pkd, skd, 8, nil); err != nil {
		t.Fatalf("a share write after the restart: %v", err)
	}
}

// A record the host hid makes the set one the log does not vouch for: no
// key loads, and nothing is written. The record comes back: the set loads
// as it was, B with its history.
func TestShareSetHiddenRecordLoadsNoKey(t *testing.T) {
	e := newTgtEnv(t, "dev", nil)
	e.looseLoad = true
	pka, pkb, _ := historyPair(t, e)
	blob, _ := e.store.Get(shareKey(pka))
	puts := e.store.putsOf(shareKey(pkb))
	recs := e.records()
	want := recs[len(recs)-1].Shares
	e.deleteShare(pka)
	e.restart()
	wantNoLoad(e, pkb)
	if e.store.putsOf(shareKey(pkb)) != puts {
		t.Fatal("a record was rewritten")
	}
	recs = e.records()
	if got := recs[len(recs)-1].Shares; got == nil || got.Current != want.Current || got.Pending != nil {
		t.Fatalf("the log's share set is %+v, want %+v", got, want)
	}
	e.putRaw(pka, blob)
	e.restart()
	if n := len(e.signer.Keys()); n != 2 || e.loadErr != nil || !e.recordOf(pkb).History {
		t.Fatalf("the record back: %d keys loaded, err %v, B history %t", n, e.loadErr, e.recordOf(pkb).History)
	}
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
	// A record that does not load is no reason to report not ready.
	if h, err := e.srv.health(); err != nil || !h.Ready || h.LoadFailed != "" {
		t.Fatalf("health with an unreadable blob stored: %+v %v", h, err)
	}
}

// A share write that did not reach the store leaves its set out of the
// commitment the next log record carries. The host kept the blob and
// stores it after that record: the start finds a set the log does not
// vouch for, loads no key and names the extra object. Once the operator
// removes it, the set loads, B with its history.
func TestShareWriteNotLandedNotVouched(t *testing.T) {
	e := newTgtEnv(t, "dev", nil)
	e.looseLoad = true
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
	wantNoLoad(e, pkc)
	e.deleteShare(pkc)
	e.restart()
	if n := len(e.signer.Keys()); n != 2 || e.loadErr != nil || !e.recordOf(pkb).History {
		t.Fatalf("the extra object removed: %d keys loaded, err %v", n, e.loadErr)
	}
}

// A share write that did not reach the store is dropped from the log at
// once: the runner writes a record without the set after, and needs no
// vote or other record for that. The host stores the kept blob and
// restarts the runner: the start finds a set the log does not vouch for,
// loads no key and names the kept record.
func TestShareWriteNotLandedDroppedAtOnce(t *testing.T) {
	e := newTgtEnv(t, "dev", nil)
	e.looseLoad = true
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
	if sh := e.records()[len(e.records())-1].Shares; sh == nil || sh.Pending != nil {
		t.Fatalf("the newest record after a failed write carries share set %+v, want no pending root", sh)
	}
	e.putRaw(pkc, blob)
	e.restart()
	wantNoLoad(e, pkc)
	if !e.recordOf(pkb).History {
		t.Fatal("B's record was rewritten: a start that loads no key writes nothing")
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

// B's record (with history) is stored and vouched for. The host hides A,
// so no key loads. B is imported again without history and that store
// write fails: the next start must not load the old record of B.
func TestFailedReimportDoesNotVouchOldRecord(t *testing.T) {
	e := newTgtEnv(t, "dev", nil)
	e.looseLoad = true
	pka, pkb, _ := historyPair(t, e)
	skb := e.secretOf(pkb)
	a, _ := e.store.Get(shareKey(pka))
	e.deleteShare(pka)
	e.restart()
	wantNoLoad(e, pkb)
	e.putRaw(pka, a)
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
	wantNoLoad(e, pka, pkb)
}

// An empty store under a log with no share set, or an empty one, is a new
// signer: it is ready.
func TestEmptyStoreEmptySetReady(t *testing.T) {
	e := newTgtEnv(t, "dev", nil)
	e.restart()
	if h, err := e.srv.health(); err != nil || !h.Ready || h.LoadFailed != "" || h.Validators != 0 {
		t.Fatalf("health %+v %v", h, err)
	}
}

// A share stored under an uppercase name does not load: a key has one
// store name, lowercase hex, so case variants cannot pass as shares.
func TestShareNameOnlyLowercase(t *testing.T) {
	e := newTgtEnv(t, "dev", nil)
	e.looseLoad = true
	sk, pk := newKey(t)
	if err := e.importSealed(pk, sk, 5, nil); err != nil {
		t.Fatal(err)
	}
	e.store.mu.Lock()
	upper := "shares/" + strings.ToUpper(hex.EncodeToString(pk[:]))
	e.store.m[upper] = e.store.m[shareKey(pk)]
	delete(e.store.m, shareKey(pk))
	e.store.mu.Unlock()
	e.restart()
	if n := len(e.signer.Keys()); n != 0 {
		t.Fatalf("%d keys loaded from an uppercase share name", n)
	}
	if e.loadErr == nil || !strings.Contains(e.loadErr.Error(), upper+": not a share name") {
		t.Fatalf("start error %v, want the uppercase name refused", e.loadErr)
	}
	if _, err := sharePubkey(upper); err == nil {
		t.Fatal("sharePubkey took an uppercase name")
	}
}
