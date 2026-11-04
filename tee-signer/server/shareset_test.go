//go:build !debugimport

package server

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lidofinance/tee-signer/platform/dev"
	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/slashing-log"
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
	// Every record removed: not ready until an import.
	if h, err := e.srv.health(); err != nil || h.Ready || !strings.Contains(h.LoadFailed, "lists no share record") {
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

// B's record (with history) is stored and vouched for. The operator
// removes every share, and B is imported again without history; that
// store write fails. The host puts the old records back: the next start
// must not load the old record of B.
func TestFailedReimportDoesNotVouchOldRecord(t *testing.T) {
	e := newTgtEnv(t, "dev", nil)
	e.looseLoad = true
	pka, pkb, _ := historyPair(t, e)
	skb := e.secretOf(pkb)
	a, _ := e.store.Get(shareKey(pka))
	b, _ := e.store.Get(shareKey(pkb))
	e.deleteShare(pka)
	e.deleteShare(pkb)
	e.restart()
	e.store.mu.Lock()
	e.store.failPut = func(k string) bool { return k == shareKey(pkb) }
	e.store.mu.Unlock()
	if err := e.importSealed(pkb, skb, 6, nil); err == nil {
		t.Fatal("an import whose store write failed succeeded")
	}
	e.store.mu.Lock()
	e.store.failPut = nil
	e.store.mu.Unlock()
	e.putRaw(pka, a)
	e.putRaw(pkb, b)
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

// Every record gone from the listing: the start loads no key and reports
// the loss, and the log keeps vouching for the set it had. A keep-alive
// record written while the runner runs on in that state carries that set
// on. The records come back: the next start loads them, B with its
// history.
func TestEveryRecordHiddenKeepsTheVouchedSet(t *testing.T) {
	e := newTgtEnv(t, "dev", nil)
	e.looseLoad = true
	pka, pkb, _ := historyPair(t, e)
	bloba, _ := e.store.Get(shareKey(pka))
	blobb, _ := e.store.Get(shareKey(pkb))
	recs := e.records()
	want := recs[len(recs)-1].Shares
	e.deleteShare(pka)
	e.deleteShare(pkb)
	e.restart()
	if n := len(e.signer.Keys()); n != 0 || e.loadErr != nil {
		t.Fatalf("every record gone: %d keys loaded, err %v", n, e.loadErr)
	}
	if h, err := e.srv.health(); err != nil || h.Ready || !strings.Contains(h.LoadFailed, "lists no share record") {
		t.Fatalf("health with every record gone: %+v %v", h, err)
	}
	// The keep-alive record of a runner that ran on for a day.
	e.clock.add(25 * 60 * 60)
	if err := e.marks.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	recs = e.records()
	if got := recs[len(recs)-1].Shares; got == nil || got.Current != want.Current || got.Pending != nil {
		t.Fatalf("the keep-alive record's share set is %+v, want the vouched set %+v", got, want)
	}
	e.putRaw(pka, bloba)
	e.putRaw(pkb, blobb)
	e.restart()
	if n := len(e.signer.Keys()); n != 2 || e.loadErr != nil || !e.recordOf(pkb).History {
		t.Fatalf("the records back: %d keys loaded, err %v", n, e.loadErr)
	}
}

// wantNotReady checks that an import was refused with NOT_READY.
func wantNotReady(t *testing.T, err error) {
	t.Helper()
	var ref *backend.RefusedError
	if !errors.As(err, &ref) || ref.Code != backend.StatusNotReady {
		t.Fatalf("import: %v, want NOT_READY", err)
	}
}

// newestEnc is the newest parseable record of e's log and its encoding.
func (e *tgtEnv) newestEnc() (*markstore.Record, []byte) {
	e.t.Helper()
	es, err := e.fl.List(ctx, markstore.Prefix(e.hash, e.setup.SignerName))
	if err != nil {
		e.t.Fatal(err)
	}
	var best *markstore.Record
	var bestEnc []byte
	for _, en := range es {
		b, err := e.fl.Get(ctx, en)
		if err != nil {
			e.t.Fatal(err)
		}
		r, err := markstore.Parse(b)
		if err != nil {
			continue
		}
		if best == nil || r.Version > best.Version {
			best, bestEnc = r, b
		}
	}
	return best, bestEnc
}

// writeNilSetRecord appends a record with no share set to e's log, as an
// image before share sets wrote it, under a fresh key of the dev key
// release. Call it with the signer closed.
func (e *tgtEnv) writeNilSetRecord() {
	e.t.Helper()
	newest, enc := e.newestEnc()
	keys := dev.NewDevKeys("server test env")
	seed, blob, err := keys.NewKey(ctx, markstore.KeyAAD(e.hash, e.setup.SignerName))
	if err != nil {
		e.t.Fatal(err)
	}
	r := *newest
	r.Version, r.PrevVersion, r.PrevHash = newest.Version+1, newest.Version, markstore.Hash(enc)
	r.Shares, r.KeyBlob = nil, blob
	rand.Read(r.Owner[:])
	if err := e.fl.Create(ctx, markstore.Name(e.hash, e.setup.SignerName, r.Version), r.Sign(ed25519.NewKeyFromSeed(seed))); err != nil {
		e.t.Fatal(err)
	}
}

// Every record listed but hidden (the store denies the reads): an import
// is refused with NOT_READY, writes no record, and the log keeps vouching
// for the set it had. The records readable again: the next start loads
// them, B with its history, and imports go through again.
func TestImportRefusedWhileRecordsHidden(t *testing.T) {
	e := newTgtEnv(t, "dev", nil)
	e.looseLoad = true
	pka, pkb, _ := historyPair(t, e)
	recs := e.records()
	want := recs[len(recs)-1].Shares
	names := map[string]bool{shareKey(pka): true, shareKey(pkb): true}
	e.store.mu.Lock()
	e.store.failGet = func(k string) bool { return names[k] }
	e.store.mu.Unlock()
	e.restart()
	if h, err := e.srv.health(); err != nil || h.Ready || !strings.Contains(h.LoadFailed, "lists share records but holds no readable share record") {
		t.Fatalf("health with every record hidden: %+v %v", h, err)
	}
	n := len(e.records())
	skc, pkc := newKey(t)
	wantNotReady(t, e.importSealed(pkc, skc, 7, nil))
	skd, pkd := newKey(t)
	_, err := e.importBatch([][32]byte{skd}, []backend.Pubkey{pkd})
	wantNotReady(t, err)
	if got, _ := e.hooks.ShareSet(); got == nil || got.Current != want.Current || got.Pending != nil || len(e.records()) != n {
		t.Fatalf("after the refused imports the share set is %+v with %d records more, want %+v and none", got, len(e.records())-n, want)
	}
	if h, err := e.srv.health(); err != nil || h.Ready || !strings.Contains(h.LoadFailed, "no readable share record") {
		t.Fatalf("health after the refused imports: %+v %v", h, err)
	}
	if _, err := e.store.Get(shareKey(pkc)); err == nil {
		t.Fatal("a refused import stored a record")
	}
	e.store.mu.Lock()
	e.store.failGet = nil
	e.store.mu.Unlock()
	e.restart()
	if n := len(e.signer.Keys()); n != 2 || e.loadErr != nil || !e.recordOf(pkb).History {
		t.Fatalf("the records readable again: %d keys loaded, err %v", n, e.loadErr)
	}
	if err := e.importSealed(pkc, skc, 7, nil); err != nil {
		t.Fatalf("an import after the records came back: %v", err)
	}
}

// The store lists no record under a vouched set that is not empty (the
// state is lost, or the operator removed every share): the start loads no
// key and reports it, and keeps the vouched set; but it takes an import,
// which records a new set over the old one. The key signs, the runner is
// ready, and the next start loads the key as vouched.
func TestImportAfterEveryRecordRemoved(t *testing.T) {
	e := newTgtEnv(t, "dev", nil)
	e.looseLoad = true
	pka, pkb, _ := historyPair(t, e)
	skb := e.secretOf(pkb)
	recs := e.records()
	old := recs[len(recs)-1].Shares
	e.deleteShare(pka)
	e.deleteShare(pkb)
	e.restart()
	if n := len(e.signer.Keys()); n != 0 || e.loadErr != nil {
		t.Fatalf("every record removed: %d keys loaded, err %v", n, e.loadErr)
	}
	if h, err := e.srv.health(); err != nil || h.Ready || !strings.Contains(h.LoadFailed, "lists no share record") {
		t.Fatalf("health with every record removed: %+v %v", h, err)
	}
	if err := e.importSealed(pkb, skb, 6, nil); err != nil {
		t.Fatalf("an import with no record listed: %v", err)
	}
	if h, err := e.srv.health(); err != nil || !h.Ready || h.LoadFailed != "" || h.Validators != 1 {
		t.Fatalf("health after the import: %+v %v", h, err)
	}
	if got, _ := e.hooks.ShareSet(); got == nil || got.Current == old.Current || got.Pending != nil {
		t.Fatalf("after the import the share set is %+v, want a new set over %+v", got, old)
	}
	e.clock.add(4 * testEpoch) // past the floor of the import
	epoch := e.signer.EpochAt(e.now())
	if err := e.signMsg(pkb, vote(epoch-1, epoch)); err != nil {
		t.Fatalf("a vote after the import: %v", err)
	}
	e.restart()
	if n := len(e.signer.Keys()); n != 1 || e.loadErr != nil || e.recordOf(pkb).History {
		t.Fatalf("after the import, the next start: %d keys loaded, err %v", n, e.loadErr)
	}
	if h, err := e.srv.health(); err != nil || !h.Ready || h.LoadFailed != "" {
		t.Fatalf("health after the next start: %+v %v", h, err)
	}
}

// One record hidden: the set is not the one the log vouches for, and an
// import is refused with NOT_READY until the store is fixed.
func TestImportRefusedWhileLoadFailed(t *testing.T) {
	e := newTgtEnv(t, "dev", nil)
	e.looseLoad = true
	pka, pkb, _ := historyPair(t, e)
	blobb, _ := e.store.Get(shareKey(pkb))
	e.deleteShare(pkb)
	e.restart()
	wantNoLoad(e, pka)
	n := len(e.records())
	skc, pkc := newKey(t)
	wantNotReady(t, e.importSealed(pkc, skc, 7, nil))
	if len(e.records()) != n {
		t.Fatal("a refused import wrote a log record")
	}
	e.putRaw(pkb, blobb)
	e.restart()
	if n := len(e.signer.Keys()); n != 2 || e.loadErr != nil || !e.recordOf(pkb).History {
		t.Fatalf("the record back: %d keys loaded, err %v", n, e.loadErr)
	}
}

// A log whose newest record has no share set (an image before share sets
// wrote it), and a store that lists the records but gives none: the
// start is not ready, commits nothing (the next record carries no share
// set either), and refuses imports. The records readable again, the
// next start takes the one-time reset and loads them.
func TestNilSetUnreadableRecordsNotReady(t *testing.T) {
	e := newTgtEnv(t, "dev", nil)
	e.looseLoad = true
	pka, pkb, _ := historyPair(t, e)
	e.signer.Close()
	e.writeNilSetRecord()
	names := map[string]bool{shareKey(pka): true, shareKey(pkb): true}
	e.store.mu.Lock()
	e.store.failGet = func(k string) bool { return names[k] }
	e.store.mu.Unlock()
	e.start()
	if n := len(e.signer.Keys()); n != 0 {
		t.Fatalf("%d keys loaded from records the store does not give", n)
	}
	if h, err := e.srv.health(); err != nil || h.Ready || !strings.Contains(h.LoadFailed, "no readable share record") {
		t.Fatalf("health with the records listed but unreadable: %+v %v", h, err)
	}
	if set, _ := e.hooks.ShareSet(); set != nil {
		t.Fatalf("the start committed share set %+v on a log with none", set)
	}
	skc, pkc := newKey(t)
	wantNotReady(t, e.importSealed(pkc, skc, 7, nil))
	e.clock.add(25 * 60 * 60)
	if err := e.marks.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	recs := e.records()
	if got := recs[len(recs)-1].Shares; got != nil {
		t.Fatalf("the keep-alive record carries share set %+v, want none", got)
	}
	e.store.mu.Lock()
	e.store.failGet = nil
	e.store.mu.Unlock()
	e.restart()
	if n := len(e.signer.Keys()); n != 2 || e.loadErr != nil {
		t.Fatalf("the records readable again: %d keys loaded, err %v", n, e.loadErr)
	}
}

// A log with no share set and a store that lists no record is a new
// signer: ready, and its first import goes through and is vouched for at
// the next start.
func TestNilSetEmptyStoreIsFresh(t *testing.T) {
	e := newTgtEnv(t, "dev", nil)
	if recs := e.records(); recs[len(recs)-1].Shares != nil {
		t.Fatalf("a new log's record carries share set %+v", recs[len(recs)-1].Shares)
	}
	if h, err := e.srv.health(); err != nil || !h.Ready || h.LoadFailed != "" {
		t.Fatalf("health of a new signer: %+v %v", h, err)
	}
	sk, pk := newKey(t)
	if err := e.importSealed(pk, sk, 5, nil); err != nil {
		t.Fatalf("the first import of a new signer: %v", err)
	}
	e.restart()
	if n := len(e.signer.Keys()); n != 1 || e.loadErr != nil {
		t.Fatalf("after the first import: %d keys loaded, err %v", n, e.loadErr)
	}
}

// A log with no share set and a store whose records are gone from the
// listing: the start cannot tell it from a new signer, so it is ready;
// but it commits nothing, so the records put back load at the next
// start, through the one-time reset.
func TestNilSetDeletedRecordsLoadAtReset(t *testing.T) {
	e := newTgtEnv(t, "dev", nil)
	e.looseLoad = true
	pka, pkb, _ := historyPair(t, e)
	bloba, _ := e.store.Get(shareKey(pka))
	blobb, _ := e.store.Get(shareKey(pkb))
	e.signer.Close()
	e.writeNilSetRecord()
	e.deleteShare(pka)
	e.deleteShare(pkb)
	e.start()
	if h, err := e.srv.health(); err != nil || !h.Ready || h.LoadFailed != "" {
		t.Fatalf("health with no record listed under a log with no share set: %+v %v", h, err)
	}
	if set, _ := e.hooks.ShareSet(); set != nil {
		t.Fatalf("the start committed share set %+v on a log with none", set)
	}
	e.clock.add(25 * 60 * 60)
	if err := e.marks.Refresh(ctx); err != nil {
		t.Fatal(err)
	}
	recs := e.records()
	if got := recs[len(recs)-1].Shares; got != nil {
		t.Fatalf("the keep-alive record carries share set %+v, want none", got)
	}
	e.putRaw(pka, bloba)
	e.putRaw(pkb, blobb)
	e.restart()
	if n := len(e.signer.Keys()); n != 2 || e.loadErr != nil {
		t.Fatalf("the records back: %d keys loaded, err %v", n, e.loadErr)
	}
}

// The state copy rolled back: the store holds the records of an older
// commit (A, and B before its re-import), not the set the log vouches
// for, and the operator cannot remove them. A batch that imports every
// share the start listed is taken and replaces the stored set; a batch
// that leaves one listed share out is refused. The keys load and sign
// after a restart.
func TestBatchOfEveryListedKeyReplacesTheSet(t *testing.T) {
	e := newTgtEnv(t, "dev", nil)
	e.looseLoad = true
	pka, pkb, _ := historyPair(t, e)
	ska, skb := e.secretOf(pka), e.secretOf(pkb)
	bloba, _ := e.store.Get(shareKey(pka))
	blobb, _ := e.store.Get(shareKey(pkb))
	e.deleteShare(pka)
	e.deleteShare(pkb)
	e.restart()
	if err := e.importSealed(pkb, skb, 6, nil); err != nil {
		t.Fatal(err)
	}
	e.putRaw(pka, bloba)
	e.putRaw(pkb, blobb)
	e.restart()
	wantNoLoad(e, pka, pkb)
	n := len(e.records())
	_, err := e.importBatch([][32]byte{ska}, []backend.Pubkey{pka})
	wantNotReady(t, err)
	if len(e.records()) != n {
		t.Fatal("a refused batch wrote a log record")
	}
	if _, err := e.importBatch([][32]byte{ska, skb}, []backend.Pubkey{pka, pkb}); err != nil {
		t.Fatalf("a batch of every listed share: %v", err)
	}
	if h, err := e.srv.health(); err != nil || !h.Ready || h.LoadFailed != "" || h.Validators != 2 {
		t.Fatalf("health after the batch: %+v %v", h, err)
	}
	if got, _ := e.hooks.ShareSet(); got == nil || got.Pending != nil || got.Current == markstore.ShareSetRoot(nil) {
		t.Fatalf("after the batch the share set is %+v, want the batch's set", got)
	}
	e.restart()
	if n := len(e.signer.Keys()); n != 2 || e.loadErr != nil || e.recordOf(pkb).History {
		t.Fatalf("after the batch, the next start: %d keys loaded, err %v", n, e.loadErr)
	}
	e.clock.add(4 * testEpoch) // past the floor of the import
	epoch := e.signer.EpochAt(e.now())
	if err := e.signMsg(pkb, vote(epoch-1, epoch)); err != nil {
		t.Fatalf("a vote after the batch: %v", err)
	}
}

// The same with every record listed but unreadable: the batch of every
// listed share is taken, one that leaves a share out is refused.
func TestBatchOfEveryListedKeyWhileRecordsHidden(t *testing.T) {
	e := newTgtEnv(t, "dev", nil)
	e.looseLoad = true
	pka, pkb, _ := historyPair(t, e)
	ska, skb := e.secretOf(pka), e.secretOf(pkb)
	names := map[string]bool{shareKey(pka): true, shareKey(pkb): true}
	e.store.mu.Lock()
	e.store.failGet = func(k string) bool { return names[k] }
	e.store.mu.Unlock()
	e.restart()
	if h, err := e.srv.health(); err != nil || h.Ready || !strings.Contains(h.LoadFailed, "no readable share record") {
		t.Fatalf("health with every record hidden: %+v %v", h, err)
	}
	_, err := e.importBatch([][32]byte{skb}, []backend.Pubkey{pkb})
	wantNotReady(t, err)
	if _, err := e.importBatch([][32]byte{ska, skb}, []backend.Pubkey{pka, pkb}); err != nil {
		t.Fatalf("a batch of every listed share: %v", err)
	}
	if h, err := e.srv.health(); err != nil || !h.Ready || h.LoadFailed != "" || h.Validators != 2 {
		t.Fatalf("health after the batch: %+v %v", h, err)
	}
	e.store.mu.Lock()
	e.store.failGet = nil
	e.store.mu.Unlock()
	e.restart()
	if n := len(e.signer.Keys()); n != 2 || e.loadErr != nil {
		t.Fatalf("after the batch, the next start: %d keys loaded, err %v", n, e.loadErr)
	}
}
