//go:build !debugimport

package server

import (
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/lidofinance/tee-signer/signer-protocol"
)

// recordOf is pk's sealed share record on e.
func (e *tgtEnv) recordOf(pk backend.Pubkey) shareRecord {
	e.t.Helper()
	var out shareRecord
	if err := e.srv.readShare(pk, func(rec *shareRecord, _ *[32]byte) error {
		out = *rec
		return nil
	}); err != nil {
		e.t.Fatal(err)
	}
	return out
}

// A key imported without history earns it with its first vote at or above
// its source floor: one record write, History set and the floor dropped,
// kept after a restart. A vote below the floor (refused) and a message
// that is not a vote write nothing.
func TestPromoteOnFirstVoteAtFloor(t *testing.T) {
	e := newTgtEnv(t, "dev", nil)
	floor := e.floorOf()
	sk, pk := newKey(t)
	if err := e.importSealed(pk, sk, 5, nil); err != nil {
		t.Fatal(err)
	}
	e.clock.add((floor + 1 - e.signer.EpochAt(e.now())) * testEpoch)
	key := shareKey(pk)
	puts := e.store.putsOf(key)
	if err := e.signMsg(pk, e.registration(pk)); err != nil {
		t.Fatal(err)
	}
	wantSlashSource(t, e.signMsg(pk, vote(floor-1, floor+1)), "a vote below the floor")
	if r := e.recordOf(pk); r.History || r.SourceFloor != floor || e.store.putsOf(key) != puts {
		t.Fatalf("before a vote at the floor: history %t floor %d, %d writes", r.History, r.SourceFloor, e.store.putsOf(key)-puts)
	}
	if err := e.signMsg(pk, vote(floor, floor+1)); err != nil {
		t.Fatal(err)
	}
	e.srv.promotions.Wait()
	if r := e.recordOf(pk); !r.History || r.SourceFloor != 0 || e.store.putsOf(key) != puts+1 {
		t.Fatalf("after a vote at the floor: history %t floor %d, %d writes", r.History, r.SourceFloor, e.store.putsOf(key)-puts)
	}
	if err := e.signMsg(pk, vote(floor, floor+2)); err != nil {
		t.Fatal(err)
	}
	e.srv.promotions.Wait()
	if n := e.store.putsOf(key); n != puts+1 {
		t.Fatalf("%d record writes after a second vote, want 1", n-puts)
	}
	e.restart()
	if r := e.recordOf(pk); !r.History {
		t.Fatal("the history flag is gone after a restart")
	}
	if _, on := e.hooks.SourceFloor(pk); on {
		t.Fatal("a source floor holds after a restart for a key with history")
	}
}

// At a handover a key that earned history goes with history and signs at
// the target without a wait. A key that never voted at its floor goes
// without history and waits for the target's floor.
func TestPromotedKeyHandsOverWithHistory(t *testing.T) {
	src := newSrcEnv(t, nil)
	tgt := newTargetOf(t, src, nil, nil, nil)
	floor := src.floorOf()
	var pks []backend.Pubkey
	for i := range 2 {
		sk, pk := newKey(t)
		if err := src.importSealed(pk, sk, uint64(5+i), nil); err != nil {
			t.Fatal(err)
		}
		pks = append(pks, pk)
	}
	earned, never := pks[0], pks[1]
	src.clock.add((floor + 1 - src.signer.EpochAt(src.now())) * testEpoch)
	if err := src.signMsg(earned, vote(floor, floor+1)); err != nil {
		t.Fatal(err)
	}
	src.srv.promotions.Wait()
	if !src.recordOf(earned).History {
		t.Fatal("no history after a vote at the floor")
	}
	order, _ := srcOrder(t, src, tgt, []byte{1, 2}, nil)
	if _, err := src.push(order); err != nil {
		t.Fatal(err)
	}
	src.clock.add(srcDelay)
	if _, imp := handOverAll(t, src, tgt, order); !imp.Done {
		t.Fatalf("import %+v", imp)
	}
	f := tgt.floorOf()
	tgt.clock.add((f - tgt.signer.EpochAt(tgt.now())) * testEpoch)
	if f <= floor {
		t.Fatalf("the target's floor %d is not above the source's %d", f, floor)
	}
	if err := tgt.attest(earned, floor, f+1); err != nil {
		t.Fatalf("the key that earned history, at its source floor %d: %v", floor, err)
	}
	wantSlashSource(t, tgt.attest(never, floor, f+1), "the key that never voted below the target's floor")
	if !tgt.recordOf(earned).History || tgt.recordOf(never).History {
		t.Fatal("the target's records do not keep the source's history state")
	}
}

// The host rolls a promoted record back to the one before the flag: the
// source refuses the handover (the record is not the one it wrote), and
// after a restart, which loads every key without history and with a
// fresh floor, both keys wait at the target.
func TestRolledBackRecordStopsTheHandover(t *testing.T) {
	src := newSrcEnv(t, nil)
	tgt := newTargetOf(t, src, nil, nil, nil)
	floor := src.floorOf()
	var pks []backend.Pubkey
	for i := range 2 {
		sk, pk := newKey(t)
		if err := src.importSealed(pk, sk, uint64(5+i), nil); err != nil {
			t.Fatal(err)
		}
		pks = append(pks, pk)
	}
	rolled, earned := pks[0], pks[1]
	src.clock.add((floor + 1 - src.signer.EpochAt(src.now())) * testEpoch)
	old, err := src.store.Get(shareKey(rolled))
	if err != nil {
		t.Fatal(err)
	}
	for _, pk := range pks {
		if err := src.signMsg(pk, vote(floor, floor+1)); err != nil {
			t.Fatal(err)
		}
	}
	src.srv.promotions.Wait()
	src.putRaw(rolled, old)

	order, _ := srcOrder(t, src, tgt, []byte{1, 2}, nil)
	if _, err := src.push(order); err != nil {
		t.Fatal(err)
	}
	src.clock.add(srcDelay)
	if _, err := handOver(t, src, tgt, order, 0); err == nil || !strings.Contains(err.Error(), "not the one this runner") {
		t.Fatalf("a handover over a rolled-back record: %v", err)
	}
	if src.srv.HandedOver() {
		t.Fatal("the source handed over")
	}
	src.restart()
	for _, pk := range pks {
		if r := src.recordOf(pk); r.History || r.SourceFloor <= floor {
			t.Fatalf("after the restart: history %t floor %d", r.History, r.SourceFloor)
		}
	}
	if _, imp := handOverAll(t, src, tgt, order); !imp.Done {
		t.Fatalf("import %+v", imp)
	}
	f := tgt.floorOf()
	tgt.clock.add((f - tgt.signer.EpochAt(tgt.now())) * testEpoch)
	for _, pk := range []backend.Pubkey{rolled, earned} {
		wantSlashSource(t, tgt.attest(pk, floor, f+1), "after the reset, below the target's floor")
	}
}

// Votes of many keys at once: each key's record is written once.
func TestPromoteConcurrent(t *testing.T) {
	e := newTgtEnv(t, "dev", nil)
	floor := e.floorOf()
	var pks []backend.Pubkey
	for i := range 8 {
		sk, pk := newKey(t)
		if err := e.importSealed(pk, sk, uint64(10+i), nil); err != nil {
			t.Fatal(err)
		}
		pks = append(pks, pk)
	}
	e.clock.add((floor + 1 - e.signer.EpochAt(e.now())) * testEpoch)
	puts := map[backend.Pubkey]int{}
	for _, pk := range pks {
		puts[pk] = e.store.putsOf(shareKey(pk))
	}
	var wg sync.WaitGroup
	for _, pk := range pks {
		for j := range 4 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				e.signMsg(pk, vote(floor, floor+1+uint64(j%2))) //nolint:errcheck // some repeat or lose the race
			}()
		}
	}
	wg.Wait()
	e.srv.promotions.Wait()
	for i, pk := range pks {
		if r := e.recordOf(pk); !r.History || e.store.putsOf(shareKey(pk)) != puts[pk]+1 {
			t.Errorf("key %d: history %t, %d record writes", i, r.History, e.store.putsOf(shareKey(pk))-puts[pk])
		}
	}
}

// A failed promotion write does not latch the key: the next vote at its
// floor writes the record.
func TestPromoteRetriesAfterAFailedWrite(t *testing.T) {
	e := newTgtEnv(t, "dev", nil)
	floor := e.floorOf()
	sk, pk := newKey(t)
	if err := e.importSealed(pk, sk, 5, nil); err != nil {
		t.Fatal(err)
	}
	e.clock.add((floor + 1 - e.signer.EpochAt(e.now())) * testEpoch)
	key := shareKey(pk)
	e.store.mu.Lock()
	e.store.failPut = func(k string) bool { return k == key }
	e.store.mu.Unlock()
	if err := e.signMsg(pk, vote(floor, floor+1)); err != nil {
		t.Fatal(err)
	}
	e.srv.promotions.Wait()
	if e.recordOf(pk).History {
		t.Fatal("history after a failed write")
	}
	e.store.mu.Lock()
	e.store.failPut = nil
	e.store.mu.Unlock()
	// Not again in the same epoch.
	puts := e.store.putsOf(key)
	if err := e.signMsg(pk, vote(floor, floor+2)); err != nil {
		t.Fatal(err)
	}
	e.srv.promotions.Wait()
	if e.recordOf(pk).History || e.store.putsOf(key) != puts {
		t.Fatal("a second try in the epoch of the failed one")
	}
	e.clock.add(testEpoch)
	if err := e.signMsg(pk, vote(floor, floor+3)); err != nil {
		t.Fatal(err)
	}
	e.srv.promotions.Wait()
	if !e.recordOf(pk).History {
		t.Fatal("no history after a vote in a later epoch once the store writes again")
	}
}

// A promotion whose store write keeps failing tries at most once per
// epoch and maxPromotionTries times per process: each try costs a mark
// log record.
func TestPromoteFailingWriteIsBounded(t *testing.T) {
	e := newTgtEnv(t, "dev", nil)
	floor := e.floorOf()
	sk, pk := newKey(t)
	if err := e.importSealed(pk, sk, 5, nil); err != nil {
		t.Fatal(err)
	}
	e.clock.add((floor + 1 - e.signer.EpochAt(e.now())) * testEpoch)
	e.store.mu.Lock()
	e.store.failPut = func(k string) bool { return k == shareKey(pk) }
	e.store.mu.Unlock()
	before := len(e.records())
	for range 5 {
		e.clock.add(testEpoch)
		en := e.signer.EpochAt(e.now())
		for j := range uint64(2) { // two votes in the epoch
			if err := e.signMsg(pk, vote(floor, en+j)); err != nil {
				t.Fatal(err)
			}
			e.srv.promotions.Wait()
		}
	}
	// One try, one pending root (each try seals the record anew); later
	// mark records carry the last one along.
	pending := map[[32]byte]bool{}
	for _, r := range e.records()[before:] {
		if r.Shares != nil && r.Shares.Pending != nil {
			pending[*r.Shares.Pending] = true
		}
	}
	if tries := len(pending); tries != maxPromotionTries {
		t.Fatalf("%d share set records for 10 votes in 5 epochs with a failing write, want %d", tries, maxPromotionTries)
	}
}

// A runner that handed over writes no promotion: the handover read every
// record under the share lock, and the tombstone ends the log.
func TestPromoteSkipsAfterHandover(t *testing.T) {
	e := newTgtEnv(t, "dev", nil)
	sk, pk := newKey(t)
	if err := e.importSealed(pk, sk, 5, nil); err != nil {
		t.Fatal(err)
	}
	puts := e.store.putsOf(shareKey(pk))
	e.srv.handedOver.Store(true)
	if err := e.srv.promoteNow(pk, e.floorOf()); err != nil {
		t.Fatal(err)
	}
	if e.store.putsOf(shareKey(pk)) != puts {
		t.Fatal("a runner that handed over wrote a promotion")
	}
	e.srv.handedOver.Store(false)
	if e.recordOf(pk).History {
		t.Fatal("history after a handover")
	}
}

// A promotion writes only over the record the runner holds: a record the
// host removed after the vote stays removed, and one it changed stays as
// it is.
func TestPromotionDoesNotRecreateARemovedRecord(t *testing.T) {
	e := newTgtEnv(t, "dev", nil)
	sk, pk := newKey(t)
	if err := e.importSealed(pk, sk, 5, nil); err != nil {
		t.Fatal(err)
	}
	held, err := e.store.Get(shareKey(pk))
	if err != nil {
		t.Fatal(err)
	}
	blob, err := e.srv.sealRecord(shareRecord{Pubkey: pk, Secret: sk[:], Index: 5, History: true})
	if err != nil {
		t.Fatal(err)
	}
	e.deleteShare(pk)
	if err := e.srv.replaceShare(pk, blob); !errors.Is(err, errShareChanged) {
		t.Fatalf("a write over a removed record: %v", err)
	}
	if _, err := e.store.Get(shareKey(pk)); err == nil {
		t.Fatal("the removed record came back")
	}
	other := append([]byte(nil), held...)
	other[len(other)-1] ^= 1
	e.putRaw(pk, other)
	if err := e.srv.replaceShare(pk, blob); !errors.Is(err, errShareChanged) {
		t.Fatalf("a write over a changed record: %v", err)
	}
	if got, _ := e.store.Get(shareKey(pk)); string(got) != string(other) {
		t.Fatal("the changed record was overwritten")
	}
	e.putRaw(pk, held)
	if err := e.srv.replaceShare(pk, blob); err != nil {
		t.Fatalf("a write over the held record: %v", err)
	}
}
