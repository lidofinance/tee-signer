//go:build !debugimport

package server

import (
	"strings"
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

// The host puts back a record of A from before a reset rewrote it: the
// source refuses the handover (the record is not the one it wrote), and
// after a restart, which loads every key without history and with a
// fresh floor, both keys wait at the target.
func TestRolledBackRecordStopsTheHandover(t *testing.T) {
	src := newSrcEnv(t, nil)
	tgt := newTargetOf(t, src, nil, nil, nil)
	floor := src.floorOf()
	var pks []backend.Pubkey
	for i := range 3 {
		sk, pk := newKey(t)
		if err := src.importSealed(pk, sk, uint64(5+i), nil); err != nil {
			t.Fatal(err)
		}
		pks = append(pks, pk)
	}
	rolled, other := pks[0], pks[2]
	old, err := src.store.Get(shareKey(rolled))
	if err != nil {
		t.Fatal(err)
	}
	src.clock.add(3 * testEpoch)
	// Not the last write's key: the set before that write is vouched too.
	src.deleteShare(pks[1]) // a reset at the next start rewrites the others
	src.restart()
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
	for _, pk := range []backend.Pubkey{rolled, other} {
		if r := src.recordOf(pk); r.History || r.SourceFloor <= floor {
			t.Fatalf("after the restart: history %t floor %d", r.History, r.SourceFloor)
		}
	}
	if _, imp := handOverAll(t, src, tgt, order); !imp.Done {
		t.Fatalf("import %+v", imp)
	}
	f := tgt.floorOf()
	tgt.clock.add((f - tgt.signer.EpochAt(tgt.now())) * testEpoch)
	for _, pk := range []backend.Pubkey{rolled, other} {
		wantSlashSource(t, tgt.attest(pk, floor, f+1), "after the reset, below the target's floor")
	}
}
