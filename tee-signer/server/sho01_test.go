//go:build !debugimport

package server

import (
	"testing"

	"github.com/lidofinance/tee-signer/governance/handoverorder"
	"github.com/lidofinance/tee-signer/slashing-log"
)

// SHO-01: a source whose host lost its pending order's body reads the slot
// as an import and signs nothing until the order is pushed again. Before,
// the push ran the order's checks under the config in force first: once a
// rotation (or an image removal) voided the order, the push failed and the
// source stayed stopped for good, since an import also refuses every
// config update. Now the same order's body comes back on its hash alone
// (the locked slot holds the hash), and the source signs again.
func TestSHO01VoidOrderBodyComesBack(t *testing.T) {
	src := newSrcEnv(t, nil)
	keys := src.addKeys(2, &srcMark)
	tgt := newTargetOf(t, src, nil, nil, nil)
	order, hash := srcOrder(t, src, tgt, []byte{1, 2}, nil)
	if _, err := src.push(order); err != nil {
		t.Fatal(err)
	}
	src.clock.add(8 * testEpoch)

	// A rotation to approvers 4 to 6 comes into force: the order's signers
	// are no longer in force.
	ce := src.cfg()
	rot := ce.body(locked, 1, ce.groupHash(locked), 0)
	rot.Locked.Approvers = approverSet(2, 4, 5, 6)
	if _, _, _, err := src.marks.PutBody(ctx, signed(t, rot, first2, []byte{4, 5, 6})); err != nil {
		t.Fatal(err)
	}
	st := src.marks.State()
	st.Locked.Pending = &markstore.Pending{Version: 1, Hash: hashOf(t, rot), EffectiveAt: src.now() + 1}
	if err := src.marks.SetState(ctx, st); err != nil {
		t.Fatal(err)
	}
	// The host loses the order's body; the runner restarts.
	delete(src.store.m, handoverOrderKey(hash))
	src.restart()
	src.clock.add(testEpoch)
	if err := src.upd.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if m := src.marks.State(); m.Locked.Version != 1 || m.Order == nil || m.Order.Hash != hash {
		t.Fatalf("the log's state %+v", m)
	}
	if src.srv.importing() == nil {
		t.Fatal("the test wants the slot read as an import")
	}

	st2, err := src.push(order)
	if err != nil {
		t.Fatalf("the order again: %v", err)
	}
	if st2.Status != handoverorder.Void {
		t.Errorf("the order's status %v, want void", st2.Status)
	}
	if o := src.srv.importing(); o != nil {
		t.Fatalf("the slot still reads as an import: %x", o.Hash[:8])
	}
	src.clock.add(8 * testEpoch) // past the restart floor
	ep := src.signer.EpochAt(src.now())
	if err := src.attest(keys[0], ep-1, ep); err != nil {
		t.Fatalf("the source after its order's body came back: %v", err)
	}
}
