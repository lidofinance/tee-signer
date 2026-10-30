//go:build !debugimport

package server

import (
	"testing"

	"github.com/lidofinance/tee-signer/governance/handoverorder"
	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/wire"
	"github.com/lidofinance/tee-signer/tee-signer/handover"
)

// SHR-01: the source checked the target's IDENTITY answer for the
// requester's nonce, so an answer read before a config update on the
// target still passed after it. The source wrote its tombstone, and the
// target, now past version 0, refused the import: the shares were left
// nowhere. Now a target reserves itself for the order before it hands out
// the identity a source accepts (the order in its import slot), which
// stops every config update; the source refuses a target that is not
// reserved for its order. Either way no tombstone is written for a target
// that cannot take the shares.
func TestSHR01StaleTargetIdentity(t *testing.T) {
	src := newSrcEnv(t, nil)
	keys := src.addKeys(2, &srcMark)
	tgt := newTargetOf(t, src, nil, nil, nil)
	src.clock.add(8 * testEpoch)
	order, _ := srcOrder(t, src, tgt, []byte{1, 2}, nil)
	if _, err := src.push(order); err != nil {
		t.Fatal(err)
	}
	src.clock.add(srcDelay)

	// The identity, then an update the target's approvers sign.
	nonce := []byte("handover-source-test-nonce-0001")
	id, pub := identityFor(t, tgt, nonce)
	if _, _, err := tgt.cfg().send(tgt.importUpdates()["open"]); err != nil {
		t.Fatalf("the target's update: %v", err)
	}
	p, err := (&handover.Request{Nonce: nonce, Identity: id, Policy: pub, Order: order}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	b, err := src.srv.dispatch(ctx, wire.Frame{Type: handover.Type, Payload: p})
	if err != nil {
		// Refused before the tombstone: the source signs on.
		if _, ok := src.hooks.HandedOverTo(); ok {
			t.Fatal("refused, but the tombstone is written")
		}
		ep := src.signer.EpochAt(src.now())
		if err := src.attest(keys[0], ep-1, ep); err != nil {
			t.Fatalf("the source after the refusal: %v", err)
		}
		return
	}
	page, err := handover.DecodeResponse(b)
	if err != nil {
		t.Fatal(err)
	}
	r, err := tgt.imp(order, page, 0)
	if err != nil || !r.Done {
		t.Fatalf("the source wrote its tombstone for a target that does not take the shares: %+v %v", r, err)
	}
}

// The reservation: the order pushed to the target takes its import slot;
// the target then refuses config updates, other orders and sealed imports,
// so the identity a source checks stays true until the import. The same
// order again reports it reserved, also after a restart, and the handover
// goes through.
func TestSHR01ReservedTarget(t *testing.T) {
	src := newSrcEnv(t, nil)
	src.addKeys(3, &srcMark)
	tgt := newTargetOf(t, src, nil, nil, nil)
	src.clock.add(8 * testEpoch)
	order, hash := srcOrder(t, src, tgt, []byte{1, 2}, nil)
	if _, err := src.push(order); err != nil {
		t.Fatal(err)
	}
	src.clock.add(srcDelay)
	st, err := tgt.push(order)
	if err != nil || st.Outcome != handoverorder.Accepted || st.Hash != hash {
		t.Fatalf("reserve: %+v %v", st, err)
	}
	if o := tgt.srv.importing(); o == nil || o.Hash != hash {
		t.Fatalf("the target's slot %+v", o)
	}
	if _, _, err := tgt.cfg().send(tgt.importUpdates()["open"]); backend.StatusOf(err) != backend.StatusNotReady {
		t.Fatalf("a config update on a reserved target: %v", err)
	}
	other, _ := srcOrder(t, src, tgt, []byte{1, 2}, func(b *handoverorder.Body) { b.NotAfter++ })
	if _, err := tgt.push(other); err == nil {
		t.Fatal("a reserved target took another order")
	}
	sec := newSecret(t)
	if _, err := tgt.srv.addShareOf(newPubkey(t), &sec, 1, nil, "sealed", nil); err == nil {
		t.Fatal("a reserved target took a sealed import")
	}
	tgt.restart()
	if st, err := tgt.push(order); err != nil || st.Outcome != handoverorder.Known {
		t.Fatalf("the order again after a restart: %+v %v", st, err)
	}
	if _, imp := handOverAll(t, src, tgt, order); !imp.Done || imp.Held != 3 {
		t.Fatalf("import %+v", imp)
	}
}
