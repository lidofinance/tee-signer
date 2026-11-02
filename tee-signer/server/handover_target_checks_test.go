//go:build !debugimport

package server

import (
	"testing"

	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/wire"
	"github.com/lidofinance/tee-signer/tee-signer/handover"
)

// An admin of a reserved target cannot end the import with shares of its
// own before the source hands over: a request that skips the origin
// checks is refused and the reservation holds. The source then hands over
// to the identity it was shown, and the target takes the source's shares.
func TestHandoverTargetTakesOnlyTheSourcesShares(t *testing.T) {
	src := newSrcEnv(t, nil)
	src.addKeys(4, &srcMark)
	tgt := newTargetOf(t, src, nil, nil, nil)
	src.clock.add(8 * testEpoch)
	order, hash := srcOrder(t, src, tgt, []byte{1, 2}, nil)
	if _, err := src.push(order); err != nil {
		t.Fatal(err)
	}
	src.clock.add(srcDelay)
	if _, err := tgt.push(order); err != nil {
		t.Fatal(err)
	}
	nonce := []byte("handover-source-test-nonce-0001")
	id, pub := identityFor(t, tgt, nonce) // reserved, empty

	fake := newSource(t, 2, testMark)
	_, err := tgt.imp(order, fake.pages(tgt.sealTo(), hash, 8)[0], handover.ImportAsImported)
	refusedImport(t, err, backend.StatusBadRequest, "origin checks are required")
	if n := len(tgt.srv.Signer.Keys()); n != 0 {
		t.Fatalf("the target took %d keys of another source", n)
	}
	if o := tgt.srv.importing(); o == nil || o.Hash != hash {
		t.Fatal("the target's reservation is gone")
	}

	p, _ := (&handover.Request{Nonce: nonce, Identity: id, Policy: pub, Order: order}).Encode()
	b, err := src.srv.dispatch(ctx, wire.Frame{Type: handover.Type, Payload: p})
	if err != nil {
		t.Fatalf("source: %v", err)
	}
	page, err := handover.DecodeResponse(b)
	if err != nil {
		t.Fatal(err)
	}
	r := tgt.mustImp(order, page, 0)
	if !r.Done || r.Held != 4 {
		t.Fatalf("the source's shares: %+v", r)
	}
}

// A target with sealed import off cannot reserve itself for a handover.
func TestHandoverReserveNeedsSealedImport(t *testing.T) {
	src := newSrcEnv(t, nil)
	src.addKeys(2, &srcMark)
	tgt := newTargetOf(t, src, nil, nil, nil)
	src.clock.add(8 * testEpoch)
	order, _ := srcOrder(t, src, tgt, []byte{1, 2}, nil)
	if _, err := src.push(order); err != nil {
		t.Fatal(err)
	}
	src.clock.add(srcDelay)
	tgt.srv.ImportKey = nil
	if _, err := tgt.push(order); backend.StatusOf(err) != backend.StatusUnsupported {
		t.Fatalf("reservation with sealed import off: %v", err)
	}
	if o := tgt.srv.importing(); o != nil {
		t.Fatalf("the target reserved itself: %x", o.Hash[:8])
	}
}

// A source refuses a target whose identity offers no import key before it
// writes its tombstone: it stays in service and hands over once the
// target can take the shares.
func TestHandoverSourceStaysWithATargetThatCannotImport(t *testing.T) {
	src := newSrcEnv(t, nil)
	src.addKeys(2, &srcMark)
	tgt := newTargetOf(t, src, nil, nil, nil)
	src.clock.add(8 * testEpoch)
	order, _ := srcOrder(t, src, tgt, []byte{1, 2}, nil)
	if _, err := src.push(order); err != nil {
		t.Fatal(err)
	}
	src.clock.add(srcDelay)
	// Reserved while it could import, then its identity offers no key.
	if _, err := tgt.push(order); err != nil {
		t.Fatal(err)
	}
	key := tgt.srv.ImportKey
	tgt.srv.ImportKey = nil
	_, err := handOver(t, src, tgt, order, 0)
	if src.srv.HandedOver() {
		t.Fatalf("the source wrote its tombstone for a target without an import key (handover: %v)", err)
	}
	if err == nil {
		t.Fatal("the source handed over to a target without an import key")
	}
	tgt.srv.ImportKey = key
	if _, last := handOverAll(t, src, tgt, order); !last.Done || last.Held != 2 {
		t.Fatalf("handover after the target can import: %+v", last)
	}
}
