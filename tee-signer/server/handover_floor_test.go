//go:build !debugimport

package server

import (
	"strings"
	"testing"

	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/wire"
	"github.com/lidofinance/tee-signer/tee-signer/handover"
)

// HSH-01: the source's device mark went to the target as every share's
// history once any key had attested, so the target exempted keys imported
// without history from every source bound. Each share now carries its own
// history state: A (no history at the source) keeps a source floor at the
// target, also after a restart, and B (imported with history) keeps none
// above its history.
func TestHSH01HandoverKeepsEachKeysHistoryState(t *testing.T) {
	src := newSrcEnv(t, nil)
	tgt := newTargetOf(t, src, nil, nil, nil)
	start := src.signer.EpochAt(src.now())
	skb, pkb := newKey(t)
	hist := &backend.Watermark{HasAttestation: true, SourceEpoch: start - 3, TargetEpoch: start - 2}
	if err := src.importSealed(pkb, skb, 6, hist); err != nil {
		t.Fatal(err)
	}
	ska, pka := newKey(t)
	floorA := src.floorOf()
	if err := src.importSealed(pka, ska, 5, nil); err != nil {
		t.Fatal(err)
	}
	// The handover follows within a few epochs: the device source (B's
	// history) is still below A's floor.
	order, _ := srcOrder(t, src, tgt, []byte{1, 2}, nil)
	if _, err := src.push(order); err != nil {
		t.Fatal(err)
	}
	src.clock.add(srcDelay)
	page, imp := handOverAll(t, src, tgt, order)
	if !imp.Done || !page.Mark.HasAttestation || page.Mark.SourceEpoch >= floorA {
		t.Fatalf("import %+v, mark %+v: want a done import under a mark with a source below %d", imp, page.Mark, floorA)
	}
	check := func(when string) {
		t.Helper()
		f := tgt.floorOf()
		tgt.clock.add((f - tgt.signer.EpochAt(tgt.now())) * testEpoch)
		e := tgt.signer.EpochAt(tgt.now())
		wantSlashSource(t, tgt.attest(pka, floorA-1, e+1), when+": A (no history at the source) below its source floor")
		if err := tgt.attest(pkb, start-3, e+1); err != nil {
			t.Errorf("%s: B at its own history's source %d: %v", when, start-3, err)
		}
	}
	check("after the import")
	tgt.restart()
	check("after a restart")
}

// Handover version 2 added each share's history state. A source and a
// target of different versions refuse each other, so a floor is never
// dropped on the way: this source refuses a version 1 request before its
// tombstone, and this target refuses a version 1 page before it stores a
// share.
func TestHandoverVersionMismatchRefused(t *testing.T) {
	src := newSrcEnv(t, nil)
	src.addKeys(2, nil)
	tgt := newTargetOf(t, src, nil, nil, nil)
	order, _ := srcOrder(t, src, tgt, []byte{1, 2}, nil)
	if _, err := src.push(order); err != nil {
		t.Fatal(err)
	}
	src.clock.add(srcDelay)
	tgt.push(order) //nolint:errcheck // reserves the target, as handOver does
	nonce := []byte("handover-version-test-nonce-0001")
	id, pub := identityFor(t, tgt, nonce)
	q, err := (&handover.Request{Nonce: nonce, Identity: id, Policy: pub, Order: order}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	q[0] = 1
	if _, err := src.srv.dispatch(ctx, wire.Frame{Type: handover.Type, Payload: q}); err == nil || !strings.Contains(err.Error(), "version 1") {
		t.Fatalf("a version 1 request: %v", err)
	}
	if src.hooks.HandedOver() {
		t.Fatal("the source wrote its tombstone for a version 1 request")
	}
	page, err := handOver(t, src, tgt, order, 0)
	if err != nil {
		t.Fatal(err)
	}
	p, err := (&handover.ImportRequest{Order: order, Page: page}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	p[2+4+len(order)+4] = 1 // the page's version byte
	if _, err := tgt.srv.dispatch(ctx, wire.Frame{Type: handover.TypeImport, Payload: p}); err == nil || !strings.Contains(err.Error(), "version 1") {
		t.Fatalf("a version 1 page: %v", err)
	}
	if n := len(tgt.signer.Keys()); n != 0 {
		t.Fatalf("the target took a version 1 page: %d keys", n)
	}
}

// A page whose source floor lies past the clock horizon is refused before
// anything is stored: it would keep the key from voting for good.
func TestHandoverSourceFloorHorizon(t *testing.T) {
	src := newSrcEnv(t, nil)
	sk, pk := newKey(t)
	if err := src.importSealed(pk, sk, 5, nil); err != nil {
		t.Fatal(err)
	}
	tgt := newTargetOf(t, src, nil, nil, nil)
	order, _ := srcOrder(t, src, tgt, []byte{1, 2}, nil)
	if _, err := src.push(order); err != nil {
		t.Fatal(err)
	}
	src.clock.add(srcDelay)
	page, err := handOver(t, src, tgt, order, 0)
	if err != nil {
		t.Fatal(err)
	}
	page.Shares[0].SourceFloor = tgt.floorOf() + 50
	if _, err := tgt.imp(order, page, 0); err == nil || !strings.Contains(err.Error(), "source floor") {
		t.Fatalf("a far-future source floor: %v", err)
	}
	if n := len(tgt.signer.Keys()); n != 0 {
		t.Fatalf("the target stored %d keys", n)
	}
}

// The target keeps the higher of the source's floor and its own clock
// floor. Behind the source's clock, the target keeps the source's floor
// and refuses a vote below it; with its clock ahead, it keeps its own.
func TestHandoverTargetTakesTheHigherFloor(t *testing.T) {
	src := newSrcEnv(t, nil)
	tgt := newTargetOf(t, src, nil, nil, nil)
	start, _ := src.clock.Now()
	tgt.clock = &fakeClock{t: start, trusted: true} // its own clock from here
	tgt.restart()
	src.clock.add(10 * testEpoch)
	floorA := src.floorOf()
	ska, pka := newKey(t)
	if err := src.importSealed(pka, ska, 5, nil); err != nil {
		t.Fatal(err)
	}
	tgt.clock.add(8 * testEpoch) // behind the source, inside the horizon
	order, _ := srcOrder(t, src, tgt, []byte{1, 2}, nil)
	if _, err := src.push(order); err != nil {
		t.Fatal(err)
	}
	src.clock.add(srcDelay)
	tgt.clock.add(srcDelay)
	own := tgt.floorOf()
	if own >= floorA {
		t.Fatalf("the target's floor %d is not below the source's %d", own, floorA)
	}
	if _, imp := handOverAll(t, src, tgt, order); !imp.Done {
		t.Fatalf("import %+v", imp)
	}
	if r := tgt.recordOf(pka); r.History || r.SourceFloor != floorA {
		t.Fatalf("behind the source: history %t floor %d, want the source's floor %d", r.History, r.SourceFloor, floorA)
	}
	f := tgt.floorOf()
	tgt.clock.add((max(f, floorA) + 1 - tgt.signer.EpochAt(tgt.now())) * testEpoch)
	e := tgt.signer.EpochAt(tgt.now())
	wantSlashSource(t, tgt.attest(pka, floorA-1, e+1), "behind the source: below the source's floor")
}

func TestHandoverTargetClockAheadKeepsItsFloor(t *testing.T) {
	src := newSrcEnv(t, nil)
	tgt := newTargetOf(t, src, nil, nil, nil)
	floorA := src.floorOf()
	ska, pka := newKey(t)
	if err := src.importSealed(pka, ska, 5, nil); err != nil {
		t.Fatal(err)
	}
	order, _ := srcOrder(t, src, tgt, []byte{1, 2}, nil)
	if _, err := src.push(order); err != nil {
		t.Fatal(err)
	}
	src.clock.add(srcDelay + 4*testEpoch)
	own := tgt.floorOf()
	if own <= floorA {
		t.Fatalf("the target's floor %d is not above the source's %d", own, floorA)
	}
	if _, imp := handOverAll(t, src, tgt, order); !imp.Done {
		t.Fatalf("import %+v", imp)
	}
	if r := tgt.recordOf(pka); r.History || r.SourceFloor != own {
		t.Fatalf("ahead of the source: history %t floor %d, want its own floor %d", r.History, r.SourceFloor, own)
	}
}

// An import with vote history gets no import floor (a liveness check: its
// history in the mark bounds it).
func TestImportWithHistoryGetsNoFloor(t *testing.T) {
	e := newTgtEnv(t, "dev", nil)
	start := e.signer.EpochAt(e.now())
	sk, pk := newKey(t)
	hist := &backend.Watermark{HasAttestation: true, SourceEpoch: start - 3, TargetEpoch: start - 2}
	if err := e.importSealed(pk, sk, 6, hist); err != nil {
		t.Fatal(err)
	}
	if r := e.recordOf(pk); !r.History || r.SourceFloor != 0 {
		t.Fatalf("history %t floor %d", r.History, r.SourceFloor)
	}
	if f, on := e.hooks.SourceFloor(pk); on {
		t.Fatalf("a source floor %d holds for a key with history", f)
	}
}
