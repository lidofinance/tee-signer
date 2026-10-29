//go:build (peer_azure || peer_aws || peer_gcp || peer_dev) && !debugimport

package server

import (
	"slices"
	"strings"
	"testing"

	"github.com/lidofinance/tee-signer/governance/dkgorder"
	"github.com/lidofinance/tee-signer/governance/setupwire"
	"github.com/lidofinance/tee-signer/signer-core/core"
	"github.com/lidofinance/tee-signer/signer-core/software"
	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/wire"
	"github.com/lidofinance/tee-signer/slashing-log"
	"github.com/lidofinance/tee-signer/tee-signer/handover"
	"github.com/lidofinance/tee-signer/tee-signer/handoverorder"
)

// Tests of the source side (handover_source.go): a source and a target in
// one process, each a dev runner with the mark
// log (tgtEnv), the pages going from one to the other as the two tools
// carry them.

// srcDelay is the sources' change_delay_seconds: a dev runner's handover
// order waits it.
const srcDelay = 60

// newSrcEnv is a source at handover generation 1, changed by change.
func newSrcEnv(t *testing.T, change func(s *setupwire.Setup)) *tgtEnv {
	t.Helper()
	return newTgtEnv(t, "dev", func(s *setupwire.Setup) {
		s.HandoverGeneration = 1
		s.Locked.ChangeDelaySeconds = u64(srcDelay)
		if change != nil {
			change(s)
		}
	})
}

// newTargetOf is a target of src: src's setup with handover_generation one
// higher and version 0 of both groups as given (the source's values in
// force), new salts; then change.
func newTargetOf(t *testing.T, src *tgtEnv, l *setupwire.Locked, o *setupwire.Open, change func(s *setupwire.Setup)) *tgtEnv {
	t.Helper()
	tgt := newTgtEnv(t, "dev", func(s *setupwire.Setup) {
		fresh, err := setupwire.DecodeSetup(src.raw)
		if err != nil {
			t.Fatal(err)
		}
		*s = *fresh
		s.HandoverGeneration++
		if l != nil {
			s.Locked = *l
		}
		if o != nil {
			s.Open = *o
		}
		for i := range s.PolicySalts.Public {
			s.PolicySalts.Public[i][0] ^= 0x5a
		}
		for i := range s.PolicySalts.Locked {
			s.PolicySalts.Locked[i][1] ^= 0x5a
		}
		if change != nil {
			change(s)
		}
	})
	// One clock for both runners: the target moves with the source.
	tgt.clock = src.clock
	tgt.restart()
	return tgt
}

// addKeys stores n shares on e: the first gen made in key generation under
// order, the rest imported; the first one raises the log to mark.
func (e *tgtEnv) addKeys(n, gen int, order [32]byte, mark *backend.Watermark) []backend.Pubkey {
	e.t.Helper()
	var out []backend.Pubkey
	for i := range n {
		sk, _ := software.NewSecret()
		other, _ := software.NewSecret()
		pk, _ := core.PubkeyOf(other)
		var origin shareOrigin
		if i < gen {
			origin = shareOrigin{generated: true, order: order[:]}
		}
		var ic *backend.Watermark
		if i == 0 {
			ic = mark
		}
		if _, err := e.srv.addShareOf(pk, &sk, uint64(200+i), ic, "sealed", origin, nil); err != nil {
			e.t.Fatal(err)
		}
		out = append(out, pk)
	}
	return out
}

// srcOrder is a handover order from src to tgt, signed by the approvers
// ids, changed by change.
func srcOrder(t *testing.T, src, tgt *tgtEnv, ids []byte, change func(b *handoverorder.Body)) ([]byte, [32]byte) {
	t.Helper()
	b := handoverorder.Body{ClusterID: src.setup.ClusterID, ChainHash: src.setup.Chain.Hash(), NotAfter: src.now() + 12*3600,
		Source: handoverorder.Runner{Name: "signer-1", SetupHash: src.hash, Verifier: dkgorder.VerifierDev},
		Target: handoverorder.Runner{Name: "signer-1b", SetupHash: tgt.hash, Verifier: dkgorder.VerifierDev}}
	if change != nil {
		change(&b)
	}
	enc, err := b.Encode()
	if err != nil {
		t.Fatal(err)
	}
	o := handoverorder.Order{Body: b}
	for _, id := range ids {
		o.Approvals = append(o.Approvals, setupwire.Approval{Position: id - 1, Signature: handoverorder.SignBody(approver(id), enc)})
	}
	raw, err := o.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return raw, handoverorder.Hash(enc)
}

// push sends HANDOVER_ORDER to e.
func (e *tgtEnv) push(order []byte) (*handoverorder.State, error) {
	b, err := e.srv.dispatch(ctx, wire.Frame{Type: handoverorder.TypeOrder, Payload: order})
	if err != nil {
		return nil, err
	}
	st, err := handoverorder.DecodeState(b)
	if err != nil {
		e.t.Fatal(err)
	}
	return st, nil
}

// identityFor is tgt's IDENTITY answer for nonce and its published setup.
func identityFor(t *testing.T, tgt *tgtEnv, nonce []byte) ([]byte, []byte) {
	t.Helper()
	p, _ := wire.EncodeAttest(nonce)
	raw, err := tgt.srv.dispatch(ctx, wire.Frame{Type: wire.TypeIdentity, Payload: p})
	if err != nil {
		t.Fatal(err)
	}
	pub, err := setupwire.PublishedOf(tgt.setup)
	if err != nil {
		t.Fatal(err)
	}
	enc, err := pub.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return raw, enc
}

// handOver sends HANDOVER to src for tgt from share start, after the
// order went to tgt, which reserves itself for it (as handover-target
// identity -order does; a target that cannot reserve itself refuses, and
// the source then refuses it too).
func handOver(t *testing.T, src, tgt *tgtEnv, order []byte, start uint32) (*handover.Response, error) {
	t.Helper()
	tgt.push(order) //nolint:errcheck // the source checks the outcome
	nonce := []byte("handover-source-test-nonce-0001")
	id, pub := identityFor(t, tgt, nonce)
	p, err := (&handover.Request{Nonce: nonce, Identity: id, Policy: pub, Order: order, Start: start}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	b, err := src.srv.dispatch(ctx, wire.Frame{Type: handover.Type, Payload: p})
	if err != nil {
		return nil, err
	}
	r, err := handover.DecodeResponse(b)
	if err != nil {
		t.Fatal(err)
	}
	return r, nil
}

// handOverAll fetches every page and passes each to the target.
func handOverAll(t *testing.T, src, tgt *tgtEnv, order []byte) (*handover.Response, *handover.ImportResponse) {
	t.Helper()
	var first *handover.Response
	var last *handover.ImportResponse
	for start := uint32(0); ; {
		r, err := handOver(t, src, tgt, order, start)
		if err != nil {
			t.Fatal(err)
		}
		if first == nil {
			first = r
		}
		last = tgt.mustImp(order, r, 0)
		start += uint32(len(r.Shares))
		if start >= r.Total {
			return first, last
		}
	}
}

// srcMark is what the source signed before: target epoch startEpoch+4.
var srcMark = testMark

// The whole handover between two runners of this branch: the order waits
// its delay while the source signs on; the first page writes the tombstone
// that names the target and carries the mark, the key origin and the day's
// exits; the source signs nothing after it, also after a restart, takes no
// other order and answers no other target; the target signs above the mark
// and keeps the exits.
func TestHandoverSource(t *testing.T) {
	src := newSrcEnv(t, nil)
	dkg := [32]byte{0xd7}
	keys := src.addKeys(300, 200, dkg, &srcMark)
	tgt := newTargetOf(t, src, nil, nil, nil)
	src.clock.add(8 * testEpoch) // past the imported mark
	order, hash := srcOrder(t, src, tgt, []byte{1, 2}, nil)

	// An exit the source signed today: its record in the log.
	day := &markstore.ExitDay{Day: src.now() / daySeconds, Stake: 32_000_000_000,
		Exits: []markstore.ExitEntry{{ValidatorIndex: 7, ExitEpoch: startEpoch, Stake: 32_000_000_000, Nonce: [32]byte{0xe1}}}}
	if err := src.hooks.RecordExits(ctx, day); err != nil {
		t.Fatal(err)
	}

	st, err := src.push(order)
	if err != nil || st.Status != handoverorder.Pending || st.ActAt != st.Arrived+srcDelay {
		t.Fatalf("order: %+v %v", st, err)
	}
	if id := identityOf(t, src.srv, []byte("n-0123456789abcdef")); id.State.Order.Kind != uint8(markstore.OrderHandover) || id.State.Order.Hash != hash {
		t.Fatalf("IDENTITY's order slot %+v", id.State.Order)
	}
	// Inside the wait the source signs (the slot holds its own order, no
	// import); after a restart it still reads the slot as its own order.
	// The handover waits.
	e := src.signer.EpochAt(src.now())
	if err := src.attest(keys[0], e-1, e); err != nil {
		t.Fatalf("the source inside the wait: %v", err)
	}
	src.restart()
	if o := src.srv.importing(); o != nil {
		t.Fatalf("after a restart the source reads its own order as an import %x", o.Hash[:8])
	}
	if _, err := handOver(t, src, tgt, order, 0); err == nil || !strings.Contains(err.Error(), "waits until") {
		t.Fatalf("inside the wait: %v", err)
	}
	if st, _ := src.push(order); st.Status != handoverorder.Pending {
		t.Fatalf("the same order again: %+v", st)
	}

	src.clock.add(srcDelay)
	page, imp := handOverAll(t, src, tgt, order)
	// The mark before the tombstone: at least what the source signed (the
	// log writes ahead of the core, slashing_mark_prewrite).
	wantMark, _ := src.marks.HandedOver()
	if wantMark.TargetEpoch < e || !wantMark.HasAttestation {
		t.Fatalf("the mark before the tombstone %+v, the source signed target %d", wantMark, e)
	}
	if page.Mark != wantMark || page.Total != 300 || page.Carry.Exits == nil || page.Carry.Exits.Stake != day.Stake {
		t.Fatalf("first page: mark %+v total %d carry %+v", page.Mark, page.Total, page.Carry)
	}
	if !imp.Done || imp.Held != 300 || imp.Generated != 200 || imp.Imported != 100 {
		t.Fatalf("import: %+v", imp)
	}
	if ko := tgt.srv.SetupState().KeyOrigin; ko.OrdersHash != backend.KeygenOrdersHash([][32]byte{dkg}) {
		t.Fatalf("target key origin %+v", ko)
	}

	// The tombstone names the target; the source signs nothing.
	recs := src.records()
	if last := recs[len(recs)-1]; last.Target == nil || *last.Target != tgt.hash || last.Mark != markstore.Tombstone {
		t.Fatalf("the source's last record %+v", last)
	}
	if err := src.attest(keys[0], startEpoch+9, startEpoch+10); err == nil {
		t.Fatal("the source signed after its tombstone")
	}
	// The target: at or below the mark refused, above it signed (past its
	// restart floor), the source's exit of the day in its log.
	if err := tgt.attest(keys[0], wantMark.SourceEpoch, wantMark.TargetEpoch); err == nil {
		t.Fatal("the target signed at the handed-over mark")
	}
	src.clock.add(8 * testEpoch)
	if err := tgt.attest(keys[0], startEpoch+15, startEpoch+16); err != nil {
		t.Fatalf("the target above the mark: %v", err)
	}
	if d, _ := tgt.hooks.Exits(); d == nil || d.Day != day.Day || d.Stake != day.Stake || len(d.Exits) != 1 || d.Exits[0].Nonce != day.Exits[0].Nonce {
		t.Fatalf("the target's exits %+v", d)
	}

	// After a restart: still nothing signed, the same mark for the same
	// target, no other order, no other target.
	src.restart()
	if err := src.attest(keys[0], startEpoch+19, startEpoch+20); err == nil {
		t.Fatal("the source signed after a restart past its tombstone")
	}
	if st, err := src.push(order); err != nil || st.Status != handoverorder.Done {
		t.Fatalf("the order after the tombstone: %+v %v", st, err)
	}
	again, err := handOver(t, src, tgt, order, 0)
	if err != nil || again.Mark != wantMark {
		t.Fatalf("the handover again after a restart: %v", err)
	}
	other := newTargetOf(t, src, nil, nil, func(s *setupwire.Setup) { s.MaxKeys = 2048 })
	o2, _ := srcOrder(t, src, other, []byte{1, 2}, nil)
	if _, err := src.push(o2); err == nil || !strings.Contains(err.Error(), "handed over to setup") {
		t.Fatalf("a second order after the tombstone: %v", err)
	}
	if _, err := handOver(t, src, other, o2, 0); err == nil || !strings.Contains(err.Error(), "one target only") {
		t.Fatalf("another target after the tombstone: %v", err)
	}
	// Past its not_after the order stays in the slot: the tombstone names
	// its target.
	src.clock.add(13 * 3600)
	if err := src.srv.Updates.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if o := identityOf(t, src.srv, []byte("n-0123456789abcdef")).State.Order; o.Hash != hash {
		t.Fatalf("the slot after the tombstone and past not_after %+v", o)
	}
	if _, err := handOver(t, src, tgt, order, 0); err != nil {
		t.Fatalf("the handover again past not_after: %v", err)
	}
}

// At its not_after a source order leaves the order slot by itself, so
// IDENTITY no longer shows it in front of a DKG order that waits: the view
// drops it, Sync writes the cleared slot to the log, and a restart keeps it
// clear. The order is then refused as expired, and a new one takes the
// slot.
func TestHandoverSourceOrderExpires(t *testing.T) {
	src := newSrcEnv(t, nil)
	src.addKeys(2, 0, [32]byte{}, &srcMark)
	tgt := newTargetOf(t, src, nil, nil, nil)
	notAfter := src.now() + 2*srcDelay
	order, hash := srcOrder(t, src, tgt, []byte{1, 2}, func(b *handoverorder.Body) { b.NotAfter = notAfter })
	if _, err := src.push(order); err != nil {
		t.Fatal(err)
	}
	slot := func() backend.Order {
		t.Helper()
		return identityOf(t, src.srv, []byte("n-0123456789abcdef")).State.Order
	}
	src.clock.add(notAfter - 1 - src.now())
	if o := slot(); o.Kind != uint8(markstore.OrderHandover) || o.Hash != hash {
		t.Fatalf("the slot a second before not_after %+v", o)
	}
	src.clock.add(1)
	if o := slot(); o.Kind != 0 {
		t.Fatalf("the slot at not_after %+v", o)
	}
	if o := src.marks.State().Order; o == nil || o.Hash != hash {
		t.Fatalf("the log's slot before Sync %+v", o)
	}
	if err := src.srv.Updates.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if o := src.marks.State().Order; o != nil {
		t.Fatalf("the log's slot after Sync %+v", o)
	}
	src.restart()
	if o := slot(); o.Kind != 0 {
		t.Fatalf("the slot after a restart %+v", o)
	}
	if _, err := handOver(t, src, tgt, order, 0); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("the expired order: %v", err)
	}
	if _, err := src.push(order); err == nil || !strings.Contains(err.Error(), "not_after") {
		t.Fatalf("the expired order pushed again: %v", err)
	}
	o2, h2 := srcOrder(t, src, tgt, []byte{1, 2}, nil)
	if st, err := src.push(o2); err != nil || st.Status != handoverorder.Pending {
		t.Fatalf("a new order: %+v %v", st, err)
	}
	if o := slot(); o.Hash != h2 {
		t.Fatalf("the slot with the new order %+v", o)
	}
}

// The target's version 0 must be the source's config in force: after a
// locked update came into force on the source, a target with the setup's
// first values is refused and one with the update's values taken.
func TestHandoverSourceConfigInForce(t *testing.T) {
	src := newSrcEnv(t, nil)
	src.addKeys(4, 0, [32]byte{}, &srcMark)
	lh, _ := src.setup.GroupHash(locked)
	fresh, _ := setupwire.DecodeSetup(src.raw)
	b := &setupwire.UpdateBody{ClusterID: src.setup.ClusterID, ChainHash: src.setup.Chain.Hash(), Group: locked, Version: 1, PrevHash: lh,
		ActivateAt: src.now() + 3*srcDelay, Locked: &fresh.Locked}
	b.Locked.BuilderGasLimitMax += 1_000_000
	b.Salts = testSalts(b)
	if _, _, err := src.srv.Updates.Accept(ctx, signed(t, b, first2, nil)); err != nil {
		t.Fatal(err)
	}
	// Pending: a handover waits for it.
	stale := newTargetOf(t, src, nil, nil, nil)
	order, _ := srcOrder(t, src, stale, []byte{1, 2}, nil)
	if _, err := src.push(order); err != nil {
		t.Fatal(err)
	}
	src.clock.add(srcDelay)
	if _, err := handOver(t, src, stale, order, 0); err == nil || !strings.Contains(err.Error(), "pending here") {
		t.Fatalf("with an update pending: %v", err)
	}
	src.clock.add(3 * srcDelay)
	if _, err := handOver(t, src, stale, order, 0); err == nil || !strings.Contains(err.Error(), "locked.builder_gas_limit_max") {
		t.Fatalf("a target with the first values: %v", err)
	}
	if ep := src.signer.EpochAt(src.now()); src.attest(src.signer.Keys()[0].Pubkey, ep-1, ep) != nil {
		t.Fatal("the source does not sign after a refused handover")
	}
	// The first order expires; the next one takes its place.
	src.clock.add(13 * 3600)
	good := newTargetOf(t, src, b.Locked, nil, nil)
	o2, _ := srcOrder(t, src, good, []byte{1, 2}, nil)
	if _, err := src.push(o2); err != nil {
		t.Fatalf("an order replacing an expired one: %v", err)
	}
	src.clock.add(srcDelay)
	if _, imp := handOverAll(t, src, good, o2); !imp.Done || imp.Held != 4 {
		t.Fatalf("import %+v", imp)
	}
}

// The checks before the tombstone: each refusal leaves the source as it
// was, signing.
func TestHandoverSourceRefusals(t *testing.T) {
	src := newSrcEnv(t, nil)
	keys := src.addKeys(3, 0, [32]byte{}, &srcMark)
	tgt := newTargetOf(t, src, nil, nil, nil)
	stillSigns := func(what string) {
		t.Helper()
		e := src.signer.EpochAt(src.now())
		if err := src.attest(keys[0], e-1, e); err != nil {
			t.Fatalf("%s: the source does not sign: %v", what, err)
		}
		if _, ok := src.hooks.HandedOverTo(); ok {
			t.Fatalf("%s: tombstone written", what)
		}
	}

	// Orders refused at intake.
	for name, c := range map[string]struct {
		ids    []byte
		change func(b *handoverorder.Body)
		want   string
	}{
		"one approver":    {[]byte{1}, nil, "approvals"},
		"another cluster": {[]byte{1, 2}, func(b *handoverorder.Body) { b.ClusterID[0] ^= 1 }, "cluster_id"},
		"another source":  {[]byte{1, 2}, func(b *handoverorder.Body) { b.Source.SetupHash[0] ^= 1 }, "its source is setup"},
		"too short":       {[]byte{1, 2}, func(b *handoverorder.Body) { b.NotAfter = src.now() + srcDelay }, "not_after"},
	} {
		o, _ := srcOrder(t, src, tgt, c.ids, c.change)
		if _, err := src.push(o); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v", name, err)
		}
	}

	// Targets refused at the handover, one order each.
	cases := []struct {
		name   string
		target func() *tgtEnv
		want   string
	}{
		{"generation 3", func() *tgtEnv {
			return newTargetOf(t, src, nil, nil, func(s *setupwire.Setup) { s.HandoverGeneration++ })
		}, "public.handover_generation"},
		{"another chain value", func() *tgtEnv {
			return newTargetOf(t, src, nil, nil, func(s *setupwire.Setup) { s.Safety.MaxSignEpochsAheadOfClock++ })
		}, "public.max_sign_epochs_ahead_of_clock"},
		{"a target that holds a key", func() *tgtEnv {
			e := newTargetOf(t, src, nil, nil, nil)
			e.addKeys(1, 0, [32]byte{}, nil)
			return e
		}, "holds 1 keys"},
		{"too small", func() *tgtEnv {
			return newTargetOf(t, src, nil, nil, func(s *setupwire.Setup) { s.MaxKeys = 2 })
		}, "max_keys is 2"},
	}
	for _, c := range cases {
		bad := c.target()
		o, _ := srcOrder(t, src, bad, []byte{1, 2}, nil)
		if _, err := src.push(o); err != nil {
			t.Fatalf("%s: order: %v", c.name, err)
		}
		src.clock.add(srcDelay)
		if _, err := handOver(t, src, bad, o, 0); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Fatalf("%s: %v", c.name, err)
		}
		// The next order replaces this one only once it is void or expired:
		// let it expire.
		src.clock.add(13 * 3600)
		stillSigns(c.name)
	}

	// The wrong target for the order: its identity is another setup's.
	o, _ := srcOrder(t, src, tgt, []byte{1, 2}, nil)
	if _, err := src.push(o); err != nil {
		t.Fatal(err)
	}
	src.clock.add(srcDelay)
	other := newTargetOf(t, src, nil, nil, func(s *setupwire.Setup) { s.MaxKeys = 512 })
	if _, err := handOver(t, src, other, o, 0); err == nil || !strings.Contains(err.Error(), "the order names") {
		t.Fatalf("another target than the order's: %v", err)
	}
	// A second order while one is active.
	o2, _ := srcOrder(t, src, other, []byte{1, 2}, nil)
	if _, err := src.push(o2); err == nil || !strings.Contains(err.Error(), "one order at a time") {
		t.Fatalf("a second order: %v", err)
	}
	// Expired.
	src.clock.add(13 * 3600)
	if _, err := handOver(t, src, tgt, o, 0); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expired: %v", err)
	}
	stillSigns("after every refusal")
	if slices.ContainsFunc(src.records(), func(r *markstore.Record) bool { return r.Target != nil }) {
		t.Fatal("a refused handover wrote a tombstone")
	}
}

// A source order in the slot is no import, also when the host lost its
// body: then the source reads the slot as an import and signs nothing
// until the order comes again, which restores the body.
func TestHandoverSourceOrderBodyLost(t *testing.T) {
	src := newSrcEnv(t, nil)
	keys := src.addKeys(2, 0, [32]byte{}, &srcMark)
	tgt := newTargetOf(t, src, nil, nil, nil)
	order, hash := srcOrder(t, src, tgt, []byte{1, 2}, nil)
	if _, err := src.push(order); err != nil {
		t.Fatal(err)
	}
	src.clock.add(8 * testEpoch)
	if err := src.attest(keys[0], startEpoch+7, startEpoch+8); err != nil {
		t.Fatal(err)
	}
	delete(src.store.m, handoverOrderKey(hash))
	src.restart()
	if err := src.attest(keys[0], startEpoch+8, startEpoch+9); err == nil || !strings.Contains(err.Error(), "handover import") {
		t.Fatalf("with the body lost: %v", err)
	}
	if st, err := src.push(order); err != nil || st.Status != handoverorder.Active {
		t.Fatalf("the order again: %+v %v", st, err)
	}
	src.clock.add(8 * testEpoch) // past the restart floor
	ep := src.signer.EpochAt(src.now())
	if err := src.attest(keys[0], ep-1, ep); err != nil {
		t.Fatalf("after the body came back: %v", err)
	}
}
