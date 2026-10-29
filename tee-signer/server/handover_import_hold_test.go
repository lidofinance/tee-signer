//go:build (peer_azure || peer_aws || peer_gcp || peer_dev) && !debugimport

package server

import (
	"bytes"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/lidofinance/tee-signer/governance/setupwire"
	"github.com/lidofinance/tee-signer/signer-core/core"
	"github.com/lidofinance/tee-signer/signer-core/software"
	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/dkgmsg"
	"github.com/lidofinance/tee-signer/signer-protocol/wire"
	wireadmin "github.com/lidofinance/tee-signer/signer-protocol/wire/admin"
	"github.com/lidofinance/tee-signer/slashing-log"
	"github.com/lidofinance/tee-signer/tee-signer/handoverorder"
	"github.com/lidofinance/tee-signer/tee-signer/keygen"
)

// Tests that the order slot of a handover import holds until every share
// is in (importslot.go): no config update, share or DKG order clears it or
// slips in, also across a restart.

// cfg is the target as the config update tests see it (config_test.go),
// for env.body, env.send and env.mustSend.
func (e *tgtEnv) cfg() *env {
	return &env{t: e.t, raw: e.raw, setup: e.setup, hash: e.hash, clock: e.clock, srv: e.srv, signer: e.signer, upd: e.upd}
}

// attestNow signs an attestation of pk for the epoch of the clock.
func (e *tgtEnv) attestNow(pk backend.Pubkey) error {
	ep := (e.now() - testGenesis) / testEpoch
	return e.attest(pk, ep-1, ep)
}

// importUpdates are config updates of the setup's approvers 1 and 2 that a
// target takes at once when no import runs (time lock 0): a rotation to
// approvers 4 to 6, a locked update of the fee recipients, and an open
// update with a fork far ahead.
func (e *tgtEnv) importUpdates() map[string][]byte {
	t, ce := e.t, e.cfg()
	rot := ce.body(locked, 1, ce.groupHash(locked), 0)
	rot.Locked.Approvers = approverSet(2, 4, 5, 6)
	fee := ce.body(locked, 1, ce.groupHash(locked), 0)
	fee.Locked.AllowedFeeRecipients = append(fee.Locked.AllowedFeeRecipients, x)
	slices.SortFunc(fee.Locked.AllowedFeeRecipients, func(a, c backend.Address) int { return bytes.Compare(a[:], c[:]) })
	fee.Salts = testSalts(fee)
	op := ce.body(open, 1, ce.groupHash(open), 0)
	op.Open.ForkSchedule = append(op.Open.ForkSchedule, setupwire.Fork{Epoch: 1 << 20, Version: v6})
	return map[string][]byte{"rotation": signed(t, rot, first2, []byte{4, 5, 6}), "locked": signed(t, fee, first2, nil), "open": signed(t, op, first2, nil)}
}

// The import's config stays the setup's version 0 until every share is in.
// The bug this guards against: a rotation that came into force mid-import
// dropped the order slot with what the old set signed, so the target
// signed before the last share was in, and the rest of the import was
// refused as an import on a runner that holds keys. Now a rotation, a
// locked and an open update are refused mid-import, also after a restart;
// the slot and version 0 hold and nothing is signed. Once the import ends
// the same rotation is taken.
func TestHandoverImportRefusesConfigUpdates(t *testing.T) {
	e := newTgtEnv(t, "dev", nil)
	src := newSource(t, 24, 0, [][32]byte{{0xd1}}, testMark)
	order, hash := e.order([]byte{1, 2}, nil)
	pages := src.pages(e.sealTo(), hash, 8)
	e.mustImp(order, pages[0], 0)
	updates := e.importUpdates()
	pk := src.shares[0].pk

	holds := func(when string) {
		t.Helper()
		for name, raw := range updates {
			_, _, err := e.cfg().send(raw)
			var r *backend.RefusedError
			if !errors.As(err, &r) || r.Code != backend.StatusNotReady || !strings.Contains(r.Detail, "handover import") {
				t.Fatalf("%s: the %s update: %v", when, name, err)
			}
		}
		e.clock.add(testEpoch)
		if err := e.upd.Sync(ctx); err != nil {
			t.Fatal(err)
		}
		m := e.marks.State()
		if m.Order == nil || m.Order.Hash != hash || m.Locked.Version != 0 || m.Open.Version != 0 || m.Locked.Pending != nil || m.Open.Pending != nil {
			t.Fatalf("%s: the log's state %+v", when, m)
		}
		refusedImport(t, e.attestNow(pk), backend.StatusNotReady, "handover import")
		if h, _ := e.srv.health(); h.Ready {
			t.Fatalf("%s: ready", when)
		}
	}
	holds("mid-import")
	e.restart()
	pages = src.pages(e.sealTo(), hash, 8)
	holds("after a restart mid-import")
	e.mustImp(order, pages[1], 0)
	holds("before the last page")
	if r := e.mustImp(order, pages[2], 0); !r.Done || r.Held != 24 {
		t.Fatalf("%+v", r)
	}

	// Done: the runner signs, and the rotation is taken and in force at
	// once.
	e.clock.add(4 * testEpoch)
	if err := e.attestNow(pk); err != nil {
		t.Fatal(err)
	}
	if st := e.cfg().mustSend(updates["rotation"], wireadmin.ConfigAccepted); st.Locked.Version != 1 || st.ApproverSetHash != newSetHash() {
		t.Fatalf("after the import: %+v", st)
	}
	e.clock.add(testEpoch)
	if err := e.attestNow(pk); err != nil {
		t.Fatal(err)
	}
}

// A rotation that reaches the log all the same (by hand here, as an older
// build or a race would have written it) comes into force but keeps the
// slot: nothing is signed, also after a restart, and the import goes on
// under its order, which the old set signed, to its end.
func TestHandoverImportSlotOutlivesRotation(t *testing.T) {
	e := newTgtEnv(t, "dev", nil)
	src := newSource(t, 16, 0, [][32]byte{{0xd1}}, testMark)
	order, hash := e.order([]byte{1, 2}, nil)
	pages := src.pages(e.sealTo(), hash, 8)
	e.mustImp(order, pages[0], 0)

	ce := e.cfg()
	rot := ce.body(locked, 1, ce.groupHash(locked), 0)
	rot.Locked.Approvers = approverSet(2, 4, 5, 6)
	if _, _, _, err := e.marks.PutBody(ctx, signed(t, rot, first2, []byte{4, 5, 6})); err != nil {
		t.Fatal(err)
	}
	st := e.marks.State()
	st.Locked.Pending = &markstore.Pending{Version: 1, Hash: hashOf(t, rot), EffectiveAt: e.now() + 1}
	if err := e.marks.SetState(ctx, st); err != nil {
		t.Fatal(err)
	}
	// The runner reads the log's state at its start.
	e.restart()
	e.clock.add(testEpoch)
	if err := e.upd.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	m := e.marks.State()
	if m.Locked.Version != 1 || m.Order == nil || m.Order.Hash != hash {
		t.Fatalf("the rotation in force: the log's state %+v", m)
	}
	if id := identityOf(t, e.srv, []byte("n-0123456789abcdef")); id.State.Order.Hash != hash || id.State.ApproverSetHash != newSetHash() {
		t.Fatalf("IDENTITY %+v", id.State)
	}
	pk := src.shares[0].pk
	refusedImport(t, e.attestNow(pk), backend.StatusNotReady, "handover import")
	e.restart()
	refusedImport(t, e.attestNow(pk), backend.StatusNotReady, "handover import")

	pages = src.pages(e.sealTo(), hash, 8)
	if r := e.mustImp(order, pages[1], 0); !r.Done || r.Held != 16 {
		t.Fatalf("%+v", r)
	}
	e.clock.add(4 * testEpoch)
	if err := e.attestNow(pk); err != nil {
		t.Fatal(err)
	}
	// Another order of the old set counts for nothing now.
	o2, h2 := e.order([]byte{1, 2}, func(b *handoverorder.Body) { b.NotAfter++ })
	_, err := e.imp(o2, newSource(t, 1, 0, [][32]byte{{0xd1}}, testMark).pages(e.sealTo(), h2, 4)[0], 0)
	refusedImport(t, err, backend.StatusBadRequest, "approver")
}

// The slot is written only on a runner still at version 0 with no key: an
// update or a share that came after the first request's checks stops the
// start. After the start a sealed import, a DKG order and a new key
// generation session are refused.
func TestHandoverImportStartChecks(t *testing.T) {
	start := func(e *tgtEnv, hash [32]byte) error {
		im := e.srv.imp.(*importer)
		im.slotMu.Lock()
		defer im.slotMu.Unlock()
		return im.start(ctx, hash, 4)
	}
	// An open update in force, or one pending.
	for name, c := range map[string]struct {
		at   func(e *tgtEnv) uint64
		want string
	}{
		"in force": {func(e *tgtEnv) uint64 { return 0 }, "came into force"},
		"pending":  {func(e *tgtEnv) uint64 { return e.now() + 600 }, "pending"},
	} {
		e := newTgtEnv(t, "dev", nil)
		ce := e.cfg()
		op := ce.body(open, 1, ce.groupHash(open), c.at(e))
		op.Open.ForkSchedule = append(op.Open.ForkSchedule, setupwire.Fork{Epoch: 1 << 20, Version: v6})
		ce.mustSend(signed(t, op, first2, nil), wireadmin.ConfigAccepted)
		_, hash := e.order([]byte{1, 2}, nil)
		refusedImport(t, start(e, hash), backend.StatusBadRequest, c.want)
		if e.srv.importing() != nil {
			t.Fatalf("%s: the slot was written", name)
		}
	}
	// A share stored since.
	e := newTgtEnv(t, "dev", nil)
	sk, _ := software.NewSecret()
	pk, _ := core.PubkeyOf(sk)
	if _, err := e.srv.addShare(pk, &sk, 1, nil, "sealed"); err != nil {
		t.Fatal(err)
	}
	_, hash := e.order([]byte{1, 2}, nil)
	refusedImport(t, start(e, hash), backend.StatusBadRequest, "empty runner only")
	if e.srv.importing() != nil {
		t.Fatal("the slot was written on a runner with a key")
	}

	// After the start.
	e = newTgtEnv(t, "dev", nil)
	src := newSource(t, 8, 0, [][32]byte{{0xd1}}, testMark)
	order, hash := e.order([]byte{1, 2}, nil)
	e.mustImp(order, src.pages(e.sealTo(), hash, 4)[0], 0)
	sk, _ = software.NewSecret()
	pk, _ = core.PubkeyOf(sk)
	_, err := e.srv.addShare(pk, &sk, 1, nil, "sealed")
	refusedImport(t, err, backend.StatusNotReady, "handover import")
	was := dkgOrders
	dkgOrders = &keygen.Orders{} // never reached: the refusal comes first
	defer func() { dkgOrders = was }()
	_, err = e.srv.dispatch(ctx, wire.Frame{Type: dkgmsg.TypeOrder, Payload: []byte{1}})
	refusedImport(t, err, backend.StatusNotReady, "no DKG order")
	hello, err := (&dkgmsg.InOrder{Order: [32]byte{1}, Type: dkgmsg.TypeHello, Payload: []byte{1}}).Encode()
	if err != nil {
		t.Fatal(err)
	}
	_, err = e.srv.dispatch(ctx, wire.Frame{Type: dkgmsg.TypeInOrder, Payload: hello})
	refusedImport(t, err, backend.StatusNotReady, "no key generation session")
}

// newSetHash is the hash of the set the rotation of importUpdates brings.
func newSetHash() [32]byte {
	s := approverSet(2, 4, 5, 6)
	return s.Hash()
}
