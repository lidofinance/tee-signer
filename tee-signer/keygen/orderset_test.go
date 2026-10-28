package keygen

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/lidofinance/tee-signer/governance/dkgorder"
	"github.com/lidofinance/tee-signer/platform/dev"
	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/dkgmsg"
)

// TKGORDER-01: a rotation renews every order. Approvers 1, 2, 3 with k = 2
// sign an order with 1 and 2; a locked update replaces approver 3 only,
// with k unchanged and a time lock of 100 s. The signatures of 1 and 2
// still verify by position, but the order arrived under another set, so it
// is void. Pushed again it is a new arrival with the new wait, and acts
// only after it.
func TestOrderVoidAfterPartialRotation(t *testing.T) {
	ns := orderCluster(t)
	raw, h := signOrder(t, orderBody(ns, dkgorder.PathDirk, "dirk"), 1, 2)
	n := ns[0]
	pushAll(t, []*orderNode{n}, raw)
	if _, err := n.orders.Manager(h, true); err != nil {
		t.Fatal(err)
	}
	l := *n.locked
	l.Approvers = approverSet(1, 2, 7)
	wait := uint64(100)
	l.ChangeDelaySeconds = &wait
	n.locked = &l
	n.setTime(1_800_000_050)
	_, err := n.orders.Manager(h, true)
	wantRefused(t, err, backend.StatusPolicyPubkey, "approver set")
	if slot := n.orders.PendingSlot(); slot.Kind != 0 {
		t.Fatalf("a void order in the pending slot: %+v", slot)
	}
	st := pushAll(t, []*orderNode{n}, raw)[0]
	if st.Outcome != dkgmsg.OrderAccepted || st.Status != dkgmsg.OrderPending || st.Arrived != 1_800_000_050 || st.ActAt != 1_800_000_150 {
		t.Fatalf("pushed again after the rotation: %+v", st)
	}
	_, err = n.orders.Manager(h, true)
	wantRefused(t, err, backend.StatusNotReady, "waits until")
	n.setTime(1_800_000_150)
	if _, err := n.orders.Manager(h, true); err != nil {
		t.Fatalf("after the new wait: %v", err)
	}
	// The record keeps the set it arrived under: a restart sees the same.
	again := newOrderNode(t, n.setup, "dev", n.store)
	again.locked, again.trusted = &l, 1_800_000_150
	if _, err := again.orders.Manager(h, true); err != nil {
		t.Fatalf("after a restart: %v", err)
	}
}

// An order record of another version than orderRecordVersion does not
// load: the runner leaves it out, and the order pushed again is a new
// arrival whose record has the version and the approver set.
func TestOrderRecordOtherVersionLeftOut(t *testing.T) {
	ns := orderCluster(t)
	raw, h := signOrder(t, orderBody(ns, dkgorder.PathDirk, "dirk"), 1, 2)
	n := ns[0]
	for _, v := range []int{0, 2} {
		rec, err := json.Marshal(map[string]any{"version": v, "order": raw, "arrived": 1_799_000_000, "act_at": 1_799_000_000,
			"approver_set_hash": n.locked.Approvers.Hash()})
		if err != nil {
			t.Fatal(err)
		}
		blob, err := dev.NewDevSealer().Seal(rec, orderAAD(h))
		if err != nil {
			t.Fatal(err)
		}
		if err := n.store.Put(orderKey(h), blob); err != nil {
			t.Fatal(err)
		}
		m := newOrderNode(t, n.setup, "dev", n.store)
		if _, err := m.orders.Manager(h, false); err == nil {
			t.Fatalf("an order record of version %d loaded", v)
		}
		st, err := m.orders.Push(context.Background(), raw)
		if err != nil {
			t.Fatal(err)
		}
		if st.Outcome != dkgmsg.OrderAccepted || st.Arrived != 1_800_000_000 {
			t.Fatalf("version %d: the push is not a new arrival: %+v", v, st)
		}
		plain, err := dev.NewDevSealer().Unseal(mustGet(t, m, h), orderAAD(h))
		if err != nil {
			t.Fatal(err)
		}
		var back struct {
			Version int          `json:"version"`
			Set     backend.Root `json:"approver_set_hash"`
		}
		if err := json.Unmarshal(plain, &back); err != nil || back.Version != orderRecordVersion || back.Set != m.locked.Approvers.Hash() {
			t.Fatalf("record after the new arrival: version %d set %x (%v), want %d and %x", back.Version, back.Set[:4], err, orderRecordVersion, m.locked.Approvers.Hash())
		}
	}
}

func mustGet(t *testing.T, n *orderNode, h [32]byte) []byte {
	t.Helper()
	b, err := n.store.Get(orderKey(h))
	if err != nil {
		t.Fatal(err)
	}
	return b
}
