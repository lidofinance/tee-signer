package server

import (
	"context"

	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/slashing-log"
)

// The import slot of a handover target (handover_import.go). While a handover import runs,
// the order slot of the mark log's state names its handover order: from the
// first handed-over share until the last one is in. The runner signs
// nothing while it is set (Server.sign), also after a restart mid-import,
// and the slot is in the locked log, so the host cannot clear it by rolling
// its store back.
//
// The same slot holds the handover order of a source (handover_source.go)
// while it waits and after the tombstone. An order names this runner's
// setup either as its source or as its target, never both, so the two do
// not meet on one runner. The source side marks its orders
// (markSourceOrder): when it takes one, and at start from the order's
// sealed body in the host store. A handover order in the slot that is not
// marked is an import. A source whose host lost the body therefore reads
// its own order as an import and signs nothing until the order is pushed
// again, which restores the body; it never reads an import as its own
// order. A source order leaves the slot at its not_after (Updates.compute);
// an import never does.
//
// The config stays at the setup's version 0 for the whole import, so
// nothing but the import's end clears the slot:
//
//   - the slot is written only on a runner whose groups are at version 0
//     with nothing pending, checked again under the lock that orders every
//     config write (setImportOrder), so an update that arrived after the
//     first request's checks stops the import before it starts;
//   - CONFIG_UPDATE is refused while the slot is set (Updates.Accept), and
//     so are a DKG order and a new key generation session (dkg.go);
//   - a rotation that comes into force keeps the slot (Updates.compute):
//     it drops what the old set signed and is pending, but the shares of an
//     import are on their way from a source that wrote its tombstone.

// ImportOrder is the handover order whose import is in progress, nil when
// none is.
func (u *Updates) ImportOrder() *markstore.Order {
	o := u.opt.Log.State().Order
	if o == nil || o.Kind != markstore.OrderHandover || u.isSourceOrder(o.Hash) {
		return nil
	}
	c := *o
	return &c
}

// markSourceOrder records that the handover order of this hash, valid
// until notAfter, names this runner as its source. The view is computed
// again by notAfter at the latest, when the order leaves the slot. Call it
// without u.mu.
func (u *Updates) markSourceOrder(hash [32]byte, notAfter uint64) {
	u.srcMu.Lock()
	if u.sourceOrders == nil {
		u.sourceOrders = map[[32]byte]uint64{}
	}
	u.sourceOrders[hash] = notAfter
	u.srcMu.Unlock()
	u.mu.Lock()
	u.next = min(u.next, notAfter)
	u.mu.Unlock()
}

func (u *Updates) isSourceOrder(hash [32]byte) bool {
	u.srcMu.Lock()
	defer u.srcMu.Unlock()
	_, ok := u.sourceOrders[hash]
	return ok
}

// expiringSourceOrder is the not_after of o when o is a source order that
// leaves the slot then: a handover order this runner is the source of,
// with no tombstone written.
func (u *Updates) expiringSourceOrder(o *markstore.Order) (uint64, bool) {
	if o == nil || o.Kind != markstore.OrderHandover {
		return 0, false
	}
	u.srcMu.Lock()
	na, ok := u.sourceOrders[o.Hash]
	handed := u.handedOver
	u.srcMu.Unlock()
	if !ok || handed == nil || handed() {
		return 0, false
	}
	return na, true
}

// setHandedOver gives the source side's tombstone check. Updates.Run may
// already be computing views, hence the lock.
func (u *Updates) setHandedOver(f func() bool) {
	u.srcMu.Lock()
	defer u.srcMu.Unlock()
	u.handedOver = f
}

// setImportOrder writes a record whose state names o in the order slot, or
// clears the slot (o nil). The rest of the state is the config in force
// now, as Sync writes it. Setting the slot needs both groups at version 0
// with nothing pending and no order: an update that arrived after the
// import's first checks refuses the start here.
func (u *Updates) setImportOrder(ctx context.Context, o *markstore.Order) error {
	t, err := u.opt.Clock.Now()
	if err != nil {
		return backend.Refused(backend.StatusClock, "handover import: clock: %v", err)
	}
	now := unix(t)
	u.writeMu.Lock()
	defer u.writeMu.Unlock()
	u.mu.Lock()
	u.reconcileLocked(now)
	next, missing := u.view.state.Clone(), u.view.missing
	u.mu.Unlock()
	if missing != nil {
		return backend.Refused(backend.StatusStorage, "handover import: the config in force is unknown: %v", missing)
	}
	if o != nil {
		switch {
		case next.Locked.Version != 0 || next.Open.Version != 0:
			return backend.Refused(backend.StatusBadRequest, "handover import: a config update came into force (locked %d, open %d); a handover target starts at version 0",
				next.Locked.Version, next.Open.Version)
		case next.Locked.Pending != nil || next.Open.Pending != nil:
			return backend.Refused(backend.StatusBadRequest, "handover import: a config update is pending here")
		case next.Order != nil:
			return backend.Refused(backend.StatusBadRequest, "handover import: an order (kind %d, %x) is in the slot", next.Order.Kind, next.Order.Hash[:8])
		}
	}
	next.Order = nil
	if o != nil {
		c := *o
		next.Order = &c
	}
	wctx, cancel := context.WithTimeout(ctx, logTimeout)
	defer cancel()
	if err := u.opt.Log.SetState(wctx, next); err != nil {
		return backend.Refused(backend.StatusStorage, "handover import: record not written to the mark log: %v", err)
	}
	u.mu.Lock()
	u.reconcileLocked(now)
	u.mu.Unlock()
	return nil
}
