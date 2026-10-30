//go:build !debugimport

// HANDOVER_ORDER and HANDOVER as a source (signer-protocol docs/protocol.md,
// "Handover"), so every image can hand its shares to the next one. Every
// release build with a setup serves it: the attestation verifier it checks
// a target with is the one of its own platform (attestation-verify/runnerclient,
// tag verifierselect), the same one its own import uses.
//
// The order. k approvers in force sign a handover order that names this
// runner's setup as the source and one target: its setup_hash, its image
// and the settings to check its attestation with. HANDOVER_ORDER checks the
// order (cluster, chain, source, signatures under the set in force, the
// target's image on the allowed list in force, a verifier this build has)
// and records it as the pending order of the mark log's state, with the
// time it acts: its arrival on the trusted clock plus the change delay in
// force, at least the images minimum (7 minutes in a testnet build, 7 days
// in the default one; the dev platform waits the change delay only). The
// record is in the locked log, so the host cannot shorten the wait by
// rolling it back; it can only lose the order's body in the host store,
// and the same order pushed again brings it back with its old time. A
// second order is refused while one is pending, unless the pending one
// has expired or is void (its approvers or image no longer in force). At
// its not_after an order leaves the slot by itself (Updates.compute), so
// it no longer stands in IDENTITY in front of a later order;
// after the tombstone it stays.
//
// The order slot also holds a handover import in progress on a target
// (importslot.go). The two never meet: a source order names this setup as
// its source, an import order as its target, and an order cannot name one
// setup as both. The sealed body in the host store says which a slot holds
// (Updates.markSourceOrder); without the body the slot reads as an import,
// which stops signing until the order is pushed again.
//
// The handover. HANDOVER carries the order again, the target's
// IDENTITY answer and its published setup (setupwire.Published). Before
// the tombstone it checks, and refuses with nothing changed:
//
//   - the order is this runner's pending order, past its wait, before its
//     not_after, signed by k approvers in force, its target image on the
//     allowed list in force;
//   - no config update is pending here;
//   - the target's published setup hashes to the order's target
//     setup_hash (H(policy_root, platform_commitment), rebuilt here from
//     the leaves and salts), which its identity carries;
//   - the target's attestation verifies with the order's settings (so its
//     measurement is the order's image) over the IDENTITY user data;
//   - its cluster_id, chain and safety values are this runner's, its
//     handover_generation is one higher, and version 0 of both its groups
//     is this runner's config in force, leaf by leaf (expectedTarget);
//   - its state shows version 0 of both groups with the hashes of its
//     published groups, nothing pending, its setup's approver set, no key
//     (key origin 0 and 0), this order in its slot (the target reserved
//     itself for it, handover_import.go reserve), and room for every share
//     (max_keys).
//
// Then the runner stops signing and adding shares, reads every stored
// share once into memory, checks that they are the loaded keys, writes the
// tombstone that names the target (markstore HandOverTo) under the lock of
// config writes, once the config in force is still the one checked
// (underCheckedConfig), and seals the page. After the tombstone, here or
// after a restart, it answers HANDOVER for that target only and with the
// same mark; the checks of the target's keys and order slot no longer
// apply, since a target that restarted mid-import holds some keys already.
//
// What goes with the shares: the mark before the tombstone (the target
// raises its log to it before it stores a share, and a fresh target log
// takes its vote history from it), each share's key origin (from its
// sealed share record) signed with this process's origin key, whose
// attestation the page carries, and the carry (package handover,
// carry.go): the key set handed over and the day's exits of the mark log,
// which every share's associated data binds. The config is carried by the
// target's setup itself: its version 0 is this runner's config in force,
// which the checks above compare.

package server

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/lidofinance/tee-signer/attestation-verify/runnerclient"
	"github.com/lidofinance/tee-signer/governance/handoverorder"
	"github.com/lidofinance/tee-signer/governance/setupwire"
	"github.com/lidofinance/tee-signer/signer-core/core"
	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/sealedimport"
	"github.com/lidofinance/tee-signer/signer-protocol/wire"
	"github.com/lidofinance/tee-signer/slashing-log"
	"github.com/lidofinance/tee-signer/tee-signer/handover"
)

// HandoverSourceOptions configure EnableHandoverSource.
type HandoverSourceOptions struct {
	// VerifierOptions go to the target's verifier (the platform's HTTP
	// client for the key sets).
	VerifierOptions []runnerclient.Option
	// LimitedEgress and PeerEndpoints: on a runner that reaches only its
	// setup's peer hosts (setup.AttestationEgress), every host the target's
	// verifier fetches a key set from must be one of them.
	LimitedEgress bool
	PeerEndpoints []string
}

// EnableHandoverSource turns HANDOVER_ORDER and HANDOVER on. It needs a
// setup with its config updates and the mark log. Call it before
// EnableHandoverImport: it tells a pending source order in the slot from
// an import.
func (s *Server) EnableHandoverSource(o HandoverSourceOptions) error {
	switch {
	case s.Updates == nil || s.SetupHash == ([32]byte{}):
		return errors.New("handover source needs a runner with a setup")
	case s.Hooks == nil || !s.Hooks.Mode().MarkLog:
		return errors.New("handover source needs the mark log")
	}
	h := &sourceHandover{s: s, opt: o}
	s.Updates.setHandedOver(func() bool { _, ok := s.Hooks.HandedOverTo(); return ok })
	if cur := s.Updates.opt.Log.State().Order; cur != nil && cur.Kind == markstore.OrderHandover {
		if ord, _, err := h.loadOrder(cur.Hash); err == nil && ord.Body.Source.SetupHash == s.SetupHash {
			s.Updates.markSourceOrder(cur.Hash, ord.Body.NotAfter)
		}
	}
	s.handoverSrc = h
	return nil
}

type sourceHandover struct {
	s   *Server
	opt HandoverSourceOptions

	// mu runs one HANDOVER_ORDER or HANDOVER at a time.
	mu namedMutex[sourceMuName]
	// shares are the shares read once for the handover, in pubkey order;
	// nil until the first HANDOVER that passed every check.
	shares []handedShare
	// carry is what the pages carry besides the shares, read with them.
	carry *handover.Carry
	// originKey signs each handed-over share's header; proof is its
	// attestation for the nonce in it and proofOrder.
	originKey  ed25519.PrivateKey
	proof      *handover.OriginProof
	proofOrder [32]byte
	// verifier is the target verifier of verifierOrder, kept so its key
	// set is fetched once for every page.
	verifier      runnerclient.DocumentVerifier
	verifierOrder [32]byte
}

// handedShare is a stored share read for the handover.
type handedShare struct {
	pk, share backend.Pubkey
	index     uint64
	secret    [32]byte
	origin    uint8
	order     [32]byte
}

func (h *sourceHandover) dev() bool { return h.s.Platform.Name == "dev" }

// orderRecord is a source order's body in the host store, sealed. The
// mark log's state holds its hash and the time it acts; this holds the
// rest.
type orderRecord struct {
	Order   []byte `json:"order"`
	Arrived uint64 `json:"arrived"`
	ActAt   uint64 `json:"act_at"`
}

const handoverOrdersPrefix = "handover/orders/"

func handoverOrderKey(h [32]byte) string { return handoverOrdersPrefix + hex.EncodeToString(h[:]) }

func (h *sourceHandover) orderAAD(hash [32]byte) []byte {
	b := append([]byte("signer-handover-order-record-v1|"), h.s.SetupHash[:]...)
	return append(b, hash[:]...)
}

func (h *sourceHandover) storeOrder(hash [32]byte, rec orderRecord) error {
	plain, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	blob, err := h.s.Platform.Sealer.Seal(plain, h.orderAAD(hash))
	if err != nil {
		return err
	}
	return h.s.Platform.Store.Put(handoverOrderKey(hash), blob)
}

// loadOrder reads the stored body of the order with this hash.
func (h *sourceHandover) loadOrder(hash [32]byte) (*handoverorder.Order, *orderRecord, error) {
	blob, err := h.s.Platform.Store.Get(handoverOrderKey(hash))
	if err != nil {
		return nil, nil, err
	}
	plain, err := h.s.Platform.Sealer.Unseal(blob, h.orderAAD(hash))
	if err != nil {
		return nil, nil, errors.New("the stored order does not unseal")
	}
	var rec orderRecord
	if err := json.Unmarshal(plain, &rec); err != nil {
		return nil, nil, err
	}
	o, err := handoverorder.Decode(rec.Order)
	if err != nil {
		return nil, nil, err
	}
	if hh, err := o.Body.Hash(); err != nil || hh != hash {
		return nil, nil, errors.New("the stored order is another one")
	}
	return o, &rec, nil
}

// handoverView is the config in force that a handover is checked against.
type handoverView struct {
	state  markstore.ConfigState
	locked *setupwire.Locked
	open   *setupwire.Open
}

// inForce is the config in force at now: the log's state with every
// update due by now active, and the values of both groups.
func (u *Updates) inForce(now uint64) (*handoverView, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.reconcileLocked(now)
	v := &u.view
	if v.locked == nil || v.open == nil {
		return nil, backend.Refused(backend.StatusStorage, "handover: the config values in force are unknown: %v", v.missing)
	}
	return &handoverView{state: v.state.Clone(), locked: v.locked, open: v.open}, nil
}

// underCheckedConfig runs write, the tombstone's write, while it holds the
// lock of config writes, and only if the config in force is still checked,
// the state the handover's checks saw: the same update in force in each
// group, nothing pending, the same order. wrote is false when it did not
// run write; err is then the refusal.
//
// A CONFIG_UPDATE taken between the checks and the tombstone would sit
// pending in the tombstone record and come into force later. Then the
// target's version 0 groups would no longer be the config in force, and a
// target that restarted mid-import could not get its shares sealed again,
// though the shares exist nowhere else. After the tombstone the mark log
// takes no record (markstore ErrHandedOver), so no update comes later; an
// update that waited for the lock is refused there.
func (u *Updates) underCheckedConfig(checked markstore.ConfigState, write func() error) (wrote bool, err error) {
	t, err := u.opt.Clock.Now()
	if err != nil {
		return false, backend.Refused(backend.StatusClock, "handover: clock: %v", err)
	}
	u.writeMu.Lock()
	defer u.writeMu.Unlock()
	u.mu.Lock()
	u.reconcileLocked(unix(t))
	now := u.view.state.Clone()
	u.mu.Unlock()
	if !now.Equal(checked) {
		return false, backend.Refused(backend.StatusBadRequest,
			"handover: the config changed during the checks (now locked %d, open %d, locked pending %d, open pending %d); nothing was handed over, send the request again",
			now.Locked.Version, now.Open.Version, pendingVersion(now.Locked), pendingVersion(now.Open))
	}
	return true, write()
}

// putOrder writes a record whose state names o, valid until notAfter, as
// the pending order. replace decides whether another pending order may go.
func (u *Updates) putOrder(ctx context.Context, now uint64, o markstore.Order, notAfter uint64, replace func(old *markstore.Order) error) error {
	u.writeMu.Lock()
	defer u.writeMu.Unlock()
	u.mu.Lock()
	u.reconcileLocked(now)
	next, missing := u.view.state.Clone(), u.view.missing
	u.mu.Unlock()
	if missing != nil {
		return backend.Refused(backend.StatusStorage, "handover order: the config in force is unknown: %v", missing)
	}
	if old := next.Order; old != nil && *old != o {
		if err := replace(old); err != nil {
			return err
		}
	}
	next.Order = &o
	// Marked before the record: from the record on, the slot must read as
	// this runner's own order, never as an import.
	u.markSourceOrder(o.Hash, notAfter)
	wctx, cancel := context.WithTimeout(ctx, logTimeout)
	defer cancel()
	if err := u.opt.Log.SetState(wctx, next); err != nil {
		return backend.Refused(backend.StatusStorage, "handover order: record not written to the mark log: %v", err)
	}
	u.mu.Lock()
	u.reconcileLocked(now)
	u.mu.Unlock()
	return nil
}

// TrustedTime is the time a handover order is checked against, as a
// config update is: the NTS clock with a quorum (any clock on the dev
// platform).
func (u *Updates) TrustedTime() (uint64, error) {
	now, err := u.trustedNow()
	if err != nil {
		return 0, backend.Refused(backend.StatusClock, "handover order: %v", err)
	}
	return now, nil
}

// targetVerifier is the verifier of the order's target: the settings the
// order names, a verifier built into this runner, the dev verifier on the
// dev platform only, and key set hosts this runner reaches.
func (h *sourceHandover) targetVerifier(b *handoverorder.Body, hash [32]byte) (runnerclient.DocumentVerifier, error) {
	if h.verifier != nil && h.verifierOrder == hash {
		return h.verifier, nil
	}
	p := b.Target
	a := runnerclient.RunnerAttestation(&p)
	switch {
	case !runnerclient.Available(a.Verifier):
		return nil, fmt.Errorf("handover order: target verifier %q is not built into this runner", a.Verifier)
	case a.Verifier == runnerclient.VerifierDev && !h.dev():
		return nil, fmt.Errorf("handover order: the dev verifier accepts unsigned documents, refused on platform %s", h.s.Platform.Name)
	}
	if h.opt.LimitedEgress {
		var missing []string
		for _, e := range a.Endpoints() {
			if !slices.Contains(h.opt.PeerEndpoints, e) {
				missing = append(missing, e)
			}
		}
		if len(missing) > 0 {
			return nil, fmt.Errorf("handover order: the target's verifier fetches its key set from %s, which this runner does not reach (its setup's peer hosts: %s)",
				strings.Join(missing, " and "), strings.Join(h.opt.PeerEndpoints, ", "))
		}
	}
	v, err := a.NewDocumentVerifier(h.opt.VerifierOptions...)
	if err != nil {
		return nil, fmt.Errorf("handover order: target settings: %w", err)
	}
	h.verifier, h.verifierOrder = v, hash
	return v, nil
}

// status is where an order stands under the config in force at now.
func (h *sourceHandover) status(o *handoverorder.Order, actAt uint64, v *handoverView, now uint64) (handoverorder.Status, string) {
	if err := o.Verify(&v.locked.Approvers); err != nil {
		return handoverorder.Void, err.Error()
	}
	if err := o.Body.CheckImage(v.locked.AllowedImageMeasurements, h.dev()); err != nil {
		return handoverorder.Void, err.Error()
	}
	switch {
	case now < actAt:
		return handoverorder.Pending, ""
	case now >= o.Body.NotAfter:
		return handoverorder.Expired, ""
	}
	return handoverorder.Active, ""
}

func stateOf(outcome uint8, hash [32]byte, o *handoverorder.Order, rec *orderRecord, st handoverorder.Status, why string) []byte {
	s := &handoverorder.State{Outcome: outcome, Status: st, Hash: hash, Why: why}
	if o != nil {
		s.NotAfter = o.Body.NotAfter
	}
	if rec != nil {
		s.Arrived, s.ActAt = rec.Arrived, rec.ActAt
	}
	return s.Encode()
}

// order serves HANDOVER_ORDER.
func (h *sourceHandover) order(ctx context.Context, payload []byte) ([]byte, error) {
	s, u := h.s, h.s.Updates
	bad := func(err error) ([]byte, error) {
		s.Log.Warn("handover order refused", "err", err)
		return nil, backend.Refused(backend.StatusBadRequest, "%v", err)
	}
	o, err := handoverorder.Decode(payload)
	if err != nil {
		return bad(err)
	}
	b := &o.Body
	hash, _ := b.Hash()
	if b.Target.SetupHash == s.SetupHash {
		// An order to this runner: it reserves itself for it (SHR-01).
		im, ok := s.imp.(*importer)
		if !ok {
			return nil, backend.Refused(backend.StatusUnsupported, "this runner takes no handed-over shares, so it reserves itself for no order")
		}
		return im.reserve(ctx, o, hash)
	}
	if err := b.Matches(u.SetupWire(), s.SetupHash); err != nil {
		return bad(err)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	// After the tombstone the order of its target reads as done; no other
	// order is taken.
	if target, ok := s.Hooks.HandedOverTo(); ok {
		if cur := u.opt.Log.State().Order; cur != nil && cur.Hash == hash && b.Target.SetupHash == target {
			_, rec, _ := h.loadOrder(hash)
			return stateOf(handoverorder.Known, hash, o, rec, handoverorder.Done, ""), nil
		}
		return bad(fmt.Errorf("handed over to setup %x already; this runner takes no other order", target[:8]))
	}
	// The slot reads as an import when it holds an order whose body this
	// runner lost (importslot.go); that order itself may come again.
	if cur := s.importing(); cur != nil && cur.Hash != hash {
		return bad(fmt.Errorf("a handover import (order %x) is in progress here; this runner hands over nothing before it ends", cur.Hash[:8]))
	}
	now, err := u.TrustedTime()
	if err != nil {
		return nil, err
	}
	v, err := u.inForce(now)
	if err != nil {
		return nil, err
	}
	if cur := v.state.Order; cur != nil && cur.Kind == markstore.OrderHandover && cur.Hash == hash {
		// The same order again: its time stays. A lost body comes back on
		// the hash in the locked slot alone, before the checks under the
		// config in force (SHO-01): those passed when the order came, and
		// an order they void now must still leave the slot as this
		// runner's own, or the runner reads it as an import and signs
		// nothing, for good. Its state says void then.
		_, rec, err := h.loadOrder(hash)
		if err != nil {
			rec = &orderRecord{Order: bytes.Clone(payload), ActAt: cur.ActAt}
			if err := h.storeOrder(hash, *rec); err != nil {
				return nil, backend.Refused(backend.StatusPlatform, "handover order: store: %v", err)
			}
		}
		u.markSourceOrder(hash, b.NotAfter)
		st, why := h.status(o, cur.ActAt, v, now)
		return stateOf(handoverorder.Known, hash, o, rec, st, why), nil
	}
	if err := o.Verify(&v.locked.Approvers); err != nil {
		return bad(err)
	}
	if err := b.CheckImage(v.locked.AllowedImageMeasurements, h.dev()); err != nil {
		return bad(err)
	}
	if _, err := h.targetVerifier(b, hash); err != nil {
		return bad(err)
	}
	wait := handoverorder.Wait(v.locked, h.dev())
	actAt := setupwire.SatAdd(now, wait)
	if b.NotAfter <= actAt {
		return bad(fmt.Errorf("handover order: not_after %d is not after %d, when it would act (arrival %d + wait %d)", b.NotAfter, actAt, now, wait))
	}
	rec := orderRecord{Order: bytes.Clone(payload), Arrived: now, ActAt: actAt}
	if err := h.storeOrder(hash, rec); err != nil {
		return nil, backend.Refused(backend.StatusPlatform, "handover order: store: %v", err)
	}
	replace := func(old *markstore.Order) error {
		if old.Kind != markstore.OrderHandover {
			return backend.Refused(backend.StatusBadRequest, "handover order: an order of kind %d is pending", old.Kind)
		}
		po, prec, err := h.loadOrder(old.Hash)
		if err != nil {
			return backend.Refused(backend.StatusBadRequest, "handover order: order %x is pending and its body is not readable here (%v); push it again to see its state",
				old.Hash[:8], err)
		}
		if st, _ := h.status(po, prec.ActAt, v, now); st != handoverorder.Expired && st != handoverorder.Void {
			return backend.Refused(backend.StatusBadRequest, "handover order: order %x is %s here until its not_after %d; one order at a time",
				old.Hash[:8], st, po.Body.NotAfter)
		}
		return nil
	}
	if err := u.putOrder(ctx, now, markstore.Order{Kind: markstore.OrderHandover, Hash: hash, ActAt: actAt}, b.NotAfter, replace); err != nil {
		var r *backend.RefusedError
		if errors.As(err, &r) && r.Code == backend.StatusBadRequest {
			s.Log.Warn("handover order refused", "err", err)
		}
		return nil, err
	}
	s.Log.Warn("handover order accepted", "order", hex.EncodeToString(hash[:6]), "target", b.Target.Name,
		"target_setup", hex.EncodeToString(b.Target.SetupHash[:8]), "verifier", b.Target.Verifier.String(),
		"act_at", actAt, "wait_s", wait, "not_after", b.NotAfter)
	return stateOf(handoverorder.Accepted, hash, o, &rec, handoverorder.Pending, ""), nil
}

// handover serves HANDOVER.
func (h *sourceHandover) handover(ctx context.Context, payload []byte) ([]byte, error) {
	s, u := h.s, h.s.Updates
	bad := func(err error) ([]byte, error) {
		s.Log.Warn("handover refused", "err", err)
		return nil, backend.Refused(backend.StatusBadRequest, "%v", err)
	}
	q, err := handover.DecodeRequest(payload)
	if err != nil {
		return bad(err)
	}
	o, err := handoverorder.Decode(q.Order)
	if err != nil {
		return bad(err)
	}
	b := &o.Body
	hash, _ := b.Hash()
	if err := b.Matches(u.SetupWire(), s.SetupHash); err != nil {
		return bad(err)
	}
	h.mu.Lock()
	defer h.mu.Unlock()

	tomb, handed := s.Hooks.HandedOverTo()
	var v *handoverView
	if handed {
		// The config is frozen at the tombstone. The checks of the order's
		// time and of the config were made before it was written.
		if b.Target.SetupHash != tomb {
			return bad(fmt.Errorf("handed over to setup %x; a tombstone names one target only", tomb[:8]))
		}
		if cur := u.opt.Log.State().Order; cur == nil || cur.Hash != hash {
			return bad(errors.New("the tombstone was written under another handover order"))
		}
		t, err := s.Platform.Clock.Now()
		if err != nil {
			return nil, backend.Refused(backend.StatusClock, "clock: %v", err)
		}
		if v, err = u.inForce(unix(t)); err != nil {
			return nil, err
		}
	} else {
		now, err := u.TrustedTime()
		if err != nil {
			return nil, err
		}
		if v, err = u.inForce(now); err != nil {
			return nil, err
		}
		cur := v.state.Order
		switch {
		case now >= b.NotAfter:
			// Before the slot check: an expired order has left the slot.
			return bad(fmt.Errorf("handover order %x expired at its not_after %d", hash[:8], b.NotAfter))
		case cur == nil || cur.Kind != markstore.OrderHandover || cur.Hash != hash:
			return bad(fmt.Errorf("handover order %x is not pending here; push it first (HANDOVER_ORDER)", hash[:8]))
		case now < cur.ActAt:
			return nil, backend.Refused(backend.StatusNotReady, "handover order %x waits until %s (%d s from now)", hash[:8],
				time.Unix(int64(min(cur.ActAt, 1<<62)), 0).UTC().Format(time.RFC3339), cur.ActAt-now)
		}
		if err := o.Verify(&v.locked.Approvers); err != nil {
			return bad(err)
		}
		if err := b.CheckImage(v.locked.AllowedImageMeasurements, h.dev()); err != nil {
			return bad(err)
		}
		if p := v.state.Locked.Pending; p != nil {
			return bad(fmt.Errorf("a locked config update (version %d) is pending here; hand over once it is in force or replaced", p.Version))
		}
		if p := v.state.Open.Pending; p != nil {
			return bad(fmt.Errorf("an open config update (version %d) is pending here; hand over once it is in force or replaced", p.Version))
		}
	}
	id, pol, err := h.checkTarget(ctx, q, b, hash, v, handed)
	if err != nil {
		return nil, err
	}
	target := b.Target.SetupHash
	if names, err := ListShares(s.Platform.Store); err != nil {
		return nil, backend.Refused(backend.StatusStorage, "stored shares: %v", err)
	} else if uint64(len(names)) > uint64(pol.MaxKeys) {
		return bad(fmt.Errorf("%d shares are stored here, the target's max_keys is %d", len(names), pol.MaxKeys))
	}

	var mark backend.Watermark
	if h.shares == nil {
		if !handed {
			// From here on nothing is signed or added: first in this
			// process, then for good with the tombstone. A failure before
			// the tombstone leaves the runner as it was.
			s.sharesMu.Lock()
			// A tombstone write that failed before left the flag set; it
			// stays set then.
			was := s.handedOver.Swap(true)
			shares, err := h.readShares(true)
			if err != nil {
				s.handedOver.Store(was)
				s.sharesMu.Unlock()
				return nil, backend.Refused(backend.StatusStorage, "stored shares: %v", err)
			}
			// The set under the lock is the one handed over: a share added
			// since the check above counts too (SHO-02).
			if uint64(len(shares)) > uint64(pol.MaxKeys) {
				s.handedOver.Store(was)
				s.sharesMu.Unlock()
				for i := range shares {
					clear(shares[i].secret[:])
				}
				return bad(fmt.Errorf("%d shares are stored here, the target's max_keys is %d", len(shares), pol.MaxKeys))
			}
			wrote, err := u.underCheckedConfig(v.state, func() error {
				var err error
				mark, err = s.Hooks.HandOverTo(ctx, target)
				return err
			})
			if !wrote {
				s.handedOver.Store(was)
				s.sharesMu.Unlock()
				for i := range shares {
					clear(shares[i].secret[:])
				}
				s.Log.Warn("handover refused", "err", err)
				return nil, err
			}
			s.sharesMu.Unlock()
			if err != nil {
				for i := range shares {
					clear(shares[i].secret[:])
				}
				s.Log.Error("handover: the mark log did not end; this process signs nothing, a restart would sign again", "err", err)
				return nil, backend.Refused(backend.StatusStorage, "mark log: %v", err)
			}
			h.shares = shares
			s.Log.Warn("handed over: tombstone written", "target_setup", hex.EncodeToString(target[:8]), "order", hex.EncodeToString(hash[:6]),
				"shares", len(shares), "target", mark.TargetEpoch, "source", mark.SourceEpoch, "block", mark.BlockSlot)
		} else {
			// A restart after the tombstone: read the shares again.
			shares, err := h.readShares(false)
			if err != nil {
				return nil, backend.Refused(backend.StatusStorage, "stored shares: %v", err)
			}
			h.shares = shares
		}
		c, err := h.readCarry()
		if err != nil {
			return nil, err
		}
		h.carry = c
	}
	if mark, err = s.Hooks.HandOverTo(ctx, target); err != nil {
		return nil, backend.Refused(backend.StatusStorage, "mark log: %v", err)
	}
	proof, err := h.originProof(ctx, q.Nonce, hash)
	if err != nil {
		return nil, err
	}
	resp := &handover.Response{Mark: mark, Total: uint32(len(h.shares)), Origin: *proof, Carry: *h.carry}
	carryHash, err := resp.CarryHash()
	if err != nil {
		return nil, backend.Refused(backend.StatusInternal, "handover carry: %v", err)
	}
	start := min(int(q.Start), len(h.shares))
	end := min(start+handover.MaxPerResponse, len(h.shares))
	// A log that never signed has an empty mark: its shares carry no
	// interchange maxima (handover.Share.CarriesMark).
	var ic *backend.Watermark
	if mark.HasBlock || mark.HasAttestation {
		m := mark
		ic = &m
	}
	for i := start; i < end; i++ {
		sh := &h.shares[i]
		x := handover.Share{SealedImportRequest: backend.SealedImportRequest{Pubkey: sh.pk, SharePubkey: sh.share, Index: sh.index,
			Interchange: ic}, Origin: sh.origin, Order: sh.order}
		if x.Sealed, err = sealedimport.SealAAD(id, x.AAD(carryHash), &sh.secret); err != nil {
			return nil, backend.Refused(backend.StatusBadKey, "seal share %s: %v", sh.pk.String()[:18], err)
		}
		x.SignOrigin(h.originKey)
		resp.Shares = append(resp.Shares, x)
	}
	s.Log.Warn("handover page", "target_setup", hex.EncodeToString(target[:8]), "shares", len(h.shares), "page_start", start,
		"page_shares", len(resp.Shares), "carried_exits", h.carry.Exits != nil)
	out, err := resp.Encode()
	if err != nil {
		return nil, backend.Refused(backend.StatusInternal, "%v", err)
	}
	return out, nil
}

// expectedTarget is the public part a target of this runner must publish,
// with the target's own salts, max_keys and slashing_log_min_lock_days
// (which the handover leaves to the target's operator): the same
// cluster_id, chain and safety values, handover_generation one higher, and
// version 0 of both groups equal to the values in force here.
func expectedTarget(src *setupwire.Setup, locked *setupwire.Locked, open *setupwire.Open, target *setupwire.Policy) (*setupwire.Policy, error) {
	if src.HandoverGeneration == ^uint64(0) {
		return nil, errors.New("handover: this setup's handover_generation has no successor")
	}
	return &setupwire.Policy{ClusterID: src.ClusterID, HandoverGeneration: src.HandoverGeneration + 1, Chain: src.Chain, Safety: src.Safety,
		MaxKeys: target.MaxKeys, SlashingLogMinLockDays: target.SlashingLogMinLockDays, Locked: *locked, Open: *open, Salts: target.Salts}, nil
}

// checkTargetPolicy compares the target's public part with expectedTarget
// leaf by leaf and names every leaf that differs.
func checkTargetPolicy(src *setupwire.Setup, locked *setupwire.Locked, open *setupwire.Open, target *setupwire.Policy) error {
	want, err := expectedTarget(src, locked, open, target)
	if err != nil {
		return err
	}
	wp, wl, wo, err := want.Leaves()
	if err != nil {
		return fmt.Errorf("handover: this runner's values do not make a target policy: %w", err)
	}
	gp, gl, gor, err := target.Leaves()
	if err != nil {
		return fmt.Errorf("handover: target policy: %w", err)
	}
	var diff []string
	for _, g := range []struct {
		what      string
		want, got []setupwire.Leaf
	}{{"public", wp, gp}, {"locked", wl, gl}, {"open", wo, gor}} {
		for i := range g.want {
			if !bytes.Equal(g.want[i].Value, g.got[i].Value) {
				diff = append(diff, g.what+"."+g.want[i].Name)
			}
		}
	}
	if len(diff) > 0 {
		return fmt.Errorf("handover: the target's setup differs from this signer's in %s (want the same cluster_id, chain and safety, "+
			"handover_generation %d, and version 0 of both groups equal to the values in force here)", strings.Join(diff, ", "), want.HandoverGeneration)
	}
	return nil
}

// checkTarget makes the checks of the target: its published setup and
// identity against the order, its attestation, its values against this
// runner's, and its state. It returns the verified identity and policy.
func (h *sourceHandover) checkTarget(ctx context.Context, q *handover.Request, b *handoverorder.Body, hash [32]byte, v *handoverView,
	handed bool) (*backend.Identity, *setupwire.Policy, error) {
	s := h.s
	bad := func(format string, args ...any) (*backend.Identity, *setupwire.Policy, error) {
		err := fmt.Errorf(format, args...)
		s.Log.Warn("handover refused: target", "err", err)
		return nil, nil, backend.Refused(backend.StatusBadRequest, "%v", err)
	}
	id, err := wire.DecodeIdentity(q.Identity)
	if err != nil {
		return bad("target identity: %v", err)
	}
	pub, err := setupwire.DecodePublished(q.Policy)
	if err != nil {
		return bad("target setup: %v", err)
	}
	sh, err := pub.SetupHash()
	if err != nil {
		return bad("target setup: %v", err)
	}
	switch {
	case sh != b.Target.SetupHash:
		return bad("the target's published setup hashes to %x, the order names %x", sh[:8], b.Target.SetupHash[:8])
	case id.State.SetupHash != sh:
		return bad("the target's identity carries setup %x, not the order's %x", id.State.SetupHash[:8], sh[:8])
	case s.ImportKey != nil && bytes.Equal(id.ImportKey, s.ImportKey.PublicKey()):
		return bad("the identity is this runner's own")
	case id.Attestation == nil:
		return bad("the target's identity carries no attestation")
	}
	verify, err := h.targetVerifier(b, hash)
	if err != nil {
		return bad("%v", err)
	}
	if err := verify(ctx, q.Nonce, backend.IdentityUserData(q.Nonce, id), id.Attestation); err != nil {
		s.Log.Warn("handover refused: target attestation", "err", err)
		return nil, nil, backend.Refused(backend.StatusBadKey, "target attestation: %v", err)
	}
	if err := checkTargetPolicy(s.Updates.SetupWire(), v.locked, v.open, pub.Policy); err != nil {
		return bad("%v", err)
	}
	_, ll, ol, err := pub.Policy.Leaves()
	if err != nil {
		return bad("target setup: %v", err)
	}
	lr, or := setupwire.GroupRoot(ll), setupwire.GroupRoot(ol)
	st := &id.State
	switch {
	case st.Locked.Version != 0 || st.Open.Version != 0 || st.Locked.Hash != lr || st.Open.Hash != or:
		return bad("the target is not at version 0 of its setup's groups (locked %d, open %d)", st.Locked.Version, st.Open.Version)
	case st.Locked.Pending.Version != 0 || st.Open.Pending.Version != 0:
		return bad("a config update is pending on the target")
	case st.ApproverSetHash != pub.Policy.Locked.Approvers.Hash():
		return bad("the target's approver set in force is not its setup's")
	}
	if !handed {
		// The target reserved itself for this order (SHR-01): from the
		// reservation on it takes no config update, so the state checked
		// above holds until the import.
		switch {
		case st.KeyOrigin.Generated != 0 || st.KeyOrigin.Imported != 0:
			return bad("the target holds %d keys already; it must be empty", st.KeyOrigin.Generated+st.KeyOrigin.Imported)
		case st.Order.Kind == 0:
			return bad("the target is not reserved for order %x: push the order to the target first (handover-target identity -order)", hash[:8])
		case st.Order.Kind != uint8(markstore.OrderHandover) || st.Order.Hash != hash:
			return bad("the target is reserved for another order (kind %d, %x)", st.Order.Kind, st.Order.Hash[:8])
		}
	}
	return id, pub.Policy, nil
}

// readShares reads every stored share once, with its key origin from its
// sealed record. check also wants them to be the loaded keys.
func (h *sourceHandover) readShares(check bool) ([]handedShare, error) {
	s := h.s
	names, err := ListShares(s.Platform.Store)
	if err != nil {
		return nil, err
	}
	out := make([]handedShare, 0, len(names))
	for _, n := range names {
		var pk backend.Pubkey
		if b, err := hex.DecodeString(strings.TrimPrefix(n, "shares/")); err != nil || len(b) != len(pk) {
			return nil, fmt.Errorf("%s: bad key name", n)
		} else {
			copy(pk[:], b)
		}
		err := s.readShare(pk, func(rec *shareRecord, sec *[32]byte) error {
			if !validOrigin(rec) {
				return errors.New("bad key origin in the share record")
			}
			sp, err := core.PubkeyOf(*sec)
			if err != nil {
				return err
			}
			hs := handedShare{pk: pk, share: sp, index: rec.Index, secret: *sec, origin: handover.OriginImported}
			if rec.Generated {
				hs.origin = handover.OriginGenerated
				if len(rec.Order) == 32 {
					hs.order = [32]byte(rec.Order)
				}
			}
			out = append(out, hs)
			return nil
		})
		if err != nil {
			for i := range out {
				clear(out[i].secret[:])
			}
			return nil, fmt.Errorf("%s: %w", n, err)
		}
	}
	sort.Slice(out, func(i, j int) bool { return bytes.Compare(out[i].pk[:], out[j].pk[:]) < 0 })
	if check {
		loaded := s.Signer.Keys()
		fail := func(err error) ([]handedShare, error) {
			for i := range out {
				clear(out[i].secret[:])
			}
			return nil, err
		}
		if len(loaded) != len(out) {
			return fail(fmt.Errorf("%d shares stored, %d loaded: refusing to hand over a different set", len(out), len(loaded)))
		}
		for _, k := range loaded {
			i, ok := slices.BinarySearchFunc(out, k.Pubkey, func(a handedShare, pk backend.Pubkey) int { return bytes.Compare(a.pk[:], pk[:]) })
			if !ok || out[i].share != k.SharePubkey {
				return fail(fmt.Errorf("loaded key %s is not among the stored shares: refusing to hand over a different set", k.Pubkey.String()[:18]))
			}
		}
	}
	return out, nil
}

// readCarry is the carry of the pages: the key set of h.shares, which
// the target must hold at the end (SHC-01), and the day's exits the mark
// log holds, with their keys. After the tombstone the log takes no record,
// so it does not change.
func (h *sourceHandover) readCarry() (*handover.Carry, error) {
	d, err := h.s.Hooks.Exits()
	if err != nil {
		return nil, backend.Refused(backend.StatusStorage, "handover carry: %v", err)
	}
	keys := make([]backend.ValidatorKey, len(h.shares))
	for i, sh := range h.shares {
		keys[i] = backend.ValidatorKey{Pubkey: sh.pk, SharePubkey: sh.share}
	}
	c := &handover.Carry{Set: handover.SetOf(keys)}
	if d != nil && len(d.Exits) > 0 {
		c.Exits = &handover.Exits{Day: d.Day, Stake: d.Stake}
		for _, e := range d.Exits {
			c.Exits.Entries = append(c.Exits.Entries, handover.Exit{Pubkey: e.Pubkey, ValidatorIndex: e.ValidatorIndex, ExitEpoch: e.ExitEpoch,
				Stake: e.Stake, Nonce: e.Nonce})
		}
	}
	if _, err := c.Encode(); err != nil {
		return nil, backend.Refused(backend.StatusInternal, "handover carry: %v", err)
	}
	return c, nil
}

// originProof is the attestation of this process's origin key for the
// request's nonce and the order.
func (h *sourceHandover) originProof(ctx context.Context, nonce []byte, order [32]byte) (*handover.OriginProof, error) {
	if h.originKey == nil {
		_, k, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, backend.Refused(backend.StatusInternal, "origin key: %v", err)
		}
		h.originKey = k
	}
	if h.proof != nil && h.proofOrder == order && bytes.Equal(h.proof.Nonce, nonce) {
		return h.proof, nil
	}
	key := [32]byte(h.originKey.Public().(ed25519.PublicKey))
	a, err := h.s.Platform.Attester.Attest(ctx, nonce, handover.OriginUserData(order, key))
	if err != nil {
		return nil, backend.Refused(backend.StatusPlatform, "origin proof: attest: %v", err)
	}
	h.proof, h.proofOrder = &handover.OriginProof{Key: key, Nonce: bytes.Clone(nonce), Attestation: a}, order
	return h.proof, nil
}

// lockers are its locks, for the check after a panic (recover.go).
func (h *sourceHandover) lockers() []sync.Locker { return []sync.Locker{&h.mu} }
