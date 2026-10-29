package keygen

import (
	"context"
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
	"github.com/lidofinance/tee-signer/governance/dkgorder"
	"github.com/lidofinance/tee-signer/governance/setupwire"
	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/dkgmsg"
	"github.com/lidofinance/tee-signer/signer-protocol/remote"
	"github.com/lidofinance/tee-signer/tee-signer/charonlock"
)

// DKG orders (research/setup-phase.md in the threshold-signer-poc repo, section 10,
// "Key generation"; backend/dkgorder). A runner with a setup takes no
// policy file. k approvers in force sign an order, the relay pushes it
// (DKG_ORDER), and the runner keeps it sealed with its arrival time. Each
// order gets a manager of its own, so one runner makes the keys of several
// orders (the Dirk fork lanes and the Charon lane) and keeps them apart:
// every session, hello and key record names its order's hash, and setup
// signing takes only keys made under the same order.
//
// An order is checked when it arrives and again at every use:
//
//   - its cluster_id and chain are the setup's, and this runner's setup is
//     one of its participants, with this runner's operator key;
//   - k approvers of the set in force signed it, and that set is the one
//     in force when it arrived: the record keeps the set's hash. After any
//     change of the set (a rotation, one key replaced, k changed) the order
//     is void until it is pushed again with k signatures of the new set over
//     the same body (same hash), which counts as a new arrival with a new
//     wait (TKGORDER-01);
//   - every participant's image is on the allowed-images list in force;
//   - every verifier it names is built in, and the dev verifier only on the
//     dev platform;
//   - on a runner with limited egress (Nitro: only the routes of its
//     setup), every host that a peer's verifier fetches a key set from is
//     one of the setup's keygen_peer_attestation_hosts (runnerclient Endpoints), so a
//     missing route stops the order here and not in a session;
//   - it acts only once the wait from its arrival has passed: the time lock
//     in force at arrival and at least the images minimum (dkgorder.Wait),
//     since it decides which setups hold new shares. The arrival uses the
//     trusted clock, as config updates do. On the dev platform, which
//     protects nothing (its key is in the binary), the wait is the time
//     lock alone, so local runners and tests need not wait a week;
//   - from not_after on it makes no more keys; the setup messages of the
//     keys it made are still signed;
//   - withdrawal credentials and deposit amounts come from the locked group
//     in force at each setup signature (decision 13).
//
// The record lives in the host's store like the shares. A host that drops
// it makes the runner forget the order: pushed again, it waits again. A
// host that brings back an old record brings back an order that arrived
// then, under the set named in it: void unless that set is still in force.
// So the host can delay key generation, which it can do anyway, but not
// shorten a wait or revive an order the approvers rotated away.

// OrdersEnv is what the DKG orders need from the runner.
type OrdersEnv struct {
	// Env is what every order's manager shares (no Verifiers: each order
	// names its own). Its StateNow and ChainNow give the identity and the
	// chain config at each use.
	Env       Env
	Setup     *setupwire.Setup
	SetupHash [32]byte
	// Locked returns the locked group in force now: approvers, time lock,
	// allowed images, withdrawal credentials and deposit amounts.
	Locked func() (*setupwire.Locked, error)
	// TrustedNow is the time an order's arrival and wait are checked
	// against. It fails when the clock is not trusted.
	TrustedNow func() (uint64, error)
	// VerifierOptions go to each participant's verifier.
	VerifierOptions []runnerclient.Option
	// LimitedEgress is set on a runner whose HTTP client reaches only
	// PeerEndpoints (setup.PeerEgress): a Nitro enclave, whose proxy
	// routes are its setup's, and a dev runner whose setup lists them.
	LimitedEgress bool
	PeerEndpoints []string
}

// Orders holds a runner's DKG orders.
type Orders struct {
	env   OrdersEnv
	mu    sync.Mutex
	known map[[32]byte]*orderEntry
}

type orderEntry struct {
	hash    [32]byte
	raw     []byte
	order   *dkgorder.Order
	self    int
	arrived uint64
	actAt   uint64
	// set is the hash of the approver set in force at arrival.
	set [32]byte
	mgr *Manager
}

// orderRecordVersion is the version of the sealed order record.
const orderRecordVersion = 1

// orderRecord is the sealed record of an order.
type orderRecord struct {
	Version int    `json:"version"`
	Order   []byte `json:"order"`
	Arrived uint64 `json:"arrived"`
	ActAt   uint64 `json:"act_at"`
	// ApproverSet is the hash of the approver set in force when the order
	// arrived (setupwire.ApproverSet.Hash).
	ApproverSet backend.Root `json:"approver_set_hash"`
}

const ordersPrefix = "dkg/orders/"

func orderKey(h [32]byte) string { return ordersPrefix + hex.EncodeToString(h[:]) }
func orderAAD(h [32]byte) []byte { return append([]byte("signer-dkg-order-record-v1|"), h[:]...) }

// NewOrders loads the stored orders. A record that does not open, or names
// an order this runner would not take, is left out with a warning.
func NewOrders(env OrdersEnv) (*Orders, error) {
	if env.Setup == nil || env.Locked == nil || env.TrustedNow == nil {
		return nil, errors.New("dkg orders: setup, locked group and clock are required")
	}
	if env.Env.Now == nil {
		env.Env.Now = time.Now
	}
	if env.Env.Log == nil {
		return nil, errors.New("dkg orders: a logger is required")
	}
	o := &Orders{env: env, known: map[[32]byte]*orderEntry{}}
	names, err := env.Env.Store.List(ordersPrefix)
	if err != nil {
		return nil, err
	}
	for _, name := range names {
		e, err := o.load(name)
		if err != nil {
			env.Env.Log.Warn("dkg order record left out", "record", name, "err", err)
			continue
		}
		o.known[e.hash] = e
	}
	if len(o.known) > 0 {
		env.Env.Log.Info("dkg orders loaded", "orders", len(o.known))
	}
	return o, nil
}

func (o *Orders) load(name string) (*orderEntry, error) {
	b, err := hex.DecodeString(strings.TrimPrefix(name, ordersPrefix))
	if err != nil || len(b) != 32 {
		return nil, errors.New("not an order record name")
	}
	h := [32]byte(b)
	blob, err := o.env.Env.Store.Get(name)
	if err != nil {
		return nil, err
	}
	plain, err := o.env.Env.Sealer.Unseal(blob, orderAAD(h))
	if err != nil {
		return nil, errors.New("does not unseal")
	}
	var rec orderRecord
	if err := json.Unmarshal(plain, &rec); err != nil {
		return nil, err
	}
	if rec.Version != orderRecordVersion {
		return nil, fmt.Errorf("order record version %d, want %d", rec.Version, orderRecordVersion)
	}
	ord, err := dkgorder.Decode(rec.Order)
	if err != nil {
		return nil, err
	}
	enc, _ := ord.Body.Encode()
	if dkgorder.Hash(enc) != h {
		return nil, errors.New("record of another order")
	}
	self, err := o.member(&ord.Body)
	if err != nil {
		return nil, err
	}
	return &orderEntry{hash: h, raw: rec.Order, order: ord, self: self, arrived: rec.Arrived, actAt: rec.ActAt,
		set: rec.ApproverSet}, nil
}

// member checks that the order is for this runner's cluster and chain and
// names this runner's setup with its operator key; it returns the position.
func (o *Orders) member(b *dkgorder.Body) (int, error) {
	if err := b.Matches(o.env.Setup); err != nil {
		return 0, err
	}
	self, ok := b.Position(o.env.SetupHash)
	if !ok {
		return 0, fmt.Errorf("dkg order: this runner's setup %x is not one of its participants", o.env.SetupHash[:8])
	}
	if b.Participants[self].OperatorKey != o.env.Env.OperatorKey {
		return 0, fmt.Errorf("dkg order: participant %d (%s) has another operator key than this runner's %x", self+1,
			b.Participants[self].Name, o.env.Env.OperatorKey[:8])
	}
	return self, nil
}

// wait is the order's wait under the locked group l.
func (o *Orders) wait(l *setupwire.Locked) uint64 {
	if o.env.Env.Platform == "dev" {
		return l.ChangeDelay()
	}
	return dkgorder.Wait(l)
}

// void says why the order does nothing under l, or "".
func (o *Orders) void(e *orderEntry, l *setupwire.Locked) string {
	if now := l.Approvers.Hash(); e.set != now {
		return fmt.Sprintf("the approver set changed since it arrived (%x, now %x); push it again with k signatures of the set in force (a new arrival, with a new wait)",
			e.set[:4], now[:4])
	}
	if err := e.order.Verify(&l.Approvers); err != nil {
		return err.Error()
	}
	if err := e.order.Body.CheckImages(l.AllowedImageMeasurements, o.env.Env.Platform == "dev"); err != nil {
		return err.Error()
	}
	if err := o.checkEgress(&e.order.Body, e.self); err != nil {
		return err.Error()
	}
	return ""
}

// checkEgress refuses an order with a peer whose verifier fetches its key
// set from a host this runner does not reach: on a runner with limited
// egress, a host outside the setup's keygen_peer_attestation_hosts. It names every such
// host, so one new setup can list them all.
func (o *Orders) checkEgress(b *dkgorder.Body, self int) error {
	if !o.env.LimitedEgress {
		return nil
	}
	var missing []string
	for i := range b.Participants {
		if i == self {
			continue
		}
		p := &b.Participants[i]
		a := runnerclient.OrderAttestation(p)
		var hosts []string
		for _, e := range a.Endpoints() {
			if !slices.Contains(o.env.PeerEndpoints, e) {
				hosts = append(hosts, e)
			}
		}
		if len(hosts) > 0 {
			missing = append(missing, fmt.Sprintf("participant %d (%s), verifier %s, fetches its key set from %s", i+1, p.Name,
				a.Verifier, strings.Join(hosts, " and ")))
		}
	}
	if len(missing) == 0 {
		return nil
	}
	listed := "none"
	if len(o.env.PeerEndpoints) > 0 {
		listed = strings.Join(o.env.PeerEndpoints, ", ")
	}
	return fmt.Errorf("dkg order: this %s runner reaches only its setup's keygen_peer_attestation_hosts (%s): %s; this signer needs a setup that lists them in keygen_peer_attestation_hosts",
		o.env.Env.Platform, listed, strings.Join(missing, "; "))
}

func (o *Orders) state(e *orderEntry, l *setupwire.Locked, now uint64, outcome uint8) *dkgmsg.OrderState {
	s := &dkgmsg.OrderState{Outcome: outcome, Hash: e.hash, Position: uint8(e.self), Arrived: e.arrived, ActAt: e.actAt,
		NotAfter: e.order.Body.NotAfter}
	switch why := o.void(e, l); {
	case why != "":
		s.Status, s.Why = dkgmsg.OrderVoid, why
	case now < e.actAt:
		s.Status = dkgmsg.OrderPending
	case now >= e.order.Body.NotAfter:
		s.Status = dkgmsg.OrderExpired
	default:
		s.Status = dkgmsg.OrderActive
	}
	return s
}

// Push takes a signed order (DKG_ORDER). The same order again answers
// OrderKnown with its state; its arrival stays. A copy whose signatures no
// longer count under the set in force is replaced by one that counts, with
// a new arrival.
func (o *Orders) Push(_ context.Context, raw []byte) (*dkgmsg.OrderState, error) {
	ord, err := dkgorder.Decode(raw)
	if err != nil {
		return nil, backend.Refused(backend.StatusBadRequest, "%v", err)
	}
	body, _ := ord.Body.Encode()
	h := dkgorder.Hash(body)
	self, err := o.member(&ord.Body)
	if err != nil {
		return nil, backend.Refused(backend.StatusBadRequest, "%v", err)
	}
	l, err := o.env.Locked()
	if err != nil {
		return nil, err
	}
	if err := ord.Verify(&l.Approvers); err != nil {
		return nil, backend.Refused(backend.StatusBadRequest, "%v", err)
	}
	if err := ord.Body.CheckImages(l.AllowedImageMeasurements, o.env.Env.Platform == "dev"); err != nil {
		return nil, backend.Refused(backend.StatusBadRequest, "%v", err)
	}
	if _, err := PolicyFromOrder(&ord.Body, h, o.env.Env.Platform, nil); err != nil {
		return nil, backend.Refused(backend.StatusBadRequest, "%v", err)
	}
	if err := o.checkEgress(&ord.Body, self); err != nil {
		return nil, backend.Refused(backend.StatusBadRequest, "%v", err)
	}
	now, err := o.env.TrustedNow()
	if err != nil {
		return nil, err
	}
	// The old session of a re-pushed order ends after o.mu is released:
	// a HELLO holds its manager's lock and reads the setup state, whose
	// order slot takes o.mu (TKGORDER-02). Deferred first, so it runs last.
	var aborted *Manager
	defer func() {
		if aborted != nil {
			aborted.Abort()
		}
	}()
	o.mu.Lock()
	defer o.mu.Unlock()
	if e := o.known[h]; e != nil && o.void(e, l) == "" {
		return o.state(e, l, now, dkgmsg.OrderKnown), nil
	}
	actAt := setupwire.SatAdd(now, o.wait(l))
	if ord.Body.NotAfter <= actAt {
		return nil, backend.Refused(backend.StatusBadRequest, "dkg order: not_after %d is not after %d, when it would act (arrival %d + wait %d)",
			ord.Body.NotAfter, actAt, now, o.wait(l))
	}
	set := l.Approvers.Hash()
	plain, err := json.Marshal(orderRecord{Version: orderRecordVersion, Order: raw, Arrived: now, ActAt: actAt, ApproverSet: set})
	if err != nil {
		return nil, err
	}
	blob, err := o.env.Env.Sealer.Seal(plain, orderAAD(h))
	if err != nil {
		return nil, backend.Refused(backend.StatusPlatform, "dkg order: seal: %v", err)
	}
	if err := o.env.Env.Store.Put(orderKey(h), blob); err != nil {
		return nil, backend.Refused(backend.StatusPlatform, "dkg order: store: %v", err)
	}
	if old := o.known[h]; old != nil {
		aborted = old.mgr
	}
	e := &orderEntry{hash: h, raw: append([]byte(nil), raw...), order: ord, self: self, arrived: now, actAt: actAt,
		set: set}
	o.known[h] = e
	o.env.Env.Log.Info("dkg order accepted", "order", hex.EncodeToString(h[:6]), "label", ord.Body.Label, "path", ord.Body.Path.String(),
		"participants", len(ord.Body.Participants), "threshold", ord.Body.Threshold, "self", self+1,
		"act_at", actAt, "not_after", ord.Body.NotAfter)
	return o.state(e, l, now, dkgmsg.OrderAccepted), nil
}

// Manager returns the manager of an order in force. forKeys (HELLO) also
// needs it before its not_after; the later rounds of a session and setup
// signing do not.
func (o *Orders) Manager(h [32]byte, forKeys bool) (*Manager, error) {
	l, err := o.env.Locked()
	if err != nil {
		return nil, err
	}
	now, err := o.env.TrustedNow()
	if err != nil {
		return nil, err
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	e := o.known[h]
	if e == nil {
		return nil, backend.Refused(backend.StatusNotReady, "dkg order %x is not known here; push it first (DKG_ORDER)", h[:6])
	}
	switch s := o.state(e, l, now, dkgmsg.OrderKnown); {
	case s.Status == dkgmsg.OrderVoid:
		return nil, backend.Refused(backend.StatusPolicyPubkey, "dkg order %x is void: %s", h[:6], s.Why)
	case s.Status == dkgmsg.OrderPending:
		return nil, backend.Refused(backend.StatusNotReady, "dkg order %x waits until %s (%d s from now)", h[:6],
			time.Unix(int64(min(e.actAt, 1<<62)), 0).UTC().Format(time.RFC3339), e.actAt-now)
	case s.Status == dkgmsg.OrderExpired && forKeys:
		return nil, backend.Refused(backend.StatusPolicyPubkey, "dkg order %x makes no keys since its not_after %d", h[:6], e.order.Body.NotAfter)
	}
	if e.mgr == nil {
		if e.mgr, err = o.newManager(e); err != nil {
			return nil, backend.Refused(backend.StatusInternal, "dkg order %x: %v", h[:6], err)
		}
	}
	return e.mgr, nil
}

func (o *Orders) newManager(e *orderEntry) (*Manager, error) {
	p, err := PolicyFromOrder(&e.order.Body, e.hash, o.env.Env.Platform, o.env.Locked)
	if err != nil {
		return nil, err
	}
	env := o.env.Env
	env.Verifiers = make([]remote.VerifyFunc, len(p.Participants))
	for i := range p.Participants {
		if env.Verifiers[i], err = p.Participants[i].Attestation.NewDKGHelloVerifier(o.env.VerifierOptions...); err != nil {
			return nil, fmt.Errorf("participant %d: %w", i+1, err)
		}
	}
	return New(p, e.hash, env)
}

// Abort ends the session in progress of an order, if any.
func (o *Orders) Abort(h [32]byte) {
	o.mu.Lock()
	e := o.known[h]
	o.mu.Unlock()
	if e != nil && e.mgr != nil {
		e.mgr.Abort()
	}
}

// PendingSlot is the order IDENTITY shows (section 4): of the orders that
// still wait out their time and are not void, the one that acts last, so
// the slot stays set while any order waits. Zero when none waits. Kind 2 is
// a DKG order.
func (o *Orders) PendingSlot() backend.Order {
	now := uint64(max(o.env.Env.Now().Unix(), 0))
	l, lerr := o.env.Locked()
	o.mu.Lock()
	defer o.mu.Unlock()
	var waiting []*orderEntry
	for _, e := range o.known {
		if now < e.actAt && (lerr != nil || o.void(e, l) == "") {
			waiting = append(waiting, e)
		}
	}
	if len(waiting) == 0 {
		return backend.Order{}
	}
	sort.Slice(waiting, func(i, j int) bool {
		a, b := waiting[i], waiting[j]
		return a.actAt > b.actAt || a.actAt == b.actAt && string(a.hash[:]) < string(b.hash[:])
	})
	return backend.Order{Kind: 2, Hash: waiting[0].hash, ActAt: waiting[0].actAt}
}

// PolicyFromOrder is the key generation policy of a DKG order: its
// participants with their attestation settings and setup_hash pinned, its
// threshold, path and ENRs. locked, if set, gives the locked group in force
// at each setup signature, from which the withdrawal credentials and the
// deposit amounts come; without it the policy signs no setup message (the
// arrival check). It refuses a verifier this program is not built with and
// the dev verifier on any platform but dev.
func PolicyFromOrder(b *dkgorder.Body, hash [32]byte, platformName string, locked func() (*setupwire.Locked, error)) (*Policy, error) {
	p := &Policy{Version: 1, Threshold: int(b.Threshold), order: true, path: b.Path.String(),
		enrs: append([]string(nil), b.CharonENRs...)}
	for i := range b.Participants {
		op := &b.Participants[i]
		a := runnerclient.OrderAttestation(op)
		where := fmt.Sprintf("dkg order: participant %d (%s)", i+1, op.Name)
		if !runnerclient.Available(a.Verifier) {
			return nil, fmt.Errorf("%s: verifier %q is not built into this runner; build it with that peer's tag (scripts/build-runner.sh PEERS=...)", where, a.Verifier)
		}
		if a.Verifier == runnerclient.VerifierDev && platformName != "dev" {
			return nil, fmt.Errorf("%s: verifier dev accepts unsigned documents, refused on platform %s", where, platformName)
		}
		if err := a.Validate(); err != nil {
			return nil, fmt.Errorf("%s: %w", where, err)
		}
		p.Participants = append(p.Participants, Participant{Name: op.Name, OperatorKey: hex.EncodeToString(op.OperatorKey[:]),
			Attestation: a, operatorKey: op.OperatorKey, setupHash: op.SetupHash, pinned: true})
	}
	if locked != nil {
		p.rulesNow = func() (*setupRules, error) {
			l, err := locked()
			if err != nil {
				return nil, err
			}
			return rulesFromLocked(p.path, p.enrs, l)
		}
	}
	return p, nil
}

// rulesFromLocked are the setup rules of an order under the locked group l:
// its withdrawal credentials (0x01 or 0x02, the address in the last 20
// bytes) and deposit amounts, 1 ETH up to 32 ETH (0x01) or 2048 ETH (0x02),
// as the policy file allowed.
func rulesFromLocked(path string, enrs []string, l *setupwire.Locked) (*setupRules, error) {
	wc := l.WithdrawalCredentials
	r := &setupRules{path: path, enrs: enrs, amounts: map[uint64]bool{}}
	switch wc[0] {
	case 0x01:
	case 0x02:
		r.compounding = true
	default:
		return nil, fmt.Errorf("locked withdrawal_credentials prefix %#02x, want 0x01 or 0x02", wc[0])
	}
	copy(r.address[:], wc[12:])
	r.credentials = charonlock.WithdrawalCredentials(r.address, r.compounding)
	if r.credentials != wc || r.address == [20]byte{} {
		return nil, errors.New("locked withdrawal_credentials: want the prefix, 11 zero bytes and a non-zero address")
	}
	if len(l.AllowedDepositAmounts) == 0 {
		return nil, errors.New("the locked group in force lists no allowed_deposit_amounts")
	}
	max := uint64(32 * gwei)
	if r.compounding {
		max = 2048 * gwei
	}
	for _, v := range l.AllowedDepositAmounts {
		if v < gwei || v > max {
			return nil, fmt.Errorf("locked deposit amount %d gwei: this runner signs deposits of 1 ETH to %d ETH", v, max/gwei)
		}
		r.amounts[v] = true
	}
	r.amountList = append([]uint64(nil), l.AllowedDepositAmounts...)
	return r, nil
}
