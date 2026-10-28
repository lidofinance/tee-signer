package keygen

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/governance/dkgorder"
	"github.com/lidofinance/tee-signer/governance/setupwire"
	"github.com/lidofinance/tee-signer/platform/dev"
	"github.com/lidofinance/tee-signer/signer-core/core"
	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/dkgmsg"
	"github.com/lidofinance/tee-signer/tee-signer/charonlock"
	"github.com/lidofinance/tee-signer/tee-signer/keygen/relay"
)

// Key generation under DKG orders, for runners with a setup: three runners
// of one cluster with a fake signer, the locked group and the trusted clock
// in the test's hands.

// orderApprover is test approver i: a key from a fixed seed.
func orderApprover(i byte) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{i}, 32))
}

func approverSet(ids ...byte) setupwire.ApproverSet {
	s := setupwire.ApproverSet{ApprovalsNeeded: 2}
	for _, i := range ids {
		s.Keys = append(s.Keys, [32]byte(orderApprover(i).Public().(ed25519.PublicKey)))
	}
	return s
}

// gcpImage and gcpOther are image digests of gcp-cs participants: the first
// on the allowed list of the test setups, the second not.
var (
	gcpImage = bytes.Repeat([]byte{0x77}, 32)
	gcpOther = bytes.Repeat([]byte{0x78}, 32)
)

// orderSetup is setupwire's dev sample made the setup of signer name in
// one test cluster: approvers 1 to 3 with k = 2, no time lock, the gcp
// image allowed, compounding credentials to testWithdrawal and 32 ETH
// deposits.
func orderSetup(t *testing.T, name string) *setupwire.Setup {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "governance", "setupwire", "testdata", "setup-dev.bin"))
	if err != nil {
		t.Fatal(err)
	}
	s, err := setupwire.DecodeSetup(raw)
	if err != nil {
		t.Fatal(err)
	}
	s.SignerName, s.ClusterID = name, [32]byte{0xc1, 0x05}
	s.Chain.GenesisForkVersion = testChain.GenesisForkVersion
	l := &s.Locked
	l.Approvers = approverSet(1, 2, 3)
	zero := uint64(0)
	l.ChangeDelaySeconds = &zero
	l.AllowedImageMeasurements = []setupwire.Image{{Kind: setupwire.ImageGCP, Measurement: gcpImage}}
	addr, _ := charonlock.Address(testWithdrawal)
	l.WithdrawalCredentials = charonlock.WithdrawalCredentials(addr, true)
	l.AllowedDepositAmounts = []uint64{32 * gwei}
	if _, err := s.Encode(); err != nil {
		t.Fatal(err)
	}
	return s
}

// orderNode is one runner with a setup that takes DKG orders.
type orderNode struct {
	*testRunner
	orders *Orders
	setup  *setupwire.Setup
	hash   [32]byte
	opKey  [32]byte

	mu        sync.Mutex
	locked    *setupwire.Locked
	trusted   uint64
	untrusted bool
	// shownSetup, if set, is the setup_hash the runner's identity carries in
	// place of its own: a runner of another setup that pretends.
	shownSetup *[32]byte
	// stateHook, if set, runs first in the runner's setup state, outside mu.
	stateHook func()
}

func (n *orderNode) lockedNow() (*setupwire.Locked, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	l := *n.locked
	return &l, nil
}

func (n *orderNode) trustedNow() (uint64, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.untrusted {
		return 0, backend.Refused(backend.StatusClock, "the clock is not trusted")
	}
	return n.trusted, nil
}

// setTime moves the trusted clock and the runner's clock to Unix second s.
func (n *orderNode) setTime(s uint64) {
	n.mu.Lock()
	n.trusted = s
	n.mu.Unlock()
	n.testRunner.mu.Lock()
	n.testRunner.now = time.Unix(int64(s), 0)
	n.testRunner.mu.Unlock()
}

// newOrderNode starts a runner of setup s on platform plat. reopen, if
// set, is the store of an earlier run of the same runner.
func newOrderNode(t *testing.T, s *setupwire.Setup, plat string, reopen *memStore) *orderNode {
	t.Helper()
	store := reopen
	if store == nil {
		store, _ = newStore(t)
	}
	ops, err := LoadOperatorKeys(dev.NewDevSealer(), store, dev.Attester{})
	if err != nil {
		t.Fatal(err)
	}
	h, err := s.Hash()
	if err != nil {
		t.Fatal(err)
	}
	r := &testRunner{store: store, logs: &bytes.Buffer{}, secrets: map[backend.Pubkey][32]byte{}, now: time.Unix(1_800_000_000, 0)}
	n := &orderNode{testRunner: r, setup: s, hash: h, opKey: ops.Public(), locked: &s.Locked, trusted: 1_800_000_000}
	n.orders, err = NewOrders(OrdersEnv{
		Env: Env{
			Platform: plat, Sealer: dev.NewDevSealer(), Store: store, Attester: dev.Attester{},
			StateNow: func() backend.SetupState {
				n.mu.Lock()
				hook := n.stateHook
				n.mu.Unlock()
				if hook != nil {
					hook()
				}
				n.mu.Lock()
				defer n.mu.Unlock()
				if n.shownSetup != nil {
					return backend.SetupState{SetupHash: *n.shownSetup}
				}
				return backend.SetupState{SetupHash: n.hash}
			},
			TLSKeyHash:  func() []byte { return []byte("tls key hash of this test runner") },
			OperatorKey: ops.Public(),
			ChainNow:    func() core.Config { return testChain },
			AddShares:   r.addShares,
			WithShare:   r.withShare,
			Sign:        r.sign,
			Keys: func() []backend.ValidatorKey {
				r.mu.Lock()
				defer r.mu.Unlock()
				return append([]backend.ValidatorKey(nil), r.keys...)
			},
			Now: func() time.Time { r.mu.Lock(); defer r.mu.Unlock(); return r.now },
			Log: newTestLogger(r),
		},
		Setup: s, SetupHash: h, Locked: n.lockedNow, TrustedNow: n.trustedNow,
	})
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// orderCluster is three dev runners of one cluster.
func orderCluster(t *testing.T) []*orderNode {
	t.Helper()
	var ns []*orderNode
	for _, name := range []string{"signer-a", "signer-b", "signer-c"} {
		ns = append(ns, newOrderNode(t, orderSetup(t, name), "dev", nil))
	}
	return ns
}

// orderBody is an order of the nodes, with the dev verifier.
func orderBody(ns []*orderNode, path dkgorder.Path, label string) dkgorder.Body {
	s := ns[0].setup
	b := dkgorder.Body{ClusterID: s.ClusterID, ChainHash: s.Chain.Hash(), Label: label, Path: path, Threshold: 2,
		NotAfter: 1_900_000_000}
	for i, n := range ns {
		b.Participants = append(b.Participants, dkgorder.Participant{Name: n.setup.SignerName, SetupHash: n.hash,
			OperatorKey: n.opKey, Verifier: dkgorder.VerifierDev})
		if path == dkgorder.PathCharon {
			b.CharonENRs = append(b.CharonENRs, "enr:-test-"+string(rune('1'+i)))
		}
	}
	return b
}

// signOrder signs b with approvers ids; approver id is at position id-1 of
// the set 1, 2, 3 and id-4 of the set 4, 5, 6.
func signOrder(t *testing.T, b dkgorder.Body, ids ...byte) ([]byte, [32]byte) {
	t.Helper()
	enc, err := b.Encode()
	if err != nil {
		t.Fatal(err)
	}
	o := &dkgorder.Order{Body: b}
	for _, id := range ids {
		o.Approvals = append(o.Approvals, setupwire.Approval{Position: (id - 1) % 3, Signature: dkgorder.SignBody(orderApprover(id), enc)})
	}
	raw, err := o.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return raw, dkgorder.Hash(enc)
}

func pushAll(t *testing.T, ns []*orderNode, raw []byte) []*dkgmsg.OrderState {
	t.Helper()
	var out []*dkgmsg.OrderState
	for i, n := range ns {
		st, err := n.orders.Push(context.Background(), raw)
		if err != nil {
			t.Fatalf("runner %d: push: %v", i+1, err)
		}
		// The answer goes through its encoding, as on the wire.
		if st, err = dkgmsg.DecodeOrderState(st.Encode()); err != nil {
			t.Fatal(err)
		}
		out = append(out, st)
	}
	return out
}

// inOrder is a runner's key generation of one order, as the relay sees it
// through DKG_IN_ORDER: each message gets the order's manager first.
type inOrder struct {
	n *orderNode
	h [32]byte
}

func (c inOrder) mgr(hello bool) (*Manager, error) { return c.n.orders.Manager(c.h, hello) }

func (c inOrder) DKGHello(ctx context.Context, q *dkgmsg.HelloRequest) ([]byte, error) {
	m, err := c.mgr(true)
	if err != nil {
		return nil, err
	}
	return m.Hello(ctx, q)
}

func (c inOrder) DKGDeal(ctx context.Context, hellos [][]byte) ([]byte, error) {
	m, err := c.mgr(false)
	if err != nil {
		return nil, err
	}
	return m.Deal(ctx, hellos)
}

func (c inOrder) DKGFinish(ctx context.Context, deals [][]byte) (*dkgmsg.Finished, error) {
	m, err := c.mgr(false)
	if err != nil {
		return nil, err
	}
	return m.Finish(ctx, deals)
}

func (c inOrder) DKGCommit(ctx context.Context, q *dkgmsg.CommitRequest) ([]backend.ValidatorKey, error) {
	m, err := c.mgr(false)
	if err != nil {
		return nil, err
	}
	return m.Commit(ctx, q)
}

func (c inOrder) DKGAbort(context.Context) error { c.n.orders.Abort(c.h); return nil }

func (c inOrder) setupSign(q *dkgmsg.SetupRequest) ([]byte, error) {
	m, err := c.mgr(false)
	if err != nil {
		return nil, err
	}
	b, err := q.Encode()
	if err != nil {
		return nil, err
	}
	return m.SetupSign(context.Background(), b)
}

func inOrders(ns []*orderNode, h [32]byte) []relay.Runner {
	out := make([]relay.Runner, len(ns))
	for i, n := range ns {
		out[i] = inOrder{n, h}
	}
	return out
}

// combineIn signs q with the runners at ids (from 1) under order h and
// combines the partials.
func combineIn(t *testing.T, ns []*orderNode, h [32]byte, ids []uint64, q *dkgmsg.SetupRequest) backend.Signature {
	t.Helper()
	var sigs []backend.Signature
	for _, id := range ids {
		b, err := inOrder{ns[id-1], h}.setupSign(q)
		if err != nil {
			t.Fatalf("runner %d: %v", id, err)
		}
		sigs = append(sigs, backend.Signature(b))
	}
	full, err := core.RecoverSignature(ids, sigs)
	if err != nil {
		t.Fatal(err)
	}
	return full
}

func wantErr(t *testing.T, err error, want string) {
	t.Helper()
	if err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("got %v, want an error with %q", err, want)
	}
}

func TestOrderLimitsAgree(t *testing.T) {
	if dkgorder.MaxParticipants != dkgmsg.MaxParticipants {
		t.Fatalf("dkgorder.MaxParticipants %d, dkgmsg.MaxParticipants %d", dkgorder.MaxParticipants, dkgmsg.MaxParticipants)
	}
}

// Two orders on the same runners: a Dirk fork lane and a Charon lane. Each
// makes its own keys, labelled with its hash and path; setup signing under
// one order takes only its own keys; credentials come from the locked group.
func TestOrdersTwoLanesOnOneCluster(t *testing.T) {
	ns := orderCluster(t)
	dirkRaw, dirkH := signOrder(t, orderBody(ns, dkgorder.PathDirk, "dirk-lanes"), 1, 2)
	charonRaw, charonH := signOrder(t, orderBody(ns, dkgorder.PathCharon, "charon"), 2, 3)
	for _, raw := range [][]byte{dirkRaw, charonRaw} {
		for i, st := range pushAll(t, ns, raw) {
			if st.Outcome != dkgmsg.OrderAccepted || st.Status != dkgmsg.OrderActive || int(st.Position) != i {
				t.Fatalf("runner %d: %+v", i+1, st)
			}
		}
	}
	// Again: known, nothing changes.
	if st := pushAll(t, ns, dirkRaw)[0]; st.Outcome != dkgmsg.OrderKnown || st.Status != dkgmsg.OrderActive {
		t.Fatalf("second push: %+v", st)
	}
	ctx := context.Background()
	dirk, err := relay.Run(ctx, inOrders(ns, dirkH), 2, relay.Options{})
	if err != nil {
		t.Fatal(err)
	}
	charon, err := relay.Run(ctx, inOrders(ns, charonH), 2, relay.Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		out  *relay.Output
		h    [32]byte
		path string
	}{{dirk, dirkH, "dirk"}, {charon, charonH, "charon"}} {
		for i, n := range ns {
			for _, gk := range c.out.Result.GroupKeys {
				rec, err := LoadKeyRecord(dev.NewDevSealer(), n.store, gk)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(rec.Order, c.h[:]) || !bytes.Equal(rec.PolicyHash, c.h[:]) || rec.Path != c.path || int(rec.Self) != i+1 {
					t.Fatalf("runner %d: key record %+v, want order %x path %s", i+1, rec, c.h[:4], c.path)
				}
				// The server marks the share generated under this order (the key origin).
				if !bytes.Equal(n.testRunner.orders[gk], c.h[:]) {
					t.Fatalf("runner %d: share handed to the server with order %x, want %x", i+1, n.testRunner.orders[gk], c.h[:4])
				}
			}
		}
	}
	// A hello of the Dirk order in a session of the Charon order is refused.
	hs := make([][]byte, 3)
	for i, n := range ns {
		q := &dkgmsg.HelloRequest{Nonce: bytes.Repeat([]byte{1}, 16), Count: 1}
		h := charonH
		if i == 2 {
			h = dirkH
		}
		if hs[i], err = (inOrder{n, h}).DKGHello(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	_, err = inOrder{ns[0], charonH}.DKGDeal(ctx, hs)
	wantRefused(t, err, backend.StatusBadKey, "another policy")

	// Deposits: the locked group's credentials and amount, Dirk keys under
	// the Dirk order only.
	gk := dirk.Result.GroupKeys[0]
	wc := ns[0].setup.Locked.WithdrawalCredentials
	q := &dkgmsg.SetupRequest{Kind: dkgmsg.SetupDeposit, Deposit: &dkgmsg.Deposit{Pubkey: gk, WithdrawalCredentials: wc, Amount: 32 * gwei}}
	_, err = inOrder{ns[0], charonH}.setupSign(q)
	wantRefused(t, err, backend.StatusPolicyPubkey, "generated under another policy")
	full := combineIn(t, ns, dirkH, []uint64{1, 3}, q)
	if !core.Verify(gk, charonlock.DepositSigningRoot(gk, wc, 32*gwei, testChain.GenesisForkVersion), full) {
		t.Fatal("combined deposit signature does not verify")
	}
	// A Charon key: registrations are for its path.
	ck := charon.Result.GroupKeys[0]
	reg := &backend.ValidatorRegistration{FeeRecipient: testFee, GasLimit: 30_000_000, Timestamp: 1, Pubkey: ck}
	combineIn(t, ns, charonH, []uint64{1, 2}, &dkgmsg.SetupRequest{Kind: dkgmsg.SetupRegistration, Registration: reg})
	_, err = inOrder{ns[0], dirkH}.setupSign(&dkgmsg.SetupRequest{Kind: dkgmsg.SetupRegistration,
		Registration: &backend.ValidatorRegistration{FeeRecipient: testFee, GasLimit: 30_000_000, Timestamp: 1, Pubkey: gk}})
	wantRefused(t, err, backend.StatusUnsupported, "Charon path only")
	for _, n := range ns {
		assertNoSecrets(t, []*testRunner{n.testRunner})
	}
}

// Withdrawal credentials and deposit amounts follow the locked group in
// force at each signature, not the order.
func TestOrderCredentialsFromLocked(t *testing.T) {
	ns := orderCluster(t)
	raw, h := signOrder(t, orderBody(ns, dkgorder.PathDirk, "dirk"), 1, 2)
	pushAll(t, ns, raw)
	out, err := relay.Run(context.Background(), inOrders(ns, h), 1, relay.Options{})
	if err != nil {
		t.Fatal(err)
	}
	gk := out.Result.GroupKeys[0]
	dep := func(wc backend.Root, amount uint64) *dkgmsg.SetupRequest {
		return &dkgmsg.SetupRequest{Kind: dkgmsg.SetupDeposit, Deposit: &dkgmsg.Deposit{Pubkey: gk, WithdrawalCredentials: wc, Amount: amount}}
	}
	old := ns[0].setup.Locked.WithdrawalCredentials
	newWC := charonlock.WithdrawalCredentials([20]byte{0x42, 0x42}, false)
	_, err = inOrder{ns[0], h}.setupSign(dep(old, 31*gwei))
	wantRefused(t, err, backend.StatusPolicyPubkey, "not in the policy")
	_, err = inOrder{ns[0], h}.setupSign(dep(newWC, 32*gwei))
	wantRefused(t, err, backend.StatusPolicyPubkey, "not the policy's")
	// A locked update in force: other credentials, two amounts.
	l := *ns[0].locked
	l.WithdrawalCredentials, l.AllowedDepositAmounts = newWC, []uint64{1 * gwei, 32 * gwei}
	ns[0].locked = &l
	_, err = inOrder{ns[0], h}.setupSign(dep(old, 32*gwei))
	wantRefused(t, err, backend.StatusPolicyPubkey, "not the policy's")
	if _, err := (inOrder{ns[0], h}).setupSign(dep(newWC, 1*gwei)); err != nil {
		t.Fatal(err)
	}
	// 0x01 credentials take deposits up to 32 ETH only; a locked group with
	// more refuses every setup signature.
	l2 := l
	l2.AllowedDepositAmounts = []uint64{64 * gwei}
	ns[0].locked = &l2
	_, err = inOrder{ns[0], h}.setupSign(dep(newWC, 64*gwei))
	wantRefused(t, err, backend.StatusPolicyPubkey, "this runner signs deposits of 1 ETH to 32 ETH")
}

// What an order must be to be taken.
func TestOrderPushRefusals(t *testing.T) {
	ns := orderCluster(t)
	body := orderBody(ns, dkgorder.PathDirk, "dirk")
	other := newOrderNode(t, orderSetup(t, "signer-x"), "dev", nil)
	cases := []struct {
		name string
		edit func(b *dkgorder.Body)
		ids  []byte
		want string
	}{
		{"other cluster", func(b *dkgorder.Body) { b.ClusterID[9] = 1 }, []byte{1, 2}, "for another cluster_id"},
		{"other chain", func(b *dkgorder.Body) { b.ChainHash[0] ^= 1 }, []byte{1, 2}, "for another chain"},
		{"not a participant", func(b *dkgorder.Body) { b.Participants[0].SetupHash = other.hash }, []byte{1, 2},
			"this runner's setup"},
		{"other operator key", func(b *dkgorder.Body) { b.Participants[0].OperatorKey = other.opKey }, []byte{1, 2},
			"has another operator key"},
		{"one approver", func(*dkgorder.Body) {}, []byte{1}, "approvals_needed is 2"},
		{"not an approver", func(*dkgorder.Body) {}, []byte{1, 5}, "does not verify"},
		{"image not allowed", func(b *dkgorder.Body) {
			b.Participants[2] = dkgorder.Participant{Name: "gcp", SetupHash: [32]byte{9}, OperatorKey: other.opKey,
				Verifier: dkgorder.VerifierGCP, Image: gcpOther, GCPAudience: "signer-runner-identity", GCPHWModels: []string{"GCP_INTEL_TDX"},
				GCPIssuer: "https://confidentialcomputing.googleapis.com", GCPServiceAccount: "s@p.iam.gserviceaccount.com", GCPProjectID: "signer-project"}
		}, []byte{1, 2}, "not on the allowed-images list"},
		{"not_after before it acts", func(b *dkgorder.Body) { b.NotAfter = 1_800_000_000 }, []byte{1, 2}, "is not after"},
	}
	for _, c := range cases {
		b := body
		b.Participants = append([]dkgorder.Participant(nil), body.Participants...)
		c.edit(&b)
		raw, _ := signOrder(t, b, c.ids...)
		_, err := ns[0].orders.Push(context.Background(), raw)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: got %v, want %q", c.name, err, c.want)
		}
	}
	raw, h := signOrder(t, body, 1, 2)
	ns[0].untrusted = true
	_, err := ns[0].orders.Push(context.Background(), raw)
	wantRefused(t, err, backend.StatusClock, "not trusted")
	ns[0].untrusted = false
	if _, err := ns[0].orders.Manager(h, true); err == nil {
		t.Fatal("an order that was refused has a manager")
	}
	_, err = ns[0].orders.Push(context.Background(), []byte("junk"))
	wantRefused(t, err, backend.StatusBadRequest, "")
}

// A cloud runner: the order waits the images minimum from its arrival, even
// with no time lock, makes keys until not_after, and keeps signing the
// setup messages of its keys after that.
func TestOrderWaitAndExpiry(t *testing.T) {
	var ns []*orderNode
	for _, name := range []string{"signer-a", "signer-b", "signer-c"} {
		ns = append(ns, newOrderNode(t, orderSetup(t, name), "gcp", nil))
	}
	b := orderBody(ns, dkgorder.PathDirk, "cloud")
	for i := range b.Participants {
		p := &b.Participants[i]
		p.Verifier, p.Image = dkgorder.VerifierGCP, gcpImage
		p.GCPAudience, p.GCPHWModels, p.GCPIssuer = "signer-runner-identity", []string{"GCP_INTEL_TDX"}, "https://confidentialcomputing.googleapis.com"
		p.GCPServiceAccount, p.GCPProjectID = "s@p.iam.gserviceaccount.com", "signer-project"
	}
	t0 := uint64(1_800_000_000)
	b.NotAfter = t0 + setupwire.ImagesMinTimeLock + 3600
	raw, h := signOrder(t, b, 1, 2)
	st := pushAll(t, ns[:1], raw)[0]
	if st.Status != dkgmsg.OrderPending || st.Arrived != t0 || st.ActAt != t0+setupwire.ImagesMinTimeLock {
		t.Fatalf("state %+v", st)
	}
	_, err := ns[0].orders.Manager(h, true)
	wantRefused(t, err, backend.StatusNotReady, "waits until")
	if slot := ns[0].orders.PendingSlot(); slot.Kind != 2 || slot.Hash != h || slot.ActAt != st.ActAt {
		t.Fatalf("pending slot %+v", slot)
	}
	// Pushed again a day later: the arrival stays.
	ns[0].setTime(t0 + 86400)
	if st2 := pushAll(t, ns[:1], raw)[0]; st2.Outcome != dkgmsg.OrderKnown || st2.ActAt != st.ActAt {
		t.Fatalf("second push %+v", st2)
	}
	// A restart reads the record: same arrival, no new wait.
	again := newOrderNode(t, ns[0].setup, "gcp", ns[0].store)
	again.setTime(t0 + 86400)
	if _, err := again.orders.Manager(h, true); err == nil || !strings.Contains(err.Error(), "waits until") {
		t.Fatalf("after a restart: %v", err)
	}
	again.setTime(st.ActAt)
	if _, err := again.orders.Manager(h, true); err != nil {
		t.Fatalf("at act_at: %v", err)
	}
	if slot := again.orders.PendingSlot(); slot.Kind != 0 {
		t.Fatalf("pending slot after act_at %+v", slot)
	}
	again.setTime(b.NotAfter)
	_, err = again.orders.Manager(h, true)
	wantRefused(t, err, backend.StatusPolicyPubkey, "makes no keys since its not_after")
	if _, err := again.orders.Manager(h, false); err != nil {
		t.Fatalf("setup signing after not_after: %v", err)
	}
	// A time lock above the images minimum makes the wait longer.
	n := newOrderNode(t, orderSetup(t, "signer-a"), "gcp", nil)
	l := *n.locked
	long := uint64(setupwire.MaxTimeLock)
	l.ChangeDelaySeconds = &long
	n.locked = &l
	b.NotAfter = t0 + long + 1
	b.Participants[0].OperatorKey = n.opKey
	raw, _ = signOrder(t, b, 1, 2)
	if st := pushAll(t, []*orderNode{n}, raw)[0]; st.ActAt != t0+long {
		t.Fatalf("wait with a 30-day time lock: %+v", st)
	}
}

// A rotation voids the old set's order; the new set's signatures over the
// same body bring it back as a new arrival, with the same hash.
func TestOrderRotationVoids(t *testing.T) {
	ns := orderCluster(t)
	raw, h := signOrder(t, orderBody(ns, dkgorder.PathDirk, "dirk"), 1, 2)
	pushAll(t, ns, raw)
	out, err := relay.Run(context.Background(), inOrders(ns, h), 1, relay.Options{})
	if err != nil {
		t.Fatal(err)
	}
	l := *ns[0].locked
	l.Approvers = approverSet(4, 5, 6)
	ns[0].locked = &l
	_, err = ns[0].orders.Manager(h, false)
	wantRefused(t, err, backend.StatusPolicyPubkey, "is void")
	ns[0].setTime(1_800_000_100)
	raw2, h2 := signOrder(t, orderBody(ns, dkgorder.PathDirk, "dirk"), 4, 5)
	if h2 != h {
		t.Fatal("new signatures changed the order hash")
	}
	st := pushAll(t, ns[:1], raw2)[0]
	if st.Outcome != dkgmsg.OrderAccepted || st.Arrived != 1_800_000_100 || st.Status != dkgmsg.OrderActive {
		t.Fatalf("re-signed order %+v", st)
	}
	// The key made before keeps its label and setup signing works again.
	wc := l.WithdrawalCredentials
	if _, err := (inOrder{ns[0], h}).setupSign(&dkgmsg.SetupRequest{Kind: dkgmsg.SetupDeposit,
		Deposit: &dkgmsg.Deposit{Pubkey: out.Result.GroupKeys[0], WithdrawalCredentials: wc, Amount: 32 * gwei}}); err != nil {
		t.Fatal(err)
	}
	// An image leaving the allowed list voids an order that names it.
	n := newOrderNode(t, orderSetup(t, "signer-a"), "gcp", nil)
	b := orderBody(ns, dkgorder.PathDirk, "img")
	b.Participants[0] = dkgorder.Participant{Name: "a", SetupHash: n.hash, OperatorKey: n.opKey, Verifier: dkgorder.VerifierGCP, Image: gcpImage,
		GCPAudience: "signer-runner-identity", GCPHWModels: []string{"GCP_INTEL_TDX"}, GCPIssuer: "https://confidentialcomputing.googleapis.com",
		GCPServiceAccount: "s@p.iam.gserviceaccount.com", GCPProjectID: "signer-project"}
	for i := 1; i < 3; i++ {
		b.Participants[i].Verifier = dkgorder.VerifierGCP
		b.Participants[i].Image = gcpImage
		b.Participants[i].GCPAudience, b.Participants[i].GCPHWModels = "signer-runner-identity", []string{"GCP_INTEL_TDX"}
		b.Participants[i].GCPIssuer = "https://confidentialcomputing.googleapis.com"
		b.Participants[i].GCPServiceAccount, b.Participants[i].GCPProjectID = "s@p.iam.gserviceaccount.com", "signer-project"
	}
	raw3, h3 := signOrder(t, b, 1, 2)
	pushAll(t, []*orderNode{n}, raw3)
	l3 := *n.locked
	l3.AllowedImageMeasurements = nil
	n.locked = &l3
	_, err = n.orders.Manager(h3, false)
	wantRefused(t, err, backend.StatusPolicyPubkey, "not on the allowed-images list")
}

// Peers check each hello's setup_hash against the order: a runner whose
// identity shows another setup is refused by its peers and by itself.
func TestOrderHelloSetupPinned(t *testing.T) {
	ns := orderCluster(t)
	raw, h := signOrder(t, orderBody(ns, dkgorder.PathDirk, "dirk"), 1, 2)
	pushAll(t, ns, raw)
	ns[2].shownSetup = &[32]byte{0xbe, 0xef}
	ctx := context.Background()
	hs := make([][]byte, 3)
	for i, n := range ns {
		var err error
		if hs[i], err = (inOrder{n, h}).DKGHello(ctx, &dkgmsg.HelloRequest{Nonce: bytes.Repeat([]byte{2}, 16), Count: 1}); err != nil {
			t.Fatal(err)
		}
	}
	_, err := inOrder{ns[0], h}.DKGDeal(ctx, hs)
	wantRefused(t, err, backend.StatusBadKey, "is not the setup_sha256")
	_, err = inOrder{ns[2], h}.DKGDeal(ctx, hs)
	wantRefused(t, err, backend.StatusBadKey, "this runner's setup_hash is not the one the order names")
}

// The IDENTITY slot shows the order that acts last while any waits.
func TestOrderPendingSlot(t *testing.T) {
	ns := orderCluster(t)
	n := ns[0]
	l := *n.locked
	lock := uint64(600)
	l.ChangeDelaySeconds = &lock
	n.locked = &l
	if s := n.orders.PendingSlot(); s != (backend.Order{}) {
		t.Fatalf("slot %+v with no order", s)
	}
	rawA, hA := signOrder(t, orderBody(ns, dkgorder.PathDirk, "a"), 1, 2)
	pushAll(t, ns[:1], rawA)
	n.setTime(1_800_000_300)
	rawB, hB := signOrder(t, orderBody(ns, dkgorder.PathCharon, "b"), 1, 2)
	pushAll(t, ns[:1], rawB)
	if s := n.orders.PendingSlot(); s.Hash != hB || s.ActAt != 1_800_000_900 {
		t.Fatalf("slot %+v, want order b at 1800000900", s)
	}
	n.setTime(1_800_000_700)
	if s := n.orders.PendingSlot(); s.Hash != hB {
		t.Fatalf("slot %+v after a acted", s)
	}
	if _, err := n.orders.Manager(hA, true); err != nil {
		t.Fatal(err)
	}
	n.setTime(1_800_000_900)
	if s := n.orders.PendingSlot(); s.Kind != 0 {
		t.Fatalf("slot %+v after both acted", s)
	}
}

// A record the host changed is left out at start; the others load.
func TestOrderRecordTampered(t *testing.T) {
	ns := orderCluster(t)
	raw, h := signOrder(t, orderBody(ns, dkgorder.PathDirk, "dirk"), 1, 2)
	pushAll(t, ns[:1], raw)
	ns[0].store.m[orderKey(h)][30] ^= 1
	again := newOrderNode(t, ns[0].setup, "dev", ns[0].store)
	_, err := again.orders.Manager(h, true)
	wantRefused(t, err, backend.StatusNotReady, "not known here")
	if !strings.Contains(again.logs.String(), "dkg order record left out") {
		t.Fatal("no warning about the record")
	}
	var refused *backend.RefusedError
	if !errors.As(err, &refused) {
		t.Fatal(err)
	}
}

func newTestLogger(r *testRunner) *slog.Logger {
	return slog.New(slog.NewTextHandler(syncWriter{r}, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

// A runner with limited egress (a Nitro enclave: only the routes of its
// setup) refuses an order with a peer whose verifier fetches its key set
// from a host outside its setup's keygen_peer_attestation_hosts, when the order arrives
// and again at use, and names every missing host. With all of them listed
// the order is taken; a runner with egress of its own takes it anyway.
func TestOrderPeerEgress(t *testing.T) {
	nitroImage := bytes.Repeat([]byte{0x11}, 144)
	azureImage := bytes.Repeat([]byte{0x22}, 32)
	s := orderSetup(t, "gsigner-2")
	s.Locked.AllowedImageMeasurements = []setupwire.Image{{Kind: setupwire.ImageNitro, Measurement: nitroImage},
		{Kind: setupwire.ImageAzure, Measurement: azureImage}, {Kind: setupwire.ImageGCP, Measurement: gcpImage}}
	n := newOrderNode(t, s, "nitro", nil)
	b := dkgorder.Body{ClusterID: s.ClusterID, ChainHash: s.Chain.Hash(), Label: "egress", Path: dkgorder.PathDirk, Threshold: 2,
		NotAfter: 1_900_000_000, Participants: []dkgorder.Participant{
			{Name: "gsigner-1", SetupHash: [32]byte{1}, OperatorKey: [32]byte(orderApprover(7).Public().(ed25519.PublicKey)), Verifier: dkgorder.VerifierAzure, Image: azureImage,
				MAAHost: "sharedneu.neu.attest.azure.net", Compliance: dkgorder.ComplianceUVM},
			{Name: "gsigner-2", SetupHash: n.hash, OperatorKey: n.opKey, Verifier: dkgorder.VerifierNitro, Image: nitroImage,
				NitroPCR3: [48]byte{0x33}},
			{Name: "gsigner-3", SetupHash: [32]byte{3}, OperatorKey: [32]byte(orderApprover(8).Public().(ed25519.PublicKey)), Verifier: dkgorder.VerifierGCP, Image: gcpImage,
				GCPAudience: "signer-runner-identity", GCPHWModels: []string{"GCP_AMD_SEV"},
				GCPIssuer: "https://confidentialcomputing.googleapis.com", GCPServiceAccount: "s@p.iam.gserviceaccount.com",
				GCPProjectID: "signer-project"},
		}}
	raw, h := signOrder(t, b, 1, 2)
	push := func(limited bool, endpoints ...string) (*dkgmsg.OrderState, error) {
		n.orders.env.LimitedEgress, n.orders.env.PeerEndpoints = limited, endpoints
		return n.orders.Push(context.Background(), raw)
	}
	const (
		maa = "participant 1 (gsigner-1), verifier azure-maa, fetches its key set from sharedneu.neu.attest.azure.net:443"
		cs  = "participant 3 (gsigner-3), verifier gcp-cs, fetches its key set from confidentialcomputing.googleapis.com:443 and www.googleapis.com:443"
	)
	_, err := push(true)
	wantRefused(t, err, backend.StatusBadRequest, "this nitro runner reaches only its setup's keygen_peer_attestation_hosts (none): "+maa+"; "+cs)
	_, err = push(true, "sharedneu.neu.attest.azure.net:443")
	wantRefused(t, err, backend.StatusBadRequest, "(sharedneu.neu.attest.azure.net:443): "+cs+"; this signer needs")
	_, err = push(true, "confidentialcomputing.googleapis.com:443", "www.googleapis.com:443")
	wantRefused(t, err, backend.StatusBadRequest, ": "+maa+"; this signer needs")
	if _, err := n.orders.Manager(h, true); err == nil {
		t.Fatal("a refused order has a manager")
	}
	all := []string{"confidentialcomputing.googleapis.com:443", "sharedneu.neu.attest.azure.net:443", "www.googleapis.com:443"}
	st, err := push(true, all...)
	if err != nil || st.Outcome != dkgmsg.OrderAccepted || st.Status != dkgmsg.OrderPending {
		t.Fatalf("all endpoints listed: %+v %v", st, err)
	}
	// At use: the same stored order under a list without the MAA host
	// (a runner that loads it with another egress) is void.
	n.orders.env.PeerEndpoints = all[:1]
	_, err = n.orders.Manager(h, true)
	wantRefused(t, err, backend.StatusPolicyPubkey, "is void: dkg order: this nitro runner reaches only")
	if slot := n.orders.PendingSlot(); slot.Kind != 0 {
		t.Fatalf("a void order in the pending slot: %+v", slot)
	}
	// A runner with egress of its own (Azure, GCP) checks nothing here.
	b.Label = "egress-2"
	raw, _ = signOrder(t, b, 1, 2)
	if st, err := push(false); err != nil || st.Outcome != dkgmsg.OrderAccepted {
		t.Fatalf("unlimited egress: %v", err)
	}
}

// TKGORDER-02: a re-pushed order aborts its old session while a HELLO of
// that session reads the setup state, which shows the pending order slot.
// Push held Orders.mu and waited for the manager's lock; HELLO held the
// manager's lock and waited for Orders.mu in PendingSlot. Both must end.
func TestOrderRepushDuringHelloDoesNotDeadlock(t *testing.T) {
	ns := orderCluster(t)
	n := ns[0]
	raw, h := signOrder(t, orderBody(ns, dkgorder.PathDirk, "dirk"), 1, 2)
	pushAll(t, ns[:1], raw)
	m, err := n.orders.Manager(h, true)
	if err != nil {
		t.Fatal(err)
	}
	// The runner's state shows the order slot, as runner/dkg_hooks.go has it.
	inState, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	n.mu.Lock()
	n.stateHook = func() {
		once.Do(func() { close(inState); <-release })
		n.orders.PendingSlot()
	}
	n.mu.Unlock()

	helloDone := make(chan error, 1)
	go func() {
		_, err := m.Hello(context.Background(), &dkgmsg.HelloRequest{Nonce: bytes.Repeat([]byte{2}, 16), Count: 1})
		helloDone <- err
	}()
	<-inState
	// A rotation voids the order; the new set signs it again and it is
	// pushed again, which aborts the old session.
	n.mu.Lock()
	l := *n.locked
	l.Approvers = approverSet(4, 5, 6)
	n.locked = &l
	n.mu.Unlock()
	raw2, _ := signOrder(t, orderBody(ns, dkgorder.PathDirk, "dirk"), 4, 5)
	pushDone := make(chan error, 1)
	go func() {
		_, err := n.orders.Push(context.Background(), raw2)
		pushDone <- err
	}()
	time.Sleep(200 * time.Millisecond) // Push takes Orders.mu and reaches Abort
	close(release)
	for name, ch := range map[string]chan error{"HELLO": helloDone, "push": pushDone} {
		select {
		case err := <-ch:
			if err != nil && name == "push" {
				t.Fatalf("push: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("%s still waits: Orders.mu and the manager's lock are taken in opposite orders", name)
		}
	}
	// IDENTITY's slot still answers.
	done := make(chan struct{})
	go func() { n.orders.PendingSlot(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("PendingSlot (IDENTITY) hangs")
	}
}

// TKGSETUP-01: a key keeps the withdrawal credentials of its first deposit
// signature. After a locked update changes the credentials, the key gets no
// deposit for the new ones, on the Dirk path (setup stays open while an
// amount is unsigned) and on the Charon path (open until the lock).
func TestOrderCredentialsStayWithTheKey(t *testing.T) {
	for _, path := range []dkgorder.Path{dkgorder.PathDirk, dkgorder.PathCharon} {
		ns := orderCluster(t)
		raw, h := signOrder(t, orderBody(ns, path, "creds"), 1, 2)
		pushAll(t, ns, raw)
		out, err := relay.Run(context.Background(), inOrders(ns, h), 1, relay.Options{})
		if err != nil {
			t.Fatal(err)
		}
		gk := out.Result.GroupKeys[0]
		dep := func(wc backend.Root, amount uint64) *dkgmsg.SetupRequest {
			return &dkgmsg.SetupRequest{Kind: dkgmsg.SetupDeposit, Deposit: &dkgmsg.Deposit{Pubkey: gk, WithdrawalCredentials: wc, Amount: amount}}
		}
		l0 := *ns[0].locked
		l0.AllowedDepositAmounts = []uint64{1 * gwei, 32 * gwei}
		ns[0].locked = &l0
		a := l0.WithdrawalCredentials
		if _, err := (inOrder{ns[0], h}).setupSign(dep(a, 1*gwei)); err != nil {
			t.Fatalf("%s: 1 ETH to A: %v", path, err)
		}
		// A locked update in force: credentials B.
		l1 := l0
		l1.WithdrawalCredentials = charonlock.WithdrawalCredentials([20]byte{0x42, 0x42}, true)
		ns[0].locked = &l1
		_, err = inOrder{ns[0], h}.setupSign(dep(l1.WithdrawalCredentials, 32*gwei))
		wantRefused(t, err, backend.StatusPolicyPubkey, "first deposit signature")
		_, err = inOrder{ns[0], h}.setupSign(dep(a, 32*gwei))
		wantRefused(t, err, backend.StatusPolicyPubkey, "not the policy's")
		// Back under A: the key's credentials again, the deposit is signed.
		ns[0].locked = &l0
		if _, err := (inOrder{ns[0], h}).setupSign(dep(a, 32*gwei)); err != nil {
			t.Fatalf("%s: 32 ETH to A: %v", path, err)
		}
	}
}
