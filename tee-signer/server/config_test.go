package server

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/governance/setupwire"
	"github.com/lidofinance/tee-signer/platform"
	"github.com/lidofinance/tee-signer/platform/dev"
	"github.com/lidofinance/tee-signer/signer-core/core"
	"github.com/lidofinance/tee-signer/signer-core/software"
	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/wire"
	wireadmin "github.com/lidofinance/tee-signer/signer-protocol/wire/admin"
	"github.com/lidofinance/tee-signer/slashing-log"
	"github.com/lidofinance/tee-signer/tee-signer/state"
)

const (
	locked = setupwire.GroupLocked
	open   = setupwire.GroupOpen

	testGenesis = 1_760_000_000 // the dev sample setup's genesis_time
	testEpoch   = 48            // its 8 slots of 6 s
	startEpoch  = 1000          // the fake clock starts 5 s into this epoch
)

var (
	ctx = context.Background()
	// v6 is a fork version no schedule of the sample setup has.
	v6 = backend.Version{0x06, 0, 0, 0x10}
	// x and y are fee recipients the sample setup does not list.
	x = backend.Address{0x55}
	y = backend.Address{0x66}
)

// fakeClock is a platform clock that the test moves.
type fakeClock struct {
	mu      sync.Mutex
	t       time.Time
	trusted bool
	err     error
}

func (c *fakeClock) Now() (time.Time, error) { c.mu.Lock(); defer c.mu.Unlock(); return c.t, c.err }
func (c *fakeClock) Source() string          { return "fake" }
func (c *fakeClock) Trusted() bool           { c.mu.Lock(); defer c.mu.Unlock(); return c.trusted }
func (c *fakeClock) add(s uint64) {
	c.mu.Lock()
	c.t = c.t.Add(time.Duration(s) * time.Second)
	c.mu.Unlock()
}
func (c *fakeClock) set(f func(*fakeClock)) { c.mu.Lock(); f(c); c.mu.Unlock() }

// approver is test approver id: a key from a fixed seed.
func approver(id byte) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{id}, 32))
}

func approverSet(k uint8, ids ...byte) setupwire.ApproverSet {
	s := setupwire.ApproverSet{ApprovalsNeeded: k}
	for _, id := range ids {
		s.Keys = append(s.Keys, [32]byte(approver(id).Public().(ed25519.PublicKey)))
	}
	return s
}

func u64(v uint64) *uint64 { return &v }

// flakyLog is the mark log with writes the test can drop, as a host can.
type flakyLog struct {
	*markstore.MarkLog
	failPut, failSet bool
	// tamper, if set, replaces the body copy the log hands out, as an
	// untrusted store can (config_recovery_test.go).
	tamper func(g setupwire.Group, v uint64, raw []byte) []byte
}

var errDropped = errors.New("the host dropped the write")

func (f *flakyLog) PutBody(ctx context.Context, raw []byte) (setupwire.Group, uint64, [32]byte, error) {
	if f.failPut {
		return 0, 0, [32]byte{}, errDropped
	}
	return f.MarkLog.PutBody(ctx, raw)
}

func (f *flakyLog) SetState(ctx context.Context, st markstore.ConfigState) error {
	if f.failSet {
		return errDropped
	}
	return f.MarkLog.SetState(ctx, st)
}

// env is a runner with a setup: its mark log in a directory, its config
// updates, a core with one validator (index 7) and a server.
type env struct {
	t      *testing.T
	raw    []byte
	setup  *setupwire.Setup
	hash   [32]byte
	clock  *fakeClock
	dir    string
	log    *flakyLog
	upd    *Updates
	signer *core.Signer
	srv    *Server
	sk     [32]byte
	pk     backend.Pubkey
	// tamper goes to the log of every start (flakyLog.tamper).
	tamper func(g setupwire.Group, v uint64, raw []byte) []byte
}

// newEnv starts a runner with the dev sample setup: approvers 1 to 3 with
// k = 2, time lock lock (nil: the image default), retention 100 days.
func newEnv(t *testing.T, lock *uint64) *env {
	t.Helper()
	return newEnvWith(t, lock, nil)
}

// newEnvWith is newEnv with change applied to the setup first.
func newEnvWith(t *testing.T, lock *uint64, change func(s *setupwire.Setup)) *env {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "governance", "setupwire", "testdata", "setup-dev.bin"))
	if err != nil {
		t.Fatal(err)
	}
	s, err := setupwire.DecodeSetup(raw)
	if err != nil {
		t.Fatal(err)
	}
	s.Locked.Approvers, s.Locked.ChangeDelaySeconds = approverSet(2, 1, 2, 3), lock
	s.SlashingLogMinLockDays = 100
	if change != nil {
		change(s)
	}
	if raw, err = s.Encode(); err != nil {
		t.Fatal(err)
	}
	sk, _ := software.NewSecret()
	pk, _ := core.PubkeyOf(sk)
	e := &env{t: t, raw: raw, setup: s, hash: mustHash(t, s), dir: t.TempDir(), sk: sk, pk: pk,
		clock: &fakeClock{t: time.Unix(testGenesis+startEpoch*testEpoch+5, 0), trusted: true}}
	e.start()
	return e
}

// start is a runner's start: claim the mark log, build the core with the
// config in force, load the validator, serve.
func (e *env) start() {
	t := e.t
	t.Helper()
	ms, err := markstore.SetupOf(e.setup, e.hash)
	if err != nil {
		t.Fatal(err)
	}
	fl, err := markstore.NewFileLog(filepath.Join(e.dir, "marks"))
	if err != nil {
		t.Fatal(err)
	}
	m, err := markstore.New(fl, e.setup.SignerName, dev.NewDevKeys("config test"), markstore.Options{Setup: ms, Clock: e.clock.Now, Log: quiet})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := m.Claim(ctx, false); err != nil {
		t.Fatal(err)
	}
	e.log = &flakyLog{MarkLog: m, tamper: e.tamper}
	if e.upd, err = NewUpdates(UpdatesOptions{Setup: e.setup, SetupHash: e.hash, Log: e.log, Clock: e.clock, Logger: quiet}); err != nil {
		t.Fatal(err)
	}
	cfg, err := e.upd.StartConfig(baseConfig(e.setup))
	if err != nil {
		t.Fatal(err)
	}
	store, sealer := &shareStore{m: map[string][]byte{}}, dev.NewDevSealer()
	hooks, err := state.New(cfg, state.Mode{Floor: true, FloorMargin: state.DefaultFloorMargin(cfg)}, e.clock, store, sealer, quiet)
	if err != nil {
		t.Fatal(err)
	}
	if e.signer, err = core.NewSigner(cfg, 4, 0, hooks); err != nil {
		t.Fatal(err)
	}
	hooks.UseClock(e.signer.EpochAt)
	t.Cleanup(e.signer.Close)
	if _, err := e.signer.AddValidator(e.pk, e.sk, 7, nil); err != nil {
		t.Fatal(err)
	}
	e.upd.Attach(e.signer)
	e.srv = &Server{Signer: e.signer, Hooks: hooks, Log: quiet, Updates: e.upd, State: e.upd.SetupState,
		Platform:  &platform.Platform{Name: "dev", Store: store, Sealer: sealer, Clock: e.clock, Attester: fakeAttester{}},
		SetupHash: e.hash, LogID: m.LogID()}
}

// restart stops the runner and starts it again on the same mark log.
func (e *env) restart() {
	e.t.Helper()
	e.signer.Close()
	e.start()
}

// baseConfig is the core config of a setup's chain, safety and version 0
// (the runner's chainConfig).
func baseConfig(s *setupwire.Setup) core.Config {
	ch := &s.Chain
	c := core.Config{GenesisValidatorsRoot: ch.GenesisValidatorsRoot, GenesisForkVersion: ch.GenesisForkVersion,
		VoluntaryExitForkVersion: ch.VoluntaryExitForkVersion, GenesisTime: ch.GenesisTime, SecondsPerSlot: ch.SecondsPerSlot,
		SlotsPerEpoch: ch.SlotsPerEpoch, Preset: ch.Preset.String(), MaxEpochsAhead: s.Safety.MaxSignEpochsAheadOfClock,
		CommitAhead: core.CommitAhead{BlockSlots: s.Safety.SlashingMarkPrewrite.BlockSlots, SourceEpochs: s.Safety.SlashingMarkPrewrite.SourceEpochs,
			TargetEpochs: s.Safety.SlashingMarkPrewrite.TargetEpochs}}
	return c.WithPolicy(policyOf(&s.Locked)).WithSchedule(scheduleOf(&s.Open)).WithSlotTimes(slotTimesOf(&s.Locked))
}

func (e *env) now() uint64 { t, _ := e.clock.Now(); return uint64(t.Unix()) }

// groupHash is the hash of group g in the setup: version 0's.
func (e *env) groupHash(g setupwire.Group) [32]byte {
	h, err := e.setup.GroupHash(g)
	if err != nil {
		e.t.Fatal(err)
	}
	return h
}

// body is an update of group g to version v on prev, activate_at at, with
// the setup's values of the group (a fresh copy to change).
func (e *env) body(g setupwire.Group, v uint64, prev [32]byte, at uint64) *setupwire.UpdateBody {
	fresh, err := setupwire.DecodeSetup(e.raw)
	if err != nil {
		e.t.Fatal(err)
	}
	b := &setupwire.UpdateBody{ClusterID: e.setup.ClusterID, ChainHash: e.setup.Chain.Hash(), Group: g, Version: v, PrevHash: prev, ActivateAt: at}
	if g == locked {
		b.Locked = &fresh.Locked
	} else {
		b.Open = &fresh.Open
	}
	b.Salts = testSalts(b)
	return b
}

// testSalts are the salts of an update body: fixed by its group, version,
// prev_hash and activate_at, so the same update made twice is the same.
func testSalts(b *setupwire.UpdateBody) setupwire.Salts {
	n := setupwire.NumOpenLeaves
	if b.Group == locked {
		n = setupwire.NumLockedLeaves
	}
	out := make(setupwire.Salts, n)
	for i := range out {
		out[i] = sha256.Sum256(fmt.Appendf(nil, "salt %d %d %x %d %d", b.Group, b.Version, b.PrevHash, b.ActivateAt, i))
	}
	return out
}

// mustHash is setup_hash of s.
func mustHash(t *testing.T, s *setupwire.Setup) [32]byte {
	t.Helper()
	h, err := s.Hash()
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func hashOf(t *testing.T, b *setupwire.UpdateBody) [32]byte {
	t.Helper()
	h, err := b.Hash()
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// by is a signature by approver id at position pos of the set in force.
type by struct {
	pos uint8
	id  byte
}

// first2 are k approvers of the setup's set.
var first2 = []by{{0, 1}, {1, 2}}

// signed is b signed by approvals and, for a rotation, by every key of
// newSet in order.
func signed(t *testing.T, b *setupwire.UpdateBody, approvals []by, newSet []byte) []byte {
	t.Helper()
	sign := func(id byte) [64]byte {
		sig, err := b.Sign(approver(id))
		if err != nil {
			t.Fatal(err)
		}
		return sig
	}
	u := setupwire.Update{Body: *b}
	for _, a := range approvals {
		u.Approvals = append(u.Approvals, setupwire.Approval{Position: a.pos, Signature: sign(a.id)})
	}
	for i, id := range newSet {
		u.NewSet = append(u.NewSet, setupwire.Approval{Position: uint8(i), Signature: sign(id)})
	}
	raw, err := u.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// rawUpdate is the 'U' layout around body bytes, without the encoder's
// checks: for bodies the encoder refuses to make.
func rawUpdate(body []byte, approvals, newSet []setupwire.Approval) []byte {
	b := binary.BigEndian.AppendUint32([]byte{'U', setupwire.UpdateVersion}, uint32(len(body)))
	b = append(b, body...)
	for _, list := range [][]setupwire.Approval{approvals, newSet} {
		b = append(b, byte(len(list)))
		for _, a := range list {
			b = append(append(b, a.Position), a.Signature[:]...)
		}
	}
	return b
}

// Offsets in a locked update body: the approver count, then the keys.
const (
	bodyVersionAt = 2 + 32 + 32 + 1
	approversAt   = bodyVersionAt + 8 + 32 + 8
)

// send sends CONFIG_UPDATE through the server.
func (e *env) send(raw []byte) (uint8, backend.SetupState, error) {
	e.t.Helper()
	p, err := wireadmin.EncodeConfigUpdate(raw)
	if err != nil {
		return 0, backend.SetupState{}, backend.Refused(backend.StatusBadRequest, "%v", err)
	}
	body, err := e.srv.dispatch(ctx, wire.Frame{Type: wireadmin.TypeConfigUpdate, Payload: p})
	if err != nil {
		return 0, backend.SetupState{}, err
	}
	o, st, err := wireadmin.DecodeConfigUpdateResponse(body)
	if err != nil {
		e.t.Fatal(err)
	}
	return o, *st, nil
}

func (e *env) mustSend(raw []byte, want uint8) backend.SetupState {
	e.t.Helper()
	o, st, err := e.send(raw)
	if err != nil || o != want {
		e.t.Fatalf("outcome %d, %v; want outcome %d", o, err, want)
	}
	return st
}

// register signs a builder registration with fee recipient fee.
func (e *env) register(fee backend.Address) error {
	m := &backend.ValidatorRegistration{FeeRecipient: fee, GasLimit: 36_000_000, Timestamp: e.now(), Pubkey: e.pk}
	cfg := e.signer.Config()
	d, err := cfg.MessageDomain(m)
	if err != nil {
		e.t.Fatal(err)
	}
	_, err = e.srv.sign(backend.SignRequest{Pubkey: e.pk, Message: m, Domain: d})
	return err
}

func (e *env) ready() bool {
	e.t.Helper()
	h, err := e.srv.health()
	if err != nil {
		e.t.Fatal(err)
	}
	return h.Ready
}

func wantCode(t *testing.T, err error, want backend.Status, detail string) {
	t.Helper()
	var r *backend.RefusedError
	if !errors.As(err, &r) || r.Code != want || !strings.Contains(r.Detail, detail) {
		t.Fatalf("got %v, want %v with %q", err, want, detail)
	}
}

func pending(v uint64, h [32]byte, at uint64) backend.PendingUpdate {
	return backend.PendingUpdate{Version: v, Hash: h, EffectiveAt: at}
}

func logPending(t *testing.T, e *env, g setupwire.Group) *markstore.Pending {
	t.Helper()
	st := e.log.State()
	gs, err := st.Group(g)
	if err != nil {
		t.Fatal(err)
	}
	return gs.Pending
}

// A locked update waits out the time lock in force: it is pending until
// arrival + wait, then its values sign. The switch needs no record; Sync
// writes the one that shows it. activate_at later than the wait moves the
// effective time; lowering the time lock to 0 waits out the old one.
func TestConfigUpdateTimeLock(t *testing.T) {
	e := newEnv(t, u64(3600))
	wantCode(t, e.register(x), backend.StatusPolicyFeeRecipient, "")
	t0 := e.now()
	b1 := e.body(locked, 1, e.groupHash(locked), t0)
	b1.Locked.AllowedFeeRecipients = append(b1.Locked.AllowedFeeRecipients, x)
	h1 := hashOf(t, b1)
	st := e.mustSend(signed(t, b1, first2, nil), wireadmin.ConfigAccepted)
	if st.Locked != (backend.ConfigGroup{Hash: e.groupHash(locked), Pending: pending(1, h1, t0+3600)}) || st.SetupHash != e.hash {
		t.Fatalf("answer %+v", st)
	}
	if p := logPending(t, e, locked); p == nil || *p != (markstore.Pending{Version: 1, Hash: h1, EffectiveAt: t0 + 3600}) {
		t.Fatalf("the record holds %+v", p)
	}
	if body, h, err := e.log.Body(locked, 1); err != nil || h != h1 || len(body) == 0 {
		t.Fatalf("the body is not in the log: %v", err)
	}
	e.clock.add(3599)
	wantCode(t, e.register(x), backend.StatusPolicyFeeRecipient, "")
	e.clock.add(1)
	if err := e.register(x); err != nil {
		t.Fatalf("at the effective time: %v", err)
	}
	if st := e.srv.SetupState(); st.Locked != (backend.ConfigGroup{Version: 1, Hash: h1}) {
		t.Fatalf("state in force %+v", st.Locked)
	}
	if logPending(t, e, locked) == nil {
		t.Fatal("a record shows the update active before Sync wrote one")
	}
	if err := e.upd.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if ls := e.log.State().Locked; ls.Version != 1 || ls.Hash != h1 || ls.Pending != nil {
		t.Fatalf("after Sync the record holds %+v", ls)
	}

	// activate_at after arrival + wait: in force at activate_at.
	t1 := e.now()
	b2 := e.body(locked, 2, h1, t1+7200)
	b2.Locked.AllowedFeeRecipients = append(b2.Locked.AllowedFeeRecipients, x, y)
	b2.Locked.ChangeDelaySeconds = u64(0)
	h2 := hashOf(t, b2)
	if st := e.mustSend(signed(t, b2, first2, nil), wireadmin.ConfigAccepted); st.Locked.Pending != pending(2, h2, t1+7200) {
		t.Fatalf("activate_at past the wait: %+v", st.Locked)
	}
	e.clock.add(7200)
	if err := e.register(y); err != nil {
		t.Fatal(err)
	}
	// Version 2 set the time lock to 0: the next update is in force at once.
	b3 := e.body(locked, 3, h2, e.now())
	b3.Locked.AllowedFeeRecipients = append(b3.Locked.AllowedFeeRecipients, x)
	h3 := hashOf(t, b3)
	if st := e.mustSend(signed(t, b3, first2, nil), wireadmin.ConfigAccepted); st.Locked != (backend.ConfigGroup{Version: 3, Hash: h3}) {
		t.Fatalf("time lock 0: %+v", st.Locked)
	}
	wantCode(t, e.register(y), backend.StatusPolicyFeeRecipient, "")
}

// With a time lock of 0 a locked update is in force when it arrives, or at
// activate_at if that is later. Without time_lock_seconds the image's
// default applies.
func TestConfigUpdateNoTimeLock(t *testing.T) {
	e := newEnv(t, u64(0))
	t0 := e.now()
	b := e.body(locked, 1, e.groupHash(locked), t0-100)
	b.Locked.AllowedFeeRecipients = append(b.Locked.AllowedFeeRecipients, x)
	h := hashOf(t, b)
	if st := e.mustSend(signed(t, b, first2, nil), wireadmin.ConfigAccepted); st.Locked != (backend.ConfigGroup{Version: 1, Hash: h}) {
		t.Fatalf("time lock 0: %+v", st.Locked)
	}
	if err := e.register(x); err != nil {
		t.Fatal(err)
	}
	b2 := e.body(locked, 2, h, t0+50)
	h2 := hashOf(t, b2)
	if st := e.mustSend(signed(t, b2, first2, nil), wireadmin.ConfigAccepted); st.Locked.Pending != pending(2, h2, t0+50) {
		t.Fatalf("time lock 0, activate_at ahead: %+v", st.Locked)
	}

	d := newEnv(t, nil)
	t0 = d.now()
	b = d.body(locked, 1, d.groupHash(locked), t0)
	if st := d.mustSend(signed(t, b, first2, nil), wireadmin.ConfigAccepted); st.Locked.Pending.EffectiveAt != t0+setupwire.DefaultTimeLock {
		t.Fatalf("default time lock: %+v", st.Locked)
	}
}

// Every check of section 6 refuses with its status, and a refused update
// writes nothing to the log.
func TestConfigUpdateRefusals(t *testing.T) {
	e := newEnv(t, u64(3600))
	t0 := e.now()
	gh := e.groupHash(locked)
	b1 := e.body(locked, 1, gh, t0)
	b1.Locked.AllowedFeeRecipients = append(b1.Locked.AllowedFeeRecipients, x)
	h1 := hashOf(t, b1)
	pendingRaw := signed(t, b1, first2, nil)
	e.mustSend(pendingRaw, wireadmin.ConfigAccepted)

	v2 := func(mod func(*setupwire.UpdateBody)) *setupwire.UpdateBody {
		b := e.body(locked, 2, gh, t0)
		b.Locked.AllowedFeeRecipients = append(b.Locked.AllowedFeeRecipients, y)
		if mod != nil {
			mod(b)
		}
		return b
	}
	enc, _ := v2(nil).Encode()
	version0 := bytes.Clone(enc)
	binary.BigEndian.PutUint64(version0[bodyVersionAt:], 0)

	cases := []struct {
		name   string
		raw    []byte
		detail string
	}{
		{"not an update", []byte("hello"), "not a config update"},
		{"trailing byte", append(bytes.Clone(pendingRaw), 0), "trailing"},
		{"version 0", rawUpdate(version0, nil, nil), "version 0"},
		{"another cluster", signed(t, v2(func(b *setupwire.UpdateBody) { b.ClusterID[0] ^= 1 }), first2, nil), "cluster_id"},
		{"another chain", signed(t, v2(func(b *setupwire.UpdateBody) { b.ChainHash[0] ^= 1 }), first2, nil), "another chain"},
		{"the pending version with other values", signed(t, v2(func(b *setupwire.UpdateBody) { b.Version = 1 }), first2, nil), "want above 1"},
		{"a jump past 2^32", signed(t, v2(func(b *setupwire.UpdateBody) { b.Version = 2 + 1<<32 }), first2, nil), "2^32"},
		{"prev_hash of the pending update", signed(t, v2(func(b *setupwire.UpdateBody) { b.PrevHash = h1 }), first2, nil), "prev_hash"},
		{"one signature", signed(t, v2(nil), []by{{0, 1}}, nil), "approvals_needed is 2"},
		{"a signature by another key", signed(t, v2(nil), []by{{0, 1}, {1, 9}}, nil), "approver 1 does not verify"},
		{"a position outside the set", signed(t, v2(nil), []by{{0, 1}, {5, 2}}, nil), "the active set has 3"},
		{"new-set signatures without a rotation", signed(t, v2(nil), first2, []byte{1, 2, 3}), "keeps the approver set"},
		{"activate_at past the horizon", signed(t, v2(func(b *setupwire.UpdateBody) {
			b.ActivateAt = t0 + 3600 + setupwire.ActivationHorizon + 1
		}), first2, nil), "activate_at"},
	}
	before := e.log.State()
	_, version := e.log.Mark()
	check := func(name string) {
		t.Helper()
		if _, v := e.log.Mark(); v != version || !e.log.State().Equal(before) {
			t.Fatalf("%s: the refused update wrote to the log", name)
		}
	}
	for _, c := range cases {
		_, _, err := e.send(c.raw)
		wantCode(t, err, backend.StatusBadRequest, c.detail)
		check(c.name)
	}
	// The horizon itself is fine.
	edge := signed(t, v2(func(b *setupwire.UpdateBody) { b.ActivateAt = t0 + 3600 + setupwire.ActivationHorizon }), first2, nil)

	// The clock: an untrusted clock, and a trusted one without a quorum.
	e.clock.set(func(c *fakeClock) { c.trusted = false })
	_, _, err := e.send(edge)
	wantCode(t, err, backend.StatusClock, "not trusted")
	check("untrusted clock")
	e.clock.set(func(c *fakeClock) { c.trusted, c.err = true, errors.New("no NTS quorum") })
	_, _, err = e.send(edge)
	wantCode(t, err, backend.StatusClock, "no NTS quorum")
	check("no quorum")
	e.clock.set(func(c *fakeClock) { c.err = nil })

	// The log drops the body, or the record: nothing becomes pending.
	e.log.failPut = true
	_, _, err = e.send(edge)
	wantCode(t, err, backend.StatusStorage, "body not written")
	check("body dropped")
	e.log.failPut, e.log.failSet = false, true
	_, _, err = e.send(edge)
	wantCode(t, err, backend.StatusStorage, "record not written")
	check("record dropped")
	e.log.failSet = false

	// The dev platform takes an update on its untrusted clock.
	e.clock.set(func(c *fakeClock) { c.trusted = false })
	e.upd.opt.AnyClock = true
	if st := e.mustSend(edge, wireadmin.ConfigAccepted); st.Locked.Pending.Version != 2 {
		t.Fatalf("state %+v", st.Locked)
	}

	// A runner without a setup takes no update; an empty payload is no update.
	plain := &Server{Log: quiet, Platform: &platform.Platform{Name: "dev"}}
	_, err = plain.dispatch(ctx, wire.Frame{Type: wireadmin.TypeConfigUpdate, Payload: pendingRaw})
	wantCode(t, err, backend.StatusUnsupported, "no setup")
	_, err = e.srv.dispatch(ctx, wire.Frame{Type: wireadmin.TypeConfigUpdate})
	wantCode(t, err, backend.StatusBadRequest, "CONFIG_UPDATE of 0 bytes")
}

// A higher version replaces the pending update with a wait of its own;
// approvers cancel by superseding with the values in force. A replaced
// update never comes into force, and its version cannot come back.
func TestConfigUpdateSupersede(t *testing.T) {
	e := newEnv(t, u64(3600))
	gh := e.groupHash(locked)
	t0 := e.now()
	b1 := e.body(locked, 1, gh, t0)
	b1.Locked.AllowedFeeRecipients = append(b1.Locked.AllowedFeeRecipients, x)
	raw1 := signed(t, b1, first2, nil)
	e.mustSend(raw1, wireadmin.ConfigAccepted)

	e.clock.add(1000)
	b2 := e.body(locked, 2, gh, t0)
	b2.Locked.AllowedFeeRecipients = append(b2.Locked.AllowedFeeRecipients, y)
	h2 := hashOf(t, b2)
	if st := e.mustSend(signed(t, b2, first2, nil), wireadmin.ConfigAccepted); st.Locked.Pending != pending(2, h2, t0+1000+3600) {
		t.Fatalf("the replacement does not wait from its own arrival: %+v", st.Locked)
	}
	e.clock.add(2600) // t0 + 3600: version 1's time
	wantCode(t, e.register(x), backend.StatusPolicyFeeRecipient, "")
	wantCode(t, e.register(y), backend.StatusPolicyFeeRecipient, "")

	// Cancel: the values in force, a higher version.
	e.clock.add(500)
	b3 := e.body(locked, 3, gh, t0)
	h3 := hashOf(t, b3)
	if st := e.mustSend(signed(t, b3, first2, nil), wireadmin.ConfigAccepted); st.Locked.Pending != pending(3, h3, t0+4100+3600) {
		t.Fatalf("cancel: %+v", st.Locked)
	}
	e.clock.add(1000) // past version 2's time
	wantCode(t, e.register(y), backend.StatusPolicyFeeRecipient, "")
	for _, raw := range [][]byte{raw1, signed(t, b2, first2, nil)} {
		_, _, err := e.send(raw)
		wantCode(t, err, backend.StatusBadRequest, "want above 3")
	}
	e.clock.add(2600)
	if st := e.srv.SetupState(); st.Locked != (backend.ConfigGroup{Version: 3, Hash: h3}) {
		t.Fatalf("after the cancel: %+v", st.Locked)
	}
	wantCode(t, e.register(x), backend.StatusPolicyFeeRecipient, "")
	if err := e.register(e.setup.Locked.AllowedFeeRecipients[0]); err != nil {
		t.Fatal(err)
	}
}

// A rotation needs k of the set in force and a signature by every key of
// the new set, whose keys pass the key rules. While it is pending only the
// old set signs. When it comes into force the open update the old set
// signed and that is still pending is dropped, from the core too.
func TestConfigUpdateRotation(t *testing.T) {
	e := newEnv(t, u64(3600))
	t0 := e.now()
	rot := e.body(locked, 1, e.groupHash(locked), t0)
	rot.Locked.Approvers = approverSet(2, 4, 5, 6)
	hr := hashOf(t, rot)
	enc, _ := rot.Encode()
	smallOrder := bytes.Clone(enc)
	copy(smallOrder[approversAt+1:], append([]byte{1}, make([]byte, 31)...)) // the identity point, of order 1
	four := e.body(locked, 1, e.groupHash(locked), t0)
	four.Locked.Approvers = approverSet(3, 4, 5, 6, 7)
	kHalf, _ := four.Encode()
	kHalf[approversAt+1+4*32] = 2 // k = 2 of 4
	sb, _ := setupwire.SignBody(approver(1), enc)
	sig := setupwire.Approval{Signature: sb}
	for _, c := range []struct {
		name, detail string
		raw          []byte
	}{
		{"no new-set signatures", "every key of the new set", signed(t, rot, first2, nil)},
		{"a new key does not sign", "new key 2", signed(t, rot, first2, []byte{4, 5, 9})},
		{"the new set alone", "approver 0 does not verify", signed(t, rot, []by{{0, 4}, {1, 5}}, []byte{4, 5, 6})},
		{"a small-order key", "small-order", rawUpdate(smallOrder, []setupwire.Approval{sig}, nil)},
		{"k of half the set", "more than half", rawUpdate(kHalf, []setupwire.Approval{sig}, nil)},
	} {
		_, _, err := e.send(c.raw)
		wantCode(t, err, backend.StatusBadRequest, c.detail)
	}
	st := e.mustSend(signed(t, rot, first2, []byte{4, 5, 6}), wireadmin.ConfigAccepted)
	if st.Locked.Pending != pending(1, hr, t0+3600) || st.ApproverSetHash != e.setup.Locked.Approvers.Hash() {
		t.Fatalf("pending rotation: %+v", st)
	}

	// Pending: the new set counts for nothing, for a supersede or an open
	// update. The old set signs an open update due after the rotation.
	cancel := e.body(locked, 2, e.groupHash(locked), t0)
	_, _, err := e.send(signed(t, cancel, []by{{0, 4}, {1, 5}}, nil))
	wantCode(t, err, backend.StatusBadRequest, "does not verify")
	op := e.body(open, 1, e.groupHash(open), t0+3700)
	op.Open.ForkSchedule = append(op.Open.ForkSchedule, setupwire.Fork{Epoch: 1100, Version: v6})
	_, _, err = e.send(signed(t, op, []by{{0, 4}, {1, 5}}, nil))
	wantCode(t, err, backend.StatusBadRequest, "does not verify")
	ho := hashOf(t, op)
	if st := e.mustSend(signed(t, op, first2, nil), wireadmin.ConfigAccepted); st.Open.Pending != pending(1, ho, t0+3700) {
		t.Fatalf("open update of the old set: %+v", st.Open)
	}
	if cfg := e.signer.Config(); cfg.ForkVersionAt(1100) != v6 {
		t.Fatal("the open update is not in the core on arrival")
	}

	// The rotation comes into force: the new set's hash, the open update gone.
	e.clock.add(3600)
	st = e.srv.SetupState()
	want := backend.SetupState{SetupHash: e.hash, Locked: backend.ConfigGroup{Version: 1, Hash: hr},
		Open: backend.ConfigGroup{Hash: e.groupHash(open)}, ApproverSetHash: rot.Locked.Approvers.Hash(),
		KeyOrigin: backend.KeyOrigin{Imported: 1}}
	if st != want {
		t.Fatalf("after the rotation %+v, want %+v", st, want)
	}
	if cfg := e.signer.Config(); cfg.ForkVersionAt(1100) == v6 {
		t.Fatal("the dropped open update stays in the core")
	}
	if err := e.upd.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if ls := e.log.State(); ls.Locked.Version != 1 || ls.Locked.Pending != nil || ls.Open.Version != 0 || ls.Open.Pending != nil {
		t.Fatalf("the record holds %+v", ls)
	}
	// The dropped update again: the old set's signatures count no more.
	_, _, err = e.send(signed(t, op, first2, nil))
	wantCode(t, err, backend.StatusBadRequest, "does not verify")
	op2 := e.body(open, 2, e.groupHash(open), e.now())
	op2.Open.ForkSchedule = append(op2.Open.ForkSchedule, setupwire.Fork{Epoch: 1100, Version: v6})
	if st := e.mustSend(signed(t, op2, []by{{0, 4}, {1, 5}}, nil), wireadmin.ConfigAccepted); st.Open.Version != 2 {
		t.Fatalf("open update of the new set: %+v", st.Open)
	}
}

// A locked update whose allowed list gains an image waits at least the
// image's minimum, whatever the time lock; one that only removes an image
// waits the time lock. activate_at may reach the minimum plus the horizon.
func TestConfigUpdateAllowedImages(t *testing.T) {
	for _, c := range []struct {
		name string
		lock uint64
		wait uint64
	}{
		{"time lock 0", 0, setupwire.ImagesMinTimeLock},
		{"time lock above the minimum", 10 * 86400, 10 * 86400},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t, u64(c.lock))
			t0 := e.now()
			add := func(v, at uint64) *setupwire.UpdateBody {
				b := e.body(locked, v, e.groupHash(locked), at)
				b.Locked.AllowedImageMeasurements = append(b.Locked.AllowedImageMeasurements, setupwire.Image{Kind: setupwire.ImageGCP, Measurement: bytes.Repeat([]byte{0x77}, 32)})
				return b
			}
			_, _, err := e.send(signed(t, add(1, t0+c.wait+setupwire.ActivationHorizon+1), first2, nil))
			wantCode(t, err, backend.StatusBadRequest, "activate_at")
			b := add(1, t0+c.wait+setupwire.ActivationHorizon)
			if st := e.mustSend(signed(t, b, first2, nil), wireadmin.ConfigAccepted); st.Locked.Pending.EffectiveAt != t0+c.wait+setupwire.ActivationHorizon {
				t.Fatalf("at the horizon: %+v", st.Locked)
			}
			b = add(2, t0)
			if st := e.mustSend(signed(t, b, first2, nil), wireadmin.ConfigAccepted); st.Locked.Pending.EffectiveAt != t0+c.wait {
				t.Fatalf("a new image waits %d s: %+v", c.wait, st.Locked)
			}
			rm := e.body(locked, 3, e.groupHash(locked), t0)
			rm.Locked.AllowedImageMeasurements = rm.Locked.AllowedImageMeasurements[:1]
			h := hashOf(t, rm)
			st := e.mustSend(signed(t, rm, first2, nil), wireadmin.ConfigAccepted)
			if c.lock == 0 && st.Locked != (backend.ConfigGroup{Version: 3, Hash: h}) ||
				c.lock != 0 && st.Locked.Pending != pending(3, h, t0+c.lock) {
				t.Fatalf("a removed image waits the time lock: %+v", st.Locked)
			}
		})
	}
}

// An open update has no wait. The core's fork rule refuses a schedule that
// changes an epoch at or below epoch(effective time) + max_epochs_ahead + 1,
// and a started fork. An accepted one is in the core at once.
func TestConfigUpdateForkRule(t *testing.T) {
	e := newEnv(t, u64(3600))
	now := e.now()
	with := func(v, at, epoch uint64) *setupwire.UpdateBody {
		b := e.body(open, v, e.groupHash(open), at)
		b.Open.ForkSchedule = append(b.Open.ForkSchedule, setupwire.Fork{Epoch: epoch, Version: v6})
		return b
	}
	later := now + 10*testEpoch // epoch 1010
	started := e.body(open, 1, e.groupHash(open), now)
	started.Open.ForkSchedule[1].Version = v6
	for name, b := range map[string]*setupwire.UpdateBody{
		"epoch 1003 from epoch 1000":      with(1, now, startEpoch+3),
		"epoch 1013, activate_at in 1010": with(1, later, startEpoch+13),
		"a started fork":                  started,
	} {
		_, _, err := e.send(signed(t, b, first2, nil))
		wantCode(t, err, backend.StatusSchedule, "fork rule")
		if e.log.State().Open.Pending != nil {
			t.Fatalf("%s: refused, but pending", name)
		}
	}
	b := with(1, now, startEpoch+4)
	h := hashOf(t, b)
	if st := e.mustSend(signed(t, b, first2, nil), wireadmin.ConfigAccepted); st.Open != (backend.ConfigGroup{Version: 1, Hash: h}) {
		t.Fatalf("open update: %+v", st.Open)
	}
	if cfg := e.signer.Config(); cfg.ForkVersionAt(startEpoch+4) != v6 {
		t.Fatal("the schedule is not in the core")
	}
	b2 := with(2, later, startEpoch+14)
	b2.PrevHash = h
	b2.Open.ForkSchedule = append(b2.Open.ForkSchedule[:len(b2.Open.ForkSchedule)-1], setupwire.Fork{Epoch: startEpoch + 4, Version: v6}, setupwire.Fork{Epoch: startEpoch + 14, Version: backend.Version{7}})
	if st := e.mustSend(signed(t, b2, first2, nil), wireadmin.ConfigAccepted); st.Open.Pending.EffectiveAt != later {
		t.Fatalf("activate_at ahead: %+v", st.Open)
	}
}

// A locked update's slot time changes: the slot time rule refuses a change
// before epoch(T) + max_sign_epochs_ahead_of_clock + 2, with T the effective
// time (arrival plus the change delay), and the core takes the new slot
// times at T with the other locked values; a restart builds the core with
// them.
func TestConfigUpdateSlotTimes(t *testing.T) {
	e := newEnv(t, u64(3600))
	t0 := e.now()
	eT := (t0 + 3600 - testGenesis) / testEpoch // epoch 1075
	with := func(epoch uint64) *setupwire.UpdateBody {
		b := e.body(locked, 1, e.groupHash(locked), t0)
		b.Locked.SlotTimeChanges = []setupwire.SlotTimeChange{{Epoch: epoch, SecondsPerSlot: 4}}
		return b
	}
	_, _, err := e.send(signed(t, with(eT+3), first2, nil))
	wantCode(t, err, backend.StatusSchedule, "slot time rule")
	same := with(eT + 3)
	same.Locked.SlotTimeChanges[0].SecondsPerSlot = 6
	_, _, err = e.send(signed(t, same, first2, nil))
	wantCode(t, err, backend.StatusBadRequest, "keeps the genesis slot time")
	b := with(eT + 4)
	h := hashOf(t, b)
	e.mustSend(signed(t, b, first2, nil), wireadmin.ConfigAccepted)
	if got := e.signer.Config().SlotTimeChanges; len(got) != 0 {
		t.Fatalf("slot times in the core before the effective time: %+v", got)
	}
	e.clock.add(3600)
	if st := e.srv.SetupState(); st.Locked != (backend.ConfigGroup{Version: 1, Hash: h}) {
		t.Fatalf("state in force %+v", st.Locked)
	}
	want := []core.SlotTimeChange{{Epoch: eT + 4, SecondsPerSlot: 4}}
	if got := e.signer.Config().SlotTimeChanges; !slices.Equal(got, want) {
		t.Fatalf("slot times in the core at the effective time: %+v", got)
	}
	// Ten epochs of 4 s slots after the change.
	at := uint64(testGenesis+(eT+4)*testEpoch) + 10*8*4
	if e.signer.EpochAt(at) != eT+14 {
		t.Fatalf("epoch %d, want %d", e.signer.EpochAt(at), eT+14)
	}
	e.restart()
	if got := e.signer.Config().SlotTimeChanges; !slices.Equal(got, want) {
		t.Fatalf("slot times after a restart: %+v", got)
	}
}

// A slot time change pending, then a fork update: the fork rule counts
// epochs under the pending slot times too. 1 s slots from epoch 1079
// (pending, in force at epoch 1075) bring the clock to epoch 1505 by
// t0 + 7200, where the slot times in force give epoch 1150. So a fork in
// force then may touch epoch 1509 at the earliest, not 1154.
func TestConfigUpdateForkRuleCountsPendingSlotTimes(t *testing.T) {
	e := newEnv(t, u64(3600))
	t0 := e.now()
	lb := e.body(locked, 1, e.groupHash(locked), t0)
	lb.Locked.SlotTimeChanges = []setupwire.SlotTimeChange{{Epoch: 1079, SecondsPerSlot: 1}}
	e.mustSend(signed(t, lb, first2, nil), wireadmin.ConfigAccepted)
	fork := func(epoch uint64) *setupwire.UpdateBody {
		b := e.body(open, 1, e.groupHash(open), t0+7200)
		b.Open.ForkSchedule = append(b.Open.ForkSchedule, setupwire.Fork{Epoch: epoch, Version: v6})
		return b
	}
	for _, epoch := range []uint64{1160, 1508} {
		_, _, err := e.send(signed(t, fork(epoch), first2, nil))
		wantCode(t, err, backend.StatusSchedule, "fork rule")
		if e.log.State().Open.Pending != nil {
			t.Fatalf("fork at %d: refused, but pending", epoch)
		}
	}
	b := fork(1509)
	h := hashOf(t, b)
	if st := e.mustSend(signed(t, b, first2, nil), wireadmin.ConfigAccepted); st.Open.Pending != pending(1, h, t0+7200) {
		t.Fatalf("open update: %+v", st.Open)
	}
	if cfg := e.signer.Config(); cfg.ForkVersionAt(1509) != v6 {
		t.Fatal("the schedule is not in the core")
	}
}

// A fork update pending, then a slot time change: a change that would bring
// the pending fork at epoch 1160 within reach before its effective time
// (t0 + 7200) is refused, under the fork rule. 1 s slots from epoch 1079
// reach epoch 1505 by then; 12 s slots reach 1114 and a change from epoch
// 1200 comes after it, so both keep the fork clear.
func TestConfigUpdateSlotTimesCountPendingFork(t *testing.T) {
	e := newEnv(t, u64(3600))
	t0 := e.now()
	ob := e.body(open, 1, e.groupHash(open), t0+7200)
	ob.Open.ForkSchedule = append(ob.Open.ForkSchedule, setupwire.Fork{Epoch: 1160, Version: v6})
	e.mustSend(signed(t, ob, first2, nil), wireadmin.ConfigAccepted)
	slot := func(v uint64, epoch, secs uint64) *setupwire.UpdateBody {
		b := e.body(locked, v, e.groupHash(locked), t0)
		b.Locked.SlotTimeChanges = []setupwire.SlotTimeChange{{Epoch: epoch, SecondsPerSlot: secs}}
		return b
	}
	_, _, err := e.send(signed(t, slot(1, 1079, 1), first2, nil))
	wantCode(t, err, backend.StatusSchedule, "refuses the pending open version 1")
	if e.log.State().Locked.Pending != nil {
		t.Fatal("refused, but pending")
	}
	e.mustSend(signed(t, slot(1, 1079, 12), first2, nil), wireadmin.ConfigAccepted)
	later := slot(2, 1200, 1)
	h := hashOf(t, later)
	if st := e.mustSend(signed(t, later, first2, nil), wireadmin.ConfigAccepted); st.Locked.Pending.Hash != h {
		t.Fatalf("locked update: %+v", st.Locked)
	}
	if cfg := e.signer.Config(); cfg.ForkVersionAt(1160) != v6 {
		t.Fatal("the pending fork left the core")
	}
}

// The same update again answers ConfigKnown and writes nothing: as the
// pending update (its signatures are checked again) and as the one in force.
func TestConfigUpdateAgain(t *testing.T) {
	e := newEnv(t, u64(3600))
	b := e.body(locked, 1, e.groupHash(locked), e.now())
	raw := signed(t, b, first2, nil)
	st := e.mustSend(raw, wireadmin.ConfigAccepted)
	_, version := e.log.Mark()
	if again := e.mustSend(raw, wireadmin.ConfigKnown); again != st {
		t.Fatalf("again: %+v, want %+v", again, st)
	}
	if _, v := e.log.Mark(); v != version {
		t.Fatal("the same update again wrote a record")
	}
	_, _, err := e.send(signed(t, b, []by{{0, 1}, {1, 9}}, nil))
	wantCode(t, err, backend.StatusBadRequest, "does not verify")
	e.clock.add(3600)
	if again := e.mustSend(raw, wireadmin.ConfigKnown); again.Locked != (backend.ConfigGroup{Version: 1, Hash: hashOf(t, b)}) {
		t.Fatalf("again in force: %+v", again.Locked)
	}
}

// The host drops the record that shows an update in force: the update is in
// force anyway, IDENTITY attests it, and a restart starts with its values.
func TestConfigUpdateWithoutTheRecord(t *testing.T) {
	e := newEnv(t, u64(3600))
	b := e.body(locked, 1, e.groupHash(locked), e.now())
	b.Locked.AllowedFeeRecipients = append(b.Locked.AllowedFeeRecipients, x)
	h := hashOf(t, b)
	e.mustSend(signed(t, b, first2, nil), wireadmin.ConfigAccepted)
	e.log.failSet = true
	e.clock.add(3600)
	if err := e.upd.Sync(ctx); err == nil {
		t.Fatal("Sync wrote through a dropped write")
	}
	if err := e.register(x); err != nil {
		t.Fatalf("in force without its record: %v", err)
	}
	inForce := backend.ConfigGroup{Version: 1, Hash: h}
	if id := identityOf(t, e.srv, []byte("nonce")); id.State.Locked != inForce {
		t.Fatalf("IDENTITY %+v", id.State.Locked)
	}
	if logPending(t, e, locked) == nil {
		t.Fatal("the record shows it active")
	}

	e.restart()
	if logPending(t, e, locked) == nil {
		t.Fatal("the restart's record shows it active")
	}
	if err := e.register(x); err != nil {
		t.Fatalf("after the restart: %v", err)
	}
	if st := e.srv.SetupState(); st.Locked != inForce {
		t.Fatalf("after the restart: %+v", st.Locked)
	}
	if err := e.upd.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if ls := e.log.State().Locked; ls.Version != 1 || ls.Pending != nil {
		t.Fatalf("after Sync the record holds %+v", ls)
	}
}

// A body the config in force needs is unreadable after a restart: the
// runner signs under the old values until the update's effective time,
// then signs nothing and reports not ready. The same update again writes
// its body back, and the runner signs under it, without a restart.
func TestConfigUpdateBodyMissing(t *testing.T) {
	t.Run("locked", func(t *testing.T) {
		e := newEnv(t, u64(3600))
		b := e.body(locked, 1, e.groupHash(locked), e.now())
		b.Locked.AllowedFeeRecipients = append(b.Locked.AllowedFeeRecipients, x)
		h := hashOf(t, b)
		raw := signed(t, b, first2, nil)
		e.mustSend(raw, wireadmin.ConfigAccepted)
		e.signer.Close()
		if err := os.Remove(filepath.Join(e.dir, "marks", markstore.BodyName(e.hash, locked, 1, 1))); err != nil {
			t.Fatal(err)
		}
		e.start()
		old := e.setup.Locked.AllowedFeeRecipients[0]
		if err := e.register(old); err != nil || !e.ready() {
			t.Fatalf("before the effective time: %v", err)
		}
		e.clock.add(3600)
		wantCode(t, e.register(old), backend.StatusStorage, "no readable copy")
		if e.ready() {
			t.Fatal("HEALTH says ready")
		}
		if st := e.srv.SetupState(); st.Locked != (backend.ConfigGroup{Version: 1, Hash: h}) || st.ApproverSetHash != (backend.Root{}) {
			t.Fatalf("state %+v", st)
		}
		if err := e.upd.Sync(ctx); err != nil || logPending(t, e, locked) == nil {
			t.Fatalf("Sync wrote a state it cannot be sure of: %v", err)
		}
		b2 := e.body(locked, 2, h, e.now())
		_, _, err := e.send(signed(t, b2, first2, nil))
		wantCode(t, err, backend.StatusStorage, "approver set in force is unknown")

		e.mustSend(raw, wireadmin.ConfigKnown)
		if err := e.register(x); err != nil || !e.ready() {
			t.Fatalf("with the body back: %v", err)
		}
		if err := e.upd.Sync(ctx); err != nil || logPending(t, e, locked) != nil {
			t.Fatalf("Sync: %v", err)
		}
	})
	t.Run("open", func(t *testing.T) {
		e := newEnv(t, u64(0))
		b := e.body(open, 1, e.groupHash(open), e.now())
		b.Open.ForkSchedule = append(b.Open.ForkSchedule, setupwire.Fork{Epoch: startEpoch + 10, Version: v6})
		raw := signed(t, b, first2, nil)
		e.mustSend(raw, wireadmin.ConfigAccepted)
		if err := e.upd.Sync(ctx); err != nil {
			t.Fatal(err)
		}
		e.signer.Close()
		if err := os.Remove(filepath.Join(e.dir, "marks", markstore.BodyName(e.hash, open, 1, 1))); err != nil {
			t.Fatal(err)
		}
		e.start()
		wantCode(t, e.register(e.setup.Locked.AllowedFeeRecipients[0]), backend.StatusStorage, "no readable copy")
		b2 := e.body(open, 2, hashOf(t, b), e.now())
		_, _, err := e.send(signed(t, b2, first2, nil))
		wantCode(t, err, backend.StatusStorage, "open values in force are unknown")
		e.mustSend(raw, wireadmin.ConfigKnown)
		if err := e.register(e.setup.Locked.AllowedFeeRecipients[0]); err != nil {
			t.Fatalf("with the body back: %v", err)
		}
		if cfg := e.signer.Config(); cfg.ForkVersionAt(startEpoch+10) != v6 {
			t.Fatal("the schedule in force is not in the core")
		}
	})
}

// A restart in the middle: the pending updates survive in the log with
// their effective times, the core starts with the pending open schedule,
// and each update comes into force at its time. A restart past both times,
// before a record shows them, starts with their values.
func TestConfigUpdateRestart(t *testing.T) {
	e := newEnv(t, u64(3600))
	t0 := e.now()
	lb := e.body(locked, 1, e.groupHash(locked), t0)
	lb.Locked.AllowedFeeRecipients = append(lb.Locked.AllowedFeeRecipients, x)
	hl := hashOf(t, lb)
	e.mustSend(signed(t, lb, first2, nil), wireadmin.ConfigAccepted)
	ob := e.body(open, 1, e.groupHash(open), t0+600)
	ob.Open.ForkSchedule = append(ob.Open.ForkSchedule, setupwire.Fork{Epoch: 1100, Version: v6})
	ho := hashOf(t, ob)
	e.mustSend(signed(t, ob, first2, nil), wireadmin.ConfigAccepted)
	before := e.srv.SetupState()
	if before.Locked.Pending != pending(1, hl, t0+3600) || before.Open.Pending != pending(1, ho, t0+600) {
		t.Fatalf("before the restart: %+v", before)
	}

	e.restart()
	if st := e.srv.SetupState(); st != before {
		t.Fatalf("after the restart %+v, want %+v", st, before)
	}
	if cfg := e.signer.Config(); cfg.ForkVersionAt(1100) != v6 {
		t.Fatal("the core does not start with the pending open schedule")
	}
	wantCode(t, e.register(x), backend.StatusPolicyFeeRecipient, "")
	e.clock.add(600)
	if st := e.srv.SetupState(); st.Open != (backend.ConfigGroup{Version: 1, Hash: ho}) || st.Locked.Pending.Version != 1 {
		t.Fatalf("at the open update's time: %+v", st)
	}
	e.clock.add(3000)
	if err := e.register(x); err != nil {
		t.Fatal(err)
	}

	e.restart()
	inForce := backend.SetupState{SetupHash: e.hash, Locked: backend.ConfigGroup{Version: 1, Hash: hl},
		Open: backend.ConfigGroup{Version: 1, Hash: ho}, ApproverSetHash: e.setup.Locked.Approvers.Hash(),
		KeyOrigin: backend.KeyOrigin{Imported: 1}}
	if st := e.srv.SetupState(); st != inForce {
		t.Fatalf("restart past both times: %+v, want %+v", st, inForce)
	}
	if err := e.register(x); err != nil {
		t.Fatal(err)
	}
	if logPending(t, e, locked) == nil || logPending(t, e, open) == nil {
		t.Fatal("a record shows them active before Sync")
	}
	if err := e.upd.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if ls := e.log.State(); ls.Locked.Pending != nil || ls.Open.Pending != nil || ls.Locked.Version != 1 || ls.Open.Version != 1 {
		t.Fatalf("after Sync the record holds %+v", ls)
	}
}

// A locked group's allowed_builder_request_auth_data_roots reach the core's
// policy as a copy.
func TestPolicyOfBuilderRequestAuthRoots(t *testing.T) {
	l := setupwire.Locked{AllowedBuilderRequestAuthDataRoots: []backend.Root{{1}, {2}}}
	p := policyOf(&l)
	if !slices.Equal(p.BuilderRequestAuthRoots, l.AllowedBuilderRequestAuthDataRoots) {
		t.Fatalf("policy roots %x", p.BuilderRequestAuthRoots)
	}
	p.BuilderRequestAuthRoots[0][0] = 9
	if l.AllowedBuilderRequestAuthDataRoots[0][0] != 1 {
		t.Fatal("the policy shares the setup's list")
	}
	if policyOf(&setupwire.Locked{}).BuilderRequestAuthRoots != nil {
		t.Fatal("an empty list gives roots")
	}
}
