package state

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/platform"
	"github.com/lidofinance/tee-signer/platform/dev"
	"github.com/lidofinance/tee-signer/signer-core/core"
	"github.com/lidofinance/tee-signer/signer-core/software"
	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/tee-signer/record"
	"github.com/lidofinance/tee-signer/trusted-time/clock"
)

const genesis = 1_000_000

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() (time.Time, error) { c.mu.Lock(); defer c.mu.Unlock(); return c.t, nil }
func (c *fakeClock) Source() string          { return "fake" }
func (c *fakeClock) Trusted() bool           { return false }
func (c *fakeClock) set(t time.Time)         { c.mu.Lock(); c.t = t; c.mu.Unlock() }

// at returns the time sec seconds into epoch e (12 s slots, 32 slots).
func at(e uint64, sec int64) time.Time {
	return time.Unix(int64(genesis+e*384)+sec, 0)
}

type memStore struct {
	mu   sync.Mutex
	m    map[string][]byte
	puts int
}

func newMemStore() *memStore { return &memStore{m: map[string][]byte{}} }

func (s *memStore) Get(k string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.m[k]
	if !ok {
		return nil, platform.ErrNotFound
	}
	return append([]byte(nil), v...), nil
}

func (s *memStore) Put(k string, v []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[k] = append([]byte(nil), v...)
	s.puts++
	return nil
}

func (s *memStore) List(p string) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for k := range s.m {
		if strings.HasPrefix(k, p) {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out, nil
}

func (s *memStore) snapshot() map[string][]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := map[string][]byte{}
	for k, v := range s.m {
		c[k] = v
	}
	return c
}

func (s *memStore) restore(snap map[string][]byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m = map[string][]byte{}
	for k, v := range snap {
		s.m[k] = v
	}
}

type node struct {
	cfg  core.Config
	mode Mode
	clk  *fakeClock
	// useClock, if set, is the clock handed to the hooks instead of clk.
	useClock platform.Clock
	store    *memStore
	sk       [32]byte
	pk       backend.Pubkey
	signer   *core.Signer
	hooks    *Hooks
	// rec, if set, is the node's external record (clone guard).
	rec   record.Store
	guard *record.Guard
}

func newNode(t testing.TB, mode Mode) *node {
	t.Helper()
	sk, _ := software.NewSecret()
	pk, _ := core.PubkeyOf(sk)
	n := &node{cfg: software.DevConfig(genesis, 12, 32), mode: mode, clk: &fakeClock{}, store: newMemStore(), sk: sk, pk: pk}
	return n
}

// start (re)starts the signer: all RAM state is lost.
func (n *node) start(t testing.TB) error {
	t.Helper()
	if n.signer != nil {
		n.signer.Close()
	}
	var clk platform.Clock = n.clk
	if n.useClock != nil {
		clk = n.useClock
	}
	h, err := New(n.cfg, n.mode, clk, n.store, dev.NewDevSealer(), quiet)
	if err != nil {
		t.Fatal(err)
	}
	if n.rec != nil {
		g, err := record.New(n.rec, "node-1", dev.NewDevSealer(), 0, quiet)
		if err != nil {
			t.Fatal(err)
		}
		if err := g.Claim(context.Background(), false); err != nil {
			return err
		}
		h.UseGuard(g)
		n.guard = g
	}
	s, err := core.NewSigner(n.cfg, 1, 0, h)
	if err != nil {
		t.Fatal(err)
	}
	n.signer, n.hooks = s, h
	_, err = s.AddValidator(n.pk, n.sk, 7, nil)
	return err
}

func (n *node) attest(source, target uint64, tag byte) error {
	a := &backend.AttestationData{Slot: target * 32, BeaconBlockRoot: backend.Root{tag},
		Source: backend.Checkpoint{Epoch: source}, Target: backend.Checkpoint{Epoch: target}}
	_, err := n.signer.Sign(n.req(a))
	return err
}

// req is a request for m with the domain the signer's config gives it.
func (n *node) req(m backend.Message) backend.SignRequest {
	cfg := n.signer.Config()
	d, _ := cfg.MessageDomain(m)
	return backend.SignRequest{Pubkey: n.pk, Message: m, Domain: d}
}

func wantStatus(t *testing.T, err error, want backend.Status) {
	t.Helper()
	if got := backend.StatusOf(err); got != want {
		t.Fatalf("got %v (%v), want %v", got, err, want)
	}
}

func wantSlashing(t *testing.T, err error) {
	t.Helper()
	if !backend.StatusOf(err).IsSlashing() {
		t.Fatalf("got %v, want a slashing refusal", err)
	}
}

func TestModeValidation(t *testing.T) {
	cfg := software.DevConfig(genesis, 12, 32)
	clk := &fakeClock{}
	if _, err := New(cfg, Mode{}, clk, nil, nil, quiet); err == nil {
		t.Fatal("no protection accepted")
	}
	if _, err := New(cfg, Mode{Floor: true, FloorMargin: 0}, clk, nil, nil, quiet); err == nil {
		t.Fatal("margin below max_epochs_ahead accepted")
	}
	if _, err := New(cfg, Mode{Floor: true, FloorMargin: cfg.MaxEpochsAhead}, clk, nil, nil, quiet); err == nil {
		t.Fatal("margin max_epochs_ahead (no spare epoch) accepted")
	}
	if _, err := New(cfg, Mode{Floor: true, FloorMargin: DefaultFloorMargin(cfg)}, clk, nil, nil, quiet); err != nil {
		t.Fatal(err)
	}
	if DefaultFloorMargin(cfg) != 2 {
		t.Fatalf("default margin %d, want max_epochs_ahead + 1 = 2", DefaultFloorMargin(cfg))
	}
	if _, err := New(cfg, Mode{Persist: true}, clk, nil, nil, quiet); err == nil {
		t.Fatal("persist without store accepted")
	}
}

func TestFloorWatermark(t *testing.T) {
	cfg := software.DevConfig(genesis, 12, 32)
	wm := FloorWatermark(cfg, 101)
	if wm.TargetEpoch != 101 || wm.SourceEpoch != 101 || wm.BlockSlot != 102*32-1 || !wm.HasBlock || !wm.HasAttestation {
		t.Fatalf("%+v", wm)
	}
	m := Merge(backend.Watermark{HasAttestation: true, SourceEpoch: 200, TargetEpoch: 90}, wm)
	if m.SourceEpoch != 200 || m.TargetEpoch != 101 || m.BlockSlot != wm.BlockSlot {
		t.Fatalf("%+v", m)
	}
}

// The rule with the default margin: after a restart in epoch E, refuse
// everything at or below E+2 (max_epochs_ahead + 1). Shows which duties
// are lost.
func TestRestartFloorRefusesAtOrBelowEpochPlusTwo(t *testing.T) {
	n := newNode(t, Mode{Floor: true, FloorMargin: 2})
	n.clk.set(at(100, 5))
	if err := n.start(t); err != nil {
		t.Fatal(err)
	}
	// The first load applies the floor too: the share may have signed elsewhere.
	wantSlashing(t, n.attest(99, 100, 1))

	n.clk.set(at(102, 5))
	if err := n.start(t); err != nil { // fresh process: floor 104
		t.Fatal(err)
	}
	if f, _ := n.hooks.Floor(n.pk); f != 104 {
		t.Fatalf("floor %d", f)
	}
	wantSlashing(t, n.attest(101, 102, 1))                           // E
	wantSlashing(t, n.attest(102, 103, 1))                           // E+1 (the clock allows it)
	wantStatus(t, n.attest(103, 104, 1), backend.StatusPolicyFuture) // E+2 is past the clock horizon
	n.clk.set(at(103, 5))
	wantStatus(t, n.attest(103, 104, 2), backend.StatusSlashSource) // E+2, source below the floor
	wantStatus(t, n.attest(104, 104, 2), backend.StatusSlashTarget) // E+2, target at the floor
	n.clk.set(at(105, 5))
	wantStatus(t, n.attest(103, 105, 1), backend.StatusSlashSource) // source below the floor
	if err := n.attest(104, 105, 1); err != nil {                   // E+3 with a current source
		t.Fatalf("E+3: %v", err)
	}
	blk := func(slot uint64) error {
		_, err := n.signer.Sign(n.req(&backend.BeaconBlockHeader{Slot: slot, ProposerIndex: 7}))
		return err
	}
	wantStatus(t, blk(105*32-1), backend.StatusSlashBlock) // last slot of E+2
	if err := blk(105 * 32); err != nil {
		t.Fatal(err)
	}
}

// staticSource is a clock source that always answers t.
type staticSource struct{ t time.Time }

func (s staticSource) Fetch(context.Context) (time.Time, error) { return s.t, nil }
func (s staticSource) Name() string                             { return "static" }

// The anchored clock advances between readings, so the floor and the
// future check see the epoch that really is running. The reading is 4 s
// before epoch 101 starts, the local clock is 10 s later: epoch 101. A clock
// that stood still would say epoch 100, put the floor at 102, and refuse
// target 102 as too far ahead. With no reading for five intervals the clock
// fails and the runner does not load a share.
func TestFloorWithAnchoredClockBetweenReadings(t *testing.T) {
	local := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	a := &clock.Anchored{Src: staticSource{at(100, 380)}, Interval: clock.DefaultInterval, Local: func() time.Time { return local }}
	if err := a.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	n := newNode(t, Mode{Floor: true, FloorMargin: 2})
	n.useClock = a

	local = local.Add(10 * time.Second)
	if err := n.start(t); err != nil {
		t.Fatal(err)
	}
	if f, _ := n.hooks.Floor(n.pk); f != 103 {
		t.Fatalf("floor %d, want epoch 101 + 2 = 103 (a clock that stands still gives 102)", f)
	}
	wantSlashing(t, n.attest(101, 102, 1)) // at the floor; not "too far ahead"

	// Time keeps running between readings: a restart 70 s after the reading
	// is still in epoch 101.
	local = local.Add(60 * time.Second)
	if err := n.start(t); err != nil {
		t.Fatal(err)
	}
	if f, _ := n.hooks.Floor(n.pk); f != 103 {
		t.Fatalf("floor %d after 70 s", f)
	}

	// Five intervals without a reading: the clock fails, no share loads.
	local = local.Add(10 * time.Second)
	if err := n.start(t); err == nil {
		t.Fatal("a share loaded on a clock without a recent reading")
	}
}

// Floor-only mode writes nothing.
func TestFloorOnlyWritesNothing(t *testing.T) {
	n := newNode(t, Mode{Floor: true, FloorMargin: 2})
	n.clk.set(at(10, 5))
	if err := n.start(t); err != nil {
		t.Fatal(err)
	}
	for e := uint64(13); e < 20; e++ {
		n.clk.set(at(e, 5))
		if err := n.attest(e-1, e, 1); err != nil {
			t.Fatal(err)
		}
	}
	if keys, _ := n.store.List(""); len(keys) != 0 {
		t.Fatalf("floor-only mode wrote %v", keys)
	}
}

// Builds before this one could store a validator's last roots under rr/
// (-persist-repeat-root). The runner never reads them now: with an older
// build's record for the last vote in the store, a restart that adds the key
// again without history refuses that vote below the floor.
func TestOldRepeatRootRecordIgnored(t *testing.T) {
	n := newNode(t, Mode{Floor: true, FloorMargin: 2})
	n.clk.set(at(10, 5))
	if err := n.start(t); err != nil {
		t.Fatal(err)
	}
	n.clk.set(at(15, 5))
	if err := n.attest(14, 15, 1); err != nil {
		t.Fatal(err)
	}
	// The record an older build wrote for that vote: magic, flags, roots.
	a := &backend.AttestationData{Slot: 15 * 32, BeaconBlockRoot: backend.Root{1},
		Source: backend.Checkpoint{Epoch: 14}, Target: backend.Checkpoint{Epoch: 15}}
	obj, err := backend.HashTreeRoot(a)
	if err != nil {
		t.Fatal(err)
	}
	root := backend.SigningRoot(obj, n.req(a).Domain)
	rec := append([]byte{'S', 'C', 'R', '1', 1, 0, 0, 0}, root[:]...)
	rec = append(rec, make([]byte, 32)...)
	blob, err := dev.NewDevSealer().Seal(rec, append([]byte("signer-repeat-roots-v1|"), n.pk[:]...))
	if err != nil {
		t.Fatal(err)
	}
	if err := n.store.Put("rr/"+hex.EncodeToString(n.pk[:]), blob); err != nil {
		t.Fatal(err)
	}
	n.clk.set(at(15, 300))
	if err := n.start(t); err != nil {
		t.Fatal(err)
	}
	wantSlashing(t, n.attest(14, 15, 1))
	if st := n.signer.Stats(); st.ExactRepeats != 0 {
		t.Fatalf("stats %+v", st)
	}
}

func TestPersistedMarksAndMissingRecord(t *testing.T) {
	n := newNode(t, Mode{Persist: true})
	n.clk.set(at(50, 5))
	if err := n.start(t); err != nil {
		t.Fatal(err)
	}
	if err := n.attest(49, 50, 1); err != nil {
		t.Fatal(err)
	}
	if err := n.start(t); err != nil {
		t.Fatal(err)
	}
	// Commit-ahead {32,1,1}: stored target bound 51, source bound 50.
	wantStatus(t, n.attest(49, 51, 2), backend.StatusSlashSource)
	wantStatus(t, n.attest(50, 51, 2), backend.StatusSlashTarget)
	n.clk.set(at(51, 5))
	if err := n.attest(50, 52, 2); err != nil {
		t.Fatal(err)
	}
	// The host deletes the record of a share that was restored from storage.
	n.store.restore(map[string][]byte{})
	n.signer.Close()
	h, _ := New(n.cfg, n.mode, n.clk, n.store, dev.NewDevSealer(), quiet)
	h.ExpectRecord(n.pk)
	s, _ := core.NewSigner(n.cfg, 1, 0, h)
	defer s.Close()
	_, err := s.AddValidator(n.pk, n.sk, 7, nil)
	if backend.StatusOf(err) != backend.StatusStorage || !strings.Contains(err.Error(), "missing") {
		t.Fatalf("deleted record: %v", err)
	}
}

// A host that rolls the store back defeats persisted-only marks: the node
// signs a second, different vote for a target it already signed.
func TestPersistedOnlyBrokenByStoreRollback(t *testing.T) {
	n := newNode(t, Mode{Persist: true})
	n.clk.set(at(49, 5))
	if err := n.start(t); err != nil {
		t.Fatal(err)
	}
	if err := n.attest(48, 49, 1); err != nil { // stores target bound 50
		t.Fatal(err)
	}
	old := n.store.snapshot()
	n.clk.set(at(51, 5))
	if err := n.attest(50, 51, 1); err != nil { // stores target bound 52
		t.Fatal(err)
	}
	n.store.restore(old) // host puts back the record with bound 50
	if err := n.start(t); err != nil {
		t.Fatal(err)
	}
	if err := n.attest(50, 51, 2); err != nil {
		t.Fatalf("expected the rollback to allow a double vote, got %v", err)
	}
}

// With an honest clock the floor stops the same rollback.
func TestFloorStopsStoreRollback(t *testing.T) {
	n := newNode(t, Mode{Persist: true, Floor: true, FloorMargin: 2})
	n.clk.set(at(50, 5))
	if err := n.start(t); err != nil {
		t.Fatal(err)
	}
	old := n.store.snapshot()
	n.clk.set(at(53, 5))
	if err := n.attest(52, 53, 1); err != nil {
		t.Fatal(err)
	}
	n.store.restore(old)
	n.clk.set(at(53, 300)) // restart later in the same epoch
	if err := n.start(t); err != nil {
		t.Fatal(err)
	}
	wantSlashing(t, n.attest(52, 53, 2))
}

// The floor trusts the clock in both directions. A host that runs the
// clock ahead, gets a vote for a future target, then restarts the node with
// the right time gets a second vote for that target.
func TestFloorBrokenByClockForwardThenBack(t *testing.T) {
	n := newNode(t, Mode{Floor: true, FloorMargin: 2})
	n.clk.set(at(100, 5))
	if err := n.start(t); err != nil {
		t.Fatal(err)
	}
	n.clk.set(at(110, 5)) // host moves the clock 10 epochs ahead
	if err := n.attest(109, 111, 1); err != nil {
		t.Fatal(err)
	}
	n.clk.set(at(100, 10)) // restart with the true time
	if err := n.start(t); err != nil {
		t.Fatal(err)
	}
	n.clk.set(at(111, 5)) // real time reaches epoch 111
	if err := n.attest(110, 111, 2); err != nil {
		t.Fatalf("expected a double vote for target 111, got %v", err)
	}
}

// Same for a clock wound back at restart by more than the spare epoch.
func TestFloorBrokenByClockRewindAtRestart(t *testing.T) {
	n := newNode(t, Mode{Floor: true, FloorMargin: 2})
	n.clk.set(at(100, 5))
	if err := n.start(t); err != nil {
		t.Fatal(err)
	}
	n.clk.set(at(105, 5))
	if err := n.attest(104, 105, 1); err != nil {
		t.Fatal(err)
	}
	n.clk.set(at(102, 5)) // restart with the clock 3 epochs behind
	if err := n.start(t); err != nil {
		t.Fatal(err)
	}
	n.clk.set(at(105, 5))
	if err := n.attest(104, 105, 2); err != nil {
		t.Fatalf("expected a double vote for target 105, got %v", err)
	}
}

// The clone guard's record is a third floor that does not trust the clock:
// the same rewind is refused when the node keeps an external record.
func TestRecordFloorStopsClockRewind(t *testing.T) {
	n := newNode(t, Mode{Floor: true, FloorMargin: 2})
	n.rec = record.NewMemStore()
	n.clk.set(at(100, 5))
	if err := n.start(t); err != nil {
		t.Fatal(err)
	}
	n.clk.set(at(105, 5))
	if err := n.attest(104, 105, 1); err != nil { // record now covers 106
		t.Fatal(err)
	}
	n.clk.set(at(102, 5))
	if err := n.start(t); err != nil {
		t.Fatal(err)
	}
	if f, _ := n.hooks.Floor(n.pk); f != 106 {
		t.Fatalf("floor %d, want the record's 106 over the clock's 104", f)
	}
	n.clk.set(at(105, 5))
	wantSlashing(t, n.attest(104, 105, 2))
	n.clk.set(at(107, 5))
	if err := n.attest(106, 107, 1); err != nil {
		t.Fatal(err)
	}
}

// Two runners from one image share the sealed share and the record. They
// run at the same time with the same honest clock, and the host sends each
// a different vote for every target. Without the record both sign (double
// votes); with it, at most one runner signs per target, and the one that
// lost the record refuses everything new.
func TestCloneGuardOnlyOneSigns(t *testing.T) {
	run := func(withRecord bool) (doubles, aSigned, bSigned int, aErr error) {
		a := newNode(t, Mode{Floor: true, FloorMargin: 2})
		if withRecord {
			a.rec = record.NewMemStore()
		}
		a.clk.set(at(200, 5))
		if err := a.start(t); err != nil {
			t.Fatal(err)
		}
		b := newNode(t, Mode{Floor: true, FloorMargin: 2})
		b.sk, b.pk, b.clk, b.rec = a.sk, a.pk, a.clk, a.rec // same share, same record
		b.store.restore(a.store.snapshot())                 // same sealed state
		a.clk.set(at(203, 5))
		if err := a.attest(202, 203, 0xa); err != nil { // a signs before the clone exists
			t.Fatal(err)
		}
		aSigned++
		if err := b.start(t); err != nil { // the clone starts and claims the record
			t.Fatal(err)
		}
		for e := uint64(204); e < 212; e++ {
			a.clk.set(at(e, 5))
			var ea, eb error
			if e%2 == 0 { // vary who is asked first
				ea = a.attest(e-1, e, 0xa)
				eb = b.attest(e-1, e, 0xb)
			} else {
				eb = b.attest(e-1, e, 0xb)
				ea = a.attest(e-1, e, 0xa)
			}
			if ea == nil {
				aSigned++
			} else {
				aErr = ea
			}
			if eb == nil {
				bSigned++
			}
			if ea == nil && eb == nil {
				doubles++
			}
		}
		return
	}
	d, as, bs, _ := run(false)
	t.Logf("without the record: a signed %d, b signed %d, double votes %d", as, bs, d)
	if d == 0 {
		t.Fatal("control: expected double votes without the record")
	}
	d, as, bs, aErr := run(true)
	t.Logf("with the record: a signed %d, b signed %d, double votes %d; a's refusal: %v", as, bs, d, aErr)
	if d != 0 || bs == 0 {
		t.Fatalf("with the record: %d double votes, b signed %d", d, bs)
	}
	if aErr == nil || backend.StatusOf(aErr) != backend.StatusStorage {
		t.Fatalf("a should be refused for the lost record, got %v", aErr)
	}
}

// The runner refuses to sign when it cannot advance the record, and signs
// again once the record is reachable.
func TestCloneGuardRefusesWithoutRecord(t *testing.T) {
	n := newNode(t, Mode{Floor: true, FloorMargin: 2})
	rs := record.NewMemStore()
	n.rec = rs
	n.clk.set(at(300, 5))
	if err := n.start(t); err != nil {
		t.Fatal(err)
	}
	n.clk.set(at(303, 5))
	rs.Fail = fmt.Errorf("table unreachable")
	err := n.attest(302, 303, 1)
	wantStatus(t, err, backend.StatusStorage)
	if !strings.Contains(err.Error(), "cannot advance record") {
		t.Fatal(err)
	}
	rs.Fail = nil
	if err := n.attest(302, 303, 1); err != nil {
		t.Fatal(err)
	}
}

type vote struct {
	source, target uint64
	tag            byte
}

// slashable returns "double", "surround" or "".
func slashable(a, b vote) string {
	if a.target == b.target {
		if a != b {
			return "double"
		}
		return ""
	}
	if (a.source < b.source && b.target < a.target) || (b.source < a.source && a.target < b.target) {
		return "surround"
	}
	return ""
}

type simResult struct{ signed, restarts, doubles, surrounds int }

func (r simResult) violations() int { return r.doubles + r.surrounds }

// simulate runs random attestation requests with random restarts and
// counts slashable pairs among everything signed. True time only moves
// forward (on average a third of an epoch per request). clockLie > 0 lets
// every clock reading be off by up to that many epochs either way;
// jitterSec > 0 lets it be off by up to that many seconds, as two honest
// time servers can disagree.
func simulate(t *testing.T, mode Mode, trials, steps int, clockLie, jitterSec int, rollback bool, seed int64) (res simResult) {
	rng := rand.New(rand.NewSource(seed))
	for trial := 0; trial < trials; trial++ {
		n := newNode(t, mode)
		trueTime := at(1000, int64(rng.Intn(384)))
		trueEpoch := func() uint64 { return n.cfg.EpochAt(uint64(trueTime.Unix())) }
		setClock := func() {
			r := trueTime
			if clockLie > 0 {
				r = r.Add(time.Duration(rng.Intn(2*clockLie+1)-clockLie) * 384 * time.Second)
			}
			if jitterSec > 0 {
				r = r.Add(time.Duration(rng.Intn(2*jitterSec+1)-jitterSec) * time.Second)
			}
			n.clk.set(r)
		}
		setClock()
		if err := n.start(t); err != nil {
			t.Fatal(err)
		}
		var snaps []map[string][]byte
		var history []vote
		for step := 0; step < steps; step++ {
			trueTime = trueTime.Add(time.Duration(rng.Intn(256)) * time.Second)
			if rng.Intn(6) == 0 {
				if rollback && len(snaps) > 0 {
					n.store.restore(snaps[rng.Intn(len(snaps))])
				}
				setClock()
				if err := n.start(t); err != nil {
					t.Fatal(err)
				}
				res.restarts++
			}
			if rng.Intn(4) == 0 {
				snaps = append(snaps, n.store.snapshot())
			}
			setClock()
			// Targets from 3 behind to 2 ahead of the true epoch; sources up
			// to 4 epochs behind the target (a chain that is slow to justify).
			target := trueEpoch() - 3 + uint64(rng.Intn(6))
			v := vote{source: target - uint64(rng.Intn(5)), target: target, tag: byte(rng.Intn(2))}
			if n.attest(v.source, v.target, v.tag) == nil {
				for _, h := range history {
					switch slashable(h, v) {
					case "double":
						res.doubles++
					case "surround":
						res.surrounds++
					}
				}
				history = append(history, v)
				res.signed++
			}
		}
		n.signer.Close()
	}
	return
}

// The randomized check behind the README claims. Honest clock: no
// violations in any mode that includes the floor, even with the store
// rolled back. Lying clock or rollback without the floor: violations.
// Clock readings that disagree by up to 30 s (honest servers): violations
// with the pre-review margin max_epochs_ahead, none with the default
// max_epochs_ahead + 1.
func TestRestartSafetyProperty(t *testing.T) {
	trials, steps := 500, 40
	if testing.Short() {
		trials = 30
	}
	floor := Mode{Floor: true, FloorMargin: 2}
	both := Mode{Floor: true, Persist: true, FloorMargin: 2}
	cases := []struct {
		name      string
		mode      Mode
		clockLie  int
		jitterSec int
		rollback  bool
		wantSafe  bool
	}{
		{"floor, honest clock", floor, 0, 0, false, true},
		{"floor without source bound, honest clock", Mode{Floor: true, FloorMargin: 2, noSourceFloor: true}, 0, 0, false, false},
		{"floor+persisted, honest clock, store rollback", both, 0, 0, true, true},
		{"persisted, store intact", Mode{Persist: true}, 0, 0, false, true},
		{"persisted, store rollback", Mode{Persist: true}, 0, 0, true, false},
		{"floor, clock off by up to 3 epochs", floor, 3, 0, false, false},
		{"floor+persisted, clock off by up to 3 epochs, store intact", both, 3, 0, false, true},
		{"floor+persisted, clock off by up to 3 epochs, store rollback", both, 3, 0, true, false},
		{"floor margin 1 (pre-review), readings off by up to 60 s", Mode{Floor: true, FloorMargin: 1, shortMargin: true}, 0, 60, false, false},
		{"floor margin 2 (default), readings off by up to 60 s", floor, 0, 60, false, true},
	}
	for i, c := range cases {
		n := trials
		if c.jitterSec > 0 {
			n *= 4 // the skew gap needs a reading near an epoch boundary: rarer
		}
		r := simulate(t, c.mode, n, steps, c.clockLie, c.jitterSec, c.rollback, int64(i+1))
		bad := r.violations()
		t.Logf("%-62s signed=%d restarts=%d double=%d surround=%d", c.name, r.signed, r.restarts, r.doubles, r.surrounds)
		if c.wantSafe && bad != 0 {
			t.Errorf("%s: %d violations", c.name, bad)
		}
		if !c.wantSafe && bad == 0 && !testing.Short() {
			t.Errorf("%s: expected violations, found none (test too weak?)", c.name)
		}
	}
}

func ExampleFloorWatermark() {
	cfg := software.DevConfig(genesis, 12, 32)
	wm := FloorWatermark(cfg, 101)
	fmt.Println(wm.BlockSlot, wm.SourceEpoch, wm.TargetEpoch)
	// Output: 3263 101 101
}
