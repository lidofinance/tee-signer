//go:build !debugimport

package server

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/governance/setupwire"
	"github.com/lidofinance/tee-signer/platform"
	"github.com/lidofinance/tee-signer/platform/dev"
	"github.com/lidofinance/tee-signer/signer-core/core"
	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/sealedimport"
	"github.com/lidofinance/tee-signer/slashing-log"
	"github.com/lidofinance/tee-signer/tee-signer/state"
)

// The test env of a dev runner with a setup and the mark log, as main
// starts it.

// devDoc is the dev platform's document over nonce and userData.
func devDoc(nonce, userData []byte) *backend.Attestation {
	doc, _ := json.Marshal(map[string]any{"nonce": nonce, "user_data": userData})
	return &backend.Attestation{Platform: "dev", Format: "dev-json", UserData: userData, Document: doc}
}

// devDocAttester answers like the dev platform, without hashing the test
// binary.
type devDocAttester struct{}

func (devDocAttester) Attest(_ context.Context, nonce, userData []byte) (*backend.Attestation, error) {
	return devDoc(nonce, userData), nil
}

// tgtEnv is a dev runner with a setup whose store and mark log outlive
// restarts.
type tgtEnv struct {
	t        *testing.T
	raw      []byte
	setup    *setupwire.Setup
	hash     [32]byte
	dir      string
	clock    *fakeClock
	store    *shareStore
	sealer   platform.Sealer
	platName string
	fl       *markstore.FileLog
	marks    *markstore.MarkLog
	hooks    *state.Hooks
	upd      *Updates
	signer   *core.Signer
	srv      *Server
	// looseLoad: a start logs LoadListedShares' error, as main does,
	// rather than failing the test; loadErr is that error.
	looseLoad bool
	loadErr   error
	// beforeLoad and afterLoad, if set, run around LoadListedShares at a
	// start.
	beforeLoad, afterLoad func()
	// lockDays: markstore.Options.LockDays of the next start. The log
	// then reports a compliance lock of that many days until lockGone.
	lockDays uint32
	lockGone bool
	// lockErr, if set, fails the log's lock read, as a host that blocks
	// the store's management API.
	lockErr error
	// logDelay, if set, is the time each call to the mark log's store
	// takes, as a remote store's round trip.
	logDelay time.Duration
	// loseShareRecord: the next record with a pending share set root
	// lands, but its write answers with a timeout, as a lost reply. Not
	// with lockDays.
	loseShareRecord bool
}

// slowLog is a mark log store whose calls take delay each.
type slowLog struct {
	markstore.Log
	delay time.Duration
}

func (l slowLog) Create(ctx context.Context, name string, data []byte) error {
	time.Sleep(l.delay)
	return l.Log.Create(ctx, name, data)
}

func (l slowLog) List(ctx context.Context, prefix string) ([]markstore.Entry, error) {
	time.Sleep(l.delay)
	return l.Log.List(ctx, prefix)
}

func (l slowLog) Get(ctx context.Context, e markstore.Entry) ([]byte, error) {
	time.Sleep(l.delay)
	return l.Log.Get(ctx, e)
}

// lostShareReplyLog is the test env's file log that loses the reply of
// the record e.loseShareRecord names.
type lostShareReplyLog struct {
	*markstore.FileLog
	e *tgtEnv
}

func (l lostShareReplyLog) Create(ctx context.Context, name string, data []byte) error {
	err := l.FileLog.Create(ctx, name, data)
	if r, perr := markstore.Parse(data); err == nil && perr == nil && l.e.loseShareRecord && r.Shares != nil && r.Shares.Pending != nil {
		l.e.loseShareRecord = false
		return context.DeadlineExceeded
	}
	return err
}

// lockedFileLog is the test env's file log with the lock it reports.
type lockedFileLog struct {
	*markstore.FileLog
	e *tgtEnv
}

func (l lockedFileLog) Lock(context.Context) (markstore.Lock, error) {
	if l.e.lockErr != nil {
		return markstore.Lock{}, l.e.lockErr
	}
	if l.e.lockGone {
		return markstore.Lock{Kind: "test lock", Mode: "none"}, nil
	}
	return markstore.Lock{Kind: "test lock", Mode: "locked", Compliance: true, Retention: time.Duration(l.e.lockDays) * 24 * time.Hour}, nil
}

// newTgtEnv starts a target with the single-mode dev sample setup
// (setup-dev-single: it takes whole keys, 1 of 1) at handover generation
// 2: approvers 1 to 3, k = 2, max_keys 1024, changed by change.
func newTgtEnv(t *testing.T, platName string, change func(s *setupwire.Setup)) *tgtEnv {
	t.Helper()
	return newTgtEnvOf(t, "setup-dev-single", platName, change)
}

// newShareTgtEnv is newTgtEnv with the threshold dev sample setup
// (setup-dev-threshold), for a runner that holds shares of splits.
func newShareTgtEnv(t *testing.T, platName string, change func(s *setupwire.Setup)) *tgtEnv {
	t.Helper()
	return newTgtEnvOf(t, "setup-dev-threshold", platName, change)
}

// newTgtEnvOf is newTgtEnv with the dev sample setup of that name.
func newTgtEnvOf(t *testing.T, sample, platName string, change func(s *setupwire.Setup)) *tgtEnv {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "governance", "setupwire", "testdata", sample+".bin"))
	if err != nil {
		t.Fatal(err)
	}
	s, err := setupwire.DecodeSetup(raw)
	if err != nil {
		t.Fatal(err)
	}
	s.HandoverGeneration, s.MaxKeys, s.SlashingLogMinLockDays = 2, 1024, 100
	s.Locked.Approvers = approverSet(2, 1, 2, 3)
	if change != nil {
		change(s)
	}
	if raw, err = s.Encode(); err != nil {
		t.Fatal(err)
	}
	e := &tgtEnv{t: t, raw: raw, setup: s, hash: mustHash(t, s), dir: t.TempDir(), platName: platName,
		clock: &fakeClock{t: time.Unix(testGenesis+startEpoch*testEpoch+5, 0), trusted: true},
		store: &shareStore{m: map[string][]byte{}}, sealer: dev.NewDevSealer()}
	e.start()
	return e
}

// start is a runner's start as main does it with the mark log: list the
// shares, claim the log, the config in force, the core with the device
// mark, a new import key, load the listed shares, the import on.
func (e *tgtEnv) start() {
	t := e.t
	t.Helper()
	ms, err := markstore.SetupOf(e.setup, e.hash)
	if err != nil {
		t.Fatal(err)
	}
	if e.fl, err = markstore.NewFileLog(filepath.Join(e.dir, "marks")); err != nil {
		t.Fatal(err)
	}
	var l markstore.Log = lostShareReplyLog{FileLog: e.fl, e: e}
	if e.lockDays > 0 {
		l = lockedFileLog{FileLog: e.fl, e: e}
	}
	if e.logDelay > 0 {
		l = slowLog{Log: l, delay: e.logDelay}
	}
	m, err := markstore.New(l, e.setup.SignerName, dev.NewDevKeys("server test env"), markstore.Options{Setup: ms, Clock: e.clock.Now, Log: quiet, LockDays: e.lockDays})
	if err != nil {
		t.Fatal(err)
	}
	stored, err := ListShares(e.store)
	if err != nil {
		t.Fatal(err)
	}
	mark, found, err := m.Claim(ctx, len(stored) > 0)
	if err != nil {
		t.Fatal(err)
	}
	e.marks = m
	if e.upd, err = NewUpdates(UpdatesOptions{Setup: e.setup, SetupHash: e.hash, Log: m, Clock: e.clock, Logger: quiet}); err != nil {
		t.Fatal(err)
	}
	cfg, err := e.upd.StartConfig(baseConfig(e.setup))
	if err != nil {
		t.Fatal(err)
	}
	cfg.DeviceMark = true
	if e.hooks, err = state.New(cfg, state.Mode{Floor: true, FloorMargin: state.DefaultFloorMargin(cfg), MarkLog: true}, e.clock, e.store, e.sealer, quiet); err != nil {
		t.Fatal(err)
	}
	e.hooks.UseMarkLog(m, mark, found)
	// The core holds max_keys keys, as main sizes it (start.go).
	if e.signer, err = core.NewSigner(cfg, e.setup.MaxKeys, 0, e.hooks); err != nil {
		t.Fatal(err)
	}
	e.hooks.UseClock(e.signer.EpochAt)
	t.Cleanup(e.signer.Close)
	e.upd.Attach(e.signer)
	e.srv = &Server{Signer: e.signer, Hooks: e.hooks, Log: quiet, Updates: e.upd, State: e.upd.SetupState,
		Platform:  &platform.Platform{Name: e.platName, Store: e.store, Sealer: e.sealer, Clock: e.clock, Attester: devDocAttester{}},
		SetupHash: e.hash, LogID: m.LogID()}
	if e.srv.ImportKey, err = sealedimport.Generate(); err != nil {
		t.Fatal(err)
	}
	if e.beforeLoad != nil {
		e.beforeLoad()
	}
	_, e.loadErr = e.srv.LoadListedShares(stored)
	if e.afterLoad != nil {
		e.afterLoad()
	}
	if e.loadErr != nil && !e.looseLoad {
		t.Fatal(e.loadErr)
	}
}

func (e *tgtEnv) restart() {
	e.t.Helper()
	e.signer.Close()
	e.start()
}

func (e *tgtEnv) now() uint64 { t, _ := e.clock.Now(); return uint64(t.Unix()) }

// sealTo is the runner's import key as a sealed import seals to it.
func (e *tgtEnv) sealTo() *backend.Identity {
	id := &backend.Identity{}
	e.srv.ImportKey.Fill(id)
	return id
}

// attest signs an attestation of pk for source and target.
func (e *tgtEnv) attest(pk backend.Pubkey, source, target uint64) error {
	m := &backend.AttestationData{Slot: target * 8, Source: backend.Checkpoint{Epoch: source}, Target: backend.Checkpoint{Epoch: target}}
	cfg := e.signer.Config()
	d, err := cfg.MessageDomain(m)
	if err != nil {
		e.t.Fatal(err)
	}
	_, err = e.srv.sign(backend.SignRequest{Pubkey: pk, Message: m, Domain: d})
	return err
}

// records are the runner's mark log records, oldest first.
func (e *tgtEnv) records() []*markstore.Record {
	e.t.Helper()
	es, err := e.fl.List(ctx, markstore.Prefix(e.hash, e.setup.SignerName))
	if err != nil {
		e.t.Fatal(err)
	}
	var out []*markstore.Record
	for _, en := range es {
		b, err := e.fl.Get(ctx, en)
		if err != nil {
			e.t.Fatal(err)
		}
		r, err := markstore.Parse(b)
		if err != nil {
			continue // a hint or a body
		}
		out = append(out, r)
	}
	slices.SortFunc(out, func(a, b *markstore.Record) int { return int(a.Version) - int(b.Version) })
	return out
}

// testMark is an interchange mark: it signed up to target epoch 1004.
var testMark = backend.Watermark{HasAttestation: true, SourceEpoch: startEpoch + 3, TargetEpoch: startEpoch + 4, HasBlock: true, BlockSlot: (startEpoch+4)*8 + 7}
