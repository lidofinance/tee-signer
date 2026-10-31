//go:build !debugimport

package server

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/lidofinance/tee-signer/devkit/fuzzcheck"
	"github.com/lidofinance/tee-signer/platform"
	"github.com/lidofinance/tee-signer/platform/dev"
	"github.com/lidofinance/tee-signer/signer-core/core"
	"github.com/lidofinance/tee-signer/signer-core/software"
	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/sealedimport"
	"github.com/lidofinance/tee-signer/slashing-log"
	"github.com/lidofinance/tee-signer/tee-signer/state"
)

// Model-based slashing safety (PLAN-fixes 4.1, MVP): random operation
// sequences against the real runner stack (server, state hooks, mark log,
// the C core), checked against an oracle that holds every signature any
// runner returned. Operations: honest and hostile votes, blocks, clock
// steps, restarts, store faults (a create that fails, a create that lands
// but loses its reply), a clone from the same state, imports with and
// without history, cover writes, a vote whose signature never leaves (a
// crash before the reply), an import into a key that already signed (a
// vote inside its last one, signed elsewhere), and a request sent again
// for an earlier vote. The pre-history of an imported key is a vote and a
// block from before the log began, as after a lost log. The oracle refuses
// a double vote, a surround and a second block at a slot, across all
// runners, the pre-history and the imported votes.
//
// FuzzSlashingModel takes the operations as bytes; TestSlashingModel runs
// seeded sequences (SLASHMODEL_SEED picks one seed, SLASHMODEL_RUNS the
// number of seeds, SLASHMODEL_OPS the length).

// faultLog makes the next Create fail before it applies (failNext) or
// apply and then fail (dropNext), as wormfake's fault plan does over HTTP.
type faultLog struct {
	markstore.Log
	failNext, dropNext bool
}

func (l *faultLog) Create(ctx context.Context, name string, data []byte) error {
	if l.failNext {
		l.failNext = false
		return errors.New("injected: store down")
	}
	err := l.Log.Create(ctx, name, data)
	if err == nil && l.dropNext {
		l.dropNext = false
		return context.DeadlineExceeded
	}
	return err
}

// modelRunner is one runner process of the model.
type modelRunner struct {
	e   tgtEnv
	log *faultLog
	ok  bool // started; false when its start refused
}

// startRunner starts a runner on base's setup, store, clock and log
// directory, as tgtEnv.start does, but returns a start error instead of
// failing the test: a runner that refuses to start signs nothing.
func startRunner(base *tgtEnv) (*modelRunner, error) {
	r := &modelRunner{e: *base}
	e := &r.e
	ms, err := markstore.SetupOf(e.setup, e.hash)
	if err != nil {
		return nil, err
	}
	fl, err := markstore.NewFileLog(filepath.Join(e.dir, "marks"))
	if err != nil {
		return nil, err
	}
	e.fl, r.log = fl, &faultLog{Log: fl}
	m, err := markstore.New(r.log, e.setup.SignerName, dev.NewDevKeys("handover import test"), markstore.Options{Setup: ms, Clock: e.clock.Now, Log: quiet})
	if err != nil {
		return nil, err
	}
	stored, err := ListShares(e.store)
	if err != nil {
		return nil, err
	}
	mark, found, err := m.Claim(ctx, len(stored) > 0)
	if err != nil {
		return r, err
	}
	e.marks = m
	if e.upd, err = NewUpdates(UpdatesOptions{Setup: e.setup, SetupHash: e.hash, Log: m, Clock: e.clock, Logger: quiet}); err != nil {
		return r, err
	}
	cfg, err := e.upd.StartConfig(baseConfig(e.setup))
	if err != nil {
		return r, err
	}
	cfg.DeviceMark = true
	mode := state.Mode{Floor: true, FloorMargin: state.DefaultFloorMargin(cfg), MarkLog: true}
	if e.hooks, err = state.New(cfg, mode, e.clock, e.store, e.sealer, quiet); err != nil {
		return r, err
	}
	e.hooks.UseMarkLog(m, mark, found)
	if e.signer, err = core.NewSigner(cfg, 64, 0, e.hooks); err != nil {
		return r, err
	}
	e.hooks.UseClock(e.signer.EpochAt)
	e.upd.Attach(e.signer)
	e.srv = &Server{Signer: e.signer, Hooks: e.hooks, Log: quiet, Updates: e.upd, State: e.upd.SetupState,
		Platform:  &platform.Platform{Name: e.platName, Store: e.store, Sealer: e.sealer, Clock: e.clock, Attester: devDocAttester{}},
		SetupHash: e.hash, LogID: m.LogID()}
	if e.srv.ImportKey, err = sealedimport.Generate(); err != nil {
		return r, err
	}
	_, _ = e.srv.LoadListedShares(stored) // a share that does not load signs nothing
	r.ok = true
	return r, nil
}

func (r *modelRunner) close() {
	if r.ok {
		r.e.signer.Close()
		r.ok = false
	}
}

// modelKey is a validator of the model and what the oracle knows of it.
type modelKey struct {
	pk    backend.Pubkey
	sk    [32]byte
	index uint64
}

type modelVote struct {
	source, target uint64
	root           byte
	who            string
}

// oracle holds every signature returned, and the pre-history of imports.
type oracle struct {
	votes  map[backend.Pubkey][]modelVote
	blocks map[backend.Pubkey]map[uint64]byte
}

func (o *oracle) vote(pk backend.Pubkey, v modelVote) error {
	if err := o.conflict(pk, v); err != nil {
		return err
	}
	o.votes[pk] = append(o.votes[pk], v)
	return nil
}

// conflict is the slashable pair v would make with a vote held, if any.
func (o *oracle) conflict(pk backend.Pubkey, v modelVote) error {
	for _, p := range o.votes[pk] {
		switch {
		case p.target == v.target && (p.source != v.source || p.root != v.root):
			return fmt.Errorf("double vote at target %d: (%d, root %d) by %s and (%d, root %d) by %s", v.target, p.source, p.root, p.who, v.source, v.root, v.who)
		case v.source < p.source && v.target > p.target, p.source < v.source && p.target > v.target:
			return fmt.Errorf("surround: (%d, %d) by %s and (%d, %d) by %s", p.source, p.target, p.who, v.source, v.target, v.who)
		}
	}
	return nil
}

func (o *oracle) block(pk backend.Pubkey, slot uint64, root byte) error {
	if o.blocks[pk] == nil {
		o.blocks[pk] = map[uint64]byte{}
	}
	if r, ok := o.blocks[pk][slot]; ok && r != root {
		return fmt.Errorf("two blocks at slot %d (roots %d and %d)", slot, r, root)
	}
	o.blocks[pk][slot] = root
	return nil
}

// runModel runs ops (one byte each, with argument bytes) and fails t on a
// violation of the oracle, with a trace of the operations.
func runModel(t *testing.T, ops []byte) (signed int) {
	base := newTgtEnv(t, "dev", nil)
	base.signer.Close() // the model starts its own runners on the same state
	const spe = 8
	e0 := base.signer.EpochAt(base.now())
	o := &oracle{votes: map[backend.Pubkey][]modelVote{}, blocks: map[backend.Pubkey]map[uint64]byte{}}
	first, err := startRunner(base)
	if err != nil {
		t.Fatal(err)
	}
	runners := []*modelRunner{first}
	defer func() {
		for _, r := range runners {
			r.close()
		}
	}()
	active := 0
	var keys []modelKey
	// Votes each key signed, returned or not, in order; and the last one
	// per runner slot since its start.
	sent := map[backend.Pubkey][]modelVote{}
	last := map[int]map[backend.Pubkey]modelVote{}
	var trace []string
	pos := 0
	next := func() byte {
		if pos >= len(ops) {
			return 0
		}
		b := ops[pos]
		pos++
		return b
	}
	fail := func(format string, args ...any) {
		t.Helper()
		t.Fatalf("%s\ntrace:\n%s", fmt.Sprintf(format, args...), joinLines(trace))
	}
	importKey := func(history bool) {
		r := runners[active]
		if !r.ok || len(keys) >= 6 {
			return
		}
		sk, err := software.NewSecret()
		if err != nil {
			t.Fatal(err)
		}
		pk, _ := core.PubkeyOf(sk)
		k := modelKey{pk: pk, sk: sk, index: uint64(10 + len(keys))}
		// Pre-history from before the log began: a vote and a block.
		pre := backend.Watermark{HasAttestation: true, SourceEpoch: e0 - 3, TargetEpoch: e0 - 1, HasBlock: true, BlockSlot: (e0-1)*spe + 3}
		var ic *backend.Watermark
		if history {
			ic = &pre
		}
		err = r.e.importSealed(pk, sk, k.index, ic)
		trace = append(trace, fmt.Sprintf("runner %d: import key %d history=%v: %v", active, len(keys), history, err))
		if err != nil {
			return
		}
		keys = append(keys, k)
		if err := o.vote(pk, modelVote{source: pre.SourceEpoch, target: pre.TargetEpoch, root: 0xff, who: "pre-history"}); err != nil {
			t.Fatal(err)
		}
		if err := o.block(pk, pre.BlockSlot, 0xff); err != nil {
			t.Fatal(err)
		}
	}
	importKey(false)
	for pos < len(ops) {
		op := next() % 19
		r := runners[active]
		epoch := r.e.signer.EpochAt(r.e.now())
		switch op {
		case 0, 1, 2, 3, 4, 16: // votes: three honest, two hostile, one honest whose reply is lost
			if len(keys) == 0 || !r.ok {
				continue
			}
			k := keys[int(next())%len(keys)]
			s, tg, root := max(epoch, 2)-2, epoch, byte(0)
			if op >= 3 && op != 16 {
				// Hostile: any source from before the log began up to the
				// clock, any target from it up to one epoch ahead.
				lo := e0 - 6
				s = lo + uint64(next())%(epoch+1-lo)
				tg = s + uint64(next())%(epoch+2-s)
				root = next() % 3
			}
			m := vote(s, tg)
			m.BeaconBlockRoot[1] = root
			err := r.e.signMsg(k.pk, m)
			lost := op == 16
			trace = append(trace, fmt.Sprintf("runner %d epoch %d: vote key %d (%d, %d) root %d lost=%v: %v", active, epoch, k.index, s, tg, root, lost, err))
			if err == nil {
				v := modelVote{source: s, target: tg, root: root}
				sent[k.pk] = append(sent[k.pk], v)
				if last[active] == nil {
					last[active] = map[backend.Pubkey]modelVote{}
				}
				last[active][k.pk] = v
			}
			if err == nil && !lost {
				signed++
				if err := o.vote(k.pk, modelVote{source: s, target: tg, root: root, who: fmt.Sprintf("runner %d", active)}); err != nil {
					fail("%v", err)
				}
			}
		case 5: // block
			if len(keys) == 0 || !r.ok {
				continue
			}
			k := keys[int(next())%len(keys)]
			slot := max(epoch*spe, 8) - 8 + uint64(next()%24)
			root := next() % 2
			m := &backend.BeaconBlockHeader{Slot: slot, ProposerIndex: k.index, BodyRoot: backend.Root{0xb0, root}}
			err := r.e.signMsg(k.pk, m)
			trace = append(trace, fmt.Sprintf("runner %d epoch %d: block key %d slot %d root %d: %v", active, epoch, k.index, slot, root, err))
			if err == nil {
				signed++
				if err := o.block(k.pk, slot, root); err != nil {
					fail("%v", err)
				}
			}
		case 6, 7, 8: // clock step: 0 to 2 epochs and some seconds
			d := uint64(next()%3)*testEpoch + uint64(next()%testEpoch)
			base.clock.add(d)
			trace = append(trace, fmt.Sprintf("clock +%d s", d))
		case 9: // restart the active runner
			r.close()
			delete(last, active)
			nr, err := startRunner(base)
			trace = append(trace, fmt.Sprintf("runner %d: restart: %v", active, err))
			if nr != nil {
				runners[active] = nr
			}
		case 10: // the next create of the active runner fails before it applies
			r.log.failNext = true
			trace = append(trace, fmt.Sprintf("runner %d: next create fails", active))
		case 11: // the next create applies and loses its reply
			r.log.dropNext = true
			trace = append(trace, fmt.Sprintf("runner %d: next create loses its reply", active))
		case 12: // a clone from the same state
			if len(runners) >= 3 {
				continue
			}
			nr, err := startRunner(base)
			trace = append(trace, fmt.Sprintf("clone runner %d: %v", len(runners), err))
			if nr != nil {
				runners = append(runners, nr)
			}
		case 13: // switch runners
			active = int(next()) % len(runners)
			trace = append(trace, fmt.Sprintf("switch to runner %d", active))
		case 14: // import, with or without history
			importKey(next()%2 == 0)
		case 15: // the cover loop's write
			if r.ok {
				err := r.e.signer.CoverEpoch(epoch + 1)
				trace = append(trace, fmt.Sprintf("runner %d: cover %d: %v", active, epoch+1, err))
			}
		case 17: // import into a key that signed: a vote inside its last one, signed elsewhere
			lv := last[active]
			k, ok := pickKey(keys, func(pk backend.Pubkey) bool { _, ok := lv[pk]; return ok }, next())
			if !ok || !r.ok {
				continue
			}
			lv0 := lv[k.pk]
			// The first vote strictly inside that no signature returned
			// conflicts with: history that already conflicts is no import.
			var in *modelVote
			for s := lv0.source + 1; s < lv0.target && in == nil; s++ {
				for tg := s; tg < lv0.target; tg++ {
					c := modelVote{source: s, target: tg, root: 0xfe, who: "import"}
					if o.conflict(k.pk, c) == nil {
						in = &c
						break
					}
				}
			}
			if in == nil {
				continue
			}
			err := r.e.signer.Import(k.pk, backend.Watermark{HasAttestation: true, SourceEpoch: in.source, TargetEpoch: in.target})
			trace = append(trace, fmt.Sprintf("runner %d: import into key %d inside (%d, %d): (%d, %d): %v", active, k.index, lv0.source, lv0.target, in.source, in.target, err))
			if err == nil {
				r.e.hooks.NoteHistory(k.pk)
				if err := o.vote(k.pk, *in); err != nil {
					t.Fatal(err)
				}
			}
		case 18: // the request for an earlier vote, sent again
			// The runner's last vote of the key, or any earlier one.
			b := next()
			lv := last[active]
			has := func(pk backend.Pubkey) bool { _, ok := lv[pk]; return ok }
			if b&1 == 0 {
				has = func(pk backend.Pubkey) bool { return len(sent[pk]) > 0 }
			}
			k, ok := pickKey(keys, has, next())
			if !ok || !r.ok {
				continue
			}
			v := lv[k.pk]
			if b&1 == 0 {
				v = sent[k.pk][int(b>>1)%len(sent[k.pk])]
			}
			m := vote(v.source, v.target)
			m.BeaconBlockRoot[1] = v.root
			err := r.e.signMsg(k.pk, m)
			trace = append(trace, fmt.Sprintf("runner %d epoch %d: vote again key %d (%d, %d) root %d: %v", active, epoch, k.index, v.source, v.target, v.root, err))
			if err == nil {
				signed++
				if err := o.vote(k.pk, modelVote{source: v.source, target: v.target, root: v.root, who: fmt.Sprintf("runner %d, again", active)}); err != nil {
					fail("%v", err)
				}
			}
		}
	}
	if os.Getenv("SLASHMODEL_TRACE") != "" {
		t.Logf("trace:\n%s", joinLines(trace))
	}
	return signed
}

// pickKey picks, by b, one of the keys has accepts.
func pickKey(keys []modelKey, has func(backend.Pubkey) bool, b byte) (modelKey, bool) {
	var ks []modelKey
	for _, k := range keys {
		if has(k.pk) {
			ks = append(ks, k)
		}
	}
	if len(ks) == 0 {
		return modelKey{}, false
	}
	return ks[int(b)%len(ks)], true
}

func joinLines(ls []string) string {
	out := ""
	for _, l := range ls {
		out += "  " + l + "\n"
	}
	return out
}

func modelOps(seed uint64, n int) []byte {
	rng := rand.New(rand.NewPCG(seed, seed^0x5eed))
	ops := make([]byte, n)
	for i := range ops {
		ops[i] = byte(rng.Uint32())
	}
	return ops
}

func envInt(name string, def int) int {
	if v, err := strconv.Atoi(os.Getenv(name)); err == nil && v > 0 {
		return v
	}
	return def
}

func TestSlashingModel(t *testing.T) {
	runs, n := envInt("SLASHMODEL_RUNS", 25), envInt("SLASHMODEL_OPS", 160)
	seeds := make([]uint64, 0, runs)
	if s, err := strconv.ParseUint(os.Getenv("SLASHMODEL_SEED"), 10, 64); err == nil {
		seeds = append(seeds, s)
	} else {
		for i := range runs {
			seeds = append(seeds, uint64(i+1))
		}
	}
	total := 0
	for _, seed := range seeds {
		t.Run(fmt.Sprintf("seed %d", seed), func(t *testing.T) { total += runModel(t, modelOps(seed, n)) })
	}
	// Liveness smoke check: the sequences sign something at all.
	t.Logf("%d runs of %d operations: %d signatures", len(seeds), n, total)
	if total == 0 && len(seeds) > 1 && !t.Failed() {
		t.Error("no run signed anything: the model checks nothing")
	}
}

func FuzzSlashingModel(f *testing.F) {
	for seed := range uint64(4) {
		f.Add(modelOps(seed+100, 80))
	}
	f.Fuzz(func(t *testing.T, ops []byte) {
		fuzzcheck.Watch(t)
		if len(ops) > 400 {
			ops = ops[:400]
		}
		runModel(t, ops)
	})
}
