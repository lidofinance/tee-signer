//go:build !debugimport

package server

import (
	"errors"
	"os"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/governance/importorder"
	"github.com/lidofinance/tee-signer/governance/setupwire"
	"github.com/lidofinance/tee-signer/signer-core/core"
	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/sealedimport"
	"github.com/lidofinance/tee-signer/signer-protocol/wire"
	wireadmin "github.com/lidofinance/tee-signer/signer-protocol/wire/admin"
)

// batchKeys are n new whole keys, for the single-mode test setup.
func batchKeys(t *testing.T, n int) (sks [][32]byte, pks []backend.Pubkey) {
	t.Helper()
	for range n {
		sk, pk := newKey(t)
		sks, pks = append(sks, sk), append(pks, pk)
	}
	return sks, pks
}

// batchPayload is an IMPORT_SHARES_SEALED payload of the keys under one
// import order that names them all; corrupt, if set, changes request i.
func (e *tgtEnv) batchPayload(sks [][32]byte, pks []backend.Pubkey, corrupt func(i int, r *backend.SealedImportRequest)) []byte {
	e.t.Helper()
	order := e.importOrder([]byte{1, 2}, pks[0], func(b *importorder.Body) {
		b.Validators = nil
		for i, pk := range pks {
			if slices.Contains(pks[:i], pk) {
				continue
			}
			b.Validators = append(b.Validators, importorder.Entry{Pubkey: pk, CommitmentsHash: importorder.CommitmentsHash([]backend.Pubkey{pk})})
		}
	})
	id := e.sealTo()
	reqs := make([]backend.SealedImportRequest, len(pks))
	for i, pk := range pks {
		sp, err := core.PubkeyOf(sks[i])
		if err != nil {
			e.t.Fatal(err)
		}
		r := &reqs[i]
		*r = backend.SealedImportRequest{Pubkey: pk, SharePubkey: sp, Index: uint64(100 + i), T: 1, N: 1, ShareIndex: 1, Commitments: []backend.Pubkey{pk}}
		if r.Sealed, err = sealedimport.Seal(id, r, &sks[i]); err != nil {
			e.t.Fatal(err)
		}
		if corrupt != nil {
			corrupt(i, r)
		}
	}
	p, err := wireadmin.EncodeImportBatch(order, reqs)
	if err != nil {
		e.t.Fatal(err)
	}
	return p
}

// importBatch sends IMPORT_SHARES_SEALED of the keys.
func (e *tgtEnv) importBatch(sks [][32]byte, pks []backend.Pubkey) ([]backend.ValidatorKey, error) {
	e.t.Helper()
	b, err := e.srv.dispatch(ctx, wire.Frame{Type: wireadmin.TypeImportBatch, Payload: e.batchPayload(sks, pks, nil)})
	if err != nil {
		return nil, err
	}
	return wire.DecodeKeys(b)
}

// keyPair imports A without vote history and B with it, as historyPair
// does, but leaves the clock: an import right after has the same floor,
// so the core writes no log record for a new floor.
func keyPair(t *testing.T, e *tgtEnv) (a, b backend.Pubkey, floor uint64) {
	t.Helper()
	floor = e.floorOf()
	start := e.signer.EpochAt(e.now())
	ska, pka := newKey(t)
	if err := e.importSealed(pka, ska, 5, nil); err != nil {
		t.Fatal(err)
	}
	skb, pkb := newKey(t)
	if err := e.importSealed(pkb, skb, 6, &backend.Watermark{HasAttestation: true, SourceEpoch: start - 3, TargetEpoch: start - 2}); err != nil {
		t.Fatal(err)
	}
	return pka, pkb, floor
}

// failPuts makes the store fail every write of the keys, without storing
// it (nil: none).
func (e *tgtEnv) failPuts(pks ...backend.Pubkey) {
	names := map[string]bool{}
	for _, pk := range pks {
		names[shareKey(pk)] = true
	}
	e.store.mu.Lock()
	e.store.failPut = func(k string) bool { return names[k] }
	e.store.mu.Unlock()
}

// wantLoaded fails unless exactly want of the keys are loaded.
func (e *tgtEnv) wantLoaded(what string, pks []backend.Pubkey, want bool) {
	e.t.Helper()
	for _, pk := range pks {
		if _, err := e.signer.State(pk); (err == nil) != want {
			e.t.Fatalf("%s: %s loaded %t, want %t", what, pk.String()[:18], err == nil, want)
		}
	}
}

// wantBefore checks that A and B load as historyPair left them, with no
// record rewritten since puts, and none of the batch.
func (e *tgtEnv) wantBefore(what string, pka, pkb backend.Pubkey, floor uint64, puts int, batch []backend.Pubkey) {
	e.t.Helper()
	if r := e.recordOf(pka); r.History || r.SourceFloor != floor || !e.recordOf(pkb).History {
		e.t.Fatalf("%s: A history %t floor %d, B history %t: the start reset", what, r.History, r.SourceFloor, e.recordOf(pkb).History)
	}
	if n := e.store.putsOf(shareKey(pka)) + e.store.putsOf(shareKey(pkb)); n != puts {
		e.t.Fatalf("%s: %d records rewritten", what, n-puts)
	}
	e.wantLoaded(what, []backend.Pubkey{pka, pkb}, true)
	e.wantLoaded(what, batch, false)
}

// A batch writes one log record, its keys load, and a start loads the set
// after it as it is.
func TestBatchOneLogRecord(t *testing.T) {
	e := newTgtEnv(t, "dev", nil)
	pka, pkb, floor := keyPair(t, e)
	sks, pks := batchKeys(t, 5)
	n := len(e.records())
	keys, err := e.importBatch(sks, pks)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 5 || keys[0].Pubkey != pks[0] || keys[4].Index != 104 {
		t.Fatalf("answer %+v", keys)
	}
	recs := e.records()
	if len(recs) != n+1 || recs[len(recs)-1].Shares.Pending == nil {
		t.Fatalf("the batch wrote %d log records, want 1 with a pending root", len(recs)-n)
	}
	e.wantLoaded("after the batch", pks, true)
	puts := e.store.putsOf(shareKey(pka)) + e.store.putsOf(shareKey(pkb))
	// The newest record still has the pending root: the set after loads.
	e.restart()
	e.wantBefore("start after the batch", pka, pkb, floor, puts, nil)
	e.wantLoaded("start after the batch", pks, true)
	// Once a later record names the set after as current, it loads too.
	e.clock.add(4 * testEpoch)
	en := e.signer.EpochAt(e.now())
	if err := e.signMsg(pks[0], vote(en-1, en)); err != nil {
		t.Fatal(err)
	}
	e.restart()
	e.wantLoaded("second start", pks, true)
}

// A batch with one bad share is refused before anything is written: no
// log record, no store write, no key.
func TestBatchRefusedWritesNothing(t *testing.T) {
	e := newTgtEnv(t, "dev", func(s *setupwire.Setup) { s.MaxKeys = 6 })
	sk, pk := newKey(t)
	if err := e.importSealed(pk, sk, 5, nil); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(sks [][32]byte, pks []backend.Pubkey) ([][32]byte, []backend.Pubkey){
		"bad seal": func(sks [][32]byte, pks []backend.Pubkey) ([][32]byte, []backend.Pubkey) {
			sks[2][0] ^= 1 // sealed under a key that is not share_pubkey's
			return sks, pks
		},
		"loaded key": func(sks [][32]byte, pks []backend.Pubkey) ([][32]byte, []backend.Pubkey) {
			sks[1], pks[1] = sk, pk
			return sks, pks
		},
		"twice": func(sks [][32]byte, pks []backend.Pubkey) ([][32]byte, []backend.Pubkey) {
			return append(sks, sks[0]), append(pks, pks[0])
		},
		"max_keys": func(sks [][32]byte, pks []backend.Pubkey) ([][32]byte, []backend.Pubkey) {
			s, p := batchKeys(t, 3)
			return append(sks, s...), append(pks, p...)
		},
		"no order": nil,
	}
	for name, change := range cases {
		sks, pks := batchKeys(t, 3)
		n, puts := len(e.records()), len(e.store.m)
		var err error
		if change == nil {
			p, _ := wireadmin.EncodeImportBatch(nil, []backend.SealedImportRequest{{Pubkey: pks[0], Sealed: []byte("x")}})
			_, err = e.srv.dispatch(ctx, wire.Frame{Type: wireadmin.TypeImportBatch, Payload: p})
		} else {
			sks, pks = change(sks, pks)
			_, err = e.importBatch(sks, pks)
		}
		if err == nil {
			t.Fatalf("%s: the batch was taken", name)
		}
		if len(e.records()) != n || len(e.store.m) != puts || len(e.signer.Keys()) != 1 {
			t.Fatalf("%s (%v): %d log records, %d stored objects and %d keys more", name, err, len(e.records())-n, len(e.store.m)-puts, len(e.signer.Keys())-1)
		}
	}
}

// A key whose record is in the set is refused in a batch; it goes in on
// its own.
func TestBatchRefusesHeldKey(t *testing.T) {
	e := newTgtEnv(t, "dev", nil)
	e.looseLoad = true
	sk, pk := newKey(t)
	if err := e.importSealed(pk, sk, 5, nil); err != nil {
		t.Fatal(err)
	}
	// A start without a clock: the record is in the set, the key is not loaded.
	e.beforeLoad = func() { e.clock.set(func(c *fakeClock) { c.err = errors.New("no clock") }) }
	e.afterLoad = func() { e.clock.set(func(c *fakeClock) { c.err = nil }) }
	e.restart()
	e.beforeLoad, e.afterLoad = nil, nil
	if _, err := e.importBatch([][32]byte{sk}, []backend.Pubkey{pk}); backend.StatusOf(err) != backend.StatusDuplicate {
		t.Fatalf("a batch with a stored key: %v", err)
	}
	if err := e.importSealed(pk, sk, 5, nil); err != nil {
		t.Fatalf("the same key on its own: %v", err)
	}
}

// One write of a batch fails. If the read back finds it, the batch
// stands; if not, the batch fails, its keys do not load, the next log
// record vouches for the set before, and starts load that set as it is,
// with no reset, also with the record the host kept stored later.
func TestBatchWriteFails(t *testing.T) {
	t.Run("landed", func(t *testing.T) {
		e := newTgtEnv(t, "dev", nil)
		pka, pkb, floor := keyPair(t, e)
		sks, pks := batchKeys(t, 4)
		e.store.mu.Lock()
		e.store.landPut = func(k string) bool { return k == shareKey(pks[2]) }
		e.store.mu.Unlock()
		if _, err := e.importBatch(sks, pks); err != nil {
			t.Fatalf("a batch whose write landed with its reply lost: %v", err)
		}
		e.store.mu.Lock()
		e.store.landPut = nil
		e.store.mu.Unlock()
		puts := e.store.putsOf(shareKey(pka)) + e.store.putsOf(shareKey(pkb))
		e.restart()
		e.wantBefore("start", pka, pkb, floor, puts, nil)
		e.wantLoaded("start", pks, true)
	})
	t.Run("not landed", func(t *testing.T) {
		e := newTgtEnv(t, "dev", nil)
		pka, pkb, floor := keyPair(t, e)
		sks, pks := batchKeys(t, 4)
		e.failPuts(pks[2])
		if _, err := e.importBatch(sks, pks); err == nil {
			t.Fatal("a batch with a write that did not land succeeded")
		}
		e.failPuts()
		e.wantLoaded("after the failed batch", pks, false)
		e.clock.add(4 * testEpoch)
		en := e.signer.EpochAt(e.now())
		if err := e.signMsg(pkb, vote(en-1, en)); err != nil {
			t.Fatal(err)
		}
		if sh := e.records()[len(e.records())-1].Shares; sh == nil || sh.Pending != nil {
			t.Fatalf("the log record after the failed batch carries %+v, want no pending root", sh)
		}
		// The host stores the record it kept.
		e.store.mu.Lock()
		e.store.m[shareKey(pks[2])] = e.store.dropped[shareKey(pks[2])]
		e.store.mu.Unlock()
		puts := e.store.putsOf(shareKey(pka)) + e.store.putsOf(shareKey(pkb))
		for i := range 2 {
			e.restart()
			e.wantBefore("start "+strconv.Itoa(i), pka, pkb, floor, puts, pks)
		}
		// A batch without every key of the failed one is refused.
		if _, err := e.importBatch(sks[:2], pks[:2]); err == nil {
			t.Fatal("a batch without every key of the failed batch was taken")
		}
		// The same batch again lands all.
		if _, err := e.importBatch(sks, pks); err != nil {
			t.Fatal(err)
		}
		e.restart()
		e.wantBefore("start after the second batch", pka, pkb, floor, puts, nil)
		e.wantLoaded("start after the second batch", pks, true)
	})
}

// A batch's writes land none, half or all. The store fails the others,
// and the runner writes a log record at once that vouches for the set
// before. The start loads the set before as it is (or, after every write,
// the set after), none of the batch's keys otherwise, and later starts
// too; the batch sent again lands.
func TestBatchCut(t *testing.T) {
	for _, landed := range []int{0, 3, 6} {
		t.Run(strconv.Itoa(landed), func(t *testing.T) {
			e := newTgtEnv(t, "dev", nil)
			pka, pkb, floor := keyPair(t, e)
			sks, pks := batchKeys(t, 6)
			e.failPuts(pks[landed:]...)
			n := len(e.records())
			_, err := e.importBatch(sks, pks)
			e.failPuts()
			// One record before the writes, and one that drops the set
			// after if a write did not land.
			want := n + 2
			if landed == 6 {
				want = n + 1
			}
			if len(e.records()) != want || (err == nil) != (landed == 6) {
				t.Fatalf("%d log records, err %v", len(e.records())-n, err)
			}
			puts := e.store.putsOf(shareKey(pka)) + e.store.putsOf(shareKey(pkb))
			e.restart()
			e.wantBefore("start", pka, pkb, floor, puts, nil)
			e.wantLoaded("start", pks, landed == 6)
			if landed == 6 {
				return
			}
			// Later log records vouch for the set before only; the next
			// start leaves the batch's records out again.
			e.clock.add(4 * testEpoch)
			en := e.signer.EpochAt(e.now())
			if err := e.signMsg(pkb, vote(en-1, en)); err != nil {
				t.Fatal(err)
			}
			e.restart()
			e.wantBefore("second start", pka, pkb, floor, puts, pks)
			if _, err := e.importBatch(sks, pks); err != nil {
				t.Fatal(err)
			}
			e.restart()
			e.wantBefore("start after the batch again", pka, pkb, floor, puts, nil)
			e.wantLoaded("start after the batch again", pks, true)
		})
	}
}

// A key of a failed batch imported on its own leaves the batch: a later
// batch need not hold it, and starts load it.
func TestBatchCutKeyAlone(t *testing.T) {
	e := newTgtEnv(t, "dev", nil)
	sks, pks := batchKeys(t, 3)
	e.failPuts(pks[2])
	if _, err := e.importBatch(sks, pks); err == nil {
		t.Fatal("a batch with a write that did not land succeeded")
	}
	e.failPuts()
	if err := e.importSealed(pks[0], sks[0], 9, nil); err != nil {
		t.Fatal(err)
	}
	e.restart()
	e.wantLoaded("start", pks[:1], true)
	e.wantLoaded("start", pks[1:], false)
	if _, err := e.importBatch(sks[1:], pks[1:]); err != nil {
		t.Fatal(err)
	}
	e.restart()
	e.wantLoaded("start after the batch", pks, true)
}

// An empty batch writes nothing and answers no key: a sender's probe.
func TestBatchEmptyProbe(t *testing.T) {
	e := newTgtEnv(t, "dev", nil)
	p, _ := wireadmin.EncodeImportBatch(nil, nil)
	n := len(e.records())
	b, err := e.srv.dispatch(ctx, wire.Frame{Type: wireadmin.TypeImportBatch, Payload: p})
	if keys, kerr := wire.DecodeKeys(b); err != nil || kerr != nil || len(keys) != 0 || len(e.records()) != n {
		t.Fatalf("empty batch: %v %v %d keys", err, kerr, len(keys))
	}
}

// TestImportBatchTiming times IMPORT_N imports (default 1000) one share at
// a time and in batches of 512 (what fits a frame), against a share store and a
// mark log store whose calls take IMPORT_DELAY each (default 20ms). It
// runs only with IMPORT_TIMING set:
//
//	IMPORT_TIMING=1 go test -run TestImportBatchTiming -v ./server/
func TestImportBatchTiming(t *testing.T) {
	if os.Getenv("IMPORT_TIMING") == "" {
		t.Skip("set IMPORT_TIMING=1 to time imports against a slow store")
	}
	n, d := 1000, 20*time.Millisecond
	if v, err := strconv.Atoi(os.Getenv("IMPORT_N")); err == nil {
		n = v
	}
	if v, err := time.ParseDuration(os.Getenv("IMPORT_DELAY")); err == nil {
		d = v
	}
	run := func(batch bool) {
		e := newTgtEnv(t, "dev", func(s *setupwire.Setup) { s.MaxKeys = uint32(n + 8) })
		e.logDelay = d
		e.restart()
		sks, pks := batchKeys(t, n)
		var payloads []wire.Frame
		for i := 0; i < n; {
			if !batch {
				payloads = append(payloads, wire.Frame{Type: wireadmin.TypeImportSealed, Payload: e.sealedImportPayload(pks[i], sks[i], uint64(i+1), nil)})
				i++
				continue
			}
			j := min(n, i+512)
			payloads = append(payloads, wire.Frame{Type: wireadmin.TypeImportBatch, Payload: e.batchPayload(sks[i:j], pks[i:j], nil)})
			i = j
		}
		recs := len(e.records())
		e.store.mu.Lock()
		e.store.delay = d
		e.store.mu.Unlock()
		start := time.Now()
		for _, f := range payloads {
			if _, err := e.srv.dispatch(ctx, f); err != nil {
				t.Fatal(err)
			}
		}
		took := time.Since(start)
		e.store.mu.Lock()
		e.store.delay = 0
		e.store.mu.Unlock()
		t.Logf("batch %t: %d imports, store delay %v: %v, %d requests, %d log records", batch, n, d, took.Round(time.Millisecond), len(payloads), len(e.records())-recs)
	}
	run(false)
	run(true)
}

// A batch fails, and fails again when sent again, at another write: the
// store holds records of both tries. The second try takes the first's tag,
// so a start leaves both out and loads the set before as it is.
func TestBatchFailsTwice(t *testing.T) {
	e := newTgtEnv(t, "dev", nil)
	pka, pkb, floor := keyPair(t, e)
	sks, pks := batchKeys(t, 4)
	for _, fail := range []backend.Pubkey{pks[3], pks[0]} {
		e.failPuts(fail)
		if _, err := e.importBatch(sks, pks); err == nil {
			t.Fatal("a batch with a write that did not land succeeded")
		}
	}
	e.failPuts()
	puts := e.store.putsOf(shareKey(pka)) + e.store.putsOf(shareKey(pkb))
	e.restart()
	e.wantBefore("start", pka, pkb, floor, puts, pks)
	if _, err := e.importBatch(sks, pks); err != nil {
		t.Fatal(err)
	}
	e.restart()
	e.wantLoaded("start after the batch", pks, true)
}
