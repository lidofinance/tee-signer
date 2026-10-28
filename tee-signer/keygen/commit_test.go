package keygen

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/governance/dkgorder"
	"github.com/lidofinance/tee-signer/platform"
	"github.com/lidofinance/tee-signer/platform/dev"
	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/dkgmsg"
	"github.com/lidofinance/tee-signer/slashing-log"
	"github.com/lidofinance/tee-signer/slashing-log/statestore"
)

// faultLog fails its failAt-th Create: refused, or (lost) taken by the
// store with the reply lost.
type faultLog struct {
	markstore.Log
	creates, failAt int
	lost            bool
}

func (f *faultLog) Create(ctx context.Context, name string, data []byte) error {
	f.creates++
	if f.creates != f.failAt {
		return f.Log.Create(ctx, name, data)
	}
	if f.lost {
		if err := f.Log.Create(ctx, name, data); err != nil {
			return err
		}
		return errors.New("injected: the reply was lost")
	}
	return errors.New("injected: the store refused")
}

// failStore fails its failAt-th write and takes the others one by one, as
// a store without the state copy does (the Nitro host agent).
type failStore struct {
	*memStore
	writes, failAt int
}

func (f *failStore) Put(k string, v []byte) error {
	if f.writes++; f.writes == f.failAt {
		return errors.New("injected: write failed")
	}
	return f.memStore.Put(k, v)
}

// held counts the validators of keys with a share in st, those with a key
// record, and those with one but not the other.
func held(t *testing.T, st platform.Store, keys []backend.Pubkey) (shares, records, lone int) {
	t.Helper()
	for _, gk := range keys {
		_, es := st.Get("shares/" + hex.EncodeToString(gk[:]))
		_, er := st.Get(keyRecordKey(gk))
		for _, err := range []error{es, er} {
			if err != nil && !errors.Is(err, platform.ErrNotFound) {
				t.Fatal(err)
			}
		}
		if es == nil {
			shares++
		}
		if er == nil {
			records++
		}
		if (es == nil) != (er == nil) {
			lone++
		}
	}
	return
}

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

// With the state copy, a key generation commit lands whole or not at all,
// whichever write fails and however (refused, or the reply lost), and the
// runner loads the shares only once they are stored. The next COMMIT
// finishes the session.
func TestDKGCommitAllOrNothingWithStateCopy(t *testing.T) {
	const count = 64
	for _, lost := range []bool{false, true} {
		for k := 1; k <= 2; k++ {
			rs := threeRunners(t)
			r := rs[0]
			l, _ := markstore.NewFileLog(t.TempDir())
			fl := &faultLog{Log: l}
			sc, err := statestore.Open(context.Background(), r.store, fl, "signer-1", dev.NewDevKeys("image-a"), statestore.Options{Log: quiet})
			if err != nil {
				t.Fatal(err)
			}
			r.m.env.Store = sc
			fins, _ := finishAll(t, rs, count)
			keys := fins[0].Result.GroupKeys
			// Write 1: the shares with their key records; write 2: the
			// session's record. Each is one commit object, so a lost reply
			// is read back and the write counts as done.
			fl.creates, fl.failAt, fl.lost = 0, k, lost
			_, err = r.DKGCommit(context.Background(), confirms(fins))
			if (err == nil) != lost {
				t.Fatalf("write %d (lost %v) failed: commit says %v", k, lost, err)
			}
			// What a restart restores from the copy alone.
			restored := &memStore{m: map[string][]byte{}}
			if _, err := statestore.Open(context.Background(), restored, l, "signer-1", dev.NewDevKeys("image-a"), statestore.Options{Log: quiet}); err != nil {
				t.Fatal(err)
			}
			shares, records, lone := held(t, restored, keys)
			stored := !(k == 1 && !lost)
			if lone != 0 || (stored && shares != count) || (!stored && shares != 0) {
				t.Fatalf("write %d (lost %v): the copy holds %d shares and %d key records of %d", k, lost, shares, records, count)
			}
			if loaded := len(r.keys); (stored && loaded != count) || (!stored && loaded != 0) {
				t.Fatalf("write %d (lost %v): %d shares loaded, %d stored", k, lost, loaded, shares)
			}
			fl.failAt = 0
			if got, err := r.DKGCommit(context.Background(), confirms(fins)); err != nil || len(got) != count {
				t.Fatalf("write %d (lost %v): commit again: %v, %d keys", k, lost, err, len(got))
			}
			p, err := r.m.getPending(fins[0].Result.Session)
			if err != nil || p.State != "committed" || len(r.keys) != count {
				t.Fatalf("write %d (lost %v): after the second commit: %v, %+v, %d loaded", k, lost, err, p, len(r.keys))
			}
		}
	}
}

// Without the state copy the store takes the writes one by one: whichever
// fails, no share is left without its key record (the records go first),
// nothing is loaded before every share is stored, and the next COMMIT
// finishes the session.
func TestDKGCommitOrderWithoutBatch(t *testing.T) {
	const count = 4
	steps := 2*count + 1 // key records, shares, the session's record
	for k := 1; k <= steps; k++ {
		rs := threeRunners(t)
		r := rs[0]
		fs := &failStore{memStore: r.store}
		r.m.env.Store = fs
		fins, _ := finishAll(t, rs, count)
		keys := fins[0].Result.GroupKeys
		fs.writes, fs.failAt = 0, k
		if _, err := r.DKGCommit(context.Background(), confirms(fins)); err == nil {
			t.Fatalf("write %d failed and the commit reported nothing", k)
		}
		shares, records, _ := held(t, r.store, keys)
		if shares > records || (k <= count && shares != 0) {
			t.Fatalf("write %d: %d shares and %d key records stored", k, shares, records)
		}
		if loaded := len(r.keys); (k <= 2*count && loaded != 0) || (k > 2*count && loaded != count) {
			t.Fatalf("write %d: %d shares loaded, %d stored", k, loaded, shares)
		}
		fs.failAt = 0
		if got, err := r.DKGCommit(context.Background(), confirms(fins)); err != nil || len(got) != count {
			t.Fatalf("write %d: commit again: %v, %d keys", k, err, len(got))
		}
		if shares, records, _ := held(t, r.store, keys); shares != count || records != count {
			t.Fatalf("write %d: after the second commit %d shares, %d records", k, shares, records)
		}
	}
}

// A committed session's record shrinks to its keys and still answers a
// repeated COMMIT. After FinishedKeep the next commit deletes it; a
// session that finished but never committed keeps its record (its shares).
func TestDKGFinishedRecords(t *testing.T) {
	rs := threeRunners(t)
	ctx := context.Background()
	full, err := rs[0].store.Get(pendingKey([32]byte{}))
	if !errors.Is(err, platform.ErrNotFound) || full != nil {
		t.Fatal("unexpected record")
	}
	first, _ := finishAll(t, rs, 8)
	before, _ := rs[0].store.Get(pendingKey(first[0].Result.Session))
	for _, r := range rs {
		if _, err := r.DKGCommit(ctx, confirms(first)); err != nil {
			t.Fatal(err)
		}
	}
	after, _ := rs[0].store.Get(pendingKey(first[0].Result.Session))
	p, err := rs[0].m.getPending(first[0].Result.Session)
	if err != nil || p.State != "committed" || len(p.Keys) != 8 || len(p.Result) != 0 || len(p.SignKeys) != 0 || len(after) >= len(before) {
		t.Fatalf("committed record: %v, %d keys, %d -> %d bytes", err, len(p.Keys), len(before), len(after))
	}
	if keys, err := rs[0].DKGCommit(ctx, confirms(first)); err != nil || len(keys) != 8 {
		t.Fatalf("repeated commit: %v, %d keys", err, len(keys))
	}

	open, _ := finishAll(t, rs, 1) // finished, never committed
	for _, r := range rs {
		r.mu.Lock()
		r.now = r.now.Add(FinishedKeep + time.Hour)
		r.mu.Unlock()
	}
	third, _ := finishAll(t, rs, 1)
	if _, err := rs[0].DKGCommit(ctx, confirms(third)); err != nil {
		t.Fatal(err)
	}
	if _, err := rs[0].store.Get(pendingKey(first[0].Result.Session)); !errors.Is(err, platform.ErrNotFound) {
		t.Fatalf("expired committed record: %v", err)
	}
	for _, f := range [][32]byte{open[0].Result.Session, third[0].Result.Session} {
		if _, err := rs[0].m.getPending(f); err != nil {
			t.Fatalf("record %x: %v", f[:4], err)
		}
	}
	_, err = rs[0].DKGCommit(ctx, confirms(first))
	wantRefused(t, err, backend.StatusNotReady, "no finished session")
}

// Under a DKG order with the state copy on: whichever write of COMMIT
// fails, and however, a restart from the copy alone finds every share with
// its key record (with the order's hash and path) or none, and the next
// COMMIT, sent to the restarted runner, finishes the session. Both paths.
func TestDKGOrderCommitStateCopyRestart(t *testing.T) {
	const count = 16
	ctx := context.Background()
	for _, path := range []dkgorder.Path{dkgorder.PathDirk, dkgorder.PathCharon} {
		for _, lost := range []bool{false, true} {
			for k := 1; k <= 2; k++ {
				t.Run(fmt.Sprintf("%s/write%d/lost=%v", path, k, lost), func(t *testing.T) {
					ns := orderCluster(t)
					n := ns[0]
					l, _ := markstore.NewFileLog(t.TempDir())
					fl := &faultLog{Log: l}
					opt := statestore.Options{SetupHash: n.hash, Log: quiet}
					sc, err := statestore.Open(ctx, n.store, fl, "signer-a", dev.NewDevKeys("image-a"), opt)
					if err != nil {
						t.Fatal(err)
					}
					// Before the order arrives: its record, the session's
					// record and the commit all go through the copy.
					n.orders.env.Env.Store = sc
					raw, h := signOrder(t, orderBody(ns, path, "state-copy"), 1, 2)
					pushAll(t, ns, raw)
					fins := finishIn(t, ns, h, count)
					keys := fins[0].Result.GroupKeys
					// Write 1: the shares with their key records; write 2:
					// the session's record.
					fl.creates, fl.failAt, fl.lost = 0, k, lost
					if _, err := (inOrder{n, h}).DKGCommit(ctx, confirms(fins)); (err == nil) != lost {
						t.Fatalf("commit says %v", err)
					}

					// A restart on an empty local store, from the copy alone.
					restored := &memStore{m: map[string][]byte{}}
					sc2, err := statestore.Open(ctx, restored, l, "signer-a", dev.NewDevKeys("image-a"), opt)
					if err != nil {
						t.Fatal(err)
					}
					shares, records, lone := held(t, restored, keys)
					stored := !(k == 1 && !lost)
					if lone != 0 || (stored && shares != count) || (!stored && shares != 0) {
						t.Fatalf("the copy holds %d shares and %d key records of %d", shares, records, count)
					}
					again := newOrderNode(t, n.setup, "dev", restored)
					if again.opKey != n.opKey {
						t.Fatal("the restart has another operator key")
					}
					again.orders.env.Env.Store = sc2
					loadStoredShares(t, again.testRunner, restored)
					if got, err := (inOrder{again, h}).DKGCommit(ctx, confirms(fins)); err != nil || len(got) != count {
						t.Fatalf("commit after the restart: %v, %d keys", err, len(got))
					}
					if shares, records, lone := held(t, restored, keys); shares != count || records != count || lone != 0 {
						t.Fatalf("after the restart and commit: %d shares, %d records", shares, records)
					}
					for _, gk := range keys {
						rec, err := LoadKeyRecord(dev.NewDevSealer(), restored, gk)
						if err != nil || !bytes.Equal(rec.Order, h[:]) || rec.Path != path.String() {
							t.Fatalf("key record: %v %+v", err, rec)
						}
					}
					m, err := again.orders.Manager(h, false)
					if err != nil {
						t.Fatal(err)
					}
					if p, err := m.getPending(fins[0].Result.Session); err != nil || p.State != "committed" {
						t.Fatalf("session record: %v %+v", err, p)
					}
				})
			}
		}
	}
}

// finishIn runs a session of count keys under order h up to FINISH.
func finishIn(t *testing.T, ns []*orderNode, h [32]byte, count int) []*dkgmsg.Finished {
	t.Helper()
	ctx := context.Background()
	q := &dkgmsg.HelloRequest{Nonce: bytes.Repeat([]byte{9}, 32), Count: uint16(count)}
	hs, ds := make([][]byte, len(ns)), make([][]byte, len(ns))
	fins := make([]*dkgmsg.Finished, len(ns))
	var err error
	for i, n := range ns {
		if hs[i], err = (inOrder{n, h}).DKGHello(ctx, q); err != nil {
			t.Fatalf("runner %d hello: %v", i+1, err)
		}
	}
	for i, n := range ns {
		if ds[i], err = (inOrder{n, h}).DKGDeal(ctx, hs); err != nil {
			t.Fatalf("runner %d deal: %v", i+1, err)
		}
	}
	for i, n := range ns {
		if fins[i], err = (inOrder{n, h}).DKGFinish(ctx, ds); err != nil {
			t.Fatalf("runner %d finish: %v", i+1, err)
		}
	}
	return fins
}

// loadStoredShares loads the shares stored in st into r, as a runner does
// at start (testRunner.addShares sealed them).
func loadStoredShares(t *testing.T, r *testRunner, st platform.Store) {
	t.Helper()
	names, err := st.List("shares/")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range names {
		var pk backend.Pubkey
		b, err := hex.DecodeString(strings.TrimPrefix(name, "shares/"))
		if err != nil || len(b) != len(pk) {
			t.Fatalf("share %s", name)
		}
		copy(pk[:], b)
		blob, err := st.Get(name)
		if err != nil {
			t.Fatal(err)
		}
		plain, err := dev.NewDevSealer().Unseal(blob, append([]byte("test share|"), pk[:]...))
		if err != nil {
			t.Fatal(err)
		}
		var sec [32]byte
		copy(sec[:], plain)
		clear(plain)
		if _, err := r.addShare(pk, &sec); err != nil {
			t.Fatal(err)
		}
	}
}
