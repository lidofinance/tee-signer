//go:build !debugimport

package server

import (
	"encoding/hex"
	"testing"

	"github.com/lidofinance/tee-signer/signer-protocol"
)

// PR #20 review: a key that was on this runner comes back without history
// (its share lost, then imported again). Repeat roots live in the core's
// RAM only, so the vote it signed before must not sign again below the
// floor, also with a record for that vote that an older build left under
// rr/ (-persist-repeat-root, now removed).
func TestReimportWithoutHistoryIgnoresOldRepeatRoot(t *testing.T) {
	e := newTgtEnv(t, "dev", nil)
	sk, pk := newKey(t)
	if err := e.importSealed(pk, sk, 10, nil); err != nil {
		t.Fatal(err)
	}
	e.clock.add(4 * testEpoch) // past the floor of the first load
	epoch := e.signer.EpochAt(e.now())
	m := vote(epoch-1, epoch)
	if err := e.signMsg(pk, m); err != nil {
		t.Fatal(err)
	}
	// The vote is at the key's source floor, so it earns the key history:
	// that record write must land before the share is lost below.
	e.srv.promotions.Wait()

	// The record an older build wrote for that vote: magic, flags, roots.
	cfg := e.signer.Config()
	d, err := cfg.MessageDomain(m)
	if err != nil {
		t.Fatal(err)
	}
	obj, err := backend.HashTreeRoot(m)
	if err != nil {
		t.Fatal(err)
	}
	root := backend.SigningRoot(obj, d)
	rec := append([]byte{'S', 'C', 'R', '1', 1, 0, 0, 0}, root[:]...)
	rec = append(rec, make([]byte, 32)...)
	blob, err := e.sealer.Seal(rec, append([]byte("signer-repeat-roots-v1|"), pk[:]...))
	if err != nil {
		t.Fatal(err)
	}
	rr := "rr/" + hex.EncodeToString(pk[:])
	if err := e.store.Put(rr, blob); err != nil {
		t.Fatal(err)
	}

	// The share is lost; the runner restarts and the key is imported again
	// without history.
	e.store.mu.Lock()
	delete(e.store.m, shareKey(pk))
	e.store.mu.Unlock()
	e.restart()
	if err := e.importSealed(pk, sk, 10, nil); err != nil {
		t.Fatal(err)
	}
	if err := e.signMsg(pk, m); !backend.StatusOf(err).IsSlashing() {
		t.Fatalf("the vote signed before the share was lost, again: %v, want a slashing refusal", err)
	}
	if st := e.signer.Stats(); st.ExactRepeats != 0 {
		t.Fatalf("stats %+v", st)
	}
	if got, err := e.store.Get(rr); err != nil || string(got) != string(blob) {
		t.Fatalf("the old record changed: %v", err)
	}
}
