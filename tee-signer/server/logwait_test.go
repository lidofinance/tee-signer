//go:build !debugimport

package server

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/wire"
	"github.com/lidofinance/tee-signer/slashing-log"
)

// writeHold stops the next record write of the mark log's store, once
// armed, until release closes: a store write that hangs, without a timer.
type writeHold struct {
	armed   atomic.Bool
	started chan struct{} // closed when the held write has begun
	release chan struct{}
}

func newWriteHold() *writeHold {
	return &writeHold{started: make(chan struct{}), release: make(chan struct{})}
}

// heldLog is a mark log store whose Create waits on hold once it is armed
// (tgtEnv.hold).
type heldLog struct {
	markstore.Log
	hold *writeHold
}

func (l heldLog) Create(ctx context.Context, name string, data []byte) error {
	if l.hold.armed.CompareAndSwap(true, false) {
		close(l.hold.started)
		<-l.hold.release
	}
	return l.Log.Create(ctx, name, data)
}

// A SIGN that needs no mark log
// record, an exact repeat of the last vote, does not wait for a record
// write in flight. The core can sign it, but dispatch asks the mark log
// whether it was lost, and that takes the log's lock, which a record write
// holds across the store call (up to a minute for a refresh or a config
// update). The write here hangs until the test lets it go; the SIGN must
// come back before that.
func TestRepeatSignDoesNotWaitForALogWrite(t *testing.T) {
	e := newShareTgtEnv(t, "dev", nil)
	e.hold = newWriteHold()
	e.restart()
	sec, pk := newSecret(t), newPubkey(t)
	if _, err := e.srv.addShare(pk, &sec, 1, nil, "sealed"); err != nil {
		t.Fatal(err)
	}
	e.clock.add(8 * testEpoch)
	if err := e.attestNow(pk); err != nil {
		t.Fatal(err)
	}
	// The same vote again: the core signs it without a record.
	ep := (e.now() - testGenesis) / testEpoch
	m := &backend.AttestationData{Slot: ep * 8, Source: backend.Checkpoint{Epoch: ep - 1}, Target: backend.Checkpoint{Epoch: ep}}
	cfg := e.signer.Config()
	d, err := cfg.MessageDomain(m)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := wire.EncodeSign(backend.SignRequest{Pubkey: pk, Message: m, Domain: d})
	if err != nil {
		t.Fatal(err)
	}
	repeat := func() error {
		_, err := e.srv.dispatch(ctx, wire.Frame{Type: wire.TypeSign, Payload: payload})
		return err
	}
	if err := repeat(); err != nil {
		t.Fatalf("exact repeat with the log idle: %v", err)
	}

	set, _ := e.hooks.ShareSet()
	e.hold.armed.Store(true)
	recorded := make(chan error, 1)
	go func() { recorded <- e.hooks.RecordShareSet(ctx, set) }()
	<-e.hold.started
	signed := make(chan error, 1)
	go func() { signed <- repeat() }()
	waited := false
	select {
	case err := <-signed:
		if err != nil {
			t.Errorf("exact repeat during a record write: %v", err)
		}
	case <-time.After(5 * time.Second):
		waited = true
		t.Errorf("an exact-repeat SIGN, which needs no record, waited for a mark log write in flight; " +
			"it must not take the log's lock that a store call holds")
	}
	close(e.hold.release)
	if err := <-recorded; err != nil {
		t.Fatalf("share set record: %v", err)
	}
	if waited {
		if err := <-signed; err != nil {
			t.Errorf("exact repeat after the record write: %v", err)
		}
	}
}
