//go:build !debugimport

package server

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/lidofinance/tee-signer/slashing-log"
)

// lostCommitLog is a state copy's object store that, once armed, lands
// the next commit object and loses its reply and the read after it.
type lostCommitLog struct {
	*markstore.FileLog
	mu            sync.Mutex
	armed         bool
	lostReadsLeft int
}

func (l *lostCommitLog) Create(ctx context.Context, name string, data []byte) error {
	err := l.FileLog.Create(ctx, name, data)
	l.mu.Lock()
	defer l.mu.Unlock()
	if err != nil || !l.armed || strings.Contains(name, "/c/") {
		return err
	}
	l.armed, l.lostReadsLeft = false, 1
	return errors.New("injected: the reply was lost")
}

func (l *lostCommitLog) read() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.lostReadsLeft > 0 {
		l.lostReadsLeft--
		return errors.New("injected: the read was lost")
	}
	return nil
}

func (l *lostCommitLog) List(ctx context.Context, prefix string) ([]markstore.Entry, error) {
	if err := l.read(); err != nil {
		return nil, err
	}
	return l.FileLog.List(ctx, prefix)
}

func (l *lostCommitLog) Get(ctx context.Context, e markstore.Entry) ([]byte, error) {
	if err := l.read(); err != nil {
		return nil, err
	}
	return l.FileLog.Get(ctx, e)
}

// With a state copy, a share write whose commit lands while its reply and
// the read back after it are lost: the copy finds its commit, so the
// import stands and the mark log vouches for the set the copy holds. The
// next import goes through, and a start loads every key, B with its
// history.
func TestShareWriteStateCopyLostReply(t *testing.T) {
	e := newTgtEnv(t, "dev", nil)
	e.looseLoad = true
	fl, err := markstore.NewFileLog(filepath.Join(e.dir, "copy"))
	if err != nil {
		t.Fatal(err)
	}
	cl := &lostCommitLog{FileLog: fl}
	e.copyLog = cl
	e.restart()
	_, pkb, _ := historyPair(t, e)
	skc, pkc := newKey(t)
	cl.mu.Lock()
	cl.armed = true
	cl.mu.Unlock()
	if err := e.importSealed(pkc, skc, 7, nil); err != nil {
		t.Errorf("an import whose commit landed with its reply lost: %v", err)
	}
	skd, pkd := newKey(t)
	if err := e.importSealed(pkd, skd, 8, nil); err != nil {
		t.Errorf("the next import: %v", err)
	}
	e.restart()
	if n := len(e.signer.Keys()); n != 4 || e.loadErr != nil {
		t.Fatalf("after a restart: %d keys loaded, err %v", n, e.loadErr)
	}
	if !e.recordOf(pkb).History {
		t.Fatal("B lost its history")
	}
}
