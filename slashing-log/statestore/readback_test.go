package statestore

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/slashing-log"
)

// lostReplyLog lands the next commit object and then fails the create
// without an answer: at once (spent: false), or once the caller's time
// limit has run out (spent: true). With lostReads set, that many reads
// after it fail too (lostReadsLeft counts them down). A read under a context that has ended fails, as with
// a real store client.
type lostReplyLog struct {
	*memLog
	mu            sync.Mutex
	armed         bool
	spent         bool
	lostReads     int
	lostReadsLeft int
}

func (l *lostReplyLog) Create(ctx context.Context, name string, data []byte) error {
	err := l.memLog.Create(ctx, name, data)
	l.mu.Lock()
	hit := err == nil && l.armed && !strings.Contains(name, "/c/")
	if hit {
		l.armed = false
	}
	spent := l.spent
	l.mu.Unlock()
	if !hit {
		return err
	}
	if spent {
		<-ctx.Done()
		return ctx.Err()
	}
	return errors.New("injected: the reply was lost")
}

func (l *lostReplyLog) read(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.lostReadsLeft > 0 {
		l.lostReadsLeft--
		return errors.New("injected: the read was lost")
	}
	return nil
}

func (l *lostReplyLog) List(ctx context.Context, prefix string) ([]markstore.Entry, error) {
	if err := l.read(ctx); err != nil {
		return nil, err
	}
	return l.memLog.List(ctx, prefix)
}

func (l *lostReplyLog) Get(ctx context.Context, e markstore.Entry) ([]byte, error) {
	if err := l.read(ctx); err != nil {
		return nil, err
	}
	return l.memLog.Get(ctx, e)
}

// A commit lands but its reply is lost, and so is the first read back or
// the rest of the commit's time limit. The store reads the name back on a
// context of its own and finds its commit: the change stands, the local
// store holds it, and the next change commits too (no ErrLost).
func TestCommitLandedReplyAndReadBackLost(t *testing.T) {
	for name, l := range map[string]*lostReplyLog{
		"read back lost":   {lostReads: 1},
		"time limit spent": {spent: true},
	} {
		t.Run(name, func(t *testing.T) {
			old := putTimeout
			putTimeout = 50 * time.Millisecond
			t.Cleanup(func() { putTimeout = old })
			l.memLog = newMemLog()
			local := newLocal(t)
			s, err := open(t, local, l, keysOf("image-a"), Options{})
			if err != nil {
				t.Fatal(err)
			}
			if err := s.Put("shares/aa", []byte("a")); err != nil {
				t.Fatal(err)
			}
			l.mu.Lock()
			l.armed, l.lostReadsLeft = true, l.lostReads
			l.mu.Unlock()
			if err := s.Put("shares/bb", []byte("b")); err != nil {
				t.Errorf("a commit that landed with its reply and read back lost: %v", err)
			}
			if v, err := local.Get("shares/bb"); err != nil || !bytes.Equal(v, []byte("b")) {
				t.Errorf("the local store after the landed commit: %q %v", v, err)
			}
			if err := s.Put("shares/cc", []byte("c")); err != nil {
				t.Errorf("the next commit: %v", err)
			}
			fresh := newLocal(t)
			if _, err := open(t, fresh, l.memLog, keysOf("image-a"), Options{}); err != nil {
				t.Fatal(err)
			}
			for k, want := range map[string]string{"shares/aa": "a", "shares/bb": "b", "shares/cc": "c"} {
				if v, err := fresh.Get(k); err != nil || string(v) != want {
					t.Errorf("restored %s: %q %v", k, v, err)
				}
			}
		})
	}
}
