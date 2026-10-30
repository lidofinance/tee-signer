package markstore

import (
	"context"
	"errors"
	"testing"
	"time"
)

// Tests that reproduce findings of an earlier security
// review. Each asserts the behaviour the finding
// asks for, so each fails until its fix lands.

// lostReplyLog writes every Create, but the first one with lose set
// answers with a timeout, as a PUT that landed whose reply was lost.
type lostReplyLog struct {
	*memLog
	lose bool
}

func (l *lostReplyLog) Create(ctx context.Context, name string, data []byte) error {
	err := l.memLog.Create(ctx, name, data)
	if err == nil && l.lose {
		l.lose = false
		return context.DeadlineExceeded
	}
	return err
}

// Issue #5 R7: each write attempt builds a new record with a fresh time
// stamp. When a write lands but its reply is lost, the next attempt finds
// its version taken by other bytes, reads its own record as another
// instance's and latches ErrLost until a restart. The retry must accept a
// record at that version with this runner's owner, previous version and
// previous hash as its own.
func TestReview5R7OwnLostReplyReadAsClone(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_800_000_000, 0)
	l := &lostReplyLog{memLog: &memLog{objs: map[string][][]byte{}}}
	m, err := New(l, "signer-1", testKey(1), Options{Setup: testSetup("signer-1"), Clock: clockAt(&now), Log: quiet})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := m.Claim(ctx, false); err != nil {
		t.Fatal(err)
	}
	if err := m.Append(ctx, mark(10)); err != nil {
		t.Fatal(err)
	}

	l.lose = true
	if err := m.Append(ctx, mark(11)); err == nil {
		t.Fatal("the lost reply did not reach Append")
	}
	now = now.Add(time.Second) // the retry comes a moment later
	err = m.Append(ctx, mark(11))
	if err != nil {
		t.Errorf("retry after a lost reply: %v (ErrLost: %v)", err, errors.Is(err, ErrLost))
	}
	if lost := m.Lost(); lost != nil {
		t.Errorf("the runner's own record latched %v: no slashable signing until a restart", lost)
	}
}
