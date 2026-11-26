package statestore

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/slashing-log"
)

// A commit never skips a name taken by an object that is not a commit,
// however long the object is locked. The copy has no write age latch, and
// a skip is safe only with one (markstore.CheckKept): a process cut off
// for the whole lock could commit at the name once the object is gone,
// beside a clone that skipped it, and a restart would drop that commit.
// The commit stops (markstore.ErrNameTaken) and writes nothing past the
// name; once the object is gone, the next commit takes the name.
func TestCommitNeverSkipsATakenName(t *testing.T) {
	const days = 30
	opt := Options{}
	for _, c := range []struct {
		name string
		lock *markstore.ObjectLock
	}{
		{name: "no retention"},
		{name: "governance", lock: &markstore.ObjectLock{Mode: "GOVERNANCE", RetainUntil: time.Now().Add(2 * days * 24 * time.Hour)}},
		{name: "compliance, one day", lock: &markstore.ObjectLock{Mode: "COMPLIANCE", Compliance: true, RetainUntil: time.Now().Add(24 * time.Hour)}},
		{name: "compliance, longer than a commit", lock: &markstore.ObjectLock{Mode: "COMPLIANCE", Compliance: true, RetainUntil: time.Now().Add(days*24*time.Hour + time.Hour)}},
		{name: "compliance, a year", lock: &markstore.ObjectLock{Mode: "COMPLIANCE", Compliance: true, RetainUntil: time.Now().Add(365 * 24 * time.Hour)}},
	} {
		t.Run(c.name, func(t *testing.T) {
			l := newMemLog()
			l.locks = map[string]markstore.ObjectLock{}
			a, _ := open(t, newLocal(t), l, keysOf("image-a"), opt)
			if err := a.Put("shares/aa", []byte("x")); err != nil {
				t.Fatal(err)
			}
			b, err := open(t, newLocal(t), l, keysOf("image-a"), opt)
			if err != nil {
				t.Fatal(err)
			}
			taken := Name(setupA, "signer-1", 2)
			l.objs[taken] = [][]byte{[]byte("not a commit")}
			if c.lock != nil {
				l.locks[taken] = *c.lock
			}
			next := Name(setupA, "signer-1", 3)
			for _, s := range []*Store{b, a} {
				if err := s.Put("shares/bb", []byte("b")); !errors.Is(err, markstore.ErrNameTaken) || len(l.objs[next]) != 0 {
					t.Fatalf("commit over the object: %v, objects past it: %d; want ErrNameTaken and none", err, len(l.objs[next]))
				}
			}
			if a.lost != nil || b.lost != nil {
				t.Fatalf("a taken name latched: %v, %v", a.lost, b.lost)
			}
			// The object goes: the first commit takes the name, the other
			// then meets it.
			delete(l.objs, taken)
			if err := a.Put("shares/cc", []byte("a")); err != nil {
				t.Fatalf("A once the name is free: %v", err)
			}
			if err := b.Put("shares/bb", []byte("b")); !errors.Is(err, ErrLost) {
				t.Fatalf("the clone after A committed: %v, want ErrLost", err)
			}
		})
	}
}

// notFoundLog answers ErrNotFound for every GET of the names in lie.
type notFoundLog struct {
	*memLog
	lie map[string]bool
}

func (l *notFoundLog) Get(ctx context.Context, e markstore.Entry) ([]byte, error) {
	if l.lie[e.Name] {
		return nil, markstore.ErrNotFound
	}
	return l.memLog.Get(ctx, e)
}

// A listed commit whose GET answers not found is not absent: the restore
// refuses to start rather than take the commit below it.
func TestListedCommitNotFoundFailsClosed(t *testing.T) {
	l := newMemLog()
	a, _ := open(t, newLocal(t), l, keysOf("image-a"), Options{})
	a.Put("shares/aa", []byte("v1"))
	a.Put("shares/aa", []byte("v2"))
	nl := &notFoundLog{memLog: l, lie: map[string]bool{Name(setupA, "signer-1", 2): true}}
	fresh := newLocal(t)
	if _, err := open(t, fresh, nl, keysOf("image-a"), Options{}); err == nil {
		v, _ := fresh.Get("shares/aa")
		t.Fatalf("restored %q over a listed commit that reads as not found; the start must fail", v)
	}
}
