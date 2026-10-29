package statestore

import (
	"bytes"
	"errors"
	"testing"

	"github.com/lidofinance/tee-signer/platform"
)

// delFailLocal is a memLocal whose next delete fails.
type delFailLocal struct {
	*memLocal
	fail bool
}

func (s *delFailLocal) Delete(k string) error {
	if s.fail {
		s.fail = false
		return errors.New("injected: delete failed")
	}
	return s.memLocal.Delete(k)
}

var _ platform.Deleter = (*delFailLocal)(nil)

// RBRSTA-01: a delete whose local part fails, in a change large enough to
// write a new segment (which keeps no record of deletes), must not leave a
// local key that the next start takes for one the copy never had. The
// start after it is clean, and the key is gone or still in both.
func TestRBRSTA01FailedDeleteInACompactingCommit(t *testing.T) {
	l := newMemLog()
	local := &delFailLocal{memLocal: newMemLocal()}
	s, err := open(t, local, l, keysOf("image-a"), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Put("handover/pending/01", []byte("session")); err != nil {
		t.Fatal(err)
	}
	c := &platform.Change{}
	c.Delete("handover/pending/01")
	c.Put("shares/big", bytes.Repeat([]byte{7}, maxInline+1)) // over maxInline: a new segment
	local.fail = true
	_ = s.Apply(c) // fails either before or after the commit
	s2, err := open(t, local, l, keysOf("image-a"), Options{})
	if err != nil {
		t.Fatalf("the start after a failed local delete: %v", err)
	}
	_, inLocal := local.m["handover/pending/01"]
	_, inCopy := s2.state["handover/pending/01"]
	if inLocal != inCopy {
		t.Fatalf("handover/pending/01: local %v, copy %v", inLocal, inCopy)
	}
}
