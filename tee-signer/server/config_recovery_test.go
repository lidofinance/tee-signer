package server

import (
	"testing"

	"github.com/lidofinance/tee-signer/governance/setupwire"
	wireadmin "github.com/lidofinance/tee-signer/signer-protocol/wire/admin"
)

// Body hands out the stored copy of an update body, or the copy the test's
// tamper makes of it: storage is untrusted, and every part of an update
// outside the hashed body is the store's choice.
func (f *flakyLog) Body(g setupwire.Group, v uint64) ([]byte, [32]byte, error) {
	raw, h, err := f.MarkLog.Body(g, v)
	if err == nil && f.tamper != nil {
		raw = f.tamper(g, v, raw)
	}
	return raw, h, err
}

// withNewSet is raw with its new-set signatures replaced by newSet; the
// body and the approvals stay, so the header hash still matches.
func withNewSet(t *testing.T, raw []byte, newSet []setupwire.Approval) []byte {
	t.Helper()
	u, err := setupwire.DecodeUpdate(raw)
	if err != nil {
		t.Fatal(err)
	}
	body, err := u.Body.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return rawUpdate(body, u.Approvals, newSet)
}

// SG-RECOVERY-01: after a restart, whether a locked update that comes into
// force is a rotation follows from its signed body (the approver set it
// brings against the one in force), never from the new-set signatures of
// the stored copy, which lie outside the body hash.
//
// A locked update that keeps the approvers, read back with forged new-set
// signatures: the old set's pending open update must stay.
func TestConfigRecoveryForgedNewSetIsNoRotation(t *testing.T) {
	e := newEnv(t, u64(3600))
	t0 := e.now()
	keep := e.body(locked, 1, e.groupHash(locked), t0)
	ev := keep.Locked.ExitAllowedValidators
	next := uint64(7)
	if len(ev) > 0 {
		next = ev[len(ev)-1] + 1
	}
	keep.Locked.ExitAllowedValidators = append(ev, next)
	e.mustSend(signed(t, keep, first2, nil), wireadmin.ConfigAccepted)
	op := e.body(open, 1, e.groupHash(open), t0+3700)
	op.Open.ForkSchedule = append(op.Open.ForkSchedule, setupwire.Fork{Epoch: 1100, Version: v6})
	ho := hashOf(t, op)
	e.mustSend(signed(t, op, first2, nil), wireadmin.ConfigAccepted)

	forged := []setupwire.Approval{{Position: 0}, {Position: 1}, {Position: 2}}
	e.tamper = func(g setupwire.Group, v uint64, raw []byte) []byte {
		if g == locked && v == 1 {
			return withNewSet(t, raw, forged)
		}
		return raw
	}
	e.restart()
	e.clock.add(3650) // the locked update is in force, the open one not yet
	st := e.srv.SetupState()
	if st.Locked.Version != 1 || st.Open.Pending != pending(1, ho, t0+3700) {
		t.Fatalf("after the restart: locked %+v, open %+v; want the open update still pending", st.Locked, st.Open)
	}
	if err := e.upd.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if ls := e.log.State(); ls.Open.Pending == nil {
		t.Fatalf("the record dropped the open update: %+v", ls.Open)
	}
	e.clock.add(100)
	if st := e.srv.SetupState(); st.Open.Version != 1 || st.Open.Hash != ho {
		t.Fatalf("the open update did not come into force: %+v", st.Open)
	}
}

// The reverse case: a real rotation read back with its new-set signatures
// stripped. The open update the old set signed must go.
func TestConfigRecoveryStrippedNewSetIsRotation(t *testing.T) {
	e := newEnv(t, u64(3600))
	t0 := e.now()
	rot := e.body(locked, 1, e.groupHash(locked), t0)
	rot.Locked.Approvers = approverSet(2, 4, 5, 6)
	e.mustSend(signed(t, rot, first2, []byte{4, 5, 6}), wireadmin.ConfigAccepted)
	op := e.body(open, 1, e.groupHash(open), t0+3700)
	op.Open.ForkSchedule = append(op.Open.ForkSchedule, setupwire.Fork{Epoch: 1100, Version: v6})
	e.mustSend(signed(t, op, first2, nil), wireadmin.ConfigAccepted)

	e.tamper = func(g setupwire.Group, v uint64, raw []byte) []byte {
		if g == locked && v == 1 {
			return withNewSet(t, raw, nil)
		}
		return raw
	}
	e.restart()
	e.clock.add(3650)
	st := e.srv.SetupState()
	if st.Locked.Version != 1 || st.Open.Pending.Version != 0 || st.ApproverSetHash != rot.Locked.Approvers.Hash() {
		t.Fatalf("after the restart: %+v; want the rotation in force and the open update gone", st)
	}
	if cfg := e.signer.Config(); cfg.ForkVersionAt(1100) == v6 {
		t.Fatal("the dropped open update stays in the core")
	}
	if err := e.upd.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if ls := e.log.State(); ls.Open.Pending != nil || ls.Open.Version != 0 {
		t.Fatalf("the record keeps the open update: %+v", ls.Open)
	}
}

// The update in force sent again with forged new-set signatures: the
// runner answers ConfigKnown, keeps the envelope it verified at arrival,
// and the forged copy decides nothing.
func TestConfigRecoveryAgainKeepsVerifiedEnvelope(t *testing.T) {
	e := newEnv(t, u64(3600))
	t0 := e.now()
	rot := e.body(locked, 1, e.groupHash(locked), t0)
	rot.Locked.Approvers = approverSet(2, 4, 5, 6)
	hr := hashOf(t, rot)
	good := signed(t, rot, first2, []byte{4, 5, 6})
	e.mustSend(good, wireadmin.ConfigAccepted)
	e.clock.add(3600)
	if st := e.srv.SetupState(); st.Locked.Version != 1 {
		t.Fatalf("rotation not in force: %+v", st.Locked)
	}
	e.mustSend(withNewSet(t, good, nil), wireadmin.ConfigKnown)
	e.upd.mu.Lock()
	cached := e.upd.bodies[bodyID{locked, updateRef{1, hr}}]
	e.upd.mu.Unlock()
	if cached == nil || len(cached.NewSet) != 3 {
		t.Fatalf("the cached envelope of the update in force was replaced: %+v", cached)
	}
}
