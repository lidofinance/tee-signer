package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/governance/setupwire"
	"github.com/lidofinance/tee-signer/slashing-log"
)

func testApprover(id byte) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{id}, 32))
}

// timeTestSetup is the dev sample setup with approvers 1 to 3, k = 2.
func timeTestSetup(t *testing.T) (*setupwire.Setup, [32]byte) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "governance", "setupwire", "testdata", "setup-dev-single.bin"))
	if err != nil {
		t.Fatal(err)
	}
	s, err := setupwire.DecodeSetup(raw)
	if err != nil {
		t.Fatal(err)
	}
	s.Locked.Approvers = setupwire.ApproverSet{ApprovalsNeeded: 2}
	for _, id := range []byte{1, 2, 3} {
		s.Locked.Approvers.Keys = append(s.Locked.Approvers.Keys, [32]byte(testApprover(id).Public().(ed25519.PublicKey)))
	}
	h, err := s.Hash()
	if err != nil {
		t.Fatal(err)
	}
	return s, h
}

// putUpdate writes an update of group g, version v on prev, signed by the
// approvers ids (id n at position n-1), as a body copy in l, and returns
// its hash.
func putUpdate(t *testing.T, l markstore.Log, s *setupwire.Setup, hash [32]byte, g setupwire.Group, v uint64, prev [32]byte,
	change func(b *setupwire.UpdateBody), ids ...byte) [32]byte {
	t.Helper()
	fresh := *s
	b := &setupwire.UpdateBody{ClusterID: s.ClusterID, ChainHash: s.Chain.Hash(), Group: g, Version: v, PrevHash: prev}
	if g == setupwire.GroupLocked {
		lk := fresh.Locked
		b.Locked = &lk
	} else {
		op := fresh.Open
		b.Open = &op
	}
	change(b)
	if err := b.DrawSalts(rand.Reader); err != nil {
		t.Fatal(err)
	}
	u := setupwire.Update{Body: *b}
	for _, id := range ids {
		sig, err := b.Sign(testApprover(id))
		if err != nil {
			t.Fatal(err)
		}
		u.Approvals = append(u.Approvals, setupwire.Approval{Position: id - 1, Signature: sig})
	}
	raw, err := u.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Create(context.Background(), markstore.BodyName(hash, g, v, 0), raw); err != nil {
		t.Fatal(err)
	}
	h, err := b.Hash()
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// The start fallback follows each group along the signed updates of the
// config log: a loosened time_policy and new time_servers are found, and
// an update without k signatures, or on another prev_hash, is not.
func TestSignedTimeValues(t *testing.T) {
	s, hash := timeTestSetup(t)
	l, err := markstore.NewFileLog(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if v, err := signedTimeValues(ctx, l, s, hash, nil); err != nil || v != nil {
		t.Fatalf("empty log: %+v %v", v, err)
	}
	lh, _ := s.GroupHash(setupwire.GroupLocked)
	oh, _ := s.GroupHash(setupwire.GroupOpen)
	ntp := setupwire.TimePolicy{Protocol: setupwire.ClockNTP, MaxBoundMs: 200, MaxSampleBoundMs: 400}
	h1 := putUpdate(t, l, s, hash, setupwire.GroupLocked, 1, lh, func(b *setupwire.UpdateBody) { b.Locked.TimePolicy = ntp }, 1, 2)
	// One signature only: not followed.
	putUpdate(t, l, s, hash, setupwire.GroupLocked, 2, h1, func(b *setupwire.UpdateBody) {
		b.Locked.TimePolicy = setupwire.TimePolicy{Protocol: setupwire.ClockNTP, MaxBoundMs: 250, MaxSampleBoundMs: 1000}
	}, 1)
	// Another prev_hash: not followed.
	putUpdate(t, l, s, hash, setupwire.GroupLocked, 3, [32]byte{9}, func(b *setupwire.UpdateBody) {
		b.Locked.TimePolicy = setupwire.TimePolicy{Protocol: setupwire.ClockNTP, MaxBoundMs: 240, MaxSampleBoundMs: 1000}
	}, 1, 2)
	putUpdate(t, l, s, hash, setupwire.GroupOpen, 1, oh, func(b *setupwire.UpdateBody) { b.Open.TimeServers = []string{"fer"} }, 2, 3)
	v, err := signedTimeValues(ctx, l, s, hash, nil)
	if err != nil || v == nil {
		t.Fatalf("%+v %v", v, err)
	}
	if v.Protocol != "ntp" || v.MaxBound != 200*time.Millisecond || v.MaxSampleBound != 400*time.Millisecond || !slices.Equal(v.Servers, []string{"fer"}) {
		t.Fatalf("values %+v", v)
	}
	if timePolicyOf(v) != ntp {
		t.Fatalf("policy %+v", timePolicyOf(v))
	}
	if v.From != "the config log (signed locked version 1, open version 1)" {
		t.Fatalf("from %q", v.From)
	}
}
