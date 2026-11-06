//go:build !debugimport

package server

import (
	"errors"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/governance/setupwire"
	"github.com/lidofinance/tee-signer/signer-protocol"
	wireadmin "github.com/lidofinance/tee-signer/signer-protocol/wire/admin"
)

// attest signs vote(source, target) through the server.
func (e *env) attest(source, target uint64) error {
	m := vote(source, target)
	cfg := e.signer.Config()
	d, err := cfg.MessageDomain(m)
	if err != nil {
		e.t.Fatal(err)
	}
	_, err = e.srv.sign(backend.SignRequest{Pubkey: e.pk, Message: m, Domain: d})
	return err
}

// Three runners of one group hold the same validator. The clock of c jumps
// ten epochs ahead, c votes there, and its clock steps back. An open update
// with a fork at the first epoch the fork rule lets a runner at the true
// time take goes into a and b; c refuses it, as the epoch it signed still
// counts. c's marks then refuse every vote up to that epoch, so c stops
// voting while a and b take the fork and keep signing. No two votes across
// the group make a slashable pair.
func TestGroupClockStepsBack(t *testing.T) {
	a, b, c := newEnv(t, u64(3600)), newEnv(t, u64(3600)), newEnv(t, u64(3600))
	for _, e := range []*env{b, c} {
		e.signer.Close()
		e.sk, e.pk = a.sk, a.pk
		e.start()
	}
	names := map[*env]string{a: "a", b: "b", c: "c"}
	o := &oracle{votes: map[backend.Pubkey][]modelVote{}, blocks: map[backend.Pubkey]map[uint64]byte{}}
	sign := func(e *env, target uint64) error {
		err := e.attest(target-1, target)
		if err == nil {
			if cerr := o.vote(e.pk, modelVote{source: target - 1, target: target, root: 0xbb, who: names[e]}); cerr != nil {
				t.Fatal(cerr)
			}
		}
		return err
	}
	step := func(epochs uint64, es ...*env) {
		for _, e := range es {
			e.clock.add(epochs * testEpoch)
		}
	}

	const lead = 8 // past the restart floor of the load
	step(lead, a, b, c)
	s := uint64(startEpoch + lead)
	for _, e := range []*env{a, b, c} {
		if err := sign(e, s); err != nil {
			t.Fatalf("%s at epoch %d: %v", names[e], s, err)
		}
	}
	step(10, c)
	if err := sign(c, s+10); err != nil {
		t.Fatalf("c at epoch %d: %v", s+10, err)
	}
	c.clock.set(func(k *fakeClock) { k.t = k.t.Add(-10 * testEpoch * time.Second) })
	if c.now() != a.now() {
		t.Fatal("c's clock is not back at the true time")
	}

	fork := s + a.setup.Safety.MaxSignEpochsAheadOfClock + 2
	u := a.body(open, 1, a.groupHash(open), a.now())
	u.Open.ForkSchedule = append(u.Open.ForkSchedule, setupwire.Fork{Epoch: fork, Version: v6})
	raw := signed(t, u, first2, nil)
	a.mustSend(raw, wireadmin.ConfigAccepted)
	b.mustSend(raw, wireadmin.ConfigAccepted)
	_, _, err := c.send(raw)
	wantCode(t, err, backend.StatusSchedule, "fork rule")
	for _, e := range []*env{a, b, c} {
		cfg := e.signer.Config()
		if got, want := cfg.ForkVersionAt(fork) == v6, e != c; got != want {
			t.Fatalf("%s holds the fork: %v, want %v", names[e], got, want)
		}
	}

	for target := s + 1; target <= fork+1; target++ {
		step(1, a, b, c)
		for _, e := range []*env{a, b} {
			if err := sign(e, target); err != nil {
				t.Fatalf("%s at epoch %d: %v", names[e], target, err)
			}
		}
		var r *backend.RefusedError
		if err := sign(c, target); !errors.As(err, &r) {
			t.Fatalf("c at epoch %d: %v, want a refusal", target, err)
		} else if target == s+1 {
			t.Logf("c refuses epoch %d: %v", target, err)
		}
	}
}
