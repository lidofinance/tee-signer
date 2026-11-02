package server

import (
	"fmt"
	"math/rand/v2"
	"testing"

	"github.com/lidofinance/tee-signer/governance/setupwire"
	"github.com/lidofinance/tee-signer/signer-protocol"
)

// Governance state machine across restarts (test plan 4.5, first part): a
// differential test. Two runners with one setup get the same random
// sequence of config updates (locked updates that keep the approvers,
// rotations between two sets, open updates, supersedes) and the same clock
// steps. Runner B also restarts at random, each time over a store that
// hands out tampered body copies (new-set signatures forged or stripped);
// runner A restarts only over an honest store. Every outcome and every
// setup state must be the same on both: neither a restart nor what the
// untrusted store chooses outside the hashed bodies may change a
// governance decision.
func TestGovernanceRestartInvariance(t *testing.T) {
	for seed := uint64(1); seed <= 16; seed++ {
		t.Run(fmt.Sprintf("seed%d", seed), func(t *testing.T) { governanceRun(t, seed, 60) })
	}
}

func governanceRun(t *testing.T, seed uint64, steps int) {
	rng := rand.New(rand.NewPCG(seed, 0x5eed))
	a, b := newEnv(t, u64(3600)), newEnv(t, u64(3600))
	b.clock.set(func(c *fakeClock) { c.t = a.clock.t })
	setA, setB := approverSet(2, 1, 2, 3), approverSet(2, 4, 5, 6)
	ids := map[[32]byte][]byte{setA.Hash(): {1, 2, 3}, setB.Hash(): {4, 5, 6}}
	sets := map[[32]byte]setupwire.ApproverSet{setA.Hash(): setA, setB.Hash(): setB}
	tampers := []func(raw []byte) []byte{
		func(raw []byte) []byte { return withNewSet(t, raw, nil) },
		func(raw []byte) []byte {
			return withNewSet(t, raw, []setupwire.Approval{{Position: 0}, {Position: 1}, {Position: 2}})
		},
	}
	extra := uint64(1)
	var log []string
	fail := func(format string, args ...any) {
		t.Helper()
		t.Fatalf("seed %d after %v: "+format, append([]any{seed, log}, args...)...)
	}
	compare := func(what string) {
		t.Helper()
		sa, sb := a.srv.SetupState(), b.srv.SetupState()
		sa.KeyOrigin, sb.KeyOrigin = backend.KeyOrigin{}, backend.KeyOrigin{}
		if sa != sb {
			fail("%s: state A %+v, B %+v", what, sa, sb)
		}
		ca, cb := a.signer.Config(), b.signer.Config()
		for _, ep := range []uint64{1100, 1300, 1500} {
			if va, vb := ca.ForkVersionAt(ep), cb.ForkVersionAt(ep); va != vb {
				fail("%s: fork version at %d: A %x, B %x", what, ep, va, vb)
			}
		}
	}
	accepted, refused, restarts := 0, 0, 0
	send := func(raw []byte) {
		t.Helper()
		oa, _, ea := a.send(raw)
		ob, _, eb := b.send(raw)
		if oa != ob || (ea == nil) != (eb == nil) {
			fail("outcomes differ: A %d %v, B %d %v", oa, ea, ob, eb)
		}
		if ea == nil {
			accepted++
		} else {
			refused++
		}
	}
	for i := 0; i < steps; i++ {
		st := a.srv.SetupState()
		cur := st.ApproverSetHash
		signers := ids[cur]
		if signers == nil {
			fail("unknown approver set %x", cur[:4])
		}
		approvals := []by{{0, signers[0]}, {1, signers[1]}}
		nextVersion := func(g backend.ConfigGroup) uint64 { return max(g.Version, g.Pending.Version) + 1 }
		// Time steps are frequent, so that updates come into force between
		// supersedes and restarts.
		op := []int{0, 1, 2, 2, 3, 3, 3, 4, 5, 6}[rng.IntN(10)]
		switch op {
		case 0, 1: // a locked update: keep the set, or rotate to the other one
			body := a.body(locked, nextVersion(st.Locked), st.Locked.Hash, a.now())
			body.Locked.Approvers = sets[cur]
			var newSet []byte
			if op == 1 {
				for h, s := range sets {
					if h != cur {
						body.Locked.Approvers, newSet = s, ids[h]
					}
				}
				log = append(log, "rotate")
			} else {
				body.Locked.ExitAllowedValidators = append(body.Locked.ExitAllowedValidators, 1_000_000+extra)
				extra++
				log = append(log, "locked")
			}
			body.Salts = testSalts(body)
			send(signed(t, body, approvals, newSet))
		case 2: // an open update with a fork far ahead
			body := a.body(open, nextVersion(st.Open), st.Open.Hash, a.now()+uint64(rng.IntN(7200)))
			body.Open.ForkSchedule = append(body.Open.ForkSchedule, setupwire.Fork{Epoch: 1100 + uint64(rng.IntN(400)), Version: v6})
			body.Salts = testSalts(body)
			send(signed(t, body, approvals, nil))
			log = append(log, "open")
		case 3: // time
			s := uint64(rng.IntN(2500))
			a.clock.add(s)
			b.clock.add(s)
			log = append(log, fmt.Sprintf("+%ds", s))
		case 4:
			if ea, eb := a.upd.Sync(ctx), b.upd.Sync(ctx); (ea == nil) != (eb == nil) {
				fail("sync: A %v, B %v", ea, eb)
			}
			log = append(log, "sync")
		case 5: // B restarts over a store that tampers with every locked copy
			tm := tampers[rng.IntN(len(tampers))]
			b.tamper = func(g setupwire.Group, v uint64, raw []byte) []byte {
				if g == locked {
					return tm(raw)
				}
				return raw
			}
			b.restart()
			restarts++
			log = append(log, "restartB")
		case 6:
			a.restart()
			log = append(log, "restartA")
		}
		compare(log[len(log)-1])
	}
	st := a.srv.SetupState()
	t.Logf("seed %d: %d updates taken, %d refused, %d tampered restarts; locked %d, open %d", seed, accepted, refused, restarts, st.Locked.Version, st.Open.Version)
}
