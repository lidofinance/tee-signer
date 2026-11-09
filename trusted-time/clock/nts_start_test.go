//go:build nts

package clock

import (
	"context"
	"crypto/x509"
	"errors"
	"math/rand/v2"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/trusted-time/nts"
)

// seeded is a randN from a fixed seed, safe for the parallel polls.
func seeded(seed uint64) func(int64) int64 {
	var mu sync.Mutex
	r := rand.New(rand.NewPCG(seed, 1))
	return func(n int64) int64 {
		mu.Lock()
		defer mu.Unlock()
		return r.Int64N(n)
	}
}

// startLoopStep is the runner's start loop (tee-signer/platforms_nts.go):
// Refresh, and if there is no quorum and 5 s are still left of the wait,
// Refresh again 5 s later.
const startLoopStep = 5 * time.Second

// triesToday is how many NTS-KE tries a server got in the start loop
// before the random start wait and retry: one at the first Refresh, then
// at the first Refresh at least Interval (16 s) later.
func triesToday(wait time.Duration) int {
	tries, next := 0, time.Duration(0)
	for at := time.Duration(0); at <= wait; at += startLoopStep {
		if at >= next {
			tries++
			next = at + NTSInterval
		}
	}
	return tries
}

// 500 signers start at the same instant and no server answers. Each runs
// the runner's start loop on its own fake clock. Their first NTS-KE
// contacts spread over the 5 s start wait instead of all coming at once;
// no signer contacts a server twice within 12 s; and each gets at least as
// many tries per server as before, in the runner's 90 s wait and in the
// 30 s wait of the e2e tests.
func TestNTSClockStartSpreadsKeyExchange(t *testing.T) {
	const signers = 500
	ops := []string{"a", "b", "c", "d"}
	for _, wait := range []time.Duration{90 * time.Second, 30 * time.Second} {
		type pair struct {
			signer int
			addr   string
		}
		tries := map[pair][]time.Duration{}
		var mu sync.Mutex
		for i := range signers {
			var local atomic.Int64
			n := &NTS{Coarse: &coarseClock{}, Local: local.Load, randN: seeded(uint64(i)),
				sleep: func(d time.Duration) { local.Add(int64(d)) },
				Dial: func(_ context.Context, _, addr string) (net.Conn, error) {
					mu.Lock()
					k := pair{i, addr}
					tries[k] = append(tries[k], time.Duration(local.Load()))
					mu.Unlock()
					return nil, errors.New("refused")
				}}
			for _, op := range ops {
				n.Servers = append(n.Servers, NTSServer{Host: op + ".test", Operator: op, KEAddr: op + ".test:4460", Roots: x509.NewCertPool()})
			}
			for n.Refresh(context.Background()) != nil && time.Duration(local.Load())+startLoopStep <= wait {
				local.Add(int64(startLoopStep))
			}
		}
		if len(tries) != signers*len(ops) {
			t.Fatalf("wait %v: %d signer-server pairs made contact, want %d", wait, len(tries), signers*len(ops))
		}
		want := triesToday(wait)
		firsts := map[string]map[time.Duration]int{}
		fewest := 1 << 30
		for k, at := range tries {
			if firsts[k.addr] == nil {
				firsts[k.addr] = map[time.Duration]int{}
			}
			firsts[k.addr][at[0].Truncate(time.Second)]++
			if at[0] >= NTSStartDelay {
				t.Fatalf("signer %d, %s: first try at %v, after the %v start wait", k.signer, k.addr, at[0], NTSStartDelay)
			}
			for j := 1; j < len(at); j++ {
				if gap := at[j] - at[j-1]; gap < NTSInterval*3/4 {
					t.Fatalf("signer %d, %s: tries %v apart (%v), want at least %v", k.signer, k.addr, gap, at, NTSInterval*3/4)
				}
			}
			fewest = min(fewest, len(at))
		}
		if fewest < want {
			t.Fatalf("wait %v: a server got %d tries, %d before", wait, fewest, want)
		}
		for addr, m := range firsts {
			peak := 0
			for _, c := range m {
				peak = max(peak, c)
			}
			// 500 over 5 seconds: about 100 a second.
			if len(m) != 5 || peak > 150 {
				t.Fatalf("wait %v, %s: first tries per second %v, want them spread over 5 s", wait, addr, m)
			}
		}
		t.Logf("wait %v: at least %d tries per server (%d before); first tries per second at %s: %v", wait, fewest, want, ops[0], firsts[ops[0]+".test:4460"])
	}
}

// All servers up: the first Refresh, after its start wait, forms the quorum.
func TestNTSClockStartQuorumAtFirstRefresh(t *testing.T) {
	fs := newServers(t, nil, "a", "b", "c", "d")
	for i := range 5 {
		n := &NTS{Coarse: &coarseClock{}, randN: seeded(uint64(i))}
		for _, f := range fs {
			n.Servers = append(n.Servers, f.srv)
		}
		var ahead atomic.Int64
		n.Local = func() int64 { return nts.Monotonic() + ahead.Load() }
		n.sleep = func(d time.Duration) { ahead.Add(int64(d)) }
		if err := refresh(t, n); err != nil {
			t.Fatal(err)
		}
		if m := n.Status().Members; len(m) != 4 || time.Duration(ahead.Load()) >= NTSStartDelay {
			t.Fatalf("first quorum %v after a start wait of %v", m, time.Duration(ahead.Load()))
		}
	}
}

// StartDelay < 0: the first Refresh does not wait.
func TestNTSClockNoStartWait(t *testing.T) {
	waited := false
	n := &NTS{StartDelay: -1, sleep: func(time.Duration) { waited = true }}
	if err := n.startWait(context.Background()); err != nil || waited {
		t.Fatalf("waited %v, err %v", waited, err)
	}
	n.StartDelay = 0
	if err := n.startWait(context.Background()); err != nil || !waited {
		t.Fatalf("default: waited %v, err %v", waited, err)
	}
}
