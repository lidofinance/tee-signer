//go:build nts

package clock

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/trusted-time/nts"
)

// TIME-BOUND-01: a quorum 214 days old gives no time. The aged bound
// overflowed to a negative value, which passed the limit, and the clock
// served the saved offset again.
func TestNTSClockLongOutageGivesNoTime(t *testing.T) {
	fs := newServers(t, nil, "a", "b", "c")
	n := newNTS(fs, &coarseClock{})
	if err := refresh(t, n); err != nil {
		t.Fatal(err)
	}
	for _, age := range []time.Duration{214 * 24 * time.Hour, 300 * 24 * time.Hour, 1 << 62} {
		ahead := int64(age)
		n.Local = func() int64 { return nts.Monotonic() + ahead }
		if _, b, err := n.Bounded(); err == nil || !strings.Contains(err.Error(), "error bound") {
			t.Fatalf("quorum %v old: bound %v, err %v; want the error bound refusal", age, b, err)
		}
	}
}

// A host that blocks NTP and runs the local counter fast moves the held
// quorum's time ahead of real time. The clock refuses once the quorum's
// samples are a minute old on that counter, so the lead stays within a
// minute whatever MaxBound is. Each step adds one second of counter time
// and runs Refresh, as Run would.
func TestNTSClockFastCounterLeadIsBounded(t *testing.T) {
	for _, mb := range []time.Duration{0, 250 * time.Millisecond, time.Second, 10 * time.Second} {
		t.Run(fmt.Sprint(mb), func(t *testing.T) {
			fs := newServers(t, nil, "a", "b", "c")
			n := newNTS(fs, &coarseClock{})
			n.Interval, n.MaxBound = NTSInterval, mb
			var ahead atomic.Int64
			n.Local = func() int64 { return nts.Monotonic() + ahead.Load() }
			if err := refresh(t, n); err != nil {
				t.Fatal(err)
			}
			n.Dial = func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("blocked by the host") }
			var lead time.Duration
			var err error
			for ahead.Load() < int64(30*time.Hour) {
				ahead.Add(int64(time.Second))
				_ = refresh(t, n)
				var got time.Time
				if got, _, err = n.Bounded(); err != nil {
					break
				}
				lead = max(lead, got.Sub(testClock()))
			}
			t.Logf("max bound %v: lead up to %v, then refused: %v", n.maxBound(), lead.Round(time.Millisecond), err)
			if err == nil {
				t.Fatal("never refused")
			}
			if lead > time.Minute {
				t.Fatalf("lead %v over a minute", lead)
			}
		})
	}
}
