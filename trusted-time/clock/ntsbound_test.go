//go:build nts

package clock

import (
	"strings"
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
