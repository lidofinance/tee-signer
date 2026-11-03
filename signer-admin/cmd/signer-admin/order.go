package main

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/lidofinance/tee-signer/governance/setupwire"
)

// orderActive is the locked group an order (handover, import, exit) is
// checked against: the setup of the order's cluster and chain, and the
// active locked update, if any.
type orderActive struct {
	setup  *setupwire.Setup
	locked *setupwire.Locked
	ref    ref
	// open, openV0 and target: handover orders only (loadHandoverActive).
	// openV0: the active file has no open update, so open is the setup's
	// version 0.
	open   *setupwire.Open
	openV0 bool
	target *setupwire.Published
}

// parseNotAfter reads -not-after: an RFC 3339 time, or a duration from now
// with h or d units ("2160h", "90d").
func parseNotAfter(s string, t time.Time) (uint64, error) {
	if at, err := time.Parse(time.RFC3339, s); err == nil {
		return uint64(max(at.Unix(), 0)), nil
	}
	if n, ok := strings.CutSuffix(s, "d"); ok {
		days, err := strconv.ParseUint(n, 10, 16)
		if err != nil {
			return 0, fmt.Errorf("-not-after %q: want an RFC 3339 time or a duration like 90d or 2160h", s)
		}
		return uint64(t.Add(time.Duration(days) * 24 * time.Hour).Unix()), nil
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("-not-after %q: want an RFC 3339 time or a duration like 90d or 2160h", s)
	}
	return uint64(t.Add(d).Unix()), nil
}
