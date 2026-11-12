//go:build nts && debugimport

package main

import (
	"testing"

	"github.com/lidofinance/tee-signer/trusted-time/clock"
)

// A debug build takes RUNNER_CLOCK_PROTOCOL on every platform (the e2e
// tests set it).
func TestClockProtocolVariableInDebug(t *testing.T) {
	t.Setenv("RUNNER_CLOCK_PROTOCOL", "ntp")
	if p, err := clockProtocol(false); err != nil || p != clock.ProtocolNTP {
		t.Fatalf("RUNNER_CLOCK_PROTOCOL=ntp off the dev platform: %v %v", p, err)
	}
}
