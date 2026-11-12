//go:build nts && !debugimport

package main

import (
	"strings"
	"testing"

	"github.com/lidofinance/tee-signer/platform"
	"github.com/lidofinance/tee-signer/trusted-time/clock"
)

// A release runner off the dev platform refuses RUNNER_CLOCK_PROTOCOL: the
// host sets the environment, and the protocol comes only from the measured
// -clock-protocol flag. The flag still works, and the dev platform keeps
// the variable.
func TestClockProtocolVariableRefusedInRelease(t *testing.T) {
	defer func() { *clockProtoFlag = "" }()
	t.Setenv("RUNNER_NTS_CLOCK", "")
	base := func(platform.Options) (*platform.Platform, error) {
		return &platform.Platform{Clock: clock.System{}}, nil
	}
	for _, v := range []string{"ntp", "nts"} {
		t.Setenv("RUNNER_CLOCK_PROTOCOL", v)
		if _, err := clockProtocol(false); err == nil || !strings.Contains(err.Error(), "set the flag in the image command") {
			t.Errorf("RUNNER_CLOCK_PROTOCOL=%s: %v", v, err)
		}
		if _, err := ntsSwitch("nitro", base)(platform.Options{}); err == nil || !strings.Contains(err.Error(), "RUNNER_CLOCK_PROTOCOL") {
			t.Errorf("nitro with RUNNER_CLOCK_PROTOCOL=%s: %v", v, err)
		}
		if _, err := ntsSwitch("dev", base)(platform.Options{}); err != nil {
			t.Errorf("dev with RUNNER_CLOCK_PROTOCOL=%s: %v", v, err)
		}
	}
	*clockProtoFlag = "ntp"
	if p, err := clockProtocol(false); err != nil || p != clock.ProtocolNTP {
		t.Fatalf("flag ntp with the variable set: %v %v", p, err)
	}
	*clockProtoFlag = ""
	t.Setenv("RUNNER_CLOCK_PROTOCOL", "")
	if p, err := clockProtocol(false); err != nil || p != clock.ProtocolNTS {
		t.Fatalf("neither set: %v %v", p, err)
	}
}
