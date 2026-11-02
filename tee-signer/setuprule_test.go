package main

import (
	"context"
	"strings"
	"testing"

	"github.com/lidofinance/tee-signer/platform"
)

// Off the dev platform a release build refuses to start without a setup,
// before the platform is built; dev keeps the flag path, and a debug build
// keeps it everywhere. -clock-check is not refused.
func TestCloudPlatformNeedsASetup(t *testing.T) {
	for _, p := range []string{"dev", "nitro", "azure", "gcp"} {
		for _, clockCheck := range []bool{false, true} {
			var events []string
			var opts platform.Options
			a := &startArgs{platformName: p, markSpec: "none", clockCheck: clockCheck}
			_, _, _, err := startPlatform(context.Background(), a, recordingPlatform(p, &events, &opts), quietLog)
			refused := err != nil && strings.Contains(err.Error(), "no -setup")
			if want := p != "dev" && !clockCheck && !flagPathAllowed(); refused != want {
				t.Errorf("platform %s, clock check %v, no setup: %v, refused want %v", p, clockCheck, err, want)
			}
			if refused && len(events) != 0 {
				t.Errorf("platform %s: built before the refusal: %v", p, events)
			}
		}
	}
}
