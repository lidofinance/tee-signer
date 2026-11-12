package main

import (
	"encoding/json"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/trusted-time/clock"
)

// trustedClock is a clock the design says the host cannot move.
type trustedClock struct{}

func (trustedClock) Now() (time.Time, error) { return time.Now(), nil }
func (trustedClock) Source() string          { return "test-trusted" }
func (trustedClock) Trusted() bool           { return true }

// Off the dev platform a release build refuses a clock the host can set;
// dev keeps the system clock, and a debug build keeps it everywhere.
func TestCloudPlatformNeedsATrustedClock(t *testing.T) {
	for _, p := range []string{"dev", "nitro", "azure", "gcp"} {
		err := checkClock(p, clock.System{})
		refused := err != nil && strings.Contains(err.Error(), "not trusted")
		if want := p != "dev" && !untrustedClockAllowed(); refused != want {
			t.Errorf("platform %s on the system clock: %v, refused want %v", p, err, want)
		}
		if err := checkClock(p, trustedClock{}); err != nil {
			t.Errorf("platform %s on a trusted clock: %v", p, err)
		}
	}
}

// The three image commands run the NTS clock with -nts-wait,
// -nts-max-bound and -nts-max-sample-bound written into the measured
// command, at the values the runner takes when neither the flag nor its
// variable is set (90s, clock.NTSMaxBound and the max bound,
// platforms_nts.go). With the flags in the command, the host environment
// (RUNNER_NTS_WAIT, RUNNER_NTS_MAX_BOUND, RUNNER_NTS_MAX_SAMPLE_BOUND)
// cannot change them.
func TestImageCommandsFixTheNTSClock(t *testing.T) {
	quoted := regexp.MustCompile(`"([^"]*)"`)
	for _, f := range []string{
		"../platform-aws/deploy/enclave/Dockerfile",
		"../platform-azure/deploy/aci-template.json",
		"../platform-gcp/deploy/Dockerfile",
	} {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if strings.HasSuffix(f, "Dockerfile") {
			execForm(t, f, string(b))
		}
		var tok []string
		for _, m := range quoted.FindAllStringSubmatch(string(b), -1) {
			tok = append(tok, m[1])
		}
		value := func(flag string) string {
			for i, s := range tok {
				if s == flag && i+1 < len(tok) {
					return tok[i+1]
				}
			}
			return ""
		}
		if !slices.Contains(tok, "-nts-clock") {
			t.Errorf("%s: no -nts-clock", f)
		}
		for flag, want := range map[string]time.Duration{"-nts-wait": 90 * time.Second, "-nts-max-bound": 100 * time.Millisecond, "-nts-max-sample-bound": 100 * time.Millisecond} {
			got, err := time.ParseDuration(value(flag))
			if err != nil || got != want {
				t.Errorf("%s: %s %q (%v), want %v", f, flag, value(flag), err, want)
			}
		}
	}
}

// execForm fails unless the Dockerfile's ENTRYPOINT, its last instruction,
// is a JSON array once the line continuations are joined. Docker runs
// anything else through a shell.
func execForm(t *testing.T, name, dockerfile string) {
	t.Helper()
	_, ep, ok := strings.Cut(dockerfile, "\nENTRYPOINT ")
	if !ok {
		t.Fatalf("%s: no ENTRYPOINT", name)
	}
	var args []string
	if err := json.Unmarshal([]byte(strings.ReplaceAll(ep, "\\\n", "")), &args); err != nil {
		t.Errorf("%s: ENTRYPOINT is not in exec form: %v", name, err)
	}
}
