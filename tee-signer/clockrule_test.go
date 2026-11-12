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

// The three image commands run the NTS clock with -nts-wait written into
// the measured command, at the value the runner takes when neither the
// flag nor its variable is set (90s, platforms_nts.go). With the flag in
// the command, the host environment (RUNNER_NTS_WAIT) cannot change it.
// The commands name none of -clock-protocol, -nts-max-bound,
// -nts-max-sample-bound and -nts-terms-confirmed: the setup gives them
// (time_policy, time_servers), and the runner refuses them with a setup on
// a cloud platform.
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
		if got, err := time.ParseDuration(value("-nts-wait")); err != nil || got != 90*time.Second {
			t.Errorf("%s: -nts-wait %q (%v), want 90s", f, value("-nts-wait"), err)
		}
		for _, s := range tok {
			for _, flag := range []string{"-clock-protocol", "-nts-max-bound", "-nts-max-sample-bound", "-nts-terms-confirmed"} {
				if s == flag || strings.HasPrefix(s, flag+"=") {
					t.Errorf("%s: the command has %s, which the setup gives", f, s)
				}
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
