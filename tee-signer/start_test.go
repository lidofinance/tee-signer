package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/lidofinance/tee-signer/governance/setupwire"
	"github.com/lidofinance/tee-signer/platform"
	"github.com/lidofinance/tee-signer/platform/setup"
	"github.com/lidofinance/tee-signer/signer-protocol/transport"
)

var quietLog = slog.New(slog.NewTextHandler(io.Discard, nil))

// sampleSetup is the sample setup of backend/setupwire for a platform.
func sampleSetup(t *testing.T, platformName string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "governance", "setupwire", "testdata", "setup-"+platformName+".bin"))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// fakeChannel hands over fixed bytes and notes the order of events.
type fakeChannel struct {
	raw      []byte
	err      error
	events   *[]string
	reported string
}

func (c *fakeChannel) Read(context.Context) ([]byte, error) {
	*c.events = append(*c.events, "setup")
	return c.raw, c.err
}
func (c *fakeChannel) String() string         { return "fake channel" }
func (c *fakeChannel) ReportExit(text string) { c.reported = text }

// withChannel runs f with ch as the only setup channel, for platformName.
func withChannel(platformName string, ch setup.Channel, f func()) {
	saved := setupChannels
	setupChannels = map[string]func() setup.Channel{platformName: func() setup.Channel { return ch }}
	defer func() { setupChannels = saved }()
	f()
}

// recordingPlatform is a platform constructor that notes when it runs and
// what options it got.
func recordingPlatform(name string, events *[]string, got *platform.Options) platformFunc {
	return func(o platform.Options) (*platform.Platform, error) {
		*events = append(*events, "platform")
		*got = o
		return &platform.Platform{Name: name}, nil
	}
}

// The start order of the setup path: the setup is read and checked first,
// then the platform is built with the options that come from it.
func TestSetupBeforePlatform(t *testing.T) {
	var events []string
	var opts platform.Options
	ch := &fakeChannel{raw: sampleSetup(t, "nitro"), events: &events}
	withChannel("nitro", ch, func() {
		a := &startArgs{platformName: "nitro", setupSrc: "platform", given: map[string]string{"setup": "platform", "record": "none"},
			params: map[string]string{"clock": "nsm"}, stateDir: "/tmp/unused"}
		s, plat, copyStore, err := startPlatform(context.Background(), a, recordingPlatform("nitro", &events, &opts), quietLog)
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(events, []string{"setup", "platform"}) {
			t.Fatalf("events %v, want the setup before the platform", events)
		}
		if plat.Name != "nitro" || copyStore != nil || opts.StateDir != "/tmp/unused" {
			t.Fatalf("platform %v, state copy %v", plat.Name, copyStore)
		}
		// The options: the setup's, plus the image's fixed one.
		want := map[string]string{"agent": "vsock:3:7101", "region": "eu-west-1", "ntp_relay": "vsock:3:7102",
			"record_creds": "record/writer-credentials.kms", "clock": "nsm"}
		for k, v := range want {
			if opts.Params[k] != v {
				t.Fatalf("option %s = %q, want %q", k, opts.Params[k], v)
			}
		}
		if !strings.Contains(opts.Params["proxy"], "signer-marks.s3.eu-west-1.amazonaws.com:443=vsock:3:8004") ||
			!strings.HasPrefix(opts.Params["kms_key_id"], "arn:aws:kms:eu-west-1:") {
			t.Fatalf("options %v", opts.Params)
		}
		if s.setup == nil || s.markSpec != "s3:bucket=signer-marks,region=eu-west-1" || s.signerID != "signer-1" ||
			s.recordSpec != "none" || s.stateSpec != "" || s.maxValidators != 1024 || len(s.caPEM) == 0 ||
			s.cfg.GenesisTime != 1_760_000_000 || s.stateCreate {
			t.Fatalf("start values %+v", s)
		}
	})
}

// A setup that is missing, does not decode, is for another platform or
// conflicts with the image's command stops the start before the platform:
// no key release ever runs for it.
func TestSetupRefusedBeforePlatform(t *testing.T) {
	nitro := sampleSetup(t, "nitro")
	cases := []struct {
		name    string
		raw     []byte
		readErr error
		given   map[string]string
		params  map[string]string
		want    string
	}{
		{name: "no setup", readErr: errors.New("the host agent has no setup"), want: "setup from fake channel: the host agent has no setup"},
		{name: "empty", raw: []byte{}, want: "setup: empty"},
		{name: "trailing byte", raw: append(slices.Clone(nitro), 0), want: "setup refused: setupwire: 1 trailing bytes"},
		{name: "cut short", raw: nitro[:100], want: "setup refused"},
		{name: "another platform's setup", raw: sampleSetup(t, "azure"), want: "platform is azure, this image is nitro"},
		{name: "the human form", raw: []byte("format = 2\n"), want: "setup refused"},
		{name: "option the setup sets", raw: nitro, params: map[string]string{"kms_key_id": "arn:other"}, want: "-platform-opt kms_key_id"},
		{name: "chain.json too", raw: nitro, given: map[string]string{"config": "/etc/signer/chain.json"}, want: "-config cannot be used with -setup"},
		{name: "mark-create", raw: nitro, given: map[string]string{"mark-create": "true"}, want: "-mark-create cannot be used with -setup"},
		{name: "DynamoDB record", raw: nitro, given: map[string]string{"record": "dynamodb:table=t,region=r"}, want: "-record dynamodb:table=t,region=r cannot be used"},
	}
	for _, c := range cases {
		var events []string
		var opts platform.Options
		ch := &fakeChannel{raw: c.raw, err: c.readErr, events: &events}
		withChannel("nitro", ch, func() {
			a := &startArgs{platformName: "nitro", setupSrc: "platform", given: c.given, params: c.params}
			_, _, _, err := startPlatform(context.Background(), a, recordingPlatform("nitro", &events, &opts), quietLog)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("%s: got %v, want %q", c.name, err, c.want)
			}
			if slices.Contains(events, "platform") {
				t.Fatalf("%s: the platform was built (events %v)", c.name, events)
			}
		})
		// The refusal goes to the host too (Nitro's EXIT).
		if !strings.HasPrefix(ch.reported, "runner: ") || !strings.Contains(ch.reported, c.want) {
			t.Fatalf("%s: reported %q", c.name, ch.reported)
		}
	}
}

// The state copy follows the setup's state store, and the start hooks run
// after the setup check and before the platform.
func TestStateCopyFromSetup(t *testing.T) {
	var events []string
	var opts platform.Options
	ch := &fakeChannel{raw: sampleSetup(t, "gcp"), events: &events}
	hooked := false
	startHooks = append(startHooks, func(st *setup.Setup, _ *slog.Logger) error {
		hooked = st != nil && !slices.Contains(events, "platform")
		return nil
	})
	defer func() { startHooks = startHooks[:len(startHooks)-1] }()
	withChannel("gcp", ch, func() {
		build := recordingPlatform("gcp", &events, &opts)
		a := &startArgs{platformName: "gcp", setupSrc: "platform",
			listens: []transport.Addr{{Network: "tcp", Address: "0.0.0.0:7100"}}}
		s, _, copyStore, err := startPlatform(context.Background(), a, build, quietLog)
		if err != nil {
			t.Fatal(err)
		}
		if copyStore == nil || opts.Durable == nil || s.stateSpec != "gcs:bucket=signer-state_gcp" || s.signerID != "signer-3" ||
			copyStore.setupHash != s.setup.SHA256 {
			t.Fatalf("state copy %+v, spec %q", copyStore, s.stateSpec)
		}
		if opts.Params["wif_provider"] == "" || opts.Params["attest_audience"] != "signer-runner-identity" {
			t.Fatalf("options %v", opts.Params)
		}
	})
	if !slices.Equal(events, []string{"setup", "platform"}) || !hooked {
		t.Fatalf("events %v, start hook before the platform %v", events, hooked)
	}
}

// The dev platform reads its setup from a file too; a cloud platform does
// not.
func TestSetupSource(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "setup.bin")
	if err := os.WriteFile(path, sampleSetup(t, "dev"), 0o600); err != nil {
		t.Fatal(err)
	}
	var events []string
	var opts platform.Options
	a := &startArgs{platformName: "dev", setupSrc: "file:" + path}
	s, _, _, err := startPlatform(context.Background(), a, recordingPlatform("dev", &events, &opts), quietLog)
	if err != nil {
		t.Fatal(err)
	}
	if s.markSpec != "file:/var/lib/signer/marks" || s.stateSpec != "file:/var/lib/signer/state-copy" || len(opts.Params) != 0 {
		t.Fatalf("dev start %+v, options %v", s, opts.Params)
	}
	for _, p := range []string{"nitro", "azure", "gcp"} {
		if _, err := setupChannelFor(p, "file:"+path); err == nil || !strings.Contains(err.Error(), "dev platform") {
			t.Fatalf("file setup on %s: %v", p, err)
		}
	}
	if _, err := setupChannelFor("dev", "env"); err == nil {
		t.Fatal("-setup env accepted")
	}
	withChannel("azure", setup.Env{Name: setup.EnvVar}, func() {
		if _, err := setupChannelFor("nitro", "platform"); err == nil {
			t.Fatal("a platform without a channel")
		}
	})
}

// The registered channels: each build's platform has one, of the kind the
// design names.
func TestRegisteredSetupChannels(t *testing.T) {
	for _, p := range builtPlatforms() {
		f, ok := setupChannels[p]
		if !ok {
			t.Fatalf("platform %s has no setup channel", p)
		}
		want := map[string]string{"nitro": "host agent vsock:3:7101", "azure": "env SIGNER_SETUP",
			"gcp": "metadata attribute signer-setup", "dev": "env SIGNER_SETUP"}[p]
		if got := f().String(); got != want {
			t.Fatalf("%s channel %q, want %q", p, got, want)
		}
	}
}

// The flag path is as before: the flags' values, no setup.
func TestFlagPath(t *testing.T) {
	var events []string
	var opts platform.Options
	a := &startArgs{platformName: "dev", params: map[string]string{"measurement": "m"}, markSpec: "file:/x", signerID: "s1",
		recordSpec: "", maxValidators: 7}
	s, _, _, err := startPlatform(context.Background(), a, recordingPlatform("dev", &events, &opts), quietLog)
	if err != nil {
		t.Fatal(err)
	}
	if s.setup != nil || s.markSpec != "file:/x" || s.maxValidators != 7 || opts.Params["measurement"] != "m" || s.caPEM != nil {
		t.Fatalf("flag path %+v", s)
	}
}

func TestCheckSetupFlags(t *testing.T) {
	ok := map[string]string{"setup": "platform", "listen": "tcp:0.0.0.0:7100", "state-dir": "/var/lib/signer",
		"restart-floor": "true", "persist-watermarks": "false", "record": "none", "nts-clock": "true",
		"platform-opt": "map[]", "log-json": "true"}
	if err := checkSetupFlags(ok); err != nil {
		t.Fatal(err)
	}
	for name := range setupRefuses {
		given := map[string]string{"setup": "platform", name: "x"}
		if err := checkSetupFlags(given); err == nil || !strings.Contains(err.Error(), "-"+name+" cannot be used with -setup") {
			t.Fatalf("-%s: %v", name, err)
		}
	}
	// The recovery flags that let a host weaken the signer are on the list.
	for _, name := range []string{"mark-create", "state-create", "record-create"} {
		if _, ok := setupRefuses[name]; !ok {
			t.Fatalf("-%s is not refused with -setup", name)
		}
	}
	if err := checkSetupFlags(map[string]string{"record": "file:/tmp/r"}); err == nil {
		t.Fatal("-record file: accepted")
	}
}

// The chain config of a setup: chain, safety and the first locked and open
// values, as chain.json held them.
func TestChainConfig(t *testing.T) {
	s, err := setupwire.DecodeSetup(sampleSetup(t, "nitro"))
	if err != nil {
		t.Fatal(err)
	}
	c, err := chainConfig(s)
	if err != nil {
		t.Fatal(err)
	}
	if c.GenesisValidatorsRoot != s.Chain.GenesisValidatorsRoot || c.GenesisForkVersion != s.Chain.GenesisForkVersion ||
		c.VoluntaryExitForkVersion != s.Chain.VoluntaryExitForkVersion || c.GenesisTime != 1_760_000_000 ||
		c.SecondsPerSlot != 6 || c.SlotsPerEpoch != 8 || c.Preset != "minimal" || c.PresetName() != "minimal" ||
		c.MaxEpochsAhead != 2 || c.CommitAhead.BlockSlots != 16 || c.CommitAhead.SourceEpochs != 2 || c.CommitAhead.TargetEpochs != 2 {
		t.Fatalf("chain and safety: %+v", c)
	}
	if len(c.Forks) != 3 || c.Forks[2].Epoch != 20 || c.Forks[2].Version != s.Open.ForkSchedule[2].Version ||
		c.GloasForkEpoch == nil || *c.GloasForkEpoch != 20 || c.GloasForkEpoch == s.Open.GloasForkEpoch {
		t.Fatalf("forks: %+v", c.Forks)
	}
	if !slices.Equal(c.ExitAllowlist, []uint64{5, 126}) || len(c.FeeRecipients) != 2 || c.GasLimitMin != 30_000_000 ||
		c.GasLimitMax != 60_000_000 || c.RegistrationMaxFutureSeconds != 3600 || c.AllowUnverifiedNonslashable ||
		len(c.BuilderRequestAuthRoots) != 2 || c.BuilderRequestAuthRoots[1] != s.Locked.AllowedBuilderRequestAuthDataRoots[1] {
		t.Fatalf("locked values: %+v", c)
	}
	if c.DeviceMark {
		t.Fatal("runner switches set from the setup")
	}
	// The floor margin follows from max_sign_epochs_ahead_of_clock.
	g, _ := setupwire.DecodeSetup(sampleSetup(t, "gcp"))
	gc, err := chainConfig(g)
	if err != nil || len(gc.Forks) != 0 || gc.GloasForkEpoch != nil || !gc.AllowUnverifiedNonslashable || gc.BuilderRequestAuthRoots != nil {
		t.Fatalf("gcp config: %+v %v", gc, err)
	}
}
