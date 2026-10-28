package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/governance/setupwire"
	"github.com/lidofinance/tee-signer/platform"
	"github.com/lidofinance/tee-signer/platform/dev"
	"github.com/lidofinance/tee-signer/platform/setup"
	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/transport"
	"github.com/lidofinance/tee-signer/slashing-log"
)

// The runner takes the key rule its platform read. On a test network every
// rule passes, and a platform that read nothing gives unread and a zero
// hash, as before. On mainnet a rule that is not locked or not read stops
// the start; a locked rule and a platform without a lock (GCP) pass. The
// flag path reads nothing.
func TestKeyRuleAtStart(t *testing.T) {
	locked := &platform.KeyRule{Hash: [32]byte{0x77}, Lock: backend.KeyLockLocked}
	open := &platform.KeyRule{Hash: [32]byte{0x78}, Lock: backend.KeyLockNotLocked, Why: "release_policy.immutable is false"}
	unread := &platform.KeyRule{Lock: backend.KeyLockUnread, Why: "AccessDenied"}
	none := &platform.KeyRule{Lock: backend.KeyLockNone, Why: "gcp"}
	accepted := platform.KeyRule{Lock: backend.KeyLockNone, Why: "gcp; the setup accepts a key rule without a lock (sealing_key_release.no_lock_accepted)"}
	devNone := &platform.KeyRule{Lock: backend.KeyLockNone, Why: "dev", NoService: true}
	for _, c := range []struct {
		name    string
		mainnet bool
		accept  bool
		rule    *platform.KeyRule
		want    platform.KeyRule
		refuse  bool
	}{
		{"testnet locked", false, false, locked, *locked, false},
		{"testnet not locked", false, false, open, *open, false},
		{"testnet unread", false, false, unread, *unread, false},
		{"testnet nothing read", false, false, nil, platform.KeyRule{Lock: backend.KeyLockUnread, Why: "the platform read no key rule"}, false},
		{"testnet gcp", false, false, none, *none, false},
		{"mainnet locked", true, false, locked, *locked, false},
		{"mainnet gcp", true, false, none, platform.KeyRule{}, true},
		{"mainnet gcp, accepted", true, true, none, accepted, false},
		{"mainnet dev", true, false, devNone, platform.KeyRule{}, true},
		{"testnet dev", false, false, devNone, *devNone, false},
		{"mainnet not locked", true, false, open, platform.KeyRule{}, true},
		{"mainnet not locked, no_lock_accepted", true, true, open, platform.KeyRule{}, true},
		{"mainnet unread", true, false, unread, platform.KeyRule{}, true},
		{"mainnet nothing read", true, false, nil, platform.KeyRule{}, true},
	} {
		got, err := keyRule(true, c.mainnet, c.accept, &platform.Platform{KeyRule: c.rule}, quietLog)
		if c.refuse {
			if err == nil || !strings.HasPrefix(err.Error(), "mainnet: ") {
				t.Errorf("%s: %+v %v, want a refusal", c.name, got, err)
			}
			continue
		}
		if err != nil || got != c.want {
			t.Errorf("%s: %+v %v, want %+v", c.name, got, err, c.want)
		}
	}
	if got, err := keyRule(false, true, false, &platform.Platform{KeyRule: open}, quietLog); err != nil || got != (platform.KeyRule{}) {
		t.Fatalf("flag path: %+v %v", got, err)
	}
}

// A setup on mainnet's genesis fork version sets platform.Options.Mainnet,
// so the platform checks the lock before its key release, and the
// platform's refusal stops the start; a test network's setup does not set
// it. The dev platform, which has no lock, passes on mainnet.
func TestStartMainnetKeyRule(t *testing.T) {
	st, err := setupwire.DecodeSetup(sampleSetup(t, "dev"))
	if err != nil {
		t.Fatal(err)
	}
	if setupwire.IsMainnet(st.Chain.GenesisForkVersion) {
		t.Fatal("the sample setup is on mainnet")
	}
	write := func(s *setupwire.Setup) string {
		b, err := s.Encode()
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(t.TempDir(), "setup.bin")
		if err := os.WriteFile(path, b, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	testnet := write(st)
	st.Chain.GenesisForkVersion = setupwire.MainnetForkVersion
	mainnet := write(st)

	for _, c := range []struct {
		path string
		want bool
	}{{testnet, false}, {mainnet, true}} {
		var events []string
		var opts platform.Options
		s, _, _, err := startPlatform(context.Background(), &startArgs{platformName: "dev", setupSrc: "file:" + c.path},
			recordingPlatform("dev", &events, &opts), quietLog)
		if err != nil || opts.Mainnet != c.want || s.mainnet != c.want {
			t.Fatalf("%s: options mainnet %v, start %+v, %v", c.path, opts.Mainnet, s, err)
		}
	}

	// The platform refuses a key rule that is not locked: the start stops
	// with its error, before the platform exists.
	refusing := func(o platform.Options) (*platform.Platform, error) {
		_, err := o.ReadKeyRule(context.Background(), func(context.Context) (platform.KeyRule, error) {
			return platform.KeyRule{Lock: backend.KeyLockNotLocked, Why: "release_policy.immutable is false"}, nil
		})
		if err != nil {
			return nil, err
		}
		return &platform.Platform{Name: "dev"}, nil
	}
	if _, _, _, err := startPlatform(context.Background(), &startArgs{platformName: "dev", setupSrc: "file:" + mainnet}, refusing, quietLog); err == nil ||
		!strings.Contains(err.Error(), "mainnet: the rule of the key that releases the sealing key is not locked") {
		t.Fatalf("mainnet, key rule not locked: %v", err)
	}
	if _, _, _, err := startPlatform(context.Background(), &startArgs{platformName: "dev", setupSrc: "file:" + testnet}, refusing, quietLog); err != nil {
		t.Fatalf("testnet, key rule not locked: %v", err)
	}

	// The dev platform itself has no real attestation: it does not start
	// on mainnet, and on other chains HEALTH's key_lock_why says why.
	if p, err := dev.New(platform.Options{StateDir: t.TempDir(), SetupHash: [32]byte{1}, Mainnet: true}); err == nil ||
		!strings.HasPrefix(err.Error(), "mainnet: the dev platform has no real attestation") {
		t.Fatalf("dev on mainnet: %+v %v", p, err)
	}
	p, err := dev.New(platform.Options{StateDir: t.TempDir(), SetupHash: [32]byte{1}})
	if err != nil || p.KeyRule == nil || p.KeyRule.Lock != backend.KeyLockNone || !strings.Contains(p.KeyRule.Why, "refused on mainnet") {
		t.Fatalf("dev on a test network: %+v %v", p, err)
	}
}

// fakeLog is a server.UpdateLog with a fixed state and body.
type fakeLog struct {
	state markstore.ConfigState
	body  []byte // the locked update the state names, or nil
}

func (f *fakeLog) State() markstore.ConfigState { return f.state.Clone() }

func (f *fakeLog) Body(g setupwire.Group, v uint64) ([]byte, [32]byte, error) {
	if f.body == nil || g != setupwire.GroupLocked {
		return nil, [32]byte{}, markstore.ErrBodyMissing
	}
	u, err := setupwire.DecodeUpdate(f.body)
	if err != nil || u.Body.Version != v {
		return nil, [32]byte{}, errors.New("no such body")
	}
	h, err := u.Body.Hash()
	return f.body, h, err
}

func (f *fakeLog) PutBody(context.Context, []byte) (setupwire.Group, uint64, [32]byte, error) {
	return 0, 0, [32]byte{}, errors.New("read only")
}

func (f *fakeLog) SetState(context.Context, markstore.ConfigState) error {
	return errors.New("read only")
}

// fixedClock is a trusted clock that stands still.
type fixedClock struct{ t time.Time }

func (c fixedClock) Now() (time.Time, error) { return c.t, nil }
func (c fixedClock) Source() string          { return "fixed" }
func (c fixedClock) Trusted() bool           { return true }

func testdata(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "governance", "setupwire", "testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// IDENTITY reports the config state in force: version 0 under the
// setup's group hashes and the setup's approvers on a first start; after a
// rotation the active update's version, hash and approver set; pending
// updates (not yet due) and the order as the record carries them.
func TestSetupState(t *testing.T) {
	st, err := setup.Load(testdata(t, "setup-nitro.bin"), "nitro")
	if err != nil {
		t.Fatal(err)
	}
	ms, err := markstore.SetupOf(st.Wire, st.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	log := &fakeLog{state: ms.First}
	updates, err := newConfigUpdates(st, log, fixedClock{time.Unix(1_790_000_000, 0)}, "nitro", nil)
	if err != nil {
		t.Fatal(err)
	}
	got := updates.SetupState()
	want := backend.SetupState{SetupHash: st.SHA256, Locked: backend.ConfigGroup{Hash: ms.First.Locked.Hash},
		Open: backend.ConfigGroup{Hash: ms.First.Open.Hash}, ApproverSetHash: st.Wire.Locked.Approvers.Hash()}
	if got != want {
		t.Fatalf("first start: %+v, want %+v", got, want)
	}

	raw := testdata(t, "update-rotation.bin")
	u, err := setupwire.DecodeUpdate(raw)
	if err != nil {
		t.Fatal(err)
	}
	h, _ := u.Body.Hash()
	// A new log state, as after a restart: the runner reads it afresh.
	state := func() backend.SetupState {
		updates, err := newConfigUpdates(st, log, fixedClock{time.Unix(1_790_000_000, 0)}, "nitro", nil)
		if err != nil {
			t.Fatal(err)
		}
		return updates.SetupState()
	}
	log.body = raw
	log.state.Locked = markstore.GroupState{Version: u.Body.Version, Hash: h}
	log.state.Open.Pending = &markstore.Pending{Version: 1, Hash: [32]byte{9}, EffectiveAt: 1_800_000_000}
	log.state.Order = &markstore.Order{Kind: markstore.OrderHandover, Hash: [32]byte{8}, ActAt: 1_900_000_000}
	got = state()
	if got.Locked != (backend.ConfigGroup{Version: u.Body.Version, Hash: h}) ||
		got.Open.Pending != (backend.PendingUpdate{Version: 1, Hash: backend.Root{9}, EffectiveAt: 1_800_000_000}) ||
		got.Order != (backend.Order{Kind: 1, Hash: backend.Root{8}, ActAt: 1_900_000_000}) {
		t.Fatalf("after the rotation: %+v", got)
	}
	if got.ApproverSetHash != u.Body.Locked.Approvers.Hash() || got.ApproverSetHash == want.ApproverSetHash {
		t.Fatal("the approver set hash is not the rotated set's")
	}

	// The active hash names another update than the readable body, or no
	// body is readable: the runner cannot say which set is active.
	log.state.Locked.Hash = [32]byte{1}
	if state().ApproverSetHash != (backend.Root{}) {
		t.Fatal("approver set hash from a body that is not the active update")
	}
	log.body = nil
	if state().ApproverSetHash != (backend.Root{}) {
		t.Fatal("approver set hash without a body")
	}
	if flagState([32]byte{7})() != (backend.SetupState{SetupHash: backend.Root{7}}) {
		t.Fatal("flag path state")
	}
}

// T-124, GCP on mainnet: a GCP setup on
// mainnet starts only with sealing_key_release.no_lock_accepted. The GCP
// constructor's read (platform.NoLock) then passes, and HEALTH's reason
// says that the setup accepts it. Off mainnet the field changes nothing.
func TestStartMainnetGCPNeedsNoLockAccepted(t *testing.T) {
	base, err := setupwire.DecodeSetup(sampleSetup(t, "gcp"))
	if err != nil {
		t.Fatal(err)
	}
	gcpBuild := func(o platform.Options) (*platform.Platform, error) {
		r, err := o.ReadKeyRule(context.Background(), platform.NoLock("GCP Cloud KMS has no lock on a key's IAM bindings"))
		if err != nil {
			return nil, err
		}
		return &platform.Platform{Name: "gcp", KeyRule: r}, nil
	}
	for _, c := range []struct {
		name            string
		mainnet, accept bool
		refuse          string
	}{
		{"mainnet", true, false, "sealing_key_release.no_lock_accepted = true"},
		{"mainnet, accepted", true, true, ""},
		{"testnet", false, false, ""},
		{"testnet, accepted", false, true, ""},
	} {
		st, _ := setupwire.DecodeSetup(sampleSetup(t, "gcp"))
		st.Chain.GenesisForkVersion = base.Chain.GenesisForkVersion
		if c.mainnet {
			st.Chain.GenesisForkVersion = setupwire.MainnetForkVersion
		}
		st.Platform.SealingKeyRelease.NoLockAccepted = c.accept
		raw, err := st.Encode()
		if err != nil {
			t.Fatal(err)
		}
		var events []string
		withChannel("gcp", &fakeChannel{raw: raw, events: &events}, func() {
			a := &startArgs{platformName: "gcp", setupSrc: "platform", listens: []transport.Addr{{Network: "tcp", Address: "0.0.0.0:7100"}}}
			s, plat, _, err := startPlatform(context.Background(), a, gcpBuild, quietLog)
			if c.refuse != "" {
				if err == nil || !strings.Contains(err.Error(), c.refuse) || !strings.Contains(err.Error(), "mainnet: the platform has no lock") {
					t.Errorf("%s: %v, want a refusal with %q", c.name, err, c.refuse)
				}
				return
			}
			if err != nil {
				t.Errorf("%s: %v", c.name, err)
				return
			}
			rule, err := keyRule(true, s.mainnet, s.noLockAccepted, plat, quietLog)
			if err != nil || rule.Lock != backend.KeyLockNone {
				t.Errorf("%s: %+v %v", c.name, rule, err)
			}
			if got := strings.Contains(rule.Why, "the setup accepts"); got != c.accept {
				t.Errorf("%s: HEALTH reason %q", c.name, rule.Why)
			}
		})
	}
}
