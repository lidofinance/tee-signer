//go:build !verifierselect

package runnerclient

import (
	"encoding/hex"
	"encoding/json"
	"flag"
	"math"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/attestation-verify/runnerclient/internal/optset"
	"github.com/lidofinance/tee-signer/attestation-verify/runnerclient/verify"
	remoteadmin "github.com/lidofinance/tee-signer/signer-admin/remote/admin"
	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/wire"
	wireadmin "github.com/lidofinance/tee-signer/signer-protocol/wire/admin"
)

// The setup pins against the fake runner of runnerclient_test.go, with the
// dev document.

var testSetupHash = backend.Root{0x5e, 0x70}

func pinOf(r backend.Root) string { return hex.EncodeToString(r[:]) }

// setupState is what a runner with a setup reports: locked version 2 with
// update 3 pending until effectiveAt, open version 1, its approver set.
func setupState(effectiveAt uint64) backend.SetupState {
	return backend.SetupState{
		SetupHash: testSetupHash,
		Locked: backend.ConfigGroup{Version: 2, Hash: backend.Root{1},
			Pending: backend.PendingUpdate{Version: 3, Hash: backend.Root{2}, EffectiveAt: effectiveAt}},
		Open:            backend.ConfigGroup{Version: 1, Hash: backend.Root{3}},
		ApproverSetHash: backend.Root{4},
	}
}

// effectiveAt is the effective activation time of the pending update in
// these tests, 2027-01-15T08:00:00Z.
const effectiveAt = 1_800_000_000

func withNow(t time.Time) Option {
	return func(o *optset.Options) { o.Now = func() time.Time { return t } }
}

func pinnedConn(t *testing.T, ca *testCA, f *fakeRunner) Connection {
	c := devConn(t, ca, f)
	c.Attestation.SetupSHA256 = pinOf(testSetupHash)
	return c
}

func TestSetupConfigRefusals(t *testing.T) {
	ca := newTestCA(t)
	cert, key := ca.issue(t, t.TempDir(), "client", time.Time{})
	good := Connection{Address: "tcp:signer-1:7100", ClientCert: cert, ClientKey: key,
		Attestation: Attestation{Verifier: VerifierDev, SetupSHA256: pinOf(testSetupHash), MinLockedVersion: 2, MinOpenVersion: 1}}
	if err := good.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, pin := range map[string]string{"0x prefix": "0x" + pinOf(testSetupHash), "upper case": strings.ToUpper(pinOf(testSetupHash))} {
		c := good
		c.Attestation.SetupSHA256 = pin
		if err := c.Validate(); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	unpinned := good
	unpinned.Attestation = Attestation{Verifier: VerifierDev, AllowUnpinnedSetup: true}
	if err := unpinned.Validate(); err != nil {
		t.Fatalf("allow_unpinned_setup with dev: %v", err)
	}
	maa := Attestation{Verifier: VerifierAzureMAA, MAAHost: "sharedweu.weu.attest.azure.net", CCEPolicySHA256: goodHostData}
	tests := []struct {
		name   string
		mutate func(a *Attestation)
		want   string
	}{
		{"short pin", func(a *Attestation) { a.SetupSHA256 = pinOf(testSetupHash)[:62] }, "setup_sha256: want 64 hex digits"},
		{"pin not hex", func(a *Attestation) { a.SetupSHA256 = strings.Repeat("zz", 32) }, "setup_sha256: want 64 hex digits"},
		{"min locked version without a pin", func(a *Attestation) { a.SetupSHA256, a.MinOpenVersion = "", 0 }, "min_locked_version: needs setup_sha256"},
		{"min open version without a pin", func(a *Attestation) { a.SetupSHA256, a.MinLockedVersion = "", 0 }, "min_open_version: needs setup_sha256"},
		{"min version with allow_unpinned_setup", func(a *Attestation) { a.SetupSHA256, a.AllowUnpinnedSetup = "", true }, "needs setup_sha256"},
		{"allow_unpinned_setup with a pin", func(a *Attestation) { a.AllowUnpinnedSetup = true }, "allow_unpinned_setup: not with setup_sha256"},
		{"allow_unpinned_setup on azure-maa", func(a *Attestation) { *a = maa; a.AllowUnpinnedSetup = true },
			`allow_unpinned_setup: for tests with the dev verifier only, not "azure-maa"`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := good
			tc.mutate(&c.Attestation)
			wantErr(t, c.Validate(), tc.want)
			_, err := c.New()
			wantErr(t, err, tc.want)
			_, err = c.Attestation.NewVerifier()
			wantErr(t, err, tc.want)
		})
	}
}

// A runner with a setup: its pin passes, another pin is refused before the
// client sends a request.
func TestSetupPin(t *testing.T) {
	ca := newTestCA(t)
	f := startFakeRunner(t, ca, devAttest)
	f.setState(setupState(effectiveAt))
	c := pinnedConn(t, ca, f)
	if err := health(t, c); err != nil {
		t.Fatalf("the pinned setup: %v", err)
	}
	if n := f.seen(wire.TypeHealth); n != 1 {
		t.Fatalf("%d HEALTH requests, want 1", n)
	}
	c.Attestation.SetupSHA256 = pinOf(backend.Root{0x99})
	wantErr(t, health(t, c), "the runner's setup_hash 5e70"+strings.Repeat("0", 60)+" is not the pinned setup_sha256 99")
	if n := f.seen(wire.TypeHealth); n != 1 {
		t.Fatal("the client sent HEALTH to a runner of another setup")
	}
}

// A runner that reports a setup and no pin: refused, unless
// allow_unpinned_setup.
func TestUnpinnedSetupRefused(t *testing.T) {
	ca := newTestCA(t)
	f := startFakeRunner(t, ca, devAttest)
	f.setState(setupState(effectiveAt))
	c := devConn(t, ca, f)
	wantErr(t, health(t, c), "the runner reports setup 5e70")
	wantErr(t, health(t, c), "no setup_sha256 is pinned")
	c.Attestation.AllowUnpinnedSetup = true
	if err := health(t, c); err != nil {
		t.Fatalf("allow_unpinned_setup: %v", err)
	}
}

// A runner on the flag path (setup_hash is the SHA-256 of its -config, the
// rest zero) connects without a pin, as before setups. A pin applies to it
// as to any runner, and so does a minimum version (it is at 0).
func TestFlagPathRunner(t *testing.T) {
	ca := newTestCA(t)
	f := startFakeRunner(t, ca, devAttest)
	c := devConn(t, ca, f)
	if err := health(t, c); err != nil {
		t.Fatalf("unpinned: %v", err)
	}
	c.Attestation.SetupSHA256 = pinOf(backend.Root{1, 2, 3})
	if err := health(t, c); err != nil {
		t.Fatalf("pinned to its config hash: %v", err)
	}
	c.Attestation.MinLockedVersion = 1
	wantErr(t, health(t, c), "the runner's locked config is at version 0, below min_locked_version 1")
	c.Attestation.MinLockedVersion = 0
	c.Attestation.SetupSHA256 = pinOf(testSetupHash)
	wantErr(t, health(t, c), "is not the pinned setup_sha256")
}

// The minimum versions count a pending update once its effective time has
// passed on this machine's clock.
func TestMinVersions(t *testing.T) {
	ca := newTestCA(t)
	f := startFakeRunner(t, ca, devAttest)
	f.setState(setupState(effectiveAt))
	before, at := time.Unix(effectiveAt-1, 0), time.Unix(effectiveAt, 0)
	tests := []struct {
		name              string
		minLocked, minOpn uint64
		now               time.Time
		want              string
	}{
		{"locked at its active version", 2, 0, before, ""},
		{"locked update still pending", 3, 0, before, "the runner's locked config is at version 2, below min_locked_version 3"},
		{"locked update in force", 3, 0, at, ""},
		{"above the pending update", 4, 0, at, "the runner's locked config is at version 3, below min_locked_version 4"},
		{"open at its version", 0, 1, before, ""},
		{"open below", 0, 2, at, "the runner's open config is at version 1, below min_open_version 2"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := pinnedConn(t, ca, f)
			c.Attestation.MinLockedVersion, c.Attestation.MinOpenVersion = tc.minLocked, tc.minOpn
			err := health(t, c, withNow(tc.now))
			if tc.want == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			wantErr(t, err, tc.want)
		})
	}
}

// NewVerifier, which share-import uses, runs
// the setup checks after the platform check.
func TestNewVerifierChecksTheSetup(t *testing.T) {
	a := Attestation{Verifier: VerifierDev, SetupSHA256: pinOf(testSetupHash), MinLockedVersion: 2}
	v, err := a.NewVerifier()
	if err != nil {
		t.Fatal(err)
	}
	nonce := []byte("a nonce")
	id := &backend.Identity{State: setupState(effectiveAt), ImportKey: []byte("k"), TLSKeyHash: []byte("t")}
	id.Attestation = devAttest(nonce, id)
	if err := v(ctx, nonce, id); err != nil {
		t.Fatal(err)
	}
	other := *id
	other.State.SetupHash[0] ^= 1
	other.Attestation = devAttest(nonce, &other)
	wantErr(t, v(ctx, nonce, &other), "is not the pinned setup_sha256")
	// The platform check comes first: a document for another nonce fails
	// there.
	wantErr(t, v(ctx, []byte("another nonce"), &other), "DevVerifier: document does not carry the nonce")
}

// A sealed import goes nowhere when the runner's setup is not the pinned
// one: the identity it would seal to fails the check, and no
// IMPORT_SHARE_SEALED reaches the runner.
func TestSealedImportRefusedForAnotherSetup(t *testing.T) {
	ca := newTestCA(t)
	f := startFakeRunner(t, ca, devAttest)
	f.setState(setupState(effectiveAt))
	c := devConn(t, ca, f)
	c.Attestation.SetupSHA256 = pinOf(backend.Root{0x99})
	cl, err := c.New(WithTimeout(5 * time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()
	_, err = remoteadmin.Wrap(cl.Client).ImportShareSealed(ctx, backend.ImportShareRequest{Index: 1}, backend.Pubkey{}, cl.Verify)
	wantErr(t, err, "is not the pinned setup_sha256")
	if n := f.seen(wireadmin.TypeImportSealed); n != 0 {
		t.Fatalf("%d sealed imports reached the runner", n)
	}
}

// WithVerified sees each connection that passed every check, once, and no
// refused one.
func TestWithVerified(t *testing.T) {
	ca := newTestCA(t)
	f := startFakeRunner(t, ca, devAttest)
	f.setState(setupState(effectiveAt))
	var mu sync.Mutex
	var got []backend.SetupState
	hook := WithVerified(func(id *backend.Identity) {
		mu.Lock()
		defer mu.Unlock()
		got = append(got, id.State)
	})
	c := pinnedConn(t, ca, f)
	cl, err := c.New(WithTimeout(5*time.Second), hook)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, err := cl.Health(ctx); err != nil {
			t.Fatal(err)
		}
	}
	cl.Close()
	if len(got) != 1 || got[0] != setupState(effectiveAt) {
		t.Fatalf("hook saw %+v, want the state once", got)
	}
	c = devConn(t, ca, f)
	wantErr(t, health(t, c, hook), "no setup_sha256 is pinned")
	if len(got) != 1 {
		t.Fatal("the hook saw a refused connection")
	}
}

func TestSetupStateHelpers(t *testing.T) {
	before, at := time.Unix(effectiveAt-60, 0), time.Unix(effectiveAt, 0)
	s := setupState(effectiveAt)
	if verify.FlagPath(&s) || !verify.FlagPath(&backend.SetupState{SetupHash: backend.Root{1}}) || !verify.FlagPath(&backend.SetupState{}) {
		t.Fatal("FlagPath")
	}
	if !verify.Waiting(s.Locked, before) || verify.Waiting(s.Locked, at) || verify.Waiting(s.Open, before) {
		t.Fatal("Waiting")
	}
	if verify.EffectiveVersion(s.Locked, before) != 2 || verify.EffectiveVersion(s.Locked, at) != 3 || verify.EffectiveVersion(s.Open, at) != 1 {
		t.Fatal("EffectiveVersion")
	}

	// CheckPending: a locked update that waits, or any order.
	err := verify.CheckPending(&s, before)
	if err == nil || !strings.Contains(err.Error(), "a locked config update is pending: version 3") ||
		!strings.Contains(err.Error(), "effective at 2027-01-15T08:00:00Z") {
		t.Fatalf("pending locked update: %v", err)
	}
	if err := verify.CheckPending(&s, at); err != nil {
		t.Fatalf("locked update in force: %v", err)
	}
	open := s
	open.Locked.Pending = backend.PendingUpdate{}
	open.Open.Pending = backend.PendingUpdate{Version: 2, Hash: backend.Root{9}, EffectiveAt: math.MaxUint64}
	if err := verify.CheckPending(&open, before); err != nil {
		t.Fatalf("pending open update: %v", err)
	}
	order := open
	order.Order = backend.Order{Kind: 1, Hash: backend.Root{5}, ActAt: effectiveAt}
	if err := verify.CheckPending(&order, at); err == nil || !strings.Contains(err.Error(), "a handover order is pending") {
		t.Fatalf("pending order: %v", err)
	}

	if verify.UnixTime(effectiveAt) != "2027-01-15T08:00:00Z" || verify.UnixTime(math.MaxUint64) != "unix 18446744073709551615" {
		t.Fatalf("UnixTime %s %s", verify.UnixTime(effectiveAt), verify.UnixTime(math.MaxUint64))
	}
	if verify.OrderKind(1) != "handover" || verify.OrderKind(2) != "kind 2" || verify.OrderKind(7) != "kind 7" {
		t.Fatal("OrderKind")
	}

	d := verify.DescribeSetup(&s, before)
	for _, want := range []string{"setup_sha256=5e70" + strings.Repeat("0", 60), "locked_version=2 locked_sha256=01" + strings.Repeat("0", 62),
		"locked_pending_version=3", "locked_pending_effective_at=2027-01-15T08:00:00Z", "open_version=1 open_sha256=03",
		"approver_set_sha256=04", "imported_keys=0"} {
		if !strings.Contains(d, want) {
			t.Fatalf("%q lacks %q", d, want)
		}
	}
	if strings.Contains(d, "effective_version") || strings.Contains(d, "order") || strings.Contains(d, "key_release") {
		t.Fatalf("%q names what is not there", d)
	}
	if d := verify.DescribeSetup(&s, at); !strings.Contains(d, "locked_version=2 locked_sha256=01"+strings.Repeat("0", 62)+" locked_effective_version=3") {
		t.Fatalf("in force: %q", d)
	}
	order.KeyReleaseHash = backend.Root{6}
	order.KeyOrigin = backend.KeyOrigin{Imported: 1}
	if d := verify.DescribeSetup(&order, at); !strings.Contains(d, "order=handover order_sha256=05") ||
		!strings.Contains(d, "order_act_at=2027-01-15T08:00:00Z") || !strings.Contains(d, "key_release_sha256=06") ||
		!strings.HasSuffix(d, " imported_keys=1") {
		t.Fatalf("order: %q", d)
	}
	flagPath := backend.SetupState{SetupHash: backend.Root{1, 2, 3}}
	if d := verify.DescribeSetup(&flagPath, at); d != "setup_sha256=010203"+strings.Repeat("0", 58)+" flag_path=true" {
		t.Fatalf("flag path: %q", d)
	}
}

func TestSetupFlagsAndJSON(t *testing.T) {
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	a := Flags(fs)
	if err := fs.Parse([]string{"-verifier", "dev", "-setup-sha256", pinOf(testSetupHash), "-min-locked-version", "3", "-min-open-version", "1"}); err != nil {
		t.Fatal(err)
	}
	if err := a.Validate(); err != nil {
		t.Fatal(err)
	}
	if a.SetupSHA256 != pinOf(testSetupHash) || a.MinLockedVersion != 3 || a.MinOpenVersion != 1 || a.AllowUnpinnedSetup {
		t.Fatalf("%+v", a)
	}
	fs = flag.NewFlagSet("t", flag.ContinueOnError)
	a = Flags(fs)
	if err := fs.Parse([]string{"-verifier", "dev", "-allow-unpinned-setup"}); err != nil || !a.AllowUnpinnedSetup || a.Validate() != nil {
		t.Fatalf("%+v %v", a, err)
	}

	// The names of the signing client's cloud.json.
	var j Attestation
	in := `{"verifier":"dev","setup_sha256":"` + pinOf(testSetupHash) + `","min_locked_version":3,"min_open_version":1}`
	if err := json.Unmarshal([]byte(in), &j); err != nil {
		t.Fatal(err)
	}
	if j.SetupSHA256 != pinOf(testSetupHash) || j.MinLockedVersion != 3 || j.MinOpenVersion != 1 || j.Validate() != nil {
		t.Fatalf("%+v", j)
	}
	j = Attestation{}
	if err := json.Unmarshal([]byte(`{"verifier":"dev","allow_unpinned_setup":true}`), &j); err != nil || !j.AllowUnpinnedSetup {
		t.Fatalf("%+v %v", j, err)
	}
}
