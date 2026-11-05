package runnerchain

import (
	"testing"

	"github.com/lidofinance/tee-signer/governance/setupwire"
)

// The times of each build: one minute in a non-prod build for each day
// of the mainnet build.
func TestLimits(t *testing.T) {
	const day, minute = 86400, 60
	if got, want := Mainnet.Limits(), (Limits{2 * day, 30 * day, 30 * day, 7 * day}); got != want {
		t.Errorf("mainnet %+v, want %+v", got, want)
	}
	for _, c := range []Chain{Hoodi, Devnet, CITest} {
		if got, want := c.Limits(), (Limits{2 * minute, 30 * minute, 30 * minute, 7 * minute}); got != want {
			t.Errorf("%s %+v, want %+v", c, got, want)
		}
	}
	if Chain("other").Limits() != Mainnet.Limits() || Chain("").Limits() != Mainnet.Limits() {
		t.Error("an unknown chain does not get the mainnet limits")
	}
}

// This build's setupwire constants are the Limits of its chain. The test
// runs under each build's tags (go test, and go test -tags nonprod,chain_<name>).
func TestBuildConstants(t *testing.T) {
	want := Limits{setupwire.DefaultTimeLock, setupwire.MaxTimeLock, setupwire.ActivationHorizon, setupwire.ImagesMinTimeLock}
	if got := Build.Limits(); got != want {
		t.Errorf("%s build: Limits %+v, setupwire %+v", Build, got, want)
	}
	if _, err := Parse(string(Build)); err != nil {
		t.Errorf("Build: %v", err)
	}
}

// Without a chain tag the build is mainnet.
func TestDefaultIsMainnet(t *testing.T) {
	if !Build.Prod() {
		t.Skipf("a %s build", Build)
	}
	if Build != Mainnet || Build.VersionSuffix() != "" || Build.CertName() != "signer-runner" {
		t.Errorf("build without a chain tag: %q, suffix %q, cert name %q", Build, Build.VersionSuffix(), Build.CertName())
	}
}

func TestParse(t *testing.T) {
	for _, s := range []string{"mainnet", "hoodi", "devnet", "ci-test"} {
		if c, err := Parse(s); err != nil || string(c) != s {
			t.Errorf("Parse(%q): %q %v", s, c, err)
		}
	}
	for _, s := range []string{"", "testnet", "citest", "Mainnet", "sepolia"} {
		if _, err := Parse(s); err == nil {
			t.Errorf("Parse(%q) accepted", s)
		}
	}
}

// Wait and CheckActivateAt under this build's chain agree with
// setupwire, which uses the build's constants.
func TestSameRulesAsSetupwire(t *testing.T) {
	l := Build.Limits()
	img := func(b byte) setupwire.Image {
		m := make([]byte, 32)
		m[0] = b
		return setupwire.Image{Kind: setupwire.ImageAzure, Measurement: m}
	}
	short, long := uint64(60), uint64(10*86400)
	lockedWith := func(tl *uint64, imgs ...setupwire.Image) *setupwire.Locked {
		return &setupwire.Locked{ChangeDelaySeconds: tl, AllowedImageMeasurements: imgs}
	}
	actives := []*setupwire.Locked{lockedWith(nil, img(1)), lockedWith(&short, img(1)), lockedWith(&long), lockedWith(new(uint64))}
	updates := []*setupwire.UpdateBody{
		{Group: setupwire.GroupOpen},
		{Group: setupwire.GroupLocked, Locked: lockedWith(nil, img(1))},
		{Group: setupwire.GroupLocked, Locked: lockedWith(nil, img(1), img(2))},
	}
	// Mainnet, a prod chain with the floor, and the ci-test row's chain.
	chains := []*setupwire.Chain{
		{GenesisForkVersion: setupwire.MainnetForkVersion, GenesisValidatorsRoot: root(t, public["mainnet"][1])},
		{GenesisForkVersion: ciTestFork, GenesisValidatorsRoot: ciTestRootBytes},
	}
	for _, ch := range chains {
		gfv := ch.GenesisForkVersion
		if got, want := l.MinTimeLock(ch), setupwire.MinChangeDelay(ch); got != want {
			t.Errorf("chain %x: MinTimeLock %d, setupwire %d", gfv, got, want)
		}
		for i, a := range actives {
			if got, want := l.TimeLock(ch, a), a.ChangeDelayOn(ch); got != want {
				t.Errorf("chain %x active %d: TimeLock %d, setupwire %d", gfv, i, got, want)
			}
			underCap := a.ChangeDelaySeconds == nil || *a.ChangeDelaySeconds <= setupwire.MaxTimeLock
			if got, want := l.CheckTimeLock(ch, a) == nil, underCap && a.CheckChangeDelay(ch) == nil; got != want {
				t.Errorf("chain %x active %d: CheckTimeLock ok %v, want %v", gfv, i, got, want)
			}
			for j, u := range updates {
				w := l.Wait(ch, a, u)
				if want := setupwire.Wait(ch, a, u); w != want {
					t.Errorf("chain %x active %d update %d: Wait %d, setupwire %d", gfv, i, j, w, want)
				}
				for _, at := range []uint64{0, 1000 + w + l.ActivationHorizon, 1001 + w + l.ActivationHorizon} {
					if got, want := l.CheckActivateAt(at, 1000, w) == nil, setupwire.CheckActivateAt(at, 1000, w) == nil; got != want {
						t.Errorf("chain %x active %d update %d activate_at %d: ok %v, setupwire %v", gfv, i, j, at, got, want)
					}
				}
			}
		}
	}
	// The floor on a prod chain, in the build's seconds: 0 and one below
	// the default are refused, the default and an absent value pass; a
	// non-prod chain takes 0.
	one := l.DefaultTimeLock - 1
	for _, c := range []struct {
		ch *setupwire.Chain
		tl *uint64
		ok bool
	}{
		{chains[0], new(uint64), false},
		{chains[0], &one, false},
		{chains[0], &l.DefaultTimeLock, true},
		{chains[0], nil, true},
		{chains[1], new(uint64), true},
	} {
		if err := l.CheckTimeLock(c.ch, lockedWith(c.tl)); (err == nil) != c.ok {
			t.Errorf("chain %x time lock %v: %v, want ok %v", c.ch.GenesisForkVersion, c.tl, err, c.ok)
		}
	}
}

// The label: "+<chain>" in HEALTH's version and "signer-runner <chain>" in
// the certificate for a non-prod build, nothing added for mainnet.
func TestMarks(t *testing.T) {
	for c, want := range map[Chain][2]string{
		Mainnet: {"", "signer-runner"},
		Hoodi:   {"+hoodi", "signer-runner hoodi"},
		Devnet:  {"+devnet", "signer-runner devnet"},
		CITest:  {"+ci-test", "signer-runner ci-test"},
	} {
		if c.VersionSuffix() != want[0] || c.CertName() != want[1] {
			t.Errorf("%s: suffix %q, cert name %q, want %q", c, c.VersionSuffix(), c.CertName(), want)
		}
		if got := FromVersion("0.1.0" + c.VersionSuffix()); got != c {
			t.Errorf("FromVersion of %s: %s", c, got)
		}
		if got, ok := FromCertName(c.CertName()); !ok || got != c {
			t.Errorf("FromCertName of %s: %s %v", c, got, ok)
		}
	}
	for v, want := range map[string]Chain{"": Mainnet, "0.1.0": Mainnet, "0.1.0+testnet": "testnet"} {
		if got := FromVersion(v); got != want {
			t.Errorf("FromVersion(%q) %q, want %q", v, got, want)
		}
	}
	for _, cn := range []string{"", "other", "signer-runner testnet", "signer-runner mainnet", "signer-runner "} {
		if c, ok := FromCertName(cn); ok {
			t.Errorf("FromCertName(%q): %s", cn, c)
		}
	}
}
