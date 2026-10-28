package flavor

import (
	"testing"

	"github.com/lidofinance/tee-signer/governance/dkgorder"
	"github.com/lidofinance/tee-signer/governance/setupwire"
)

// The values of each flavour: one minute in a testnet build for each day of
// the default build.
func TestLimits(t *testing.T) {
	const day, minute = 86400, 60
	if got, want := Default.Limits(), (Limits{2 * day, 30 * day, 30 * day, 7 * day}); got != want {
		t.Errorf("default %+v, want %+v", got, want)
	}
	if got, want := Testnet.Limits(), (Limits{2 * minute, 30 * minute, 30 * minute, 7 * minute}); got != want {
		t.Errorf("testnet %+v, want %+v", got, want)
	}
	if Flavor("other").Limits() != Default.Limits() {
		t.Error("an unknown flavour does not get the default limits")
	}
}

// This build's setupwire constants are the Limits of its flavour. The test
// runs under both tags (go test and go test -tags testnet).
func TestBuildConstants(t *testing.T) {
	want := Limits{setupwire.DefaultTimeLock, setupwire.MaxTimeLock, setupwire.ActivationHorizon, setupwire.ImagesMinTimeLock}
	if got := Build.Limits(); got != want {
		t.Errorf("%s build: Limits %+v, setupwire %+v", Build, got, want)
	}
	if Build != Default && Build != Testnet {
		t.Errorf("Build %q", Build)
	}
}

// Wait, OrderWait and CheckActivateAt under this build's flavour agree with
// setupwire and dkgorder, which use the build's constants.
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
	for i, a := range actives {
		if got, want := l.TimeLock(a), a.ChangeDelay(); got != want {
			t.Errorf("active %d: TimeLock %d, setupwire %d", i, got, want)
		}
		if got, want := l.OrderWait(a, false), dkgorder.Wait(a); got != want {
			t.Errorf("active %d: OrderWait %d, dkgorder %d", i, got, want)
		}
		if got := l.OrderWait(a, true); got != a.ChangeDelay() {
			t.Errorf("active %d: dev OrderWait %d, want the time lock %d", i, got, a.ChangeDelay())
		}
		if got, want := l.CheckTimeLock(a) == nil, a.ChangeDelaySeconds == nil || *a.ChangeDelaySeconds <= setupwire.MaxTimeLock; got != want {
			t.Errorf("active %d: CheckTimeLock ok %v, want %v", i, got, want)
		}
		for j, u := range updates {
			w := l.Wait(a, u)
			if want := setupwire.Wait(a, u); w != want {
				t.Errorf("active %d update %d: Wait %d, setupwire %d", i, j, w, want)
			}
			for _, at := range []uint64{0, 1000 + w + l.ActivationHorizon, 1001 + w + l.ActivationHorizon} {
				if got, want := l.CheckActivateAt(at, 1000, w) == nil, setupwire.CheckActivateAt(at, 1000, w) == nil; got != want {
					t.Errorf("active %d update %d activate_at %d: ok %v, setupwire %v", i, j, at, got, want)
				}
			}
		}
	}
}

func TestMarks(t *testing.T) {
	for v, want := range map[string]Flavor{"0.1.0": Default, "0.1.0" + VersionSuffix: Testnet, "": Default, "testnet": Default} {
		if got := FromVersion(v); got != want {
			t.Errorf("FromVersion(%q) %s, want %s", v, got, want)
		}
	}
	for cn, want := range map[string]Flavor{DefaultCertName: Default, TestnetCertName: Testnet, "": Default, "other": Default} {
		if got := FromCertName(cn); got != want {
			t.Errorf("FromCertName(%q) %s, want %s", cn, got, want)
		}
	}
}
