package setupwire

import (
	"testing"

	"github.com/lidofinance/tee-signer/signer-protocol/buildchain"
)

// The image constants of this build are its chain's values: the long
// waits in the mainnet build, the short ones in a non-prod build. Run under
// each build's tags: go test, and go test -tags nonprod,chain_<name>.
func TestBuildChainConstants(t *testing.T) {
	type times struct{ timeLock, maxTimeLock, horizon, imagesMin uint64 }
	long, short := times{48 * 3600, 30 * 86400, 30 * 86400, 7 * 86400}, times{2 * 60, 30 * 60, 30 * 60, 7 * 60}
	want, ok := map[string]times{"mainnet": long, "hoodi": short, "devnet": short, "ci-test": short}[buildchain.Name]
	if !ok {
		t.Fatalf("buildchain.Name %q", buildchain.Name)
	}
	if (want == long) != buildchain.Prod {
		t.Fatalf("%s build: Prod %v with times %+v", buildchain.Name, buildchain.Prod, want)
	}
	if got := (times{DefaultTimeLock, MaxTimeLock, ActivationHorizon, ImagesMinTimeLock}); got != want {
		t.Fatalf("%s build: %+v, want %+v", buildchain.Name, got, want)
	}
	// A non-prod build has one minute for each day of the mainnet build.
	for i, p := range [][2]uint64{
		{buildchain.MainnetTimeLock, buildchain.ShortTimeLock},
		{buildchain.MainnetMaxTimeLock, buildchain.ShortMaxTimeLock},
		{buildchain.MainnetActivationHorizon, buildchain.ShortActivationHorizon},
		{buildchain.MainnetImagesMinTimeLock, buildchain.ShortImagesMinTimeLock},
	} {
		if p[0]/86400*60 != p[1] || p[0]%86400 != 0 {
			t.Errorf("value %d: mainnet %d s, non-prod %d s, want one minute per day", i, p[0], p[1])
		}
	}

	// The rules use them: no time lock in the setup means the image
	// default, a gained image waits the images minimum, the cap holds.
	l := &Locked{}
	if l.ChangeDelay() != want.timeLock {
		t.Errorf("TimeLock %d, want %d", l.ChangeDelay(), want.timeLock)
	}
	gain := &UpdateBody{Group: GroupLocked, Locked: &Locked{AllowedImageMeasurements: []Image{{Kind: ImageGCP, Measurement: make([]byte, 32)}}}}
	if w := Wait(sampleChain().GenesisForkVersion, &Locked{ChangeDelaySeconds: new(uint64)}, gain); w != want.imagesMin {
		t.Errorf("Wait with time lock 0 and a new image %d, want %d", w, want.imagesMin)
	}
	// On a prod chain the floor is the default time lock, in this build's
	// seconds.
	if w := Wait(MainnetForkVersion, &Locked{ChangeDelaySeconds: new(uint64)}, &UpdateBody{Group: GroupLocked, Locked: &Locked{}}); w != want.timeLock {
		t.Errorf("Wait on a prod chain with time lock 0 %d, want the floor %d", w, want.timeLock)
	}
	if err := CheckActivateAt(1000+want.imagesMin+want.horizon, 1000, want.imagesMin); err != nil {
		t.Error(err)
	}
	if err := CheckActivateAt(1001+want.imagesMin+want.horizon, 1000, want.imagesMin); err == nil {
		t.Error("activate_at past the horizon accepted")
	}
	// TestSetupRefusals checks the cap, MaxTimeLock + 1, under each tag.
}
