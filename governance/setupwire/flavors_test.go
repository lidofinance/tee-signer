package setupwire

import (
	"testing"

	"github.com/lidofinance/tee-signer/signer-protocol/buildflavor"
)

// The image constants of this build are its flavour's values. Run under
// both tags: go test, and go test -tags testnet.
func TestFlavorConstants(t *testing.T) {
	type times struct{ timeLock, maxTimeLock, horizon, imagesMin uint64 }
	want, ok := map[string]times{
		"default": {48 * 3600, 30 * 86400, 30 * 86400, 7 * 86400},
		"testnet": {2 * 60, 30 * 60, 30 * 60, 7 * 60},
	}[buildflavor.Name]
	if !ok {
		t.Fatalf("buildflavor.Name %q", buildflavor.Name)
	}
	if got := (times{DefaultTimeLock, MaxTimeLock, ActivationHorizon, ImagesMinTimeLock}); got != want {
		t.Fatalf("%s build: %+v, want %+v", buildflavor.Name, got, want)
	}
	// A testnet build has one minute for each day of the default build.
	for i, p := range [][2]uint64{
		{buildflavor.DefaultFlavorTimeLock, buildflavor.TestnetFlavorTimeLock},
		{buildflavor.DefaultFlavorMaxTimeLock, buildflavor.TestnetFlavorMaxTimeLock},
		{buildflavor.DefaultFlavorActivationHorizon, buildflavor.TestnetFlavorActivationHorizon},
		{buildflavor.DefaultFlavorImagesMinTimeLock, buildflavor.TestnetFlavorImagesMinTimeLock},
	} {
		if p[0]/86400*60 != p[1] || p[0]%86400 != 0 {
			t.Errorf("value %d: default %d s, testnet %d s, want one minute per day", i, p[0], p[1])
		}
	}

	// The rules use them: no time lock in the setup means the image
	// default, a gained image waits the images minimum, the cap holds.
	l := &Locked{}
	if l.ChangeDelay() != want.timeLock {
		t.Errorf("TimeLock %d, want %d", l.ChangeDelay(), want.timeLock)
	}
	gain := &UpdateBody{Group: GroupLocked, Locked: &Locked{AllowedImageMeasurements: []Image{{Kind: ImageGCP, Measurement: make([]byte, 32)}}}}
	if w := Wait(&Locked{ChangeDelaySeconds: new(uint64)}, gain); w != want.imagesMin {
		t.Errorf("Wait with time lock 0 and a new image %d, want %d", w, want.imagesMin)
	}
	if err := CheckActivateAt(1000+want.imagesMin+want.horizon, 1000, want.imagesMin); err != nil {
		t.Error(err)
	}
	if err := CheckActivateAt(1001+want.imagesMin+want.horizon, 1000, want.imagesMin); err == nil {
		t.Error("activate_at past the horizon accepted")
	}
	// TestSetupRefusals checks the cap, MaxTimeLock + 1, under each tag.
}
