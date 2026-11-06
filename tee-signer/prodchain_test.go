//go:build !nonprod

package main

import (
	"context"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/lidofinance/tee-signer/governance/setupwire"
	"github.com/lidofinance/tee-signer/platform"
	"github.com/lidofinance/tee-signer/platform/setup"
)

// nitroSetupOn is the Nitro sample setup with these genesis values and
// mainnet's slot times.
func nitroSetupOn(t *testing.T, fork, root string) []byte {
	t.Helper()
	s, err := setupwire.DecodeSetup(sampleSetup(t, "nitro"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := hex.Decode(s.Chain.GenesisForkVersion[:], []byte(fork)); err != nil {
		t.Fatal(err)
	}
	if _, err := hex.Decode(s.Chain.GenesisValidatorsRoot[:], []byte(root)); err != nil {
		t.Fatal(err)
	}
	s.Chain.GenesisTime, s.Chain.SecondsPerSlot, s.Chain.SlotsPerEpoch = setupwire.MainnetGenesisTime, setupwire.MainnetSecondsPerSlot, setupwire.MainnetSlotsPerEpoch
	s.Chain.Preset = setupwire.PresetMainnet
	s.Platform.SealingKeyRelease.KMSKeyCreationDate = 1793895285 // required on a prod chain
	out, err := s.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// On a cloud platform the mainnet build starts on mainnet with its exact
// values only. The check runs as the channel reads the setup, so the
// platform never starts on another chain, and the Nitro host gets the
// reason.
func TestMainnetBuildStartsOnMainnetOnly(t *testing.T) {
	const (
		mainnetFork = "00000000"
		mainnetRoot = "4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95"
		hoodiFork   = "10000910"
		hoodiRoot   = "212f13fc4df078b6cb7db228f1c8307566dcecf900867401a92023d7ba99cb5f"
	)
	for _, c := range []struct {
		name, fork, root string
		ok               bool
	}{
		{"mainnet", mainnetFork, mainnetRoot, true},
		{"hoodi", hoodiFork, hoodiRoot, false},
		{"hoodi fork version, mainnet root", hoodiFork, mainnetRoot, false},
		{"ci-test fork version, mainnet root", "00000001", mainnetRoot, false},
		{"devnet fork version, mainnet root", "10000038", mainnetRoot, false},
		{"mainnet fork version, hoodi root", mainnetFork, hoodiRoot, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			var events []string
			var opts platform.Options
			fake := &fakeChannel{raw: nitroSetupOn(t, c.fork, c.root), events: &events}
			ch := mainnetChannel(func() setup.Channel { return fake })()
			if _, ok := ch.(setup.Reporter); !ok {
				t.Fatal("the wrapper dropped the channel's Reporter")
			}
			withChannel("nitro", ch, func() {
				a := &startArgs{platformName: "nitro", setupSrc: "platform", given: map[string]string{"setup": "platform"},
					params: map[string]string{"clock": "nsm"}, stateDir: "/tmp/unused"}
				s, _, _, err := startPlatform(context.Background(), a, recordingPlatform("nitro", &events, &opts), quietLog)
				if c.ok {
					if err != nil || !s.prod || !opts.Prod {
						t.Fatalf("start %+v, prod %v: %v", s, opts.Prod, err)
					}
					return
				}
				if err == nil || !strings.Contains(err.Error(), "a mainnet build runs on mainnet") {
					t.Fatalf("started: %v", err)
				}
				if len(events) != 1 || events[0] != "setup" {
					t.Fatalf("events %v, want no platform", events)
				}
				if !strings.Contains(fake.reported, "a mainnet build runs on mainnet") {
					t.Fatalf("reported %q", fake.reported)
				}
			})
		})
	}
}

// Every cloud channel of this binary is wrapped; dev is not.
func TestMainnetChannelsWrapped(t *testing.T) {
	for name, f := range setupChannels {
		switch f().(type) {
		case mainnetChecked, mainnetReporter:
			if name == "dev" {
				t.Errorf("dev channel wrapped")
			}
		default:
			if name != "dev" {
				t.Errorf("%s channel not wrapped", name)
			}
		}
	}
}
