package main

import (
	"context"
	"flag"
	"testing"

	"github.com/lidofinance/tee-signer/governance/setupwire"
	"github.com/lidofinance/tee-signer/platform"
	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/buildflavor"
)

// Release gate: only a testnet build has -allow-unlisted-image, so no
// default build, and no cloud image of one, can serve an image the allowed
// list in force does not name. scripts/build-runner.sh checks the built
// binaries for the flag's name too. Run under both tags: go test, go test
// -tags testnet.
func TestImageOverrideOnlyInTestnetBuilds(t *testing.T) {
	f := flag.Lookup("allow-unlisted-image")
	switch buildflavor.Name {
	case "testnet":
		if f == nil {
			t.Fatal("a testnet build without -allow-unlisted-image")
		}
		if imageOverride() {
			t.Fatal("the override is on without the flag")
		}
	default:
		if f != nil {
			t.Fatal("a default build has -allow-unlisted-image")
		}
		if imageOverride() {
			t.Fatal("a default build turned the override on")
		}
	}
}

// startImageCheck before the shares load: a cloud platform that cannot
// name its own image keeps the shares sealed; a runner without a setup's
// list (nil Updates) and the dev platform load them.
func TestStartImageCheckWithholdsShares(t *testing.T) {
	ctx := context.Background()
	for _, c := range []struct {
		name string
		plat *platform.Platform
		load bool
		want string
	}{
		{"gcp without an image", &platform.Platform{Name: "gcp"}, false, backend.ImageUnknown},
		{"azure with one, no list", &platform.Platform{Name: "azure", SelfImage: func(context.Context) (setupwire.Image, error) {
			return setupwire.Image{Kind: setupwire.ImageAzure, Measurement: make([]byte, 32)}, nil
		}}, true, backend.ImageNotApplicable},
		{"dev", &platform.Platform{Name: "dev"}, true, backend.ImageNotApplicable},
	} {
		g, load, err := startImageCheck(ctx, c.plat, nil, quietLog)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if st, _ := g.Status(nil); load != c.load || st.State != c.want {
			t.Fatalf("%s: load %v, state %s; want %v, %s", c.name, load, st.State, c.load, c.want)
		}
	}
}
