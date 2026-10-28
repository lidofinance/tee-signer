//go:build testnet

package server

import (
	"testing"

	"github.com/lidofinance/tee-signer/governance/setupwire"
	"github.com/lidofinance/tee-signer/signer-protocol"
)

// The testnet build's override: an image the list does not name signs,
// and HEALTH says so (state override, ready). Without the setting the same
// runner refuses. Run with go test -tags testnet.
func TestImageCheckTestnetOverride(t *testing.T) {
	mine, other := testImage(setupwire.ImageNitro, 0x41), testImage(setupwire.ImageNitro, 0x42)
	e := gatedEnv(t, nil, "nitro", mine, other)
	wantCode(t, e.signWire(), backend.StatusNotReady, "image check:")

	g, err := NewImageGate(ctx, ImageGateOptions{Platform: "nitro", SelfImage: selfIs(mine), Override: true, Log: quiet})
	if err != nil {
		t.Fatal(err)
	}
	e.srv.Image = g
	if err := e.signWire(); err != nil {
		t.Fatalf("override: %v", err)
	}
	wantImageState(t, e, backend.ImageOverride, true)
	// The override does not cover a runner that cannot name its image.
	g, err = NewImageGate(ctx, ImageGateOptions{Platform: "nitro", Override: true, Log: quiet})
	if err != nil {
		t.Fatal(err)
	}
	e.srv.Image = g
	wantCode(t, e.signWire(), backend.StatusNotReady, "cannot tell its own image")
}
