//go:build !verifierselect

package runnerclient

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/governance/flavor"
	"github.com/lidofinance/tee-signer/signer-protocol/wire"
)

func startTestnetRunner(t *testing.T, ca *testCA) *fakeRunner {
	t.Helper()
	return startFakeRunnerAs(t, ca, devAttest, flavor.TestnetCertName, "0.1.0"+flavor.VersionSuffix)
}

// A testnet runner is refused in the handshake, before IDENTITY.
func TestTestnetRunnerRefused(t *testing.T) {
	ca := newTestCA(t)
	f := startTestnetRunner(t, ca)
	wantErr(t, health(t, devConn(t, ca, f)), "the runner is a testnet build")
	if n := f.seen(wire.TypeIdentity) + f.seen(wire.TypeHealth); n != 0 {
		t.Errorf("the client sent %d requests to a refused runner", n)
	}
}

// allow_testnet_build accepts it, and the client reads its flavour.
func TestTestnetRunnerAllowed(t *testing.T) {
	ca := newTestCA(t)
	f := startTestnetRunner(t, ca)
	c := devConn(t, ca, f)
	c.AllowTestnetBuild = true
	cl, err := c.New(WithTimeout(5 * time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()
	h, err := cl.Health(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if fl := flavor.FromVersion(h.Version); fl != flavor.Testnet || h.Version != "0.1.0+testnet" {
		t.Errorf("flavour %s, version %q", fl, h.Version)
	}
	// The setting does not refuse a default runner.
	d := startFakeRunner(t, ca, devAttest)
	c = devConn(t, ca, d)
	c.AllowTestnetBuild = true
	if err := health(t, c); err != nil {
		t.Errorf("default runner with allow_testnet_build: %v", err)
	}
}

func TestAllowTestnetBuildSetting(t *testing.T) {
	var c Connection
	if err := json.Unmarshal([]byte(`{"address":"tcp:h:1","allow_testnet_build":true}`), &c); err != nil || !c.AllowTestnetBuild {
		t.Fatalf("%v %+v", err, c)
	}
	out, err := json.Marshal(Connection{})
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(out, &m); err != nil {
		t.Fatal(err)
	}
	if _, ok := m["allow_testnet_build"]; ok {
		t.Error("allow_testnet_build written when false")
	}
}
