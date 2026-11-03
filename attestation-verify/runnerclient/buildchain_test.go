package runnerclient

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/governance/runnerchain"
	"github.com/lidofinance/tee-signer/signer-protocol/wire"
)

func startChainRunner(t *testing.T, ca *testCA, c runnerchain.Chain) *fakeRunner {
	t.Helper()
	return startFakeRunnerAs(t, ca, devAttest, c.CertName(), "0.1.0"+c.VersionSuffix())
}

// A non-prod runner is refused in the handshake, before IDENTITY, unless
// allow_chain_build names its chain.
func TestNonProdRunnerRefused(t *testing.T) {
	ca := newTestCA(t)
	for _, c := range []runnerchain.Chain{runnerchain.Hoodi, runnerchain.Devnet, runnerchain.CITest} {
		f := startChainRunner(t, ca, c)
		wantErr(t, health(t, devConn(t, ca, f)), "the runner is a "+string(c)+" build")
		// The setting of another chain does not accept it.
		for _, other := range []runnerchain.Chain{runnerchain.Hoodi, runnerchain.Devnet, runnerchain.CITest} {
			if other == c {
				continue
			}
			conn := devConn(t, ca, f)
			conn.AllowChainBuild = string(other)
			wantErr(t, health(t, conn), `set allow_chain_build to "`+string(c)+`"`)
		}
		if n := f.seen(wire.TypeIdentity) + f.seen(wire.TypeHealth); n != 0 {
			t.Errorf("%s: the client sent %d requests to a refused runner", c, n)
		}
	}
}

// A certificate name no build makes is refused, whatever the setting: the
// "testnet" name of earlier builds among them.
func TestUnknownBuildRefused(t *testing.T) {
	ca := newTestCA(t)
	for _, cn := range []string{"signer-runner testnet", "signer-runner mainnet", "other"} {
		f := startFakeRunnerAs(t, ca, devAttest, cn, "0.1.0+testnet")
		for _, allow := range []string{"", "hoodi", "devnet"} {
			conn := devConn(t, ca, f)
			conn.AllowChainBuild = allow
			wantErr(t, health(t, conn), "not a build this client knows")
		}
	}
}

// allow_chain_build accepts the runner of that chain, and the client reads
// its build from the version.
func TestNonProdRunnerAllowed(t *testing.T) {
	ca := newTestCA(t)
	for _, c := range []runnerchain.Chain{runnerchain.Hoodi, runnerchain.Devnet, runnerchain.CITest} {
		f := startChainRunner(t, ca, c)
		conn := devConn(t, ca, f)
		conn.AllowChainBuild = string(c)
		cl, err := conn.New(WithTimeout(5 * time.Second))
		if err != nil {
			t.Fatal(err)
		}
		h, err := cl.Health(ctx)
		cl.Close()
		if err != nil {
			t.Fatalf("%s: %v", c, err)
		}
		if got := runnerchain.FromVersion(h.Version); got != c || h.Version != "0.1.0+"+string(c) {
			t.Errorf("%s: build %s, version %q", c, got, h.Version)
		}
	}
	// The setting does not refuse a mainnet runner.
	d := startFakeRunner(t, ca, devAttest)
	conn := devConn(t, ca, d)
	conn.AllowChainBuild = "hoodi"
	if err := health(t, conn); err != nil {
		t.Errorf("mainnet runner with allow_chain_build: %v", err)
	}
}

func TestAllowChainBuildSetting(t *testing.T) {
	var c Connection
	if err := json.Unmarshal([]byte(`{"address":"tcp:h:1","allow_chain_build":"ci-test"}`), &c); err != nil || c.AllowChainBuild != "ci-test" {
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
	if _, ok := m["allow_chain_build"]; ok {
		t.Error("allow_chain_build written when empty")
	}
	// Only the chain of a non-prod build.
	ca := newTestCA(t)
	f := startFakeRunner(t, ca, devAttest)
	for _, v := range []string{"mainnet", "testnet", "citest", "sepolia", "Hoodi"} {
		conn := devConn(t, ca, f)
		conn.AllowChainBuild = v
		if err := conn.Validate(); err == nil || !strings.Contains(err.Error(), "allow_chain_build") {
			t.Errorf("allow_chain_build %q: %v", v, err)
		}
	}
}
