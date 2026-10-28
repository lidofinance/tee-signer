package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lidofinance/tee-signer/signer-core/core"
	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/wire"
)

// charon-shims gives each node's cloud.json its runner, the policy's
// attestation settings and 8 connections, so the selection proofs at an
// epoch start do not queue on one connection.
func TestCharonShimsCloudJSON(t *testing.T) {
	f := newFixture(t, charonSetupJSON, 2)
	var runners []string
	for i := range 3 {
		runners = append(runners, fmt.Sprintf(`{"address":"tcp:127.0.0.1:%d","client_cert":"c.pem","client_key":"k.pem"}`, 7101+i))
	}
	cfg := filepath.Join(f.dir, "coordinator.json")
	if err := os.WriteFile(cfg, []byte(`{"policy":"policy.json","runners":[`+strings.Join(runners, ",")+"]}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(f.dir, "shims")
	if err := cmdCharonShims([]string{"-config", cfg, "-platform", "dev", "-result", f.resultPath,
		"-chain", "../../../governance/chains/chain.testnet.json", "-out-dir", out}); err != nil {
		t.Fatal(err)
	}
	for i := range 3 {
		var cloud struct {
			Address     string `json:"address"`
			Connections int    `json:"connections"`
			Attestation struct {
				Verifier string `json:"verifier"`
			} `json:"attestation"`
			Accounts string `json:"accounts"`
		}
		b, err := os.ReadFile(filepath.Join(out, fmt.Sprintf("node%d", i), "cloud.json"))
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(b, &cloud); err != nil {
			t.Fatalf("node%d cloud.json: %v %s", i, err, b)
		}
		if cloud.Connections != 8 || cloud.Address != fmt.Sprintf("tcp:127.0.0.1:%d", 7101+i) ||
			cloud.Attestation.Verifier != "dev" || cloud.Accounts != "accounts.json" {
			t.Fatalf("node%d cloud.json: %s", i, b)
		}
	}
}

// charonShimsFor runs charon-shims over a 3-participant fixture with the
// chain config chain and returns the folder of the shims.
func charonShimsFor(t *testing.T, chain core.Config) string {
	t.Helper()
	f := newFixture(t, charonSetupJSON, 1)
	var runners []string
	for i := range 3 {
		runners = append(runners, fmt.Sprintf(`{"address":"tcp:127.0.0.1:%d","client_cert":"c.pem","client_key":"k.pem"}`, 7101+i))
	}
	cfg := filepath.Join(f.dir, "coordinator.json")
	if err := os.WriteFile(cfg, []byte(`{"policy":"policy.json","runners":[`+strings.Join(runners, ",")+"]}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	chainPath := filepath.Join(f.dir, "chain.json")
	if err := writeJSON(chainPath, chain); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(f.dir, "shims")
	if err := cmdCharonShims([]string{"-config", cfg, "-platform", "dev", "-result", f.resultPath,
		"-chain", chainPath, "-out-dir", out}); err != nil {
		t.Fatal(err)
	}
	return out
}

// TKGARTIFACT-02: the shim's client reads identity_version from cloud.json.
// Each cloud.json names the runners' version.
func TestCharonShimsIdentityVersion(t *testing.T) {
	chain, _, err := core.LoadConfig("../../../governance/chains/chain.testnet.json")
	if err != nil {
		t.Fatal(err)
	}
	out := charonShimsFor(t, chain)
	for i := range 3 {
		var cloud struct {
			IdentityVersion *int `json:"identity_version"`
		}
		b, err := os.ReadFile(filepath.Join(out, fmt.Sprintf("node%d", i), "cloud.json"))
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(b, &cloud); err != nil {
			t.Fatal(err)
		}
		if cloud.IdentityVersion == nil || *cloud.IdentityVersion != wire.IdentityVersion {
			t.Fatalf("node%d cloud.json: identity_version %v, the runners answer version %d only\n%s", i, cloud.IdentityVersion, wire.IdentityVersion, b)
		}
	}
}

// TKGARTIFACT-03: shim.yml carries every chain field the shim reads, with
// the values of the runners' chain config, gloas_fork_epoch included (0
// too): without it the shim refuses every Gloas duty.
func TestCharonShimsChainRoundTrip(t *testing.T) {
	base, _, err := core.LoadConfig("../../../governance/chains/chain.testnet.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name  string
		gloas *uint64
	}{{"gloas at epoch 20", ptr(uint64(20))}, {"gloas at genesis", ptr(uint64(0))}, {"no gloas", nil}} {
		t.Run(tc.name, func(t *testing.T) {
			chain := base
			chain.Forks = append([]core.Fork(nil), base.Forks...)
			chain.Preset = "minimal"
			if tc.gloas != nil {
				chain.Forks = append(chain.Forks, core.Fork{Epoch: *tc.gloas, Version: backend.Version{0x07, 0, 0, 1}})
				if *tc.gloas == 0 {
					chain.Forks = []core.Fork{{Epoch: 0, Version: backend.Version{0x07, 0, 0, 1}}}
				}
				chain.GloasForkEpoch = tc.gloas
			}
			if err := chain.Validate(); err != nil {
				t.Fatal(err)
			}
			out := charonShimsFor(t, chain)
			b, err := os.ReadFile(filepath.Join(out, "node0", "shim.yml"))
			if err != nil {
				t.Fatal(err)
			}
			got := readShimChain(t, b)
			want := shimChain{Preset: "minimal", SlotsPerEpoch: chain.SlotsPerEpoch,
				GenesisForkVersion:       hex0x(chain.GenesisForkVersion[:]),
				GenesisValidatorsRoot:    hex0x(chain.GenesisValidatorsRoot[:]),
				VoluntaryExitForkVersion: hex0x(chain.VoluntaryExitForkVersion[:]), GloasForkEpoch: chain.GloasForkEpoch}
			for _, f := range chain.Forks {
				want.Forks = append(want.Forks, shimFork{f.Epoch, hex0x(f.Version[:])})
			}
			gj, _ := json.Marshal(got)
			wj, _ := json.Marshal(want)
			if !bytes.Equal(gj, wj) {
				t.Fatalf("shim.yml chain:\n got %s\nwant %s\n%s", gj, wj, b)
			}
		})
	}
}

func ptr[T any](v T) *T { return &v }

// readShimChain decodes the chain section of shim.yml: a JSON object (YAML
// flow mapping) after "chain:", strict as the shim's loader is.
func readShimChain(t *testing.T, yml []byte) shimChain {
	t.Helper()
	for _, l := range strings.Split(string(yml), "\n") {
		v, ok := strings.CutPrefix(l, "chain: ")
		if !ok {
			continue
		}
		var c shimChain
		dec := json.NewDecoder(strings.NewReader(v))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&c); err != nil {
			t.Fatalf("shim.yml chain section: %v\n%s", err, yml)
		}
		return c
	}
	t.Fatalf("shim.yml has no chain section on one line:\n%s", yml)
	return shimChain{}
}
