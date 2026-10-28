package signing

import (
	"fmt"
	"strings"
	"testing"

	"github.com/attestantio/go-eth2-client/spec/phase0"

	"github.com/lidofinance/tee-signer/web3signer-api/eth2"
)

const mainnetGVR = "0x4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95"

// mainnetPin is the mainnet schedule from genesis to Fulu, as gateway/scripts/configure.sh writes it.
func mainnetPin(t *testing.T) *Pin {
	t.Helper()
	gvr, err := parseRoot(mainnetGVR)
	if err != nil {
		t.Fatal(err)
	}
	p := &Pin{GenesisValidatorsRoot: gvr}
	for i, e := range []phase0.Epoch{0, 74240, 144896, 194048, 269568, 364032, 411392} {
		p.Forks = append(p.Forks, ForkEpoch{Epoch: e, Version: phase0.Version{byte(i), 0, 0, 0}})
	}

	return p
}

func attestationBody(forkInfo string, target uint64) string {
	return fmt.Sprintf(`{"type":"ATTESTATION","fork_info":%s,"attestation":{"slot":"%d","index":"0",
		"beacon_block_root":"0x%064x","source":{"epoch":"%d","root":"0x%064x"},"target":{"epoch":"%d","root":"0x%064x"}}}`,
		forkInfo, target*32, 1, target-1, 2, target, 3)
}

func pinForkInfo(prev, cur string, epoch uint64, gvr string) string {
	return fmt.Sprintf(`{"fork":{"previous_version":"%s","current_version":"%s","epoch":"%d"},"genesis_validators_root":"%s"}`,
		prev, cur, epoch, gvr)
}

func TestPinnedChainRefusesForeignForkInfo(t *testing.T) {
	chain := mustChain("mainnet")
	chain.Pin = mainnetPin(t)
	fulu := pinForkInfo("0x05000000", "0x06000000", 411392, mainnetGVR)

	job, err := Parse([]byte(attestationBody(fulu, 420000)), chain)
	if err != nil {
		t.Fatalf("mainnet fork_info: %v", err)
	}
	want, err := eth2.ComputeDomain(eth2.DomainBeaconAttester, phase0.Version{6, 0, 0, 0}, chain.Pin.GenesisValidatorsRoot)
	if err != nil || job.Domain != want {
		t.Fatalf("domain %#x, want %#x (%v)", job.Domain, want, err)
	}
	// Before the Fulu epoch the same fork_info gives the Electra version, as the schedule does.
	if _, err := Parse([]byte(attestationBody(fulu, 411000)), chain); err != nil {
		t.Fatalf("Electra epoch with the Fulu fork_info: %v", err)
	}

	cases := map[string]struct {
		body, msg string
	}{
		"another chain's genesis_validators_root (Sepolia)": {
			attestationBody(pinForkInfo("0x05000000", "0x06000000", 411392,
				"0xd8ea171f3c94aea21ebc42a1ed61052acf3f9209c00e4efbaaddac09ed9b8078"), 420000),
			"is not the configured chain's",
		},
		"a fork that is not in the schedule (Fulu at another epoch)": {
			attestationBody(pinForkInfo("0x05000000", "0x06000000", 400000, mainnetGVR), 420000), "not in the configured fork schedule",
		},
		"made-up fork versions": {
			attestationBody(pinForkInfo("0x05000000", "0x99000000", 411392, mainnetGVR), 420000), "not in the configured fork schedule",
		},
		"an old fork_info (Deneb) for an epoch after Electra": {
			attestationBody(pinForkInfo("0x03000000", "0x04000000", 269568, mainnetGVR), 420000), "the configured chain has 0x06000000",
		},
	}
	for name, c := range cases {
		_, err := Parse([]byte(c.body), chain)
		if !IsBadRequest(err) || !strings.Contains(err.Error(), c.msg) {
			t.Errorf("%s: want a bad request with %q, got %v", name, c.msg, err)
		}
	}

	// Generic Sign and block requests go through the same check.
	randao := `{"type":"RANDAO_REVEAL","fork_info":` + pinForkInfo("0x05000000", "0x06000000", 411392, "0x"+strings.Repeat("ab", 32)) +
		`,"randao_reveal":{"epoch":"420000"}}`
	if _, err := Parse([]byte(randao), chain); !IsBadRequest(err) {
		t.Errorf("RANDAO with another genesis_validators_root: %v", err)
	}
	block := `{"type":"BLOCK_V2","fork_info":` + pinForkInfo("0x04000000", "0x05000000", 364032, mainnetGVR) +
		`,"beacon_block":{"version":"FULU","block_header":{"slot":"13440000","proposer_index":"1","parent_root":"0x` +
		strings.Repeat("01", 32) + `","state_root":"0x` + strings.Repeat("02", 32) + `","body_root":"0x` + strings.Repeat("03", 32) + `"}}}`
	if _, err := Parse([]byte(block), chain); !IsBadRequest(err) {
		t.Errorf("block with the Electra fork_info at a Fulu slot: %v", err)
	}
}

func TestPinSchedule(t *testing.T) {
	p := mainnetPin(t)
	for epoch, want := range map[phase0.Epoch]byte{0: 0, 74239: 0, 74240: 1, 411391: 5, 411392: 6, 1 << 40: 6} {
		if got := p.versionAt(epoch); got != (phase0.Version{want, 0, 0, 0}) {
			t.Errorf("versionAt(%d) = %#x, want 0x%02x000000", epoch, got, want)
		}
	}
	genesis := &phase0.Fork{PreviousVersion: phase0.Version{}, CurrentVersion: phase0.Version{}, Epoch: 0}
	if !p.knows(genesis) {
		t.Error("the genesis fork is not known")
	}
	// Devnet: several forks at epoch 0; the state carries the last one.
	dev := &Pin{Forks: []ForkEpoch{{0, phase0.Version{1}}, {0, phase0.Version{2}}, {0, phase0.Version{3}}}}
	if !dev.knows(&phase0.Fork{PreviousVersion: phase0.Version{2}, CurrentVersion: phase0.Version{3}}) ||
		dev.versionAt(0) != (phase0.Version{3}) {
		t.Error("devnet schedule with forks at epoch 0")
	}
	// A genesis state built at the last of those forks carries it as previous
	// and current version (what Lighthouse and Teku sent on a local devnet).
	if !dev.knows(&phase0.Fork{PreviousVersion: phase0.Version{3}, CurrentVersion: phase0.Version{3}}) {
		t.Error("devnet genesis fork (previous = current = last fork at epoch 0) is not known")
	}
	// Version 2 as previous and current at epoch 0 is no state of this chain.
	// (The genesis entry, version 1, stays known as its own previous version;
	// the version check after it refuses it for any epoch.)
	if dev.knows(&phase0.Fork{PreviousVersion: phase0.Version{2}, CurrentVersion: phase0.Version{2}}) {
		t.Error("fork version 2 as previous and current at epoch 0 is known, but the chain starts at version 3")
	}
	if dev.knows(&phase0.Fork{PreviousVersion: phase0.Version{3}, CurrentVersion: phase0.Version{3}, Epoch: 5}) {
		t.Error("previous = current at a later epoch is known")
	}
}

// TestDevnetForkInfo parses an attestation with the fork_info a local devnet's
// validator clients send: Fulu at genesis, previous and
// current version both 0x70000038.
func TestDevnetForkInfo(t *testing.T) {
	gvr := "0x" + strings.Repeat("d1", 32)
	root, err := parseRoot(gvr)
	if err != nil {
		t.Fatal(err)
	}
	chain := mustChain("mainnet")
	chain.Pin = &Pin{GenesisValidatorsRoot: root, Forks: []ForkEpoch{{0, phase0.Version{0x10, 0, 0, 0x38}}}}
	for v := byte(0x20); v <= 0x70; v += 0x10 {
		chain.Pin.Forks = append(chain.Pin.Forks, ForkEpoch{0, phase0.Version{v, 0, 0, 0x38}})
	}
	job, err := Parse([]byte(attestationBody(pinForkInfo("0x70000038", "0x70000038", 0, gvr), 7)), chain)
	if err != nil {
		t.Fatalf("devnet fork_info: %v", err)
	}
	want, err := eth2.ComputeDomain(eth2.DomainBeaconAttester, phase0.Version{0x70, 0, 0, 0x38}, root)
	if err != nil || job.Domain != want {
		t.Fatalf("domain %#x, want %#x (%v)", job.Domain, want, err)
	}
	if _, err := Parse([]byte(attestationBody(pinForkInfo("0x60000038", "0x60000038", 0, gvr), 7)), chain); !IsBadRequest(err) {
		t.Errorf("Electra as the genesis fork of a chain that starts at Fulu: want a bad request, got %v", err)
	}
}

// Lodestar v1.49.0 puts the current epoch in fork_info.fork on a devnet whose
// forks all start at epoch 0. The fork in force is still known; a fork from an
// earlier period is not.
func TestForkEpochInsideItsPeriod(t *testing.T) {
	p := &Pin{Forks: []ForkEpoch{
		{Epoch: 0, Version: phase0.Version{1}}, {Epoch: 0, Version: phase0.Version{2}}, {Epoch: 0, Version: phase0.Version{3}},
	}}
	if !p.knows(&phase0.Fork{PreviousVersion: phase0.Version{2}, CurrentVersion: phase0.Version{3}, Epoch: 6}) {
		t.Fatal("the fork in force with a later epoch must be known")
	}
	if p.knows(&phase0.Fork{PreviousVersion: phase0.Version{1}, CurrentVersion: phase0.Version{2}, Epoch: 6}) {
		t.Fatal("a fork that is no longer in force at that epoch must not be known")
	}
	q := &Pin{Forks: []ForkEpoch{{Epoch: 0, Version: phase0.Version{1}}, {Epoch: 10, Version: phase0.Version{2}}}}
	if q.knows(&phase0.Fork{PreviousVersion: phase0.Version{1}, CurrentVersion: phase0.Version{2}, Epoch: 9}) {
		t.Fatal("a fork epoch before the fork starts must not be known")
	}
	if !q.knows(&phase0.Fork{PreviousVersion: phase0.Version{1}, CurrentVersion: phase0.Version{2}, Epoch: 12}) {
		t.Fatal("a fork epoch inside the fork's period must be known")
	}
}
