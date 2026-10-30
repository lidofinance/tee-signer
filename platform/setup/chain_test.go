package setup

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lidofinance/tee-signer/governance/setuptext"
	"github.com/lidofinance/tee-signer/governance/setupwire"
)

func chainFile(t *testing.T, path ...string) *ChainFile {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(append([]string{"..", "..", "governance", "chains"}, path...)...))
	if err != nil {
		t.Fatal(err)
	}
	c, err := ParseChainFile(b)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// Hoodi's chain.json lists four forks at epoch 0; the setup holds the last
// one, which is the one in force from epoch 0.
func TestChainSchedule(t *testing.T) {
	sched, err := chainFile(t, "hoodi.json").Schedule()
	if err != nil {
		t.Fatal(err)
	}
	if len(sched) != 4 || sched[0].Epoch != 0 || sched[0].Version != [4]byte{0x50, 0, 0x09, 0x10} ||
		sched[1].Epoch != 2048 || sched[3].Epoch != 132352 {
		t.Fatalf("schedule %v", sched)
	}
	c := &ChainFile{Forks: []chainFork{{Epoch: 5}, {Epoch: 3}}, SecondsPerSlot: 1, SlotsPerEpoch: 1}
	if _, err := c.Schedule(); err == nil {
		t.Fatal("descending forks accepted")
	}
	if _, err := ParseChainFile([]byte(`{"seconds_per_slot": 12, "slots_per_epoch": 32, "unknown": 1}`)); err == nil {
		t.Fatal("unknown field accepted")
	}
}

// A setup built from a chain.json (ChainLines plus the operator's other
// lines) matches that chain, and no other.
func TestChainLinesAndCompare(t *testing.T) {
	hoodi := chainFile(t, "hoodi.json")
	lines, err := ChainLines(hoodi)
	if err != nil {
		t.Fatal(err)
	}
	keys := map[string]bool{}
	for _, l := range strings.Split(lines, "\n") {
		if k, _, ok := strings.Cut(l, " = "); ok {
			keys[k] = true
		}
	}
	sample, err := os.ReadFile(filepath.Join("..", "..", "governance", "setuptext", "testdata", "setup-nitro.conf"))
	if err != nil {
		t.Fatal(err)
	}
	var human strings.Builder
	for _, l := range strings.Split(string(sample), "\n") {
		if k, _, ok := strings.Cut(l, " = "); ok && keys[k] {
			continue
		}
		human.WriteString(l + "\n")
	}
	human.WriteString(lines)
	s, err := setuptext.ParseSetup("hoodi.conf", []byte(human.String()))
	if err != nil {
		t.Fatalf("%v\n%s", err, human.String())
	}
	if err := CompareChain(s, hoodi); err != nil {
		t.Fatal(err)
	}
	if s.Chain.Preset != setupwire.PresetMainnet || s.Safety.MaxSignEpochsAheadOfClock != 2 || s.Locked.BuilderGasLimitMax != 200_000_000 ||
		len(s.Open.ForkSchedule) != 4 || s.Open.GloasForkEpoch == nil || *s.Open.GloasForkEpoch != 132352 {
		t.Fatalf("setup from hoodi.json: %+v %+v", s.Chain, s.Open)
	}
	// Another chain, or the same chain with one chain field changed.
	if err := CompareChain(s, chainFile(t, "chain.testnet.json")); err == nil || !strings.Contains(err.Error(), "genesis_validators_root") {
		t.Fatalf("testnet: %v", err)
	}
	for name, mutate := range map[string]func(c *ChainFile){
		"genesis time":    func(c *ChainFile) { c.GenesisTime++ },
		"a fork moved":    func(c *ChainFile) { c.Forks[5].Epoch++ },
		"no gloas":        func(c *ChainFile) { c.GloasForkEpoch = nil },
		"exit version":    func(c *ChainFile) { c.VoluntaryExitForkVersion[0]++ },
		"minimal preset":  func(c *ChainFile) { c.Preset = "minimal" },
		"seconds a slot":  func(c *ChainFile) { c.SecondsPerSlot = 6 },
		"genesis version": func(c *ChainFile) { c.GenesisForkVersion[3]++ },
	} {
		c := chainFile(t, "hoodi.json")
		mutate(c)
		if err := CompareChain(s, c); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
	// Policy fields are not chain fields.
	c := chainFile(t, "hoodi.json")
	c.GasLimitMax, c.MaxEpochsAhead = 1, 9
	if err := CompareChain(s, c); err != nil {
		t.Fatalf("policy fields compared: %v", err)
	}
}
