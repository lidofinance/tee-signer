package setup

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/lidofinance/tee-signer/governance/setupwire"
	"github.com/lidofinance/tee-signer/signer-protocol"
)

// ChainFile is a runner chain.json (core.Config's file form, cloud/chains):
// what the images held before the setup. The deploy scripts still pick a
// chain by name (cloud/chains/chain.sh), so they compare the setup with it.
type ChainFile struct {
	GenesisValidatorsRoot    backend.Root    `json:"genesis_validators_root"`
	GenesisForkVersion       backend.Version `json:"genesis_fork_version"`
	Forks                    []chainFork     `json:"forks"`
	VoluntaryExitForkVersion backend.Version `json:"voluntary_exit_fork_version"`
	GenesisTime              uint64          `json:"genesis_time"`
	SecondsPerSlot           uint64          `json:"seconds_per_slot"`
	SlotsPerEpoch            uint64          `json:"slots_per_epoch"`

	MaxEpochsAhead               uint64            `json:"max_epochs_ahead"`
	ExitAllowlist                []uint64          `json:"exit_allowlist"`
	FeeRecipients                []backend.Address `json:"fee_recipients"`
	GasLimitMin                  uint64            `json:"gas_limit_min"`
	GasLimitMax                  uint64            `json:"gas_limit_max"`
	RegistrationMaxFutureSeconds uint64            `json:"registration_max_future_seconds"`
	CommitAhead                  struct {
		BlockSlots   uint64 `json:"block_slots"`
		SourceEpochs uint64 `json:"source_epochs"`
		TargetEpochs uint64 `json:"target_epochs"`
	} `json:"commit_ahead"`
	AllowUnverifiedNonslashable bool    `json:"allow_unverified_nonslashable"`
	Preset                      string  `json:"preset,omitempty"`
	GloasForkEpoch              *uint64 `json:"gloas_fork_epoch,omitempty"`
}

type chainFork struct {
	Epoch   uint64          `json:"epoch"`
	Version backend.Version `json:"version"`
}

// ParseChainFile reads a runner chain.json strictly.
func ParseChainFile(b []byte) (*ChainFile, error) {
	var c ChainFile
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("chain.json: %w", err)
	}
	if c.SecondsPerSlot == 0 || c.SlotsPerEpoch == 0 {
		return nil, errors.New("chain.json: seconds_per_slot and slots_per_epoch must be non-zero")
	}
	return &c, nil
}

// preset is the preset in force, as core.Config.PresetName decides it.
func (c *ChainFile) preset() string {
	switch {
	case c.Preset != "":
		return c.Preset
	case c.SlotsPerEpoch == 8:
		return "minimal"
	}
	return "mainnet"
}

// Schedule is the file's fork schedule as a setup holds it: one fork per
// epoch. Where the file lists several forks at one epoch (Hoodi starts at
// epoch 0 with four), the last one is in force from that epoch, so it is
// the one kept: the signer computes the same domain for every epoch.
func (c *ChainFile) Schedule() ([]setupwire.Fork, error) {
	var out []setupwire.Fork
	for i, f := range c.Forks {
		if i > 0 && f.Epoch < c.Forks[i-1].Epoch {
			return nil, errors.New("chain.json: forks must be in ascending epoch order")
		}
		if n := len(out); n > 0 && out[n-1].Epoch == f.Epoch {
			out[n-1].Version = f.Version
			continue
		}
		out = append(out, setupwire.Fork{Epoch: f.Epoch, Version: f.Version})
	}
	return out, nil
}

// CompareChain refuses a setup whose chain identity or first fork schedule
// differs from the chain file's: the fields cloud/chains/chain.sh calls
// chain fields, with the forks as Schedule gives them.
func CompareChain(s *setupwire.Setup, c *ChainFile) error {
	sched, err := c.Schedule()
	if err != nil {
		return err
	}
	ch := &s.Chain
	var diffs []string
	diff := func(name string, setup, file any) {
		if fmt.Sprint(setup) != fmt.Sprint(file) {
			diffs = append(diffs, fmt.Sprintf("%s: setup %v, chain.json %v", name, setup, file))
		}
	}
	forks := func(fs []setupwire.Fork) string {
		parts := make([]string, len(fs))
		for i, f := range fs {
			parts[i] = fmt.Sprintf("%d:%#x", f.Epoch, f.Version[:])
		}
		return "[" + strings.Join(parts, " ") + "]"
	}
	diff("genesis_validators_root", fmt.Sprintf("%#x", ch.GenesisValidatorsRoot[:]), fmt.Sprintf("%#x", c.GenesisValidatorsRoot[:]))
	diff("genesis_fork_version", fmt.Sprintf("%#x", ch.GenesisForkVersion[:]), fmt.Sprintf("%#x", c.GenesisForkVersion[:]))
	diff("genesis_time", ch.GenesisTime, c.GenesisTime)
	diff("seconds_per_slot", ch.SecondsPerSlot, c.SecondsPerSlot)
	diff("slots_per_epoch", ch.SlotsPerEpoch, c.SlotsPerEpoch)
	diff("preset", ch.Preset, c.preset())
	diff("voluntary_exit_fork_version", fmt.Sprintf("%#x", ch.VoluntaryExitForkVersion[:]), fmt.Sprintf("%#x", c.VoluntaryExitForkVersion[:]))
	diff("fork_schedule", forks(s.Open.ForkSchedule), forks(sched))
	gloas := func(p *uint64) string {
		if p == nil {
			return "none"
		}
		return fmt.Sprint(*p)
	}
	diff("gloas_fork_epoch", gloas(s.Open.GloasForkEpoch), gloas(c.GloasForkEpoch))
	if len(diffs) > 0 {
		return fmt.Errorf("the setup is not of this chain: %s", strings.Join(diffs, "; "))
	}
	return nil
}

// ChainLines writes the chain, safety and open parts of a human setup file
// from a chain file, and the locked values the file holds, for an operator
// who builds a setup for a chain (cloud/azure/chain-from-devnet.sh writes
// a devnet's chain.json). The rest of the setup (names, platform,
// approvers) is the operator's.
func ChainLines(c *ChainFile) (string, error) {
	sched, err := c.Schedule()
	if err != nil {
		return "", err
	}
	var b strings.Builder
	kv := func(k string, v any) { fmt.Fprintf(&b, "%s = %v\n", k, v) }
	hex := func(p []byte) string { return fmt.Sprintf("0x%x", p) }
	b.WriteString("# chain: fixed for the life of the signer\n")
	kv("genesis_validators_root", hex(c.GenesisValidatorsRoot[:]))
	kv("genesis_fork_version", hex(c.GenesisForkVersion[:]))
	kv("genesis_time", c.GenesisTime)
	kv("seconds_per_slot", c.SecondsPerSlot)
	kv("slots_per_epoch", c.SlotsPerEpoch)
	kv("preset", c.preset())
	kv("voluntary_exit_fork_version", hex(c.VoluntaryExitForkVersion[:]))
	b.WriteString("\n# safety: fixed; the floor margin is max_sign_epochs_ahead_of_clock + 1\n")
	kv("max_sign_epochs_ahead_of_clock", c.MaxEpochsAhead)
	kv("slashing_mark_prewrite.block_slots", c.CommitAhead.BlockSlots)
	kv("slashing_mark_prewrite.source_epochs", c.CommitAhead.SourceEpochs)
	kv("slashing_mark_prewrite.target_epochs", c.CommitAhead.TargetEpochs)
	b.WriteString("\n# locked: the values chain.json holds; add the others\n")
	for _, a := range c.FeeRecipients {
		kv("allowed_fee_recipients", hex(a[:]))
	}
	kv("builder_gas_limit_min", c.GasLimitMin)
	kv("builder_gas_limit_max", c.GasLimitMax)
	kv("builder_registration_max_future_seconds", c.RegistrationMaxFutureSeconds)
	for _, i := range c.ExitAllowlist {
		kv("exit_allowed_validators", i)
	}
	kv("allow_unverified_nonslashable_signing", c.AllowUnverifiedNonslashable)
	b.WriteString("\n# open: the fork schedule, one fork per epoch\n")
	for _, f := range sched {
		kv("fork_schedule", fmt.Sprintf("%d %s", f.Epoch, hex(f.Version[:])))
	}
	if c.GloasForkEpoch != nil {
		kv("gloas_fork_epoch", *c.GloasForkEpoch)
	}
	return b.String(), nil
}
