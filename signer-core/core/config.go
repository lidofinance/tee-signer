package core

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/bits"
	"os"

	"github.com/lidofinance/tee-signer/signer-protocol"
)

// Fork is one entry of the fork schedule.
type Fork struct {
	Epoch   uint64          `json:"epoch"`
	Version backend.Version `json:"version"`
}

// CommitAhead sets how far past a signed message the durable watermark
// reaches (see the signer core README, "Commit ahead").
type CommitAhead struct {
	BlockSlots   uint64 `json:"block_slots"`
	SourceEpochs uint64 `json:"source_epochs"`
	TargetEpochs uint64 `json:"target_epochs"`
}

// Config is the chain and policy configuration of a signer, the Go form of
// sc_config. In an enclave it must be part of the measured image or bound
// into the attestation (the runner binds its sha256).
type Config struct {
	GenesisValidatorsRoot    backend.Root    `json:"genesis_validators_root"`
	GenesisForkVersion       backend.Version `json:"genesis_fork_version"`
	Forks                    []Fork          `json:"forks"`
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

	// BuilderRequestAuthRoots lists the hash_tree_root of each data value a
	// BuilderRequestAuth may carry (backend.BuilderRequestAuthDataRoot);
	// empty refuses them all. A config without it keeps its bytes.
	BuilderRequestAuthRoots []backend.Root `json:"builder_request_auth_roots,omitempty"`

	CommitAhead CommitAhead `json:"commit_ahead"`

	// AllowUnverifiedNonslashable lets the runner sign bare roots
	// (RootMessage) of every type but RANDAO: selection proof, aggregate and
	// proof, sync committee message, sync selection proof, contribution and
	// proof, and from the Gloas fork on PTC vote, payload envelope and
	// proposer preferences. Dirk's generic Sign sends them for stock clients
	// when it cannot find the message behind the root. The runner cannot
	// check those: each such signature is unverified. They cannot slash. As
	// bare roots the Gloas ones skip the fee recipient, gas limit and
	// one-per-slot checks of their typed kinds. Off
	// (absent) refuses them all. The typed kinds (9 to 13) carry the whole
	// message, the core checks it, and they sign whatever this says.
	AllowUnverifiedNonslashable bool `json:"allow_unverified_nonslashable"`

	// Preset is the consensus preset whose sizes the aggregate and sync
	// committee messages use: "mainnet" or "minimal". Absent: minimal when
	// slots_per_epoch is 8, else mainnet. A config without it keeps its
	// bytes and hash.
	Preset string `json:"preset,omitempty"`

	// GloasForkEpoch is the chain's GLOAS_FORK_EPOCH, which must be the
	// epoch of an entry in Forks. Absent (nil): Gloas is not scheduled and
	// the core refuses every Gloas message (PTC vote, payload envelope,
	// proposer preferences). A config without it keeps its bytes, so its
	// hash and the images built from it stay the same.
	GloasForkEpoch *uint64 `json:"gloas_fork_epoch,omitempty"`

	// DeviceMark is the core's SC_MARKS_PER_DEVICE: one mark for every
	// validator, kept by DeviceMarkHooks. Not part of the chain config file:
	// the runner sets it when it keeps its mark in a mark store (-mark-store).
	DeviceMark bool `json:"-"`

	// SlotTimeChanges are the slot time changes in force (the core's
	// sc_slot_times; a setup's locked slot_time_changes): from the first slot
	// of Epoch on, a slot lasts SecondsPerSlot seconds. SecondsPerSlot above
	// is the genesis slot time. Absent: one slot time from genesis on, and a
	// config without it keeps its bytes and hash.
	SlotTimeChanges []SlotTimeChange `json:"slot_time_changes,omitempty"`
}

// SlotTimeChange is one slot time change.
type SlotTimeChange struct {
	Epoch          uint64 `json:"epoch"`
	SecondsPerSlot uint64 `json:"seconds_per_slot"`
}

// LoadConfig reads a JSON config file and returns it with the raw bytes.
func LoadConfig(path string) (Config, []byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Config{}, nil, err
	}
	var c Config
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return Config{}, nil, fmt.Errorf("%s: %w", path, err)
	}
	return c, raw, c.Validate()
}

// Validate checks what the core would reject, with readable errors.
func (c *Config) Validate() error {
	switch {
	case c.SecondsPerSlot == 0 || c.SlotsPerEpoch == 0:
		return errors.New("config: seconds_per_slot and slots_per_epoch must be non-zero")
	case len(c.Forks) > maxForks:
		return fmt.Errorf("config: at most %d forks", maxForks)
	case len(c.ExitAllowlist) > maxExitAllowlist:
		return fmt.Errorf("config: at most %d exit_allowlist entries", maxExitAllowlist)
	case len(c.FeeRecipients) > maxFeeRecipients:
		return fmt.Errorf("config: at most %d fee_recipients", maxFeeRecipients)
	case len(c.BuilderRequestAuthRoots) > maxBuilderAuthRoots:
		return fmt.Errorf("config: at most %d builder_request_auth_roots", maxBuilderAuthRoots)
	case c.GasLimitMin > c.GasLimitMax:
		return errors.New("config: gas_limit_min > gas_limit_max")
	}
	for i := 1; i < len(c.Forks); i++ {
		if c.Forks[i].Epoch < c.Forks[i-1].Epoch {
			return errors.New("config: forks must be in ascending epoch order")
		}
	}
	switch c.Preset {
	case "", "mainnet", "minimal":
	default:
		return fmt.Errorf("config: preset %q, want mainnet or minimal", c.Preset)
	}
	if c.GloasForkEpoch != nil {
		found := false
		for _, f := range c.Forks {
			found = found || f.Epoch == *c.GloasForkEpoch
		}
		if !found {
			return fmt.Errorf("config: gloas_fork_epoch %d is not the epoch of a fork in forks", *c.GloasForkEpoch)
		}
	}
	return checkSlotTimes(c, c.SlotTimeChanges)
}

// checkSlotTimes is sc_slot_times_check: at most maxSlotTimes changes,
// epochs ascending and above 0, each change another slot time than the one
// before it, and every product and start time within 64 bits.
func checkSlotTimes(c *Config, changes []SlotTimeChange) error {
	if len(changes) > maxSlotTimes {
		return fmt.Errorf("config: at most %d slot_time_changes", maxSlotTimes)
	}
	startSlot, start, secs := uint64(0), c.GenesisTime, c.SecondsPerSlot
	for i, ch := range changes {
		switch {
		case ch.Epoch == 0 || ch.SecondsPerSlot == 0:
			return errors.New("config: slot_time_changes: epoch and seconds_per_slot must be non-zero")
		case i > 0 && ch.Epoch <= changes[i-1].Epoch:
			return errors.New("config: slot_time_changes must be in ascending epoch order")
		case ch.SecondsPerSlot == secs:
			return fmt.Errorf("config: slot_time_changes: epoch %d keeps the slot time before it", ch.Epoch)
		}
		if hi, _ := bits.Mul64(ch.SecondsPerSlot, c.SlotsPerEpoch); hi != 0 {
			return errors.New("config: slot_time_changes: an epoch's length overflows 64 bits")
		}
		hi, slot := bits.Mul64(ch.Epoch, c.SlotsPerEpoch)
		hi2, dur := bits.Mul64(slot-startSlot, secs)
		s, carry := bits.Add64(start, dur, 0)
		if hi != 0 || hi2 != 0 || carry != 0 {
			return errors.New("config: slot_time_changes: the start of a change does not fit 64 bits")
		}
		startSlot, start, secs = slot, s, ch.SecondsPerSlot
	}
	return nil
}

// PresetName is the preset in force: Preset, else minimal for 8 slots per
// epoch and mainnet otherwise.
func (c *Config) PresetName() string {
	switch {
	case c.Preset != "":
		return c.Preset
	case c.SlotsPerEpoch == 8:
		return "minimal"
	}
	return "mainnet"
}

// SlotAt is the slot at unix time t (0 before genesis) under the genesis
// slot time and SlotTimeChanges, piece by piece, like sc_slot_at.
func (c *Config) SlotAt(t uint64) uint64 {
	if t <= c.GenesisTime || c.SecondsPerSlot == 0 {
		return 0
	}
	startSlot, start, secs := uint64(0), c.GenesisTime, c.SecondsPerSlot
	for _, ch := range c.SlotTimeChanges {
		hi, slot := bits.Mul64(ch.Epoch, c.SlotsPerEpoch)
		if hi != 0 || slot < startSlot {
			break
		}
		hi, dur := bits.Mul64(slot-startSlot, secs)
		end, carry := bits.Add64(start, dur, 0)
		if hi != 0 || carry != 0 || t < end {
			break
		}
		startSlot, start, secs = slot, end, ch.SecondsPerSlot
	}
	if s, carry := bits.Add64(startSlot, (t-start)/secs, 0); carry == 0 {
		return s
	}
	return math.MaxUint64
}

// EpochAt is the epoch at unix time t (0 before genesis), like sc_epoch_at.
func (c *Config) EpochAt(t uint64) uint64 {
	if c.SlotsPerEpoch == 0 {
		return 0
	}
	return c.SlotAt(t) / c.SlotsPerEpoch
}

// SecondsPerSlotAt is the slot time of epoch e.
func (c *Config) SecondsPerSlotAt(e uint64) uint64 {
	s := c.SecondsPerSlot
	for _, ch := range c.SlotTimeChanges {
		if ch.Epoch <= e {
			s = ch.SecondsPerSlot
		}
	}
	return s
}

// WithSlotTimes returns a copy of c with the slot time changes changes.
func (c Config) WithSlotTimes(changes []SlotTimeChange) Config {
	c.SlotTimeChanges = append([]SlotTimeChange(nil), changes...)
	return c
}

// ForkVersionAt is the fork version active at epoch.
func (c *Config) ForkVersionAt(epoch uint64) backend.Version {
	v := c.GenesisForkVersion
	for _, f := range c.Forks {
		if f.Epoch <= epoch {
			v = f.Version
		}
	}
	return v
}

// Domain computes the domain the core uses for dt at epoch: exits use the
// configured exit fork version (EIP-7044), builder registrations use the
// genesis fork version and a zero genesis validators root.
func (c *Config) Domain(dt backend.DomainType, epoch uint64) backend.Root {
	switch dt {
	case backend.DomainApplicationBuilder, backend.DomainBuilderRequestAuth:
		return backend.ComputeDomain(dt, c.GenesisForkVersion, backend.Root{})
	case backend.DomainVoluntaryExit:
		return backend.ComputeDomain(dt, c.VoluntaryExitForkVersion, c.GenesisValidatorsRoot)
	}
	return backend.ComputeDomain(dt, c.ForkVersionAt(epoch), c.GenesisValidatorsRoot)
}

// MessageDomain is the domain the core signs m under, from this chain config
// and its fork schedule: the domain type of m's kind and the fork version of
// its epoch, with Domain's rules for exits and builder registrations. For a
// RootMessage it is the domain of its type at its epoch. Aggregates and
// contributions go through the C core's decoder for their slot. An unknown
// message type is a *backend.RefusedError with StatusUnsupported.
func (c *Config) MessageDomain(m backend.Message) (backend.Root, error) {
	var dt backend.DomainType
	var epoch uint64
	switch v := m.(type) {
	case *backend.AttestationData:
		dt, epoch = backend.DomainBeaconAttester, v.Target.Epoch
	case *backend.BeaconBlockHeader:
		dt, epoch = backend.DomainBeaconProposer, v.Slot/c.SlotsPerEpoch
	case *backend.VoluntaryExit:
		dt, epoch = backend.DomainVoluntaryExit, v.Epoch
	case *backend.ValidatorRegistration:
		dt = backend.DomainApplicationBuilder
	case *backend.RootMessage:
		t, ok := v.Type.DomainType()
		if !ok {
			return backend.Root{}, backend.Refused(backend.StatusUnsupported, "root message type %d", v.Type)
		}
		dt, epoch = t, v.Epoch
	case *backend.PayloadAttestationData:
		dt, epoch = backend.DomainPTCAttester, v.Slot/c.SlotsPerEpoch
	case *backend.PayloadEnvelope:
		dt, epoch = backend.DomainBeaconBuilder, v.Payload.SlotNumber/c.SlotsPerEpoch
	case *backend.ProposerPreferences:
		dt, epoch = backend.DomainProposerPreferences, v.ProposalSlot/c.SlotsPerEpoch
	case *backend.BuilderRequestAuth:
		dt = backend.DomainBuilderRequestAuth
	default:
		_, t, slot, ok, err := c.typedParts(m)
		if err != nil {
			return backend.Root{}, err
		}
		if !ok {
			return backend.Root{}, backend.Refused(backend.StatusUnsupported, "message type %T", m)
		}
		dt, epoch = t, slot/c.SlotsPerEpoch
	}
	return c.Domain(dt, epoch), nil
}

// SigningRoot computes the signing root of m for this chain, independent of
// the C core. Tests use it to check signatures. A RootMessage is signed
// under its own Domain.
func (c *Config) SigningRoot(m backend.Message) (backend.Root, error) {
	if r, ok, err := c.typedSigningRoot(m); ok {
		return r, err
	}
	obj, err := backend.HashTreeRoot(m)
	if err != nil {
		return backend.Root{}, err
	}
	if v, ok := m.(*backend.RootMessage); ok {
		return backend.SigningRoot(obj, v.Domain), nil
	}
	domain, err := c.MessageDomain(m)
	if err != nil {
		return backend.Root{}, err
	}
	return backend.SigningRoot(obj, domain), nil
}

// Schedule is a fork schedule: the forks and the Gloas fork epoch of a
// Config, the values an `open` config update replaces (Signer.SetSchedule).
type Schedule struct {
	Forks          []Fork  `json:"forks"`
	GloasForkEpoch *uint64 `json:"gloas_fork_epoch,omitempty"`
}

// Schedule returns a copy of c's fork schedule.
func (c *Config) Schedule() Schedule {
	s := Schedule{Forks: append([]Fork(nil), c.Forks...)}
	if c.GloasForkEpoch != nil {
		e := *c.GloasForkEpoch
		s.GloasForkEpoch = &e
	}
	return s
}

// WithSchedule returns a copy of c with the fork schedule s.
func (c Config) WithSchedule(s Schedule) Config {
	c.Forks = append([]Fork(nil), s.Forks...)
	c.GloasForkEpoch = nil
	if s.GloasForkEpoch != nil {
		e := *s.GloasForkEpoch
		c.GloasForkEpoch = &e
	}
	return c
}

// Policy is the signing policy of a Config: the values of a `locked` config
// update that the cloud runner signs by (Signer.SetPolicy).
type Policy struct {
	ExitAllowlist                []uint64          `json:"exit_allowlist"`
	FeeRecipients                []backend.Address `json:"fee_recipients"`
	GasLimitMin                  uint64            `json:"gas_limit_min"`
	GasLimitMax                  uint64            `json:"gas_limit_max"`
	RegistrationMaxFutureSeconds uint64            `json:"registration_max_future_seconds"`
	AllowUnverifiedNonslashable  bool              `json:"allow_unverified_nonslashable"`
	BuilderRequestAuthRoots      []backend.Root    `json:"builder_request_auth_roots,omitempty"`
}

// Policy returns a copy of c's signing policy.
func (c *Config) Policy() Policy {
	return Policy{
		ExitAllowlist:                append([]uint64(nil), c.ExitAllowlist...),
		FeeRecipients:                append([]backend.Address(nil), c.FeeRecipients...),
		GasLimitMin:                  c.GasLimitMin,
		GasLimitMax:                  c.GasLimitMax,
		RegistrationMaxFutureSeconds: c.RegistrationMaxFutureSeconds,
		AllowUnverifiedNonslashable:  c.AllowUnverifiedNonslashable,
		BuilderRequestAuthRoots:      append([]backend.Root(nil), c.BuilderRequestAuthRoots...),
	}
}

// WithPolicy returns a copy of c with the signing policy p.
func (c Config) WithPolicy(p Policy) Config {
	c.ExitAllowlist = append([]uint64(nil), p.ExitAllowlist...)
	c.FeeRecipients = append([]backend.Address(nil), p.FeeRecipients...)
	c.GasLimitMin, c.GasLimitMax = p.GasLimitMin, p.GasLimitMax
	c.RegistrationMaxFutureSeconds = p.RegistrationMaxFutureSeconds
	c.AllowUnverifiedNonslashable = p.AllowUnverifiedNonslashable
	c.BuilderRequestAuthRoots = append([]backend.Root(nil), p.BuilderRequestAuthRoots...)
	return c
}
