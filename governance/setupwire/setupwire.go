// Package setupwire holds the setup of a signer and its config updates: the
// binary encoding, its strict decoder, the human "key = value" form, the
// salted policy tree and the platform commitment that setup_hash covers
// (policy.go), the registry of signing contexts, and the value checks that
// need no clock or stored state. The runner and signer-config use it.
// attestation-verify/docs/attestation-statement.md gives the layouts and
// hashes byte by byte.
//
// A setup has a public part and a private part.
// The public part holds the chain, the safety values, max_keys,
// slashing_log_min_lock_days and both config groups; every field of it is a
// leaf of the policy tree, with a salt of its own. The private part is the
// rest of the platform part, committed by one salted hash. setup_hash is
// SHA-256 over policy_root and platform_commitment, so a verifier who gets
// the policy leaves learns nothing of the private part.
//
// Integers are big endian. str is len:u8 and 1 to 255 bytes. A list has a
// count and a cap. An optional field has a presence byte, 0 or 1. Lists
// without an order of their own (CA certificates, tags, images, fee
// recipients, exit allowlist, deposit amounts, BuilderRequestAuth data
// roots, peer attestation hosts) are
// sorted and hold no duplicates, forks and slot time changes are in
// ascending epoch order, and the approver list keeps its order, because
// signatures name positions in it. Enum values start at 1, so a zero byte
// is never a valid choice.
//
//	setup    = 'S' public public_salts locked locked_salts open open_salts
//	           platform_salt[32] private
//	public   = setup_format_version:u8(1) cluster_id[32] handover_generation:u64
//	           chain safety max_keys:u32 slashing_log_min_lock_days:u32
//	chain    = genesis_validators_root[32] genesis_fork_version[4] genesis_time:u64
//	           seconds_per_slot:u64 slots_per_epoch:u64 preset:u8 voluntary_exit_fork_version[4]
//	safety   = max_sign_epochs_ahead_of_clock:u64 slashing_mark_prewrite.block_slots:u64
//	           slashing_mark_prewrite.source_epochs:u64 slashing_mark_prewrite.target_epochs:u64
//	locked   = n:u8 {key[32]} approvals_needed:u8 has:u8 [change_delay_seconds:u64]
//	           image_count:u8 {kind:u8 measurement[144 nitro, else 32]}
//	           fee_count:u8 {address[20]} builder_gas_limit_min:u64 builder_gas_limit_max:u64
//	           builder_registration_max_future_seconds:u64 exit_count:u16 {index:u64}
//	           exit_stake_cap_per_day:u64 exit_approvals_needed:u8
//	           min_activation_balance:u64 max_effective_balance:u64
//	           withdrawal_credentials[32] deposit_count:u8 {amount:u64}
//	           allow_unverified_nonslashable_signing:u8 bare_root_domains:u16
//	           slot_time_change_count:u8 {epoch:u64 seconds_per_slot:u64}
//	           builder_request_auth_count:u8 {data_root[32]}
//	open    = fork_count:u8 {epoch:u64 version[4]} has:u8 [gloas_fork_epoch:u64]
//	X_salts  = salt[32] for each leaf of group X, in leaf order (policy.go)
//	private  = signer_name:str platform:u8 ca_count:u8 {der_len:u16 der}
//	           slashing_log_store has:u8 [encrypted_state_store] sealing_key_release
//	           host_count:u8 {host_port:str}
//	store    = nitro: bucket:str region:str
//	           | azure: account:str container:str subscription:str resource_group:str
//	           | gcp: bucket:str | dev: dir:str
//	sealing_key_release = nitro: region:str kms_key_id:str
//	           | azure: maa_endpoint:str akv_endpoint:str kid:str
//	           | gcp: wif_provider:str kms_key:str attest_audience:str no_lock_accepted:u8
//	                  unsafe_single_key_accepted:u8
//	           | dev: (nothing)
//
// Each field of public, locked and open is one leaf of the policy tree, and
// its bytes above are the leaf's value. The platform byte decides the
// layout of the stores and the key release. Amounts are Gwei. update.go has
// the CONFIG_UPDATE layout.
//
// The dev platform is for local runners and tests (the runner's -platform
// dev). It protects nothing. A dev setup differs from a cloud one in three
// places: its stores are local directories (dir, an absolute path that the
// runner opens as a file: store), it has no key release fields (the dev
// platform's key is fixed in the binary), and it may list peer attestation
// hosts for a local test. A cloud image refuses it (CheckPlatform).
package setupwire

import (
	"bytes"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"math/bits"
	"path"
	"regexp"
	"slices"
	"strings"

	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/buildflavor"
)

const (
	// FormatVersion is setup_format_version, the setup's second byte.
	FormatVersion = 1

	kindSetup  = 'S'
	kindBody   = 'B'
	kindUpdate = 'U'
)

// Image constants; the times are
// the build flavour's (backend/buildflavor). MaxKeysCap is "above 5,000" there.
const (
	DefaultTimeLock   = buildflavor.TimeLock // seconds, when the setup names no change delay
	MaxTimeLock       = buildflavor.MaxTimeLock
	ActivationHorizon = buildflavor.ActivationHorizon // past the required wait
	ImagesMinTimeLock = buildflavor.ImagesMinTimeLock
	MaxKeysCap        = 8192
	MaxSetup          = 64 << 10 // bytes
	MaxAllowedImages  = 32
)

// Caps of the other lists and values.
const (
	MaxAllowedClientCA = 4
	MaxForks           = 16   // SC_MAX_FORKS
	MaxExitAllowlist   = 1024 // SC_MAX_EXIT_ALLOWLIST
	MaxFeeRecipients   = 64   // SC_MAX_FEE_RECIPIENTS
	MaxDepositAmounts  = 8
	MaxPeerHosts       = 16  // the Nitro port map's block for them (runner/setup)
	MaxSignerName      = 128 // markstore.CheckSigner
	MaxSlotTimeChanges = 16  // SC_MAX_SLOT_TIME_CHANGES
	// MaxBuilderRequestAuthDataRoots caps allowed_builder_request_auth_data_roots.
	MaxBuilderRequestAuthDataRoots = 16
	// MaxLockDays is 100 years, the longest Object Lock retention S3 takes;
	// a longer one could never pass the runner's lock check.
	MaxLockDays = 36500
)

// MaxPlatformPrivate caps the private part, the bytes platform_commitment
// covers. The attestation circuits hash it with a fixed bound (MAX_PRIVATE
// in circuits/lib/src/platform.nr), so a setup with a longer private part
// could never be proven. Four P-256 client CA certificates take about 2 KB.
const MaxPlatformPrivate = 2560 // bytes

// Ranges of the safety values. A huge max_sign_epochs_ahead_of_clock would switch the clock
// guard off; a huge prewrite would let one vote raise the stored mark far
// past the clock.
const (
	MinSignEpochsAhead = 1
	MaxSignEpochsAhead = 16
	MaxPrewriteSlots   = 64 // slashing_mark_prewrite.block_slots
	MaxPrewriteEpochs  = 8  // slashing_mark_prewrite.source_epochs and target_epochs
)

// Platform is the platform a setup is for.
type Platform uint8

const (
	PlatformNitro Platform = 1
	PlatformAzure Platform = 2
	PlatformGCP   Platform = 3
	PlatformDev   Platform = 4 // local runners and tests, protects nothing
)

// Preset is the consensus preset.
type Preset uint8

const (
	PresetMainnet Preset = 1
	PresetMinimal Preset = 2
)

// Group is one of the two config groups (section 6).
type Group uint8

const (
	GroupLocked Group = 1 // waits for the change delay
	GroupOpen   Group = 2 // no change delay
)

// ImageKind is the platform of an allowed image.
type ImageKind uint8

const (
	ImageNitro ImageKind = 1 // PCR0, PCR1, PCR2
	ImageAzure ImageKind = 2 // CCE policy hash
	ImageGCP   ImageKind = 3 // image digest (sha256)
	ImageTA    ImageKind = 4 // TA hash
)

var (
	platformNames = []string{PlatformNitro: "nitro", PlatformAzure: "azure", PlatformGCP: "gcp", PlatformDev: "dev"}
	presetNames   = []string{PresetMainnet: "mainnet", PresetMinimal: "minimal"}
	groupNames    = []string{GroupLocked: "locked", GroupOpen: "open"}
	imageNames    = []string{ImageNitro: "nitro", ImageAzure: "azure", ImageGCP: "gcp", ImageTA: "ta"}
	// rootDomainNames is indexed by bit: bit n is domain type 0x0n000000.
	rootDomainNames = []string{2: "randao", 5: "selection_proof", 6: "aggregate_and_proof",
		7: "sync_committee", 8: "sync_committee_selection_proof", 9: "contribution_and_proof"}
)

func enumName(names []string, v uint8) string {
	if int(v) < len(names) && names[v] != "" {
		return names[v]
	}
	return fmt.Sprintf("%d", v)
}

func enumValue(names []string, s string) (uint8, bool) {
	for i, n := range names {
		if n != "" && n == s {
			return uint8(i), true
		}
	}
	return 0, false
}

func enumValid(names []string, v uint8) bool { return int(v) < len(names) && names[v] != "" }

func (p Platform) String() string  { return enumName(platformNames, uint8(p)) }
func (p Preset) String() string    { return enumName(presetNames, uint8(p)) }
func (g Group) String() string     { return enumName(groupNames, uint8(g)) }
func (k ImageKind) String() string { return enumName(imageNames, uint8(k)) }

// ParsePlatform reads nitro, azure, gcp or dev.
func ParsePlatform(s string) (Platform, error) {
	if v, ok := enumValue(platformNames, s); ok {
		return Platform(v), nil
	}
	return 0, fmt.Errorf("platform %q, want nitro, azure, gcp or dev", s)
}

// The names of the enum values, indexed by value ("" for an unused value),
// for the human form (governance/setuptext).
func PresetNames() []string    { return slices.Clone(presetNames) }
func GroupNames() []string     { return slices.Clone(groupNames) }
func ImageKindNames() []string { return slices.Clone(imageNames) }

// RootDomainNames is indexed by bit: bit n is domain type 0x0n000000.
func RootDomainNames() []string { return slices.Clone(rootDomainNames) }

// Size is the length of a measurement of this kind.
func (k ImageKind) Size() int {
	switch k {
	case ImageNitro:
		return 3 * 48
	case ImageAzure, ImageGCP, ImageTA:
		return 32
	}
	return 0
}

// Setup is the one-time setup (section 2). Locked and Open are version 0
// of the two config groups. ClusterID to Open, with PolicySalts, make the
// public part (the policy tree); SignerName and Platform, with
// PlatformSalt, the private part.
type Setup struct {
	ClusterID              [32]byte
	HandoverGeneration     uint64
	Chain                  Chain
	Safety                 Safety
	MaxKeys                uint32
	SlashingLogMinLockDays uint32
	Locked                 Locked
	Open                   Open
	// PolicySalts are the salts of the policy leaves. signer-config setup
	// draws them once per cluster, so every signer of a cluster with the
	// same public values has the same policy_root.
	PolicySalts PolicySalts

	SignerName string
	Platform   PlatformConfig
	// PlatformSalt is the salt of platform_commitment, one per signer.
	PlatformSalt [32]byte
}

// Chain is the chain identity. It never changes.
type Chain struct {
	GenesisValidatorsRoot    backend.Root
	GenesisForkVersion       backend.Version
	GenesisTime              uint64
	SecondsPerSlot           uint64
	SlotsPerEpoch            uint64
	Preset                   Preset
	VoluntaryExitForkVersion backend.Version
}

// SlashingMarkPrewrite is core.CommitAhead: how far past a signed message
// the stored mark is written ahead.
type SlashingMarkPrewrite struct {
	BlockSlots   uint64
	SourceEpochs uint64
	TargetEpochs uint64
}

// Safety holds the slashing settings. The floor margin is
// MaxSignEpochsAheadOfClock + 1.
type Safety struct {
	MaxSignEpochsAheadOfClock uint64
	SlashingMarkPrewrite      SlashingMarkPrewrite
}

// PlatformConfig is the setup's private platform part.
type PlatformConfig struct {
	Platform            Platform
	AllowedClientCA     [][]byte // DER CA certificates, sorted
	SlashingLogStore    Store
	EncryptedStateStore *Store // Azure, GCP and dev only; nil: none
	SealingKeyRelease   KeyRelease
	// PeerAttestationHosts are the host:port names that the runner's
	// attestation verifier fetches key sets from over HTTPS when it checks
	// the other image of a handover: an Azure peer's MAA host, Google's
	// Confidential Space issuer and key host.
	// Nitro and dev only: a Nitro enclave reaches no host but the routes of
	// its setup, and on dev the list limits the runner the same way, for
	// tests. Sorted, without repeats.
	PeerAttestationHosts []string
}

// Store names a bucket. The platform decides the fields: Nitro (S3) Bucket
// and Region, Azure (Blob) Account, Container, Subscription and
// ResourceGroup, GCP (GCS) Bucket, dev (a local directory) Dir. An Azure
// store names the account's subscription and resource group because the
// lock check reads the container's immutability policy from the management
// plane, which addresses the account by them.
type Store struct {
	Bucket        string
	Region        string
	Account       string
	Container     string
	Subscription  string
	ResourceGroup string
	Dir           string
}

// KeyRelease names the sealing key-release resources. Nitro: Region and
// KMSKeyID. Azure: MAAEndpoint, AKVEndpoint and KID. GCP: WIFProvider,
// KMSKey and AttestAudience. Dev: none.
type KeyRelease struct {
	Region         string
	KMSKeyID       string
	MAAEndpoint    string
	AKVEndpoint    string
	KID            string
	WIFProvider    string
	KMSKey         string
	AttestAudience string
	// NoLockAccepted (GCP only, sealing_key_release.no_lock_accepted): the
	// setup accepts that Cloud KMS has no lock on the rule of the key that
	// releases the sealing key. Without it a mainnet runner on GCP does
	// not start (platform.Options.CheckKeyRule).
	NoLockAccepted bool
	// UnsafeSingleKeyAccepted (GCP only,
	// sealing_key_release.unsafe_single_key_accepted): the setup accepts
	// that this signer holds keys alone (an import order with t = n = 1).
	// Without it a GCP signer refuses such an order (CheckThresholdOn):
	// see UnsafeSingleKeyWarning. signer-admin setup sets it with
	// -allow-gcp-unsafe-single-key.
	UnsafeSingleKeyAccepted bool
}

// Image is an entry of the allowed-images list.
type Image struct {
	Kind        ImageKind
	Measurement []byte // Kind.Size() bytes
}

// RootDomains is a set of domain types for bare roots: bit n is domain
// type 0x0n000000. Only the bits rootDomainNames names may be set.
type RootDomains uint16

// SlotTimeChange starts a new slot time: from the first slot of Epoch on,
// a slot lasts SecondsPerSlot seconds. slots_per_epoch never changes.
type SlotTimeChange struct {
	Epoch          uint64
	SecondsPerSlot uint64
}

// Locked is the config group that waits for the change delay.
type Locked struct {
	Approvers ApproverSet
	// ChangeDelaySeconds nil: DefaultTimeLock. 0: no change delay.
	ChangeDelaySeconds                  *uint64
	AllowedImageMeasurements            []Image           // sorted
	AllowedFeeRecipients                []backend.Address // sorted
	BuilderGasLimitMin                  uint64
	BuilderGasLimitMax                  uint64
	BuilderRegistrationMaxFutureSeconds uint64
	ExitAllowedValidators               []uint64 // sorted validator indices
	ExitStakeCapPerDay                  uint64   // Gwei
	ExitApprovalsNeeded                 uint8
	MinActivationBalance                uint64 // Gwei
	MaxEffectiveBalance                 uint64 // Gwei
	WithdrawalCredentials               backend.Root
	AllowedDepositAmounts               []uint64 // Gwei, sorted
	AllowUnverifiedNonslashableSigning  bool
	BareRootDomains                     RootDomains
	// SlotTimeChanges are the slot time changes after genesis, ascending
	// epochs. The genesis slot time is Chain.SecondsPerSlot.
	SlotTimeChanges []SlotTimeChange
	// AllowedBuilderRequestAuthDataRoots are the BuilderRequestAuth data the
	// signer signs: each entry is hash_tree_root of the data field as SSZ
	// ByteList[4096] (builder-specs, Gloas). Threshold keys can then use the
	// builder API, not only p2p bids and self-build. Sorted, without
	// repeats; empty: no BuilderRequestAuth is signed.
	AllowedBuilderRequestAuthDataRoots []backend.Root
}

// Fork is one entry of the fork schedule.
type Fork struct {
	Epoch   uint64
	Version backend.Version
}

// Open is the config group without a change delay.
type Open struct {
	ForkSchedule   []Fork // ascending epochs
	GloasForkEpoch *uint64
}

// ChangeDelay is the change delay the group sets: ChangeDelaySeconds, or
// the image default when it is absent.
func (l *Locked) ChangeDelay() uint64 {
	if l.ChangeDelaySeconds == nil {
		return DefaultTimeLock
	}
	return *l.ChangeDelaySeconds
}

// writer appends fields. The caller checks the values first, so lengths
// and counts fit their fields.
type writer struct{ b []byte }

func (w *writer) u8(v uint8)   { w.b = append(w.b, v) }
func (w *writer) u16(v uint16) { w.b = binary.BigEndian.AppendUint16(w.b, v) }
func (w *writer) u32(v uint32) { w.b = binary.BigEndian.AppendUint32(w.b, v) }
func (w *writer) u64(v uint64) { w.b = binary.BigEndian.AppendUint64(w.b, v) }
func (w *writer) raw(p []byte) { w.b = append(w.b, p...) }
func (w *writer) str(s string) { w.u8(uint8(len(s))); w.b = append(w.b, s...) }
func (w *writer) flag(on bool) {
	if on {
		w.u8(1)
	} else {
		w.u8(0)
	}
}

var errShort = errors.New("setupwire: message too short")

// reader takes fields off a byte slice. After the first error every read
// returns zero values and err keeps that error.
type reader struct {
	b   []byte
	err error
}

func (r *reader) fail(err error) {
	if r.err == nil {
		r.err = err
	}
}

func (r *reader) take(n int) []byte {
	if r.err != nil {
		return nil
	}
	if n < 0 || n > len(r.b) {
		r.err = errShort
		return nil
	}
	v := r.b[:n]
	r.b = r.b[n:]
	return v
}

func (r *reader) u8() uint8 {
	if v := r.take(1); v != nil {
		return v[0]
	}
	return 0
}

func (r *reader) u16() uint16 {
	if v := r.take(2); v != nil {
		return binary.BigEndian.Uint16(v)
	}
	return 0
}

func (r *reader) u32() uint32 {
	if v := r.take(4); v != nil {
		return binary.BigEndian.Uint32(v)
	}
	return 0
}

func (r *reader) u64() uint64 {
	if v := r.take(8); v != nil {
		return binary.BigEndian.Uint64(v)
	}
	return 0
}

func (r *reader) fixed(dst []byte) { copy(dst, r.take(len(dst))) }

// str reads len:u8 and the bytes; an empty string is refused.
func (r *reader) str(what string) string {
	n := int(r.u8())
	if r.err == nil && n == 0 {
		r.fail(fmt.Errorf("setupwire: %s is empty", what))
	}
	return string(r.take(n))
}

// flag reads a presence or boolean byte: 0 or 1.
func (r *reader) flag(what string) bool {
	v := r.u8()
	if v > 1 {
		r.fail(fmt.Errorf("setupwire: %s byte is %d, want 0 or 1", what, v))
	}
	return v == 1
}

// count reads a u8 (or u16 when wide) count and refuses one above max.
func (r *reader) count(what string, max int, wide bool) int {
	var n int
	if wide {
		n = int(r.u16())
	} else {
		n = int(r.u8())
	}
	if n > max {
		r.fail(fmt.Errorf("setupwire: %d %s, at most %d", n, what, max))
		return 0
	}
	return n
}

// salts reads n salts.
func (r *reader) salts(n int) Salts {
	out := make(Salts, n)
	for i := range out {
		r.fixed(out[i][:])
	}
	return out
}

// header reads the kind and version bytes.
func (r *reader) header(kind byte, what string, version uint8) {
	if k := r.u8(); r.err == nil && k != kind {
		r.fail(fmt.Errorf("setupwire: not a %s (kind byte %#02x, want %#02x)", what, k, kind))
	}
	if v := r.u8(); r.err == nil && v != version {
		r.fail(fmt.Errorf("setupwire: %s version %d, want %d", what, v, version))
	}
}

// done fails if bytes are left over.
func (r *reader) done() error {
	if r.err == nil && len(r.b) != 0 {
		r.err = fmt.Errorf("setupwire: %d trailing bytes", len(r.b))
	}
	return r.err
}

// Encode checks the setup and returns its binary form.
func (s *Setup) Encode() ([]byte, error) {
	if err := s.Check(); err != nil {
		return nil, err
	}
	w := &writer{}
	s.write(w)
	if len(w.b) > MaxSetup {
		return nil, fmt.Errorf("setup: %d bytes, at most %d", len(w.b), MaxSetup)
	}
	return w.b, nil
}

func (s *Setup) write(w *writer) {
	w.u8(kindSetup)
	writeFields(w, s.publicFields())
	writeSalts(w, s.PolicySalts.Public)
	writeFields(w, s.Locked.fields())
	writeSalts(w, s.PolicySalts.Locked)
	writeFields(w, s.Open.fields())
	writeSalts(w, s.PolicySalts.Open)
	w.raw(s.PlatformSalt[:])
	s.writePrivate(w)
}

func writeSalts(w *writer, s Salts) {
	for _, salt := range s {
		w.raw(salt[:])
	}
}

// writePrivate writes the private part, the bytes platform_commitment covers.
func (s *Setup) writePrivate(w *writer) {
	w.str(s.SignerName)
	writePlatform(w, &s.Platform)
}

// DecodeSetup reads a setup strictly: it refuses input above MaxSetup, a
// private part above MaxPlatformPrivate, a kind or format it does not know, a count above its cap, a presence byte
// other than 0 or 1, unknown enum values or bits, unsorted or repeated
// list entries, values the checks refuse, a zero salt, trailing bytes, and
// anything that does not encode back to the same bytes.
func DecodeSetup(b []byte) (*Setup, error) {
	if len(b) > MaxSetup {
		return nil, fmt.Errorf("setupwire: setup is %d bytes, at most %d", len(b), MaxSetup)
	}
	r := &reader{b: b}
	r.setupHeader()
	s := &Setup{}
	r.fixed(s.ClusterID[:])
	s.HandoverGeneration = r.u64()
	readChain(r, &s.Chain)
	readSafety(r, &s.Safety)
	s.MaxKeys = r.u32()
	s.SlashingLogMinLockDays = r.u32()
	s.PolicySalts.Public = r.salts(NumPublicLeaves)
	readLocked(r, &s.Locked)
	s.PolicySalts.Locked = r.salts(NumLockedLeaves)
	readOpen(r, &s.Open)
	s.PolicySalts.Open = r.salts(NumOpenLeaves)
	r.fixed(s.PlatformSalt[:])
	s.SignerName = r.str("signer_name")
	readPlatform(r, &s.Platform)
	if err := r.done(); err != nil {
		return nil, err
	}
	again, err := s.Encode()
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(again, b) {
		return nil, errors.New("setupwire: setup does not encode back to the same bytes")
	}
	return s, nil
}

// setupHeader reads a setup's kind byte and setup_format_version.
func (r *reader) setupHeader() {
	if k := r.u8(); r.err == nil && k != kindSetup {
		r.fail(fmt.Errorf("setupwire: not a setup (kind byte %#02x, want %#02x)", k, kindSetup))
	}
	if v := r.u8(); r.err == nil && v != FormatVersion {
		r.fail(fmt.Errorf("setupwire: setup format %d, want %d", v, FormatVersion))
	}
}

// Hash is the chain hash an update body carries.
func (c *Chain) Hash() [32]byte {
	w := &writer{}
	writeChain(w, c)
	return CtxChain.Hash(w.b)
}

// GroupHash is the hash of a group of the setup, the prev_hash of the
// group's first update: the root of the group's salted leaves.
func (s *Setup) GroupHash(g Group) ([32]byte, error) {
	if err := s.Check(); err != nil {
		return [32]byte{}, err
	}
	switch g {
	case GroupLocked:
		return s.Locked.Root(s.PolicySalts.Locked)
	case GroupOpen:
		return s.Open.Root(s.PolicySalts.Open)
	}
	return [32]byte{}, fmt.Errorf("unknown group %d", g)
}

// CheckPlatform refuses a setup for another platform than the image's.
func (s *Setup) CheckPlatform(image Platform) error {
	if s.Platform.Platform != image {
		return fmt.Errorf("setup: platform is %s, this image is %s", s.Platform.Platform, image)
	}
	return nil
}

// Encode returns the group's values as a setup and an update body carry
// them (without the salts).
func (l *Locked) Encode() ([]byte, error) {
	if err := l.Check(); err != nil {
		return nil, err
	}
	w := &writer{}
	writeFields(w, l.fields())
	return w.b, nil
}

// Encode returns the group's values as a setup and an update body carry
// them (without the salts).
func (o *Open) Encode() ([]byte, error) {
	if err := o.Check(); err != nil {
		return nil, err
	}
	w := &writer{}
	writeFields(w, o.fields())
	return w.b, nil
}

// field is one field of a group: its name, which is also the name of its
// policy leaf and its key in the human form, and the writer of its bytes,
// the leaf's value.
type field struct {
	name  string
	write func(w *writer)
}

func writeFields(w *writer, fs []field) {
	for _, f := range fs {
		f.write(w)
	}
}

// publicFields are the fields of the public part, in leaf order.
func (s *Setup) publicFields() []field {
	fs := []field{
		{"setup_format_version", func(w *writer) { w.u8(FormatVersion) }},
		{"cluster_id", func(w *writer) { w.raw(s.ClusterID[:]) }},
		{"handover_generation", func(w *writer) { w.u64(s.HandoverGeneration) }},
	}
	fs = append(fs, s.Chain.fields()...)
	sf := &s.Safety
	return append(fs,
		field{"max_sign_epochs_ahead_of_clock", func(w *writer) { w.u64(sf.MaxSignEpochsAheadOfClock) }},
		field{"slashing_mark_prewrite.block_slots", func(w *writer) { w.u64(sf.SlashingMarkPrewrite.BlockSlots) }},
		field{"slashing_mark_prewrite.source_epochs", func(w *writer) { w.u64(sf.SlashingMarkPrewrite.SourceEpochs) }},
		field{"slashing_mark_prewrite.target_epochs", func(w *writer) { w.u64(sf.SlashingMarkPrewrite.TargetEpochs) }},
		field{"max_keys", func(w *writer) { w.u32(s.MaxKeys) }},
		field{"slashing_log_min_lock_days", func(w *writer) { w.u32(s.SlashingLogMinLockDays) }},
	)
}

func (c *Chain) fields() []field {
	return []field{
		{"genesis_validators_root", func(w *writer) { w.raw(c.GenesisValidatorsRoot[:]) }},
		{"genesis_fork_version", func(w *writer) { w.raw(c.GenesisForkVersion[:]) }},
		{"genesis_time", func(w *writer) { w.u64(c.GenesisTime) }},
		{"seconds_per_slot", func(w *writer) { w.u64(c.SecondsPerSlot) }},
		{"slots_per_epoch", func(w *writer) { w.u64(c.SlotsPerEpoch) }},
		{"preset", func(w *writer) { w.u8(uint8(c.Preset)) }},
		{"voluntary_exit_fork_version", func(w *writer) { w.raw(c.VoluntaryExitForkVersion[:]) }},
	}
}

func writeChain(w *writer, c *Chain) { writeFields(w, c.fields()) }

func readChain(r *reader, c *Chain) {
	r.fixed(c.GenesisValidatorsRoot[:])
	r.fixed(c.GenesisForkVersion[:])
	c.GenesisTime = r.u64()
	c.SecondsPerSlot = r.u64()
	c.SlotsPerEpoch = r.u64()
	c.Preset = Preset(r.u8())
	r.fixed(c.VoluntaryExitForkVersion[:])
}

func readSafety(r *reader, s *Safety) {
	s.MaxSignEpochsAheadOfClock = r.u64()
	s.SlashingMarkPrewrite.BlockSlots = r.u64()
	s.SlashingMarkPrewrite.SourceEpochs = r.u64()
	s.SlashingMarkPrewrite.TargetEpochs = r.u64()
}

func writePlatform(w *writer, p *PlatformConfig) {
	w.u8(uint8(p.Platform))
	w.u8(uint8(len(p.AllowedClientCA)))
	for _, c := range p.AllowedClientCA {
		w.u16(uint16(len(c)))
		w.raw(c)
	}
	writeStore(w, p.Platform, &p.SlashingLogStore)
	w.flag(p.EncryptedStateStore != nil)
	if p.EncryptedStateStore != nil {
		writeStore(w, p.Platform, p.EncryptedStateStore)
	}
	writeKeyRelease(w, p.Platform, &p.SealingKeyRelease)
	w.u8(uint8(len(p.PeerAttestationHosts)))
	for _, h := range p.PeerAttestationHosts {
		w.str(h)
	}
}

func readPlatform(r *reader, p *PlatformConfig) {
	p.Platform = Platform(r.u8())
	if r.err == nil && !enumValid(platformNames, uint8(p.Platform)) {
		r.fail(fmt.Errorf("setupwire: unknown platform %d", p.Platform))
	}
	for range r.count("allowed_client_ca certificates", MaxAllowedClientCA, false) {
		n := int(r.u16())
		p.AllowedClientCA = append(p.AllowedClientCA, bytes.Clone(r.take(n)))
	}
	readStore(r, p.Platform, &p.SlashingLogStore, "slashing_log_store")
	if r.flag("encrypted_state_store presence") {
		p.EncryptedStateStore = &Store{}
		readStore(r, p.Platform, p.EncryptedStateStore, "encrypted_state_store")
	}
	readKeyRelease(r, p.Platform, &p.SealingKeyRelease)
	for range r.count("peer_attestation_hosts", MaxPeerHosts, false) {
		p.PeerAttestationHosts = append(p.PeerAttestationHosts, r.str("peer_attestation_hosts"))
	}
}

func writeStore(w *writer, p Platform, s *Store) {
	switch p {
	case PlatformNitro:
		w.str(s.Bucket)
		w.str(s.Region)
	case PlatformAzure:
		w.str(s.Account)
		w.str(s.Container)
		w.str(s.Subscription)
		w.str(s.ResourceGroup)
	case PlatformGCP:
		w.str(s.Bucket)
	case PlatformDev:
		w.str(s.Dir)
	}
}

func readStore(r *reader, p Platform, s *Store, what string) {
	switch p {
	case PlatformNitro:
		s.Bucket = r.str(what + ".bucket")
		s.Region = r.str(what + ".region")
	case PlatformAzure:
		s.Account = r.str(what + ".account")
		s.Container = r.str(what + ".container")
		s.Subscription = r.str(what + ".subscription")
		s.ResourceGroup = r.str(what + ".resource_group")
	case PlatformGCP:
		s.Bucket = r.str(what + ".bucket")
	case PlatformDev:
		s.Dir = r.str(what + ".dir")
	}
}

func writeKeyRelease(w *writer, p Platform, k *KeyRelease) {
	switch p {
	case PlatformNitro:
		w.str(k.Region)
		w.str(k.KMSKeyID)
	case PlatformAzure:
		w.str(k.MAAEndpoint)
		w.str(k.AKVEndpoint)
		w.str(k.KID)
	case PlatformGCP:
		w.str(k.WIFProvider)
		w.str(k.KMSKey)
		w.str(k.AttestAudience)
		w.flag(k.NoLockAccepted)
		w.flag(k.UnsafeSingleKeyAccepted)
	}
}

func readKeyRelease(r *reader, p Platform, k *KeyRelease) {
	switch p {
	case PlatformNitro:
		k.Region = r.str("sealing_key_release.region")
		k.KMSKeyID = r.str("sealing_key_release.kms_key_id")
	case PlatformAzure:
		k.MAAEndpoint = r.str("sealing_key_release.maa_endpoint")
		k.AKVEndpoint = r.str("sealing_key_release.akv_endpoint")
		k.KID = r.str("sealing_key_release.kid")
	case PlatformGCP:
		k.WIFProvider = r.str("sealing_key_release.wif_provider")
		k.KMSKey = r.str("sealing_key_release.kms_key")
		k.AttestAudience = r.str("sealing_key_release.attest_audience")
		k.NoLockAccepted = r.flag("sealing_key_release.no_lock_accepted")
		k.UnsafeSingleKeyAccepted = r.flag("sealing_key_release.unsafe_single_key_accepted")
	}
}

// fields are the fields of the locked group, in leaf order.
func (l *Locked) fields() []field {
	return []field{
		{"approvers", func(w *writer) {
			w.u8(uint8(len(l.Approvers.Keys)))
			for _, k := range l.Approvers.Keys {
				w.raw(k[:])
			}
		}},
		{"approvals_needed", func(w *writer) { w.u8(l.Approvers.ApprovalsNeeded) }},
		{"change_delay_seconds", func(w *writer) {
			w.flag(l.ChangeDelaySeconds != nil)
			if l.ChangeDelaySeconds != nil {
				w.u64(*l.ChangeDelaySeconds)
			}
		}},
		{"allowed_image_measurements", func(w *writer) {
			w.u8(uint8(len(l.AllowedImageMeasurements)))
			for _, im := range l.AllowedImageMeasurements {
				w.u8(uint8(im.Kind))
				w.raw(im.Measurement)
			}
		}},
		{"allowed_fee_recipients", func(w *writer) {
			w.u8(uint8(len(l.AllowedFeeRecipients)))
			for _, a := range l.AllowedFeeRecipients {
				w.raw(a[:])
			}
		}},
		{"builder_gas_limit_min", func(w *writer) { w.u64(l.BuilderGasLimitMin) }},
		{"builder_gas_limit_max", func(w *writer) { w.u64(l.BuilderGasLimitMax) }},
		{"builder_registration_max_future_seconds", func(w *writer) { w.u64(l.BuilderRegistrationMaxFutureSeconds) }},
		{"exit_allowed_validators", func(w *writer) {
			w.u16(uint16(len(l.ExitAllowedValidators)))
			for _, i := range l.ExitAllowedValidators {
				w.u64(i)
			}
		}},
		{"exit_stake_cap_per_day", func(w *writer) { w.u64(l.ExitStakeCapPerDay) }},
		{"exit_approvals_needed", func(w *writer) { w.u8(l.ExitApprovalsNeeded) }},
		{"min_activation_balance", func(w *writer) { w.u64(l.MinActivationBalance) }},
		{"max_effective_balance", func(w *writer) { w.u64(l.MaxEffectiveBalance) }},
		{"withdrawal_credentials", func(w *writer) { w.raw(l.WithdrawalCredentials[:]) }},
		{"allowed_deposit_amounts", func(w *writer) {
			w.u8(uint8(len(l.AllowedDepositAmounts)))
			for _, a := range l.AllowedDepositAmounts {
				w.u64(a)
			}
		}},
		{"allow_unverified_nonslashable_signing", func(w *writer) { w.flag(l.AllowUnverifiedNonslashableSigning) }},
		{"bare_root_domains", func(w *writer) { w.u16(uint16(l.BareRootDomains)) }},
		{"slot_time_changes", func(w *writer) {
			w.u8(uint8(len(l.SlotTimeChanges)))
			for _, c := range l.SlotTimeChanges {
				w.u64(c.Epoch)
				w.u64(c.SecondsPerSlot)
			}
		}},
		{"allowed_builder_request_auth_data_roots", func(w *writer) {
			w.u8(uint8(len(l.AllowedBuilderRequestAuthDataRoots)))
			for _, r := range l.AllowedBuilderRequestAuthDataRoots {
				w.raw(r[:])
			}
		}},
	}
}

func readLocked(r *reader, l *Locked) {
	for range r.count("approvers", MaxApprovers, false) {
		var k [32]byte
		r.fixed(k[:])
		l.Approvers.Keys = append(l.Approvers.Keys, k)
	}
	l.Approvers.ApprovalsNeeded = r.u8()
	if r.flag("change_delay_seconds presence") {
		v := r.u64()
		l.ChangeDelaySeconds = &v
	}
	for range r.count("allowed_image_measurements", MaxAllowedImages, false) {
		kind := ImageKind(r.u8())
		if r.err == nil && kind.Size() == 0 {
			r.fail(fmt.Errorf("setupwire: unknown image kind %d", kind))
		}
		l.AllowedImageMeasurements = append(l.AllowedImageMeasurements, Image{Kind: kind, Measurement: bytes.Clone(r.take(kind.Size()))})
	}
	for range r.count("allowed_fee_recipients", MaxFeeRecipients, false) {
		var a backend.Address
		r.fixed(a[:])
		l.AllowedFeeRecipients = append(l.AllowedFeeRecipients, a)
	}
	l.BuilderGasLimitMin = r.u64()
	l.BuilderGasLimitMax = r.u64()
	l.BuilderRegistrationMaxFutureSeconds = r.u64()
	for range r.count("exit_allowed_validators entries", MaxExitAllowlist, true) {
		l.ExitAllowedValidators = append(l.ExitAllowedValidators, r.u64())
	}
	l.ExitStakeCapPerDay = r.u64()
	l.ExitApprovalsNeeded = r.u8()
	l.MinActivationBalance = r.u64()
	l.MaxEffectiveBalance = r.u64()
	r.fixed(l.WithdrawalCredentials[:])
	for range r.count("allowed_deposit_amounts", MaxDepositAmounts, false) {
		l.AllowedDepositAmounts = append(l.AllowedDepositAmounts, r.u64())
	}
	l.AllowUnverifiedNonslashableSigning = r.flag("allow_unverified_nonslashable_signing")
	l.BareRootDomains = RootDomains(r.u16())
	for range r.count("slot_time_changes", MaxSlotTimeChanges, false) {
		l.SlotTimeChanges = append(l.SlotTimeChanges, SlotTimeChange{Epoch: r.u64(), SecondsPerSlot: r.u64()})
	}
	for range r.count("allowed_builder_request_auth_data_roots", MaxBuilderRequestAuthDataRoots, false) {
		var root backend.Root
		r.fixed(root[:])
		l.AllowedBuilderRequestAuthDataRoots = append(l.AllowedBuilderRequestAuthDataRoots, root)
	}
}

// fields are the fields of the open group, in leaf order.
func (o *Open) fields() []field {
	return []field{
		{"fork_schedule", func(w *writer) {
			w.u8(uint8(len(o.ForkSchedule)))
			for _, f := range o.ForkSchedule {
				w.u64(f.Epoch)
				w.raw(f.Version[:])
			}
		}},
		{"gloas_fork_epoch", func(w *writer) {
			w.flag(o.GloasForkEpoch != nil)
			if o.GloasForkEpoch != nil {
				w.u64(*o.GloasForkEpoch)
			}
		}},
	}
}

func readOpen(r *reader, o *Open) {
	for range r.count("fork_schedule entries", MaxForks, false) {
		f := Fork{Epoch: r.u64()}
		r.fixed(f.Version[:])
		o.ForkSchedule = append(o.ForkSchedule, f)
	}
	if r.flag("gloas_fork_epoch presence") {
		v := r.u64()
		o.GloasForkEpoch = &v
	}
}

// Value checks. They need no clock and no stored state; the runner adds
// those of section 6 (versions against its state, the wait, the fork rule
// and the slot time rule).

var (
	signerNameRE  = regexp.MustCompile(`^[a-z0-9._-]+$`) // markstore.CheckSigner
	regionRE      = regexp.MustCompile(`^[a-z0-9-]{1,32}$`)
	s3BucketRE    = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)
	gcsBucketRE   = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{1,220}[a-z0-9]$`)
	azAccountRE   = regexp.MustCompile(`^[a-z0-9]{3,24}$`)
	azContainerRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$`)
	// A subscription ID in the lower-case form az prints, and a resource
	// group name in ASCII (Azure allows Unicode letters too; one spelling
	// keeps one encoding). A group name must not end with a period.
	azSubscriptionRE  = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	azResourceGroupRE = regexp.MustCompile(`^[A-Za-z0-9_().-]{0,89}[A-Za-z0-9_()-]$`)
	// As runner/platform/azure: host names without scheme or path, and a
	// Key Vault key name with an optional version.
	hostRE = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?(:[0-9]{1,5})?$`)
	kidRE  = regexp.MustCompile(`^[A-Za-z0-9-]{1,127}(/[0-9a-f]{32})?$`)
	// A peer attestation host: a lower-case host name and a port, the form
	// the runner's HTTP client dials (host:port of the URL, port 443 for
	// https).
	endpointRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]*[a-z0-9])?:[1-9][0-9]{0,4}$`)
)

// CheckEndpoint is the rule for one peer attestation host:
// host:port with a lower-case host name and a port from 1 to 65535 without
// leading zeros.
func CheckEndpoint(e string) error {
	if err := checkRE("peer_attestation_hosts", e, endpointRE); err != nil {
		return fmt.Errorf("%w (want host:port, for example sharedneu.neu.attest.azure.net:443)", err)
	}
	if _, port, _ := strings.Cut(e, ":"); len(port) == 5 && port > "65535" {
		return fmt.Errorf("peer_attestation_hosts: %q: port above 65535", e)
	}
	return nil
}

// checkText is the rule for strings without a pattern of their own: 1 to
// 255 bytes of printable ASCII without space and '#', so every value can be
// written as one line of the human file and read back the same.
func checkText(key, s string) error {
	if len(s) == 0 || len(s) > 255 {
		return fmt.Errorf("%s: want 1 to 255 characters", key)
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; c < 0x21 || c > 0x7e || c == '#' {
			return fmt.Errorf("%s: printable ASCII only, no space or '#'", key)
		}
	}
	return nil
}

func checkRE(key, s string, re *regexp.Regexp) error {
	if err := checkText(key, s); err != nil {
		return err
	}
	if !re.MatchString(s) {
		return fmt.Errorf("%s: %q does not match %s", key, s, re)
	}
	return nil
}

// Check applies the value rules to the whole setup and checks its salts.
func (s *Setup) Check() error {
	if err := s.CheckValues(); err != nil {
		return err
	}
	if err := s.PolicySalts.check(); err != nil {
		return err
	}
	if s.PlatformSalt == ([32]byte{}) {
		return errors.New("setup: platform_salt is zero; signer-config setup draws it")
	}
	return nil
}

// CheckValues applies the value rules to the whole setup, without the
// salts: a setup that signer-config read from a human file before it drew
// them.
func (s *Setup) CheckValues() error {
	if len(s.SignerName) > MaxSignerName || !signerNameRE.MatchString(s.SignerName) {
		return fmt.Errorf("setup: signer_name %q: 1 to %d characters of a-z, 0-9, '-', '_', '.'", s.SignerName, MaxSignerName)
	}
	if err := s.checkPublic(); err != nil {
		return err
	}
	if err := s.Platform.Check(); err != nil {
		return err
	}
	if err := s.checkGroups(); err != nil {
		return err
	}
	return s.checkPrivateSize()
}

// checkPublic applies the rules of the public group.
func (s *Setup) checkPublic() error {
	if s.ClusterID == ([32]byte{}) {
		return errors.New("setup: cluster_id is zero")
	}
	if s.HandoverGeneration == 0 {
		return errors.New("setup: handover_generation is 0, want 1 or more")
	}
	if err := s.Chain.Check(); err != nil {
		return err
	}
	if err := s.Safety.Check(); err != nil {
		return err
	}
	if s.MaxKeys == 0 || s.MaxKeys > MaxKeysCap {
		return fmt.Errorf("setup: max_keys %d, want 1 to %d", s.MaxKeys, MaxKeysCap)
	}
	if s.SlashingLogMinLockDays == 0 || s.SlashingLogMinLockDays > MaxLockDays {
		return fmt.Errorf("setup: slashing_log_min_lock_days %d, want 1 to %d", s.SlashingLogMinLockDays, MaxLockDays)
	}
	return nil
}

// checkGroups applies the rules of the locked and open groups.
func (s *Setup) checkGroups() error {
	if err := s.Locked.Check(); err != nil {
		return err
	}
	if err := CheckSlotTimes(&s.Chain, s.Locked.SlotTimeChanges); err != nil {
		return fmt.Errorf("locked: %w", err)
	}
	return s.Open.Check()
}

// checkPrivateSize applies MaxPlatformPrivate. It comes last, after the
// checks that keep every length within what writePrivate encodes, so a
// setup refused for another reason keeps its error.
func (s *Setup) checkPrivateSize() error {
	w := &writer{}
	s.writePrivate(w)
	if n := len(w.b); n > MaxPlatformPrivate {
		return fmt.Errorf("setup: the private part (signer_name and platform) is %d bytes, at most %d, the bound of the attestation circuits; "+
			"cut %d bytes, for example with fewer or smaller allowed_client_ca certificates", n, MaxPlatformPrivate, n-MaxPlatformPrivate)
	}
	return nil
}

// Check applies the chain rules.
func (c *Chain) Check() error {
	switch {
	case !enumValid(presetNames, uint8(c.Preset)):
		return fmt.Errorf("chain: preset %d, want mainnet or minimal", c.Preset)
	case c.SecondsPerSlot == 0 || c.SlotsPerEpoch == 0:
		return errors.New("chain: seconds_per_slot and slots_per_epoch must be non-zero")
	}
	if hi, _ := bits.Mul64(c.SecondsPerSlot, c.SlotsPerEpoch); hi != 0 {
		return errors.New("chain: seconds_per_slot * slots_per_epoch overflows 64 bits")
	}
	return nil
}

// Check applies the safety ranges.
func (s *Safety) Check() error {
	if v := s.MaxSignEpochsAheadOfClock; v < MinSignEpochsAhead || v > MaxSignEpochsAhead {
		return fmt.Errorf("safety: max_sign_epochs_ahead_of_clock %d, want %d to %d", v, MinSignEpochsAhead, MaxSignEpochsAhead)
	}
	p := &s.SlashingMarkPrewrite
	if p.BlockSlots > MaxPrewriteSlots {
		return fmt.Errorf("safety: slashing_mark_prewrite.block_slots %d, at most %d", p.BlockSlots, MaxPrewriteSlots)
	}
	if p.SourceEpochs > MaxPrewriteEpochs {
		return fmt.Errorf("safety: slashing_mark_prewrite.source_epochs %d, at most %d", p.SourceEpochs, MaxPrewriteEpochs)
	}
	if p.TargetEpochs > MaxPrewriteEpochs {
		return fmt.Errorf("safety: slashing_mark_prewrite.target_epochs %d, at most %d", p.TargetEpochs, MaxPrewriteEpochs)
	}
	return nil
}

// Check applies the platform rules. Which stores and key-release fields may
// be set depends on the platform.
func (p *PlatformConfig) Check() error {
	if !enumValid(platformNames, uint8(p.Platform)) {
		return fmt.Errorf("platform: %d, want nitro, azure, gcp or dev", p.Platform)
	}
	if n := len(p.AllowedClientCA); n < 1 || n > MaxAllowedClientCA {
		return fmt.Errorf("platform: %d allowed_client_ca certificates, want 1 to %d", n, MaxAllowedClientCA)
	}
	for i, der := range p.AllowedClientCA {
		if len(der) > math.MaxUint16 {
			return fmt.Errorf("platform: allowed_client_ca %d is %d bytes, at most %d", i, len(der), math.MaxUint16)
		}
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return fmt.Errorf("platform: allowed_client_ca %d: %w", i, err)
		}
		if !c.BasicConstraintsValid || !c.IsCA {
			return fmt.Errorf("platform: allowed_client_ca %d (%s) is not a CA certificate", i, c.Subject)
		}
		if i > 0 && bytes.Compare(p.AllowedClientCA[i-1], der) >= 0 {
			return errors.New("platform: allowed_client_ca certificates must be sorted by their bytes, without repeats")
		}
	}
	if err := p.SlashingLogStore.check(p.Platform, "slashing_log_store"); err != nil {
		return err
	}
	if p.EncryptedStateStore != nil {
		if p.Platform == PlatformNitro {
			return errors.New("platform: nitro keeps its state on the parent, encrypted_state_store must be absent")
		}
		if err := p.EncryptedStateStore.check(p.Platform, "encrypted_state_store"); err != nil {
			return err
		}
	}
	if err := p.SealingKeyRelease.check(p.Platform); err != nil {
		return err
	}
	if n := len(p.PeerAttestationHosts); n > 0 {
		if p.Platform != PlatformNitro && p.Platform != PlatformDev {
			return fmt.Errorf("platform: peer_attestation_hosts is for nitro and dev; a %s runner reaches its peers' key sets without routes", p.Platform)
		}
		if n > MaxPeerHosts {
			return fmt.Errorf("platform: %d peer_attestation_hosts, at most %d", n, MaxPeerHosts)
		}
		for i, e := range p.PeerAttestationHosts {
			if err := CheckEndpoint(e); err != nil {
				return fmt.Errorf("platform: %w", err)
			}
			if i > 0 && p.PeerAttestationHosts[i-1] >= e {
				return errors.New("platform: peer_attestation_hosts must be sorted, without repeats")
			}
		}
	}
	return nil
}

func (s *Store) check(p Platform, what string) error {
	var errs []error
	only := func(set ...string) {
		names := []string{"bucket", "region", "account", "container", "subscription", "resource_group", "dir"}
		vals := []string{s.Bucket, s.Region, s.Account, s.Container, s.Subscription, s.ResourceGroup, s.Dir}
		for i, v := range vals {
			if v != "" && !slices.Contains(set, names[i]) {
				errs = append(errs, fmt.Errorf("%s.%s does not apply to %s", what, names[i], p))
			}
		}
	}
	switch p {
	case PlatformNitro:
		only("bucket", "region")
		errs = append(errs, checkRE(what+".bucket", s.Bucket, s3BucketRE), checkRE(what+".region", s.Region, regionRE))
	case PlatformAzure:
		only("account", "container", "subscription", "resource_group")
		errs = append(errs, checkRE(what+".account", s.Account, azAccountRE), checkRE(what+".container", s.Container, azContainerRE),
			checkRE(what+".subscription", s.Subscription, azSubscriptionRE), checkRE(what+".resource_group", s.ResourceGroup, azResourceGroupRE))
	case PlatformGCP:
		only("bucket")
		errs = append(errs, checkRE(what+".bucket", s.Bucket, gcsBucketRE))
	case PlatformDev:
		only("dir")
		errs = append(errs, checkDir(what+".dir", s.Dir))
	}
	return firstErr("platform", errs)
}

func (k *KeyRelease) check(p Platform) error {
	var errs []error
	only := func(set ...string) {
		names := []string{"region", "kms_key_id", "maa_endpoint", "akv_endpoint", "kid", "wif_provider", "kms_key", "attest_audience"}
		vals := []string{k.Region, k.KMSKeyID, k.MAAEndpoint, k.AKVEndpoint, k.KID, k.WIFProvider, k.KMSKey, k.AttestAudience}
		for i, v := range vals {
			if v != "" && !slices.Contains(set, names[i]) {
				errs = append(errs, fmt.Errorf("sealing_key_release.%s does not apply to %s", names[i], p))
			}
		}
	}
	switch p {
	case PlatformNitro:
		only("region", "kms_key_id")
		errs = append(errs, checkRE("sealing_key_release.region", k.Region, regionRE), checkText("sealing_key_release.kms_key_id", k.KMSKeyID))
	case PlatformAzure:
		only("maa_endpoint", "akv_endpoint", "kid")
		errs = append(errs, checkRE("sealing_key_release.maa_endpoint", k.MAAEndpoint, hostRE),
			checkRE("sealing_key_release.akv_endpoint", k.AKVEndpoint, hostRE), checkRE("sealing_key_release.kid", k.KID, kidRE))
	case PlatformGCP:
		only("wif_provider", "kms_key", "attest_audience")
		errs = append(errs, checkText("sealing_key_release.wif_provider", k.WIFProvider), checkText("sealing_key_release.kms_key", k.KMSKey),
			checkText("sealing_key_release.attest_audience", k.AttestAudience))
	case PlatformDev:
		only()
	}
	if k.NoLockAccepted && p != PlatformGCP {
		errs = append(errs, fmt.Errorf("sealing_key_release.no_lock_accepted does not apply to %s: only GCP has a key rule without a lock", p))
	}
	if k.UnsafeSingleKeyAccepted && p != PlatformGCP {
		errs = append(errs, fmt.Errorf("sealing_key_release.unsafe_single_key_accepted does not apply to %s: only GCP has a key rule without a lock", p))
	}
	return firstErr("platform", errs)
}

// checkDir is the rule for a dev store: an absolute, clean path, so the
// setup names the same directory whatever the runner's working directory.
func checkDir(key, s string) error {
	if err := checkText(key, s); err != nil {
		return err
	}
	if !strings.HasPrefix(s, "/") || path.Clean(s) != s {
		return fmt.Errorf("%s: %q is not an absolute, clean path", key, s)
	}
	return nil
}

func firstErr(part string, errs []error) error {
	for _, err := range errs {
		if err != nil {
			return fmt.Errorf("%s: %w", part, err)
		}
	}
	return nil
}

// Check applies the value rules of the locked group (section 6, step 8,
// and section 8). The slot time changes are checked against the chain by
// CheckSlotTimes.
func (l *Locked) Check() error {
	if err := l.Approvers.Check(); err != nil {
		return fmt.Errorf("locked: %w", err)
	}
	n := len(l.Approvers.Keys)
	if l.ChangeDelaySeconds != nil && *l.ChangeDelaySeconds > MaxTimeLock {
		return fmt.Errorf("locked: change_delay_seconds %d, at most %d", *l.ChangeDelaySeconds, MaxTimeLock)
	}
	if len(l.AllowedImageMeasurements) > MaxAllowedImages {
		return fmt.Errorf("locked: %d allowed_image_measurements, at most %d", len(l.AllowedImageMeasurements), MaxAllowedImages)
	}
	for i, im := range l.AllowedImageMeasurements {
		if im.Kind.Size() == 0 {
			return fmt.Errorf("locked: allowed_image_measurements: unknown kind %d", im.Kind)
		}
		if len(im.Measurement) != im.Kind.Size() {
			return fmt.Errorf("locked: allowed_image_measurements: a %s measurement is %d bytes, want %d", im.Kind, len(im.Measurement), im.Kind.Size())
		}
		if i > 0 && compareImages(l.AllowedImageMeasurements[i-1], im) >= 0 {
			return errors.New("locked: allowed_image_measurements must be sorted, without repeats")
		}
	}
	if len(l.AllowedFeeRecipients) > MaxFeeRecipients {
		return fmt.Errorf("locked: %d allowed_fee_recipients, at most %d", len(l.AllowedFeeRecipients), MaxFeeRecipients)
	}
	for i := 1; i < len(l.AllowedFeeRecipients); i++ {
		if bytes.Compare(l.AllowedFeeRecipients[i-1][:], l.AllowedFeeRecipients[i][:]) >= 0 {
			return errors.New("locked: allowed_fee_recipients must be sorted, without repeats")
		}
	}
	if l.BuilderGasLimitMin > l.BuilderGasLimitMax {
		return fmt.Errorf("locked: builder_gas_limit_min %d above builder_gas_limit_max %d", l.BuilderGasLimitMin, l.BuilderGasLimitMax)
	}
	if len(l.ExitAllowedValidators) > MaxExitAllowlist {
		return fmt.Errorf("locked: %d exit_allowed_validators entries, at most %d", len(l.ExitAllowedValidators), MaxExitAllowlist)
	}
	if !slices.IsSorted(l.ExitAllowedValidators) || hasRepeat(l.ExitAllowedValidators) {
		return errors.New("locked: exit_allowed_validators must be sorted, without repeats")
	}
	if l.ExitApprovalsNeeded < MinThreshold || int(l.ExitApprovalsNeeded) > n {
		return fmt.Errorf("locked: exit_approvals_needed %d, want %d to the %d approvers: one approver alone must not approve an exit", l.ExitApprovalsNeeded, MinThreshold, n)
	}
	if l.MinActivationBalance == 0 || l.MinActivationBalance > l.MaxEffectiveBalance {
		return errors.New("locked: want 0 < min_activation_balance <= max_effective_balance")
	}
	if err := CheckCredentials(l.WithdrawalCredentials); err != nil {
		return fmt.Errorf("locked: %w", err)
	}
	if len(l.AllowedDepositAmounts) > MaxDepositAmounts {
		return fmt.Errorf("locked: %d allowed_deposit_amounts, at most %d", len(l.AllowedDepositAmounts), MaxDepositAmounts)
	}
	if !slices.IsSorted(l.AllowedDepositAmounts) || hasRepeat(l.AllowedDepositAmounts) {
		return errors.New("locked: allowed_deposit_amounts must be sorted, without repeats")
	}
	for _, a := range l.AllowedDepositAmounts {
		if a == 0 || a > l.MaxEffectiveBalance {
			return fmt.Errorf("locked: deposit amount %d Gwei, want 1 to max_effective_balance (%d)", a, l.MaxEffectiveBalance)
		}
	}
	for bit := range 16 {
		if l.BareRootDomains&(1<<bit) != 0 && !enumValid(rootDomainNames, uint8(bit)) {
			return fmt.Errorf("locked: bare_root_domains: domain type 0x%02x000000 can never be signed as a bare root", bit)
		}
	}
	if len(l.SlotTimeChanges) > MaxSlotTimeChanges {
		return fmt.Errorf("locked: %d slot_time_changes, at most %d", len(l.SlotTimeChanges), MaxSlotTimeChanges)
	}
	for i, c := range l.SlotTimeChanges {
		switch {
		case c.Epoch == 0:
			return errors.New("locked: slot_time_changes: epoch 0 is the genesis slot time, seconds_per_slot of the chain")
		case c.SecondsPerSlot == 0:
			return fmt.Errorf("locked: slot_time_changes: epoch %d: seconds per slot 0", c.Epoch)
		case i > 0 && c.Epoch <= l.SlotTimeChanges[i-1].Epoch:
			return errors.New("locked: slot_time_changes must be in ascending epoch order, one change per epoch")
		case i > 0 && c.SecondsPerSlot == l.SlotTimeChanges[i-1].SecondsPerSlot:
			return fmt.Errorf("locked: slot_time_changes: epoch %d keeps the slot time of the change before (%d s)", c.Epoch, c.SecondsPerSlot)
		}
	}
	if n := len(l.AllowedBuilderRequestAuthDataRoots); n > MaxBuilderRequestAuthDataRoots {
		return fmt.Errorf("locked: %d allowed_builder_request_auth_data_roots, at most %d", n, MaxBuilderRequestAuthDataRoots)
	}
	for i := 1; i < len(l.AllowedBuilderRequestAuthDataRoots); i++ {
		if bytes.Compare(l.AllowedBuilderRequestAuthDataRoots[i-1][:], l.AllowedBuilderRequestAuthDataRoots[i][:]) >= 0 {
			return errors.New("locked: allowed_builder_request_auth_data_roots must be sorted, without repeats")
		}
	}
	return nil
}

// CompareImages is the order of AllowedImageMeasurements: by kind, then by
// measurement.
func CompareImages(a, b Image) int { return compareImages(a, b) }

func compareImages(a, b Image) int {
	if a.Kind != b.Kind {
		return int(a.Kind) - int(b.Kind)
	}
	return bytes.Compare(a.Measurement, b.Measurement)
}

func hasRepeat(s []uint64) bool {
	for i := 1; i < len(s); i++ {
		if s[i] == s[i-1] {
			return true
		}
	}
	return false
}

// CheckCredentials is the TA's rule for withdrawal credentials: prefix 0x01
// or 0x02, 11 zero bytes, an execution address that is not zero.
func CheckCredentials(wc backend.Root) error {
	if wc[0] != 0x01 && wc[0] != 0x02 {
		return fmt.Errorf("withdrawal_credentials prefix %#02x, want 0x01 or 0x02", wc[0])
	}
	if [11]byte(wc[1:12]) != [11]byte{} {
		return errors.New("withdrawal_credentials: bytes 1 to 11 must be zero")
	}
	if [20]byte(wc[12:]) == [20]byte{} {
		return errors.New("withdrawal_credentials: the address is zero")
	}
	return nil
}

// Check applies the value rules of the open group that need no clock: the
// fork rule of section 7 is the runner's.
func (o *Open) Check() error {
	if len(o.ForkSchedule) > MaxForks {
		return fmt.Errorf("open: %d fork_schedule entries, at most %d", len(o.ForkSchedule), MaxForks)
	}
	for i := 1; i < len(o.ForkSchedule); i++ {
		if o.ForkSchedule[i].Epoch <= o.ForkSchedule[i-1].Epoch {
			return errors.New("open: fork_schedule must be in ascending epoch order, one fork per epoch")
		}
	}
	if o.GloasForkEpoch != nil && !slices.ContainsFunc(o.ForkSchedule, func(f Fork) bool { return f.Epoch == *o.GloasForkEpoch }) {
		return fmt.Errorf("open: gloas_fork_epoch %d is not the epoch of a fork in fork_schedule", *o.GloasForkEpoch)
	}
	return nil
}
