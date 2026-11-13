// Package setupwire holds the setup of a signer and its config updates: the
// binary encoding, its strict decoder, the human "key = value" form, the
// salted policy tree and the platform commitment that setup_hash covers
// (policy.go), the registry of signing contexts, and the value checks that
// need no clock or stored state. The runner and signer-admin use it.
// attestation-verify/docs/attestation-statement.md gives the layouts and
// hashes byte by byte.
//
// A setup has a public part and a private part.
// The public part holds the chain, the safety values, max_keys,
// slashing_log_min_lock_days, signing_mode and both config groups; every
// field of it is a leaf of the policy tree, with a salt of its own. The private part is the
// rest of the platform part, committed by one salted hash. setup_hash is
// SHA-256 over policy_root and platform_commitment, so a verifier who gets
// the policy leaves learns nothing of the private part.
//
// Integers are big endian. str is len:u8 and 1 to 255 bytes. A list has a
// count and a cap. An optional field has a presence byte, 0 or 1. Lists
// without an order of their own (CA certificates, tags, images, fee
// recipients, withdrawal credentials, deposit amounts, BuilderRequestAuth
// data roots, revoked certificates, time servers) are
// sorted and hold no duplicates, forks and slot time changes are in
// ascending epoch order, and the approver list keeps its order, because
// signatures name positions in it. Enum values start at 1, so a zero byte
// is never a valid choice.
//
//	setup    = 'S' public public_salts locked locked_salts open open_salts
//	           platform_salt[32] private
//	public   = setup_format_version:u8(6) cluster_id[32] handover_generation:u64
//	           chain safety max_keys:u32 slashing_log_min_lock_days:u32
//	           signing_mode:u8
//	chain    = genesis_validators_root[32] genesis_fork_version[4] genesis_time:u64
//	           seconds_per_slot:u64 slots_per_epoch:u64 preset:u8 voluntary_exit_fork_version[4]
//	safety   = max_sign_epochs_ahead_of_clock:u64 slashing_mark_prewrite.block_slots:u64
//	           slashing_mark_prewrite.source_epochs:u64 slashing_mark_prewrite.target_epochs:u64
//	locked   = n:u8 {key[32]} approvals_needed:u8 has:u8 [change_delay_seconds:u64]
//	           image_count:u8 {kind:u8 measurement[144 nitro, else 32]}
//	           fee_count:u8 {address[20]} builder_gas_limit_min:u64 builder_gas_limit_max:u64
//	           builder_registration_max_future_seconds:u64
//	           allow_unverified_nonslashable_signing:u8 bare_root_domains:u16
//	           slot_time_change_count:u8 {epoch:u64 seconds_per_slot:u64}
//	           builder_request_auth_count:u8 {data_root[32]}
//	           time_policy deposit_policy exit_policy
//	time_policy    = version:u8(1) protocol:u8 max_bound_ms:u16 max_sample_bound_ms:u16
//	deposit_policy = version:u8(1) credential_count:u8 {withdrawal_credentials[32]}
//	                 deposit_count:u8 {amount:u64} min_activation_balance:u64
//	                 max_effective_balance:u64
//	exit_policy    = version:u8(1) validator_count:u16 {pubkey[48]} stake_cap_per_day:u64
//	                 approvals_needed:u8
//	open     = fork_count:u8 {epoch:u64 version[4]} has:u8 [gloas_fork_epoch:u64]
//	           revoked_client_certs time_servers
//	revoked_client_certs = version:u8(1) revoked_count:u8 {sha256[32]}
//	time_servers   = version:u8(1) server_count:u8 {spec:str}
//	X_salts  = salt[32] for each leaf of group X, in leaf order (policy.go)
//	private  = signer_name:str platform:u8 ca_count:u8 {der_len:u16 der}
//	           slashing_log_store has:u8 [encrypted_state_store] sealing_key_release
//	store    = nitro: bucket:str region:str
//	           | azure: account:str container:str subscription:str resource_group:str
//	           | gcp: bucket:str | dev: dir:str
//	sealing_key_release = nitro: region:str kms_key_id:str has:u8 [kms_key_creation_date:u64]
//	           | azure: maa_endpoint:str akv_endpoint:str kid:str
//	           | gcp: wif_provider:str kms_key:str attest_audience:str no_lock_accepted:u8
//	                  unsafe_single_key_accepted:u8 has:u8 [project_number:u64]
//	           | dev: (nothing)
//
// Each field of public, locked and open is one leaf of the policy tree, and
// its bytes above are the leaf's value. The platform byte decides the
// layout of the stores and the key release. Amounts are Gwei. update.go has
// the CONFIG_UPDATE layout.
//
// time_policy, deposit_policy, exit_policy, revoked_client_certs and
// time_servers start with a version byte of their own. This version of the package reads version 1
// of each and refuses any other. A later image can read a higher version
// too, and a config update can then move the field to it without a new
// setup format: an update leaves setup_hash alone.
//
// deposit_policy and exit_policy are in place for features that come back
// later. The runner does not use deposit_policy yet. exit_policy must be
// empty (no validators, zero cap, zero approvals): Check refuses any other
// value, so nobody takes it for a rule the runner enforces.
//
// The dev platform is for local runners and tests (the runner's -platform
// dev). It protects nothing. A dev setup differs from a cloud one in two
// places: its stores are local directories (dir, an absolute path that the
// runner opens as a file: store), and it has no key release fields (the dev
// platform's key is fixed in the binary). A cloud image refuses it
// (CheckPlatform).
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
	"github.com/lidofinance/tee-signer/signer-protocol/buildchain"
)

const (
	// FormatVersion is setup_format_version, the setup's second byte.
	// Format 2 added signing_mode, the last leaf of the public part.
	// Format 3 dropped the exit approval fields of the locked group
	// (exit_allowed_validators, exit_stake_cap_per_day,
	// exit_approvals_needed).
	// Format 4 dropped peer_attestation_hosts, the last field of the
	// private part.
	// Format 5 added sealing_key_release.kms_key_creation_date to the
	// Nitro key release.
	// Format 6 folded min_activation_balance, max_effective_balance,
	// withdrawal_credentials and allowed_deposit_amounts of the locked
	// group into deposit_policy (a list of withdrawal credentials), added
	// time_policy and exit_policy to the locked group, revoked_client_certs
	// and time_servers to the open group, and
	// sealing_key_release.project_number to the GCP key release.
	FormatVersion = 6

	// The versions of the leaf values that carry a version byte of their own.
	TimePolicyVersion    = 1
	DepositPolicyVersion = 1
	ExitPolicyVersion    = 1
	TimeServersVersion   = 1
	// RevokedClientCertsVersion lets a later version add, for example, an
	// expiry to each entry.
	RevokedClientCertsVersion = 1

	kindSetup  = 'S'
	kindBody   = 'B'
	kindUpdate = 'U'
)

// Image constants; the times are
// the build chain's (signer-protocol/buildchain). MaxKeysCap is "above 5,000" there.
const (
	DefaultTimeLock   = buildchain.TimeLock // seconds, when the setup names no change delay
	MaxTimeLock       = buildchain.MaxTimeLock
	ActivationHorizon = buildchain.ActivationHorizon // past the required wait
	ImagesMinTimeLock = buildchain.ImagesMinTimeLock
	MaxKeysCap        = 8192
	MaxSetup          = 64 << 10 // bytes
	MaxAllowedImages  = 32
)

// Caps of the other lists and values.
const (
	MaxAllowedClientCA = 4
	MaxForks           = 16 // SC_MAX_FORKS
	MaxFeeRecipients   = 64 // SC_MAX_FEE_RECIPIENTS
	MaxDepositAmounts  = 8
	MaxSignerName      = 128 // markstore.CheckSigner
	MaxSlotTimeChanges = 16  // SC_MAX_SLOT_TIME_CHANGES
	// MaxBuilderRequestAuthDataRoots caps allowed_builder_request_auth_data_roots.
	MaxBuilderRequestAuthDataRoots = 16
	// MaxLockDays is 100 years, the longest Object Lock retention S3 takes;
	// a longer one could never pass the runner's lock check.
	MaxLockDays = 36500
	// MaxWithdrawalCredentials caps deposit_policy.withdrawal_credentials.
	MaxWithdrawalCredentials = 16
	// MaxRevokedClientCerts caps revoked_client_certs. Adding entries is
	// fast; dropping one needs every approver in force (changes.go), for
	// example to make room once the list is full.
	MaxRevokedClientCerts = 128
	// MaxTimeServers caps time_servers, the servers a setup adds to the
	// image's default set. The runner dials at most nts.MaxServers (16, the
	// Rust quorum's limit) in all, the default set (6 today) included, so
	// this must stay at most nts.MaxServers minus the size of the default
	// set: a longer list would pass here and fail only at start. Governance
	// does not import trusted-time; tee-signer's
	// TestMaxTimeServersFitsTheQuorum ties the numbers together.
	MaxTimeServers = 10
	// MaxTimeServerSpec is the longest time_servers entry: an ID of up to
	// 32 octets (ntscatalog.MaxLabel), '@' and a host name.
	MaxTimeServerSpec = 255
)

// Ranges of time_policy, in milliseconds. The runner's clock refuses a
// larger error bound than 250 ms, and 1 s takes the sample cap off
// (tee-signer/platforms_nts.go).
const (
	DefaultMaxBoundMs   = 100
	MaxMaxBoundMs       = 250
	MaxMaxSampleBoundMs = 1000
	// MinMaxSampleBoundMs is the smallest sample cap: the clock takes a
	// sample at receipt only while its bound plus the aging over the join
	// age (38 ms) is within the cap, so a smaller cap leaves little room.
	MinMaxSampleBoundMs = 80
)

// MaxKMSKeyCreationDate is 9999-12-31T23:59:59Z, the last time the text
// form (RFC 3339) can write.
const MaxKMSKeyCreationDate = 253402300799

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
	GroupLocked Group = 1 // a loosening change waits for the change delay (changes.go)
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

// SigningMode says how the signer holds its keys. It is a leaf of the
// public part, so it is under setup_hash, the approvers see it in the
// setup they sign, and it cannot change without a new setup.
type SigningMode uint8

const (
	// SigningModeThreshold: the signer holds shares of t-of-n splits with
	// n >= 2 and refuses a 1 of 1 import order.
	SigningModeThreshold SigningMode = 1
	// SigningModeSingle: the signer holds whole keys, 1 of 1 import orders
	// only (CheckThresholdOn).
	SigningModeSingle SigningMode = 2
)

// ClockProtocol is how the runner's clock asks its time servers
// (time_policy.protocol). One deployment uses one protocol.
type ClockProtocol uint8

const (
	ClockNTS ClockProtocol = 1 // NTS, authenticated (RFC 8915)
	ClockNTP ClockProtocol = 2 // plain NTP, unauthenticated
)

var (
	clockProtocolNames = []string{ClockNTS: "nts", ClockNTP: "ntp"}
	signingModeNames   = []string{SigningModeThreshold: "threshold", SigningModeSingle: "single"}
	platformNames      = []string{PlatformNitro: "nitro", PlatformAzure: "azure", PlatformGCP: "gcp", PlatformDev: "dev"}
	presetNames        = []string{PresetMainnet: "mainnet", PresetMinimal: "minimal"}
	groupNames         = []string{GroupLocked: "locked", GroupOpen: "open"}
	imageNames         = []string{ImageNitro: "nitro", ImageAzure: "azure", ImageGCP: "gcp", ImageTA: "ta"}
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
func (m SigningMode) String() string {
	return enumName(signingModeNames, uint8(m))
}
func (p ClockProtocol) String() string { return enumName(clockProtocolNames, uint8(p)) }

// ParseSigningMode reads threshold or single.
func ParseSigningMode(s string) (SigningMode, error) {
	if v, ok := enumValue(signingModeNames, s); ok {
		return SigningMode(v), nil
	}
	return 0, fmt.Errorf("signing_mode %q, want threshold or single", s)
}

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
func SigningModeNames() []string {
	return slices.Clone(signingModeNames)
}
func ClockProtocolNames() []string { return slices.Clone(clockProtocolNames) }

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
	SigningMode            SigningMode
	Locked                 Locked
	Open                   Open
	// PolicySalts are the salts of the policy leaves. signer-admin setup
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
	// Only a single-mode setup may say it, and a single-mode GCP setup
	// must (Check, CheckThresholdOn): see UnsafeSingleKeyWarning.
	// signer-admin setup sets it with -allow-gcp-unsafe-single-key.
	UnsafeSingleKeyAccepted bool
	// KMSKeyCreationDate (Nitro only,
	// sealing_key_release.kms_key_creation_date): the key's CreationDate
	// as KMS DescribeKey gives it, in Unix seconds; 0 when absent. The
	// approvers check in CloudTrail that the key was created with its
	// final locked policy and pin that creation here, so a key that had a
	// mutable phase, or another key under the same alias, has another
	// date and the runner does not start (AWS-KMS-02). Required on a prod
	// chain (CheckValues).
	KMSKeyCreationDate uint64
	// ProjectNumber (GCP only, sealing_key_release.project_number): the
	// number of the Google Cloud project that holds the stores, so the
	// runner can check that the mark and state buckets are in it (rv-d3u.6);
	// 0 when absent. Required on a prod chain (CheckValues), as
	// KMSKeyCreationDate is on Nitro.
	ProjectNumber uint64
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
	// ChangeDelaySeconds nil: DefaultTimeLock. 0: no change delay, which
	// only a non-prod chain takes (MinChangeDelay).
	ChangeDelaySeconds                  *uint64
	AllowedImageMeasurements            []Image           // sorted
	AllowedFeeRecipients                []backend.Address // sorted
	BuilderGasLimitMin                  uint64
	BuilderGasLimitMax                  uint64
	BuilderRegistrationMaxFutureSeconds uint64
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
	TimePolicy                         TimePolicy
	DepositPolicy                      DepositPolicy
	ExitPolicy                         ExitPolicy
	// RequiredFeatures (required_features, version 1) are the features a
	// runner must have to run under this group: sorted, without repeats,
	// each 1 to MaxFeatureName of a-z, 0-9 and '_', at most
	// MaxRequiredFeatures. A runner refuses a group that names a feature
	// it does not have (CheckFeatures).
	RequiredFeatures []string
}

// required_features limits and names.
const (
	RequiredFeaturesLeaf    = "required_features"
	RequiredFeaturesVersion = 1
	MaxRequiredFeatures     = 16
	MaxFeatureName          = 32
)

var featureRE = regexp.MustCompile(`^[a-z0-9_]{1,32}$`)

// UnknownFeatures are the required features not in known, in list order;
// nil when the runner knows them all.
func (l *Locked) UnknownFeatures(known []string) []string {
	var out []string
	for _, f := range l.RequiredFeatures {
		if !slices.Contains(known, f) {
			out = append(out, f)
		}
	}
	return out
}

// CheckFeatures refuses a group that requires a feature not in known,
// naming those features.
func (l *Locked) CheckFeatures(known []string) error {
	if unknown := l.UnknownFeatures(known); len(unknown) > 0 {
		return fmt.Errorf("required_features %s: this runner does not have them", strings.Join(unknown, ", "))
	}
	return nil
}

// TimePolicy is how the runner's clock works (time_policy, version 1). The
// servers are time_servers in the open group, added to the image's
// default set.
type TimePolicy struct {
	Protocol ClockProtocol
	// MaxBoundMs: the clock fails above this error bound, 1 to 250.
	MaxBoundMs uint16
	// MaxSampleBoundMs: a sample with a wider bound joins no quorum, from
	// MaxBoundMs to 1000 (no cap).
	MaxSampleBoundMs uint16
}

// DepositPolicy holds the deposit values (deposit_policy, version 1). The
// runner does not use them yet: deposits, with key generation in the TEE,
// come back later.
type DepositPolicy struct {
	// WithdrawalCredentials: 1 to MaxWithdrawalCredentials, sorted, each
	// as CheckCredentials says.
	WithdrawalCredentials []backend.Root
	AllowedDepositAmounts []uint64 // Gwei, sorted
	MinActivationBalance  uint64   // Gwei
	MaxEffectiveBalance   uint64   // Gwei
}

// ExitPolicy holds the exit approval values (exit_policy, version 1). Exit
// approvals are not in this version: every field must be empty or zero
// (Check), so the policy cannot look enforced.
type ExitPolicy struct {
	AllowedValidators []backend.Pubkey
	StakeCapPerDay    uint64 // Gwei
	ApprovalsNeeded   uint8
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
	// RevokedClientCerts are SHA-256 hashes of client leaf, intermediate or
	// CA certificates (DER) the runner refuses. Sorted, without repeats, at
	// most MaxRevokedClientCerts. An update adds entries with the usual
	// signature count; one that drops an entry needs every approver in
	// force (Update.Decide).
	RevokedClientCerts [][32]byte
	// TimeServers (time_servers, version 1) are the NTS or NTP servers the
	// clock dials besides the image's default set: catalog IDs, "id" for
	// the entry's own host or "id@host" for one of its alt hosts
	// (trusted-time/ntscatalog, Catalog.WithConfirmed). Sorted, without
	// repeats, an ID at most once. The approvers' signature confirms the
	// terms of "ask" operators. Which IDs exist is the runner's check.
	TimeServers []string
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
	s.SigningMode = SigningMode(r.u8())
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

// ImageKind is the kind of allowed_image_measurements entry a runner on p
// checks its own image against. The dev platform has none: ok is false.
func (p Platform) ImageKind() (k ImageKind, ok bool) {
	switch p {
	case PlatformNitro:
		return ImageNitro, true
	case PlatformAzure:
		return ImageAzure, true
	case PlatformGCP:
		return ImageGCP, true
	}
	return 0, false
}

// CheckOwnImageListed refuses a setup whose allowed_image_measurements
// lists no image of the signer's own platform. Its runner would sign and
// import nothing until a locked update lists its image. The tools that
// make and check setups call it; the runner does not, it checks its own
// measurement at run time (tee-signer/server.ImageGate).
func (s *Setup) CheckOwnImageListed() error {
	if s.Platform.Platform.ImageListed(s.Locked.AllowedImageMeasurements) {
		return nil
	}
	k, _ := s.Platform.Platform.ImageKind()
	return fmt.Errorf("setup: platform is %s, but allowed_image_measurements lists no %s image: the runner would refuse every import and signature until a locked update lists its image; add a line allowed_image_measurements = %s ...", s.Platform.Platform, k, k)
}

// ImageListed reports whether images, an allowed_image_measurements list,
// holds an image of p's kind. The dev platform has no kind and passes any
// list. CheckOwnImageListed applies it to a setup, and signer-admin draft
// to a locked update for each signer of the cluster. It is the rule by
// kind, for a signer whose running image is unknown; a tool that knows
// the measurement a runner reports checks it with Image.Listed.
func (p Platform) ImageListed(images []Image) bool {
	k, ok := p.ImageKind()
	return !ok || slices.ContainsFunc(images, func(im Image) bool { return im.Kind == k })
}

// Listed reports whether images, an allowed_image_measurements list, names
// im: an entry of the same kind and measurement.
func (im Image) Listed(images []Image) bool {
	return slices.ContainsFunc(images, func(x Image) bool { return compareImages(x, im) == 0 })
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
		field{"signing_mode", func(w *writer) { w.u8(uint8(s.SigningMode)) }},
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
		w.flag(k.KMSKeyCreationDate != 0)
		if k.KMSKeyCreationDate != 0 {
			w.u64(k.KMSKeyCreationDate)
		}
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
		w.flag(k.ProjectNumber != 0)
		if k.ProjectNumber != 0 {
			w.u64(k.ProjectNumber)
		}
	}
}

func readKeyRelease(r *reader, p Platform, k *KeyRelease) {
	switch p {
	case PlatformNitro:
		k.Region = r.str("sealing_key_release.region")
		k.KMSKeyID = r.str("sealing_key_release.kms_key_id")
		if r.flag("sealing_key_release.kms_key_creation_date presence") {
			k.KMSKeyCreationDate = r.u64()
		}
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
		if r.flag("sealing_key_release.project_number presence") {
			k.ProjectNumber = r.u64()
		}
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
		{"time_policy", func(w *writer) {
			t := &l.TimePolicy
			w.u8(TimePolicyVersion)
			w.u8(uint8(t.Protocol))
			w.u16(t.MaxBoundMs)
			w.u16(t.MaxSampleBoundMs)
		}},
		{"deposit_policy", func(w *writer) {
			d := &l.DepositPolicy
			w.u8(DepositPolicyVersion)
			w.u8(uint8(len(d.WithdrawalCredentials)))
			for _, wc := range d.WithdrawalCredentials {
				w.raw(wc[:])
			}
			w.u8(uint8(len(d.AllowedDepositAmounts)))
			for _, a := range d.AllowedDepositAmounts {
				w.u64(a)
			}
			w.u64(d.MinActivationBalance)
			w.u64(d.MaxEffectiveBalance)
		}},
		{"exit_policy", func(w *writer) {
			e := &l.ExitPolicy
			w.u8(ExitPolicyVersion)
			w.u16(uint16(len(e.AllowedValidators)))
			for _, pk := range e.AllowedValidators {
				w.raw(pk[:])
			}
			w.u64(e.StakeCapPerDay)
			w.u8(e.ApprovalsNeeded)
		}},
		{RequiredFeaturesLeaf, func(w *writer) {
			w.u8(RequiredFeaturesVersion)
			w.u8(uint8(len(l.RequiredFeatures)))
			for _, f := range l.RequiredFeatures {
				w.str(f)
			}
		}},
	}
}

// version reads the version byte of a leaf value and refuses any but want.
func (r *reader) version(what string, want uint8) {
	if v := r.u8(); r.err == nil && v != want {
		r.fail(fmt.Errorf("setupwire: %s version %d, want %d", what, v, want))
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
	t := &l.TimePolicy
	r.version("time_policy", TimePolicyVersion)
	t.Protocol = ClockProtocol(r.u8())
	t.MaxBoundMs = r.u16()
	t.MaxSampleBoundMs = r.u16()
	d := &l.DepositPolicy
	r.version("deposit_policy", DepositPolicyVersion)
	for range r.count("deposit_policy.withdrawal_credentials", MaxWithdrawalCredentials, false) {
		var wc backend.Root
		r.fixed(wc[:])
		d.WithdrawalCredentials = append(d.WithdrawalCredentials, wc)
	}
	for range r.count("deposit_policy.allowed_deposit_amounts", MaxDepositAmounts, false) {
		d.AllowedDepositAmounts = append(d.AllowedDepositAmounts, r.u64())
	}
	d.MinActivationBalance = r.u64()
	d.MaxEffectiveBalance = r.u64()
	e := &l.ExitPolicy
	r.version("exit_policy", ExitPolicyVersion)
	// Exit approvals are not in this version: no validator may be listed,
	// so the count's cap is 0.
	r.count("exit_policy.allowed_validators", 0, true)
	e.StakeCapPerDay = r.u64()
	e.ApprovalsNeeded = r.u8()
	r.version(RequiredFeaturesLeaf, RequiredFeaturesVersion)
	for range r.count(RequiredFeaturesLeaf, MaxRequiredFeatures, false) {
		l.RequiredFeatures = append(l.RequiredFeatures, r.str("required_features entry"))
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
		{"revoked_client_certs", func(w *writer) {
			w.u8(RevokedClientCertsVersion)
			w.u8(uint8(len(o.RevokedClientCerts)))
			for _, h := range o.RevokedClientCerts {
				w.raw(h[:])
			}
		}},
		{"time_servers", func(w *writer) {
			w.u8(TimeServersVersion)
			w.u8(uint8(len(o.TimeServers)))
			for _, s := range o.TimeServers {
				w.str(s)
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
	r.version("revoked_client_certs", RevokedClientCertsVersion)
	for range r.count("revoked_client_certs", MaxRevokedClientCerts, false) {
		var h [32]byte
		r.fixed(h[:])
		o.RevokedClientCerts = append(o.RevokedClientCerts, h)
	}
	r.version("time_servers", TimeServersVersion)
	for range r.count("time_servers", MaxTimeServers, false) {
		o.TimeServers = append(o.TimeServers, r.str("time_servers entry"))
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
	// As platform-azure/azure: host names without scheme or path, and a
	// Key Vault key name with an optional version.
	hostRE = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?(:[0-9]{1,5})?$`)
	kidRE  = regexp.MustCompile(`^[A-Za-z0-9-]{1,127}(/[0-9a-f]{32})?$`)
	// A KMS key or alias ARN, with the account: a bare key ID or alias
	// resolves in the account of the parent's credentials. As
	// platform-aws/nitro checkKeyID.
	kmsKeyARNRE = regexp.MustCompile(`^arn:(aws|aws-cn|aws-us-gov):kms:([a-z0-9-]+):[0-9]{12}:(key|alias)/[A-Za-z0-9/_-]+$`)
)

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
		return errors.New("setup: platform_salt is zero; signer-admin setup draws it")
	}
	return s.checkSingleOnGCP()
}

// checkSingleOnGCP refuses a single-mode GCP setup without
// sealing_key_release.unsafe_single_key_accepted (UnsafeSingleKeyWarning),
// so a GCP runner does not start from one. It is a rule of Check, not of
// CheckValues: signer-admin setup reads the human file first and adds the
// acceptance after (-allow-gcp-unsafe-single-key), then refuses the setup
// with the reason if it still lacks it.
func (s *Setup) checkSingleOnGCP() error {
	if s.SigningMode == SigningModeSingle && s.Platform.Platform == PlatformGCP && !s.Platform.SealingKeyRelease.UnsafeSingleKeyAccepted {
		return errors.New("setup: signing_mode = single on gcp needs sealing_key_release.unsafe_single_key_accepted = true (signer-admin setup -allow-gcp-unsafe-single-key): " + UnsafeSingleKeyWarning)
	}
	return nil
}

// CheckValues applies the value rules to the whole setup, without the
// salts: a setup that signer-admin read from a human file before it drew
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
	if s.Platform.Platform == PlatformNitro && s.Platform.SealingKeyRelease.KMSKeyCreationDate == 0 && s.Chain.Prod() {
		return errors.New("setup: a prod chain on nitro needs sealing_key_release.kms_key_creation_date, the CreationDate of a KMS key the approvers checked in CloudTrail was created locked (platform-aws/deploy/README.md)")
	}
	if s.Platform.Platform == PlatformGCP && s.Platform.SealingKeyRelease.ProjectNumber == 0 && s.Chain.Prod() {
		return errors.New("setup: a prod chain on gcp needs sealing_key_release.project_number, the number of the project that holds the stores (gcloud projects describe PROJECT --format='value(projectNumber)')")
	}
	// The acceptance of a key held alone means nothing in a threshold
	// setup, whose runner refuses every 1 of 1 order.
	if s.Platform.SealingKeyRelease.UnsafeSingleKeyAccepted && s.SigningMode != SigningModeSingle {
		return fmt.Errorf("setup: sealing_key_release.unsafe_single_key_accepted needs signing_mode = single (signing_mode is %s)", s.SigningMode)
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
	if !enumValid(signingModeNames, uint8(s.SigningMode)) {
		return fmt.Errorf("setup: signing_mode %d, want %d (threshold) or %d (single)", s.SigningMode, SigningModeThreshold, SigningModeSingle)
	}
	return nil
}

// checkGroups applies the rules of the locked and open groups, with the
// chain's slot time rule on the locked one. The change delay floor is not
// here: the decoder runs these rules on a pinned setup too, and a setup
// made before the floor must keep starting (Locked.CheckChangeDelay).
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
	return p.SealingKeyRelease.check(p.Platform)
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
		errs = append(errs, checkRE("sealing_key_release.region", k.Region, regionRE), checkKMSKeyID(k.KMSKeyID, k.Region))
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
	if k.KMSKeyCreationDate != 0 && p != PlatformNitro {
		errs = append(errs, fmt.Errorf("sealing_key_release.kms_key_creation_date does not apply to %s", p))
	}
	if k.ProjectNumber != 0 && p != PlatformGCP {
		errs = append(errs, fmt.Errorf("sealing_key_release.project_number does not apply to %s", p))
	}
	if k.KMSKeyCreationDate > MaxKMSKeyCreationDate {
		errs = append(errs, fmt.Errorf("sealing_key_release.kms_key_creation_date %d is after year 9999", k.KMSKeyCreationDate))
	}
	return firstErr("platform", errs)
}

// checkKMSKeyID is the rule for sealing_key_release.kms_key_id: a key or
// alias ARN in region.
func checkKMSKeyID(id, region string) error {
	const key = "sealing_key_release.kms_key_id"
	if err := checkRE(key, id, kmsKeyARNRE); err != nil {
		return fmt.Errorf("%w (a key or alias ARN with the account)", err)
	}
	if r := kmsKeyARNRE.FindStringSubmatch(id)[2]; r != region {
		return fmt.Errorf("%s: the key is in region %s, not sealing_key_release.region %s", key, r, region)
	}
	return nil
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
	if err := l.TimePolicy.Check(); err != nil {
		return fmt.Errorf("locked: %w", err)
	}
	if err := l.DepositPolicy.Check(); err != nil {
		return fmt.Errorf("locked: %w", err)
	}
	if err := l.ExitPolicy.Check(); err != nil {
		return fmt.Errorf("locked: %w", err)
	}
	if n := len(l.RequiredFeatures); n > MaxRequiredFeatures {
		return fmt.Errorf("locked: %d required_features, at most %d", n, MaxRequiredFeatures)
	}
	for i, f := range l.RequiredFeatures {
		if !featureRE.MatchString(f) {
			return fmt.Errorf("locked: required_features: %q: 1 to %d characters of a-z, 0-9, '_'", f, MaxFeatureName)
		}
		if i > 0 && l.RequiredFeatures[i-1] >= f {
			return errors.New("locked: required_features must be sorted, without repeats")
		}
	}
	return nil
}

// Check applies the ranges of time_policy.
func (t *TimePolicy) Check() error {
	if !enumValid(clockProtocolNames, uint8(t.Protocol)) {
		return fmt.Errorf("time_policy.protocol %d, want %d (nts) or %d (ntp)", t.Protocol, ClockNTS, ClockNTP)
	}
	if t.MaxBoundMs == 0 || t.MaxBoundMs > MaxMaxBoundMs {
		return fmt.Errorf("time_policy.max_bound_ms %d, want 1 to %d", t.MaxBoundMs, MaxMaxBoundMs)
	}
	if t.MaxSampleBoundMs < max(t.MaxBoundMs, MinMaxSampleBoundMs) || t.MaxSampleBoundMs > MaxMaxSampleBoundMs {
		return fmt.Errorf("time_policy.max_sample_bound_ms %d, want max(max_bound_ms (%d), %d) to %d", t.MaxSampleBoundMs, t.MaxBoundMs, MinMaxSampleBoundMs, MaxMaxSampleBoundMs)
	}
	return nil
}

// Check applies the rules of deposit_policy: the rules of the format 5
// fields, with one to MaxWithdrawalCredentials credentials in place of one.
func (d *DepositPolicy) Check() error {
	if n := len(d.WithdrawalCredentials); n < 1 || n > MaxWithdrawalCredentials {
		return fmt.Errorf("deposit_policy: %d withdrawal_credentials, want 1 to %d", n, MaxWithdrawalCredentials)
	}
	for i, wc := range d.WithdrawalCredentials {
		if err := CheckCredentials(wc); err != nil {
			return fmt.Errorf("deposit_policy: %w", err)
		}
		if i > 0 && bytes.Compare(d.WithdrawalCredentials[i-1][:], wc[:]) >= 0 {
			return errors.New("deposit_policy: withdrawal_credentials must be sorted, without repeats")
		}
	}
	if d.MinActivationBalance == 0 || d.MinActivationBalance > d.MaxEffectiveBalance {
		return errors.New("deposit_policy: want 0 < min_activation_balance <= max_effective_balance")
	}
	if len(d.AllowedDepositAmounts) > MaxDepositAmounts {
		return fmt.Errorf("deposit_policy: %d allowed_deposit_amounts, at most %d", len(d.AllowedDepositAmounts), MaxDepositAmounts)
	}
	if !slices.IsSorted(d.AllowedDepositAmounts) || hasRepeat(d.AllowedDepositAmounts) {
		return errors.New("deposit_policy: allowed_deposit_amounts must be sorted, without repeats")
	}
	for _, a := range d.AllowedDepositAmounts {
		if a == 0 || a > d.MaxEffectiveBalance {
			return fmt.Errorf("deposit_policy: deposit amount %d Gwei, want 1 to max_effective_balance (%d)", a, d.MaxEffectiveBalance)
		}
	}
	return nil
}

// Check refuses an exit_policy that is not empty: exit approvals are not in
// this version.
func (e *ExitPolicy) Check() error {
	if len(e.AllowedValidators) != 0 || e.StakeCapPerDay != 0 || e.ApprovalsNeeded != 0 {
		return errors.New("exit_policy: exit approvals are not in this version; allowed_validators must be empty, stake_cap_per_day and approvals_needed 0")
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
	if n := len(o.RevokedClientCerts); n > MaxRevokedClientCerts {
		return fmt.Errorf("open: %d revoked_client_certs, at most %d", n, MaxRevokedClientCerts)
	}
	for i, h := range o.RevokedClientCerts {
		if h == ([32]byte{}) {
			return errors.New("open: revoked_client_certs: a zero hash names no certificate")
		}
		if i > 0 && bytes.Compare(o.RevokedClientCerts[i-1][:], h[:]) >= 0 {
			return errors.New("open: revoked_client_certs must be sorted, without repeats")
		}
	}
	return checkTimeServers(o.TimeServers)
}

// timeServerRE is the syntax of a time_servers entry: a catalog ID (1 to
// 32 of a-z, 0-9, '.' and '-', as ntscatalog's IDs), and for an alt host
// '@' and a lower-case host name.
var timeServerRE = regexp.MustCompile(`^[a-z0-9.-]{1,32}(@[a-z0-9]([a-z0-9.-]*[a-z0-9])?)?$`)

// checkTimeServers applies the syntax rules of time_servers: at most
// MaxTimeServers entries, sorted, without repeats, each ID once. Whether an
// ID names an entry of the image's catalog, and the minimum number of
// servers, are the runner's checks.
func checkTimeServers(specs []string) error {
	if len(specs) > MaxTimeServers {
		return fmt.Errorf("open: %d time_servers, at most %d", len(specs), MaxTimeServers)
	}
	ids := map[string]bool{}
	for i, s := range specs {
		if len(s) > MaxTimeServerSpec || !timeServerRE.MatchString(s) {
			return fmt.Errorf("open: time_servers entry %q: want ID or ID@HOST, an ID of 1 to 32 of a-z, 0-9, '.' and '-'", s)
		}
		if i > 0 && specs[i-1] >= s {
			return errors.New("open: time_servers must be sorted, without repeats")
		}
		id, _, _ := strings.Cut(s, "@")
		if ids[id] {
			return fmt.Errorf("open: time_servers names %q twice", id)
		}
		ids[id] = true
	}
	return nil
}
