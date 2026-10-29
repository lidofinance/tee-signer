// Package backend is the interface between the Dirk fork and a secure
// signing backend. A backend holds one threshold share per validator and
// does all signing, slashing protection and policy checks itself; the
// caller only sends typed messages and gets partial signatures back.
//
// Implementations:
//
//	software  in-process signer core, dev only (package software)
//	remote    client for an enclave runner over TCP, unix socket or vsock
//	          (package remote, protocol in package wire)
package backend

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"math"
	"slices"
)

// IndexUnknown means a validator is not bound to an index.
const IndexUnknown uint64 = math.MaxUint64

// ValidatorKey describes one loaded validator share.
type ValidatorKey struct {
	Pubkey      Pubkey `json:"pubkey"`       // validator (account) key, as on chain
	SharePubkey Pubkey `json:"share_pubkey"` // key of the share this backend holds
	Index       uint64 `json:"index"`        // IndexUnknown if not bound
}

// SignRequest asks for a partial signature over one message.
type SignRequest struct {
	Pubkey  Pubkey  // validator (account) key
	Message Message // *AttestationData, *BeaconBlockHeader, *VoluntaryExit, *ValidatorRegistration, *RootMessage, or Gloas *PayloadAttestationData, *PayloadEnvelope, *ProposerPreferences
	// Domain is the domain the caller computed for Message. The signer
	// computes its own from its chain config and fork schedule and refuses
	// the request if they differ (StatusDomainMismatch), so a signer that
	// missed a fork update makes no signature instead of an invalid one. A
	// *RootMessage carries its domain in its own Domain field and ignores
	// this one.
	Domain Root
}

// Attestation is a backend-specific attestation document.
type Attestation struct {
	Platform string `json:"platform"` // dev, nitro, gcp, azure, software
	Format   string `json:"format"`   // see the platform docs, e.g. "aws-nitro-cose-sign1"
	// UserData is what the runner bound into the document: IdentityUserData
	// for IDENTITY, AttestUserData for ATTEST.
	UserData []byte `json:"user_data"`
	Document []byte `json:"document"`
}

// Health reports the state of a backend.
type Health struct {
	Platform   string `json:"platform"`
	Version    string `json:"version"`
	Ready      bool   `json:"ready"`
	Validators int    `json:"validators"`
	// ConfigHash is the hash of the backend's config: Setup.SetupHash on a
	// runner.
	ConfigHash Root `json:"config_hash"`
	// Setup is the setup and config state that IDENTITY and ATTEST attest,
	// here unattested. A backend without a setup (software) leaves it nil.
	Setup *SetupState `json:"setup,omitempty"`
	// KeyLock is the lock of the rule of the key that releases the sealing
	// key (KeyLock.String: locked, not_locked, none or unread), as the
	// runner read it at start next to key_release_hash. Unattested here;
	// the setup state of IDENTITY and ATTEST does not carry it. Runners
	// without a setup and runners before it leave it out.
	KeyLock string `json:"key_lock,omitempty"`
	// KeyLockWhy says what the key lock rests on: what keeps the rule
	// open, why it was not read, or, for a platform without a lock, that
	// the setup accepts that.
	KeyLockWhy string `json:"key_lock_why,omitempty"`
	// Image is the runner's check of its own image against
	// allowed_image_measurements in force (docs/protocol.md, "Image
	// check"). Unattested here; the attestation document carries the image
	// itself. Runners without a setup and runners before the check leave it
	// out.
	Image *ImageCheck `json:"image,omitempty"`
	// MarkLogLost says why a runner signs nothing after another instance
	// took its mark log over (markstore.ErrLost); Ready is then false.
	// Empty otherwise, and from runners before it.
	MarkLogLost string `json:"mark_log_lost,omitempty"`
	// RequestPanic says which state-changing request panicked; the
	// runner then signs and changes nothing until it restarts, and Ready
	// is false. Empty otherwise, and from runners before it.
	RequestPanic string `json:"request_panic,omitempty"`
	ClockSource  string `json:"clock_source"`
	ClockTrusted bool   `json:"clock_trusted"` // the platform claims the clock resists the host
	ClockUnix    uint64 `json:"clock_unix"`    // whole seconds
	// ClockUnixMS is the same reading in milliseconds. Runners before it
	// leave it out (zero).
	ClockUnixMS uint64 `json:"clock_unix_ms,omitempty"`
	// NTS is the state of the NTS clock, when the runner uses one. Runners
	// before it and runners with another clock leave it out (nil).
	NTS *ClockNTS `json:"clock_nts,omitempty"`
	// Restart protection in force: "floor", "persisted" or "floor+persisted".
	RestartMode string `json:"restart_mode"`
	StartedUnix uint64 `json:"started_unix"`
	// Record describes the clone guard (external single-writer record), or
	// "none".
	Record string `json:"record,omitempty"`
	// AllowUnverifiedNonslashable is the config switch of that name: the
	// runner signs bare roots it cannot check (root types 2 to 6).
	AllowUnverifiedNonslashable bool `json:"allow_unverified_nonslashable"`
	// UnverifiedSignatures counts those signatures since the runner started.
	UnverifiedSignatures uint64 `json:"unverified_signatures"`
	// Stats are the signer core's counters since the start, when the
	// backend has them. Counts only: no key, root or signature.
	Stats *SignerStats `json:"stats,omitempty"`
}

// ClockNTS is what HEALTH reports of the runner's NTS clock (runner/clock
// NTS), measured inside the TEE when the answer is made. Durations are in
// milliseconds.
type ClockNTS struct {
	// Quorum is true when the clock answers: a quorum that passed every
	// check is in force and BoundNowMS is within MaxBoundMS. With no
	// quorum yet, BoundNowMS, OffsetFromHostMS, Members and QuorumAgeMS
	// are zero.
	Quorum bool `json:"quorum"`
	// BoundNowMS is the error bound of the signer's time now: the bound of
	// the last quorum grown by rho since then. Real time is within
	// +-BoundNowMS of the time the signer uses. Signing fails above
	// MaxBoundMS.
	BoundNowMS float64 `json:"bound_now_ms"`
	MaxBoundMS float64 `json:"max_bound_ms"`
	// OffsetFromHostMS is the NTS time minus the system clock inside the
	// TEE (the clock the host sets). The runner does not use the system
	// clock; this shows how far off it is.
	OffsetFromHostMS float64 `json:"offset_from_host_ms"`
	// Members are the operators of the last quorum.
	Members []string `json:"members"`
	// QuorumAgeMS is the time since the last quorum, on the local
	// monotonic clock.
	QuorumAgeMS float64 `json:"quorum_age_ms"`
	// Refusals counts the reads of the clock refused because the bound was
	// over MaxBoundMS, since the runner started.
	Refusals int64 `json:"refusals"`
	// DriftPPM is the rate error of the local clock against NTS, within
	// +-DriftErrPPM, over DriftBaselineS seconds. RhoViolations counts the
	// quorums the drift check refused.
	DriftPPM       float64 `json:"drift_ppm"`
	DriftErrPPM    float64 `json:"drift_err_ppm"`
	DriftBaselineS float64 `json:"drift_baseline_s"`
	RhoViolations  int64   `json:"rho_violations"`
	// CoarseDiffMS is the NTS time minus the HTTPS-date quorum at the last
	// quorum (0 to 1000 ms with honest sources: the coarse time is whole
	// seconds).
	CoarseDiffMS float64 `json:"coarse_diff_ms"`
}

// SignerStats are the counters of the signer core (sc_signer_stats).
type SignerStats struct {
	Signatures       uint64 `json:"signatures"`
	HashCacheHits    uint64 `json:"hash_cache_hits"`
	HashCacheMisses  uint64 `json:"hash_cache_misses"`
	WatermarkWrites  uint64 `json:"watermark_writes"`
	ExactRepeats     uint64 `json:"exact_repeats"`
	RepeatRootWrites uint64 `json:"repeat_root_writes"`
}

// Identity is what a runner proves about one boot: its setup and config
// state, the HPKE public key that share imports are encrypted to, and the
// key of the TLS certificate it serves. The runner generates both keys
// inside the TEE at start; the private halves never leave it, so a restart
// or a second instance has other keys.
type Identity struct {
	// State is the runner's setup and config state.
	State SetupState
	// HPKE suite of ImportKey (RFC 9180 identifiers).
	ImportKEM, ImportKDF, ImportAEAD uint16
	ImportKey                        []byte // serialized HPKE public key
	// TLSKeyHash is sha256 of the DER SubjectPublicKeyInfo of the runner's
	// TLS certificate, or empty when the runner serves no TLS.
	TLSKeyHash []byte
	// Attestation binds IdentityUserData(nonce, identity).
	Attestation *Attestation
}

// AttestOnlyClientOID is the extended key usage of the attest-only client
// role (attestation-prover.md, signer change 7). A client certificate whose
// leaf, or any CA certificate of its verified chain, lists it next to
// clientAuth may send HEALTH, PUBLIC_KEYS, ATTEST and IDENTITY only, and
// gets at most AttestOnlyPerMinute fresh attestations a minute
// (docs/protocol.md, "Client roles"). A certificate without it keeps every
// right, as before. The OID sits under Microsoft's arc for OIDs made from
// a GUID, 1.2.840.113556.1.8000.2554, followed by the GUID
// c05fdecc-b314-44f1-95d4-1ba3e69d79fa in seven parts and arc 1 for this
// role: no registry entry is needed, and Go's x509 parser takes every arc
// (it refuses arcs of 2^31 and more, so the 2.25 UUID arc does not work).
var AttestOnlyClientOID = asn1.ObjectIdentifier{1, 2, 840, 113556, 1, 8000, 2554,
	49247, 57036, 45844, 17649, 38356, 1811430, 10320378, 1}

// AdminClientOID is the extended key usage of the admin client role
// (docs/protocol.md, "Client roles"): the only role that may send imports,
// config updates, exit approvals, orders, key generation and handover
// messages. It counts only when the leaf and the leaf's direct issuer both
// list it and that issuer is an intermediate, not the pinned root
// (runner/attls.Role). Same GUID arc as AttestOnlyClientOID, last arc 2.
var AdminClientOID = asn1.ObjectIdentifier{1, 2, 840, 113556, 1, 8000, 2554,
	49247, 57036, 45844, 17649, 38356, 1811430, 10320378, 2}

// RunnerChainOID is a non-critical extension of the runner's TLS
// certificate: an OCTET STRING of 4 bytes, the genesis fork version of
// the chain the runner signs for. The certificate's key is the one the
// attested identity names, so the value comes from the runner's code.
// Clients refuse a runner whose value says mainnet unless their settings
// say mainnet, and the reverse (attestation-verify/runnerclient). A
// certificate without it leaves the decision to the client's setting.
// Same GUID arc as AttestOnlyClientOID, last arc 3.
var RunnerChainOID = asn1.ObjectIdentifier{1, 2, 840, 113556, 1, 8000, 2554,
	49247, 57036, 45844, 17649, 38356, 1811430, 10320378, 3}

// AttestOnlyPerMinute is the image constant of attestation-prover.md,
// signer change 8: the fresh attestations (ATTEST or IDENTITY answers for a
// new nonce) an attest-only certificate gets in any minute. More get
// RATE_LIMITED. The prover needs one an hour, the dashboard's proof check
// two a minute.
const AttestOnlyPerMinute = 4

// The contexts of the two user data hashes. They are entries of the
// registry in backend/setupwire (CtxRunnerIdentity, CtxRunnerAttest), which
// imports this package; a test there checks that the names agree.
const (
	IdentityContext = "signer-runner-identity-v1"
	AttestContext   = "signer-runner-attest-v1"
)

// SetupState is what a runner says about its setup and config in IDENTITY,
// ATTEST and HEALTH (research/setup-phase.md in the threshold-signer-poc repo,
// section 4, and research/attestation-prover.md, "Signer changes", item 6):
// setup_hash, the state of both config groups as the mark log holds it, the
// hash of the active approver set, the pending order, the key-release hash
// and the key origin. A runner without a setup (the flag path of tests and
// local runners) puts the SHA-256 of its chain config file in SetupHash and
// leaves the rest zero.
type SetupState struct {
	SetupHash Root        `json:"setup_hash"`
	Locked    ConfigGroup `json:"locked"`
	Open      ConfigGroup `json:"open"`
	// ApproverSetHash is over approvals_needed and the approver keys in order (setupwire
	// ApproverSet.Hash). Zero: the runner cannot read the active set.
	ApproverSetHash Root      `json:"approver_set_hash"`
	Order           Order     `json:"order"`
	KeyReleaseHash  Root      `json:"key_release_hash"`
	KeyOrigin       KeyOrigin `json:"key_origin"`
}

// ConfigGroup is the state of one config group: the active version, the
// hash of the update that set it (for version 0, the hash of the group in
// the setup), and the pending update.
type ConfigGroup struct {
	Version uint64        `json:"version"`
	Hash    Root          `json:"hash"`
	Pending PendingUpdate `json:"pending"`
}

// PendingUpdate is an update that waits for its effective activation time.
// All zero: none. A pending update has a version above the active one, so
// never 0.
type PendingUpdate struct {
	Version     uint64 `json:"version"`
	Hash        Root   `json:"hash"`
	EffectiveAt uint64 `json:"effective_at"` // Unix seconds
}

// Order is the pending handover order (kind 1). Kind 0, all zero: none.
// Kind 2 was the DKG order of earlier builds and no longer occurs.
type Order struct {
	Kind  uint8  `json:"kind"`
	Hash  Root   `json:"hash"`
	ActAt uint64 `json:"act_at"` // Unix seconds
}

// KeyOrigin says where the runner's loaded keys come from
// (attestation-prover.md, "Signer changes", item 6): how many it made in key
// generation, how many it imported, and KeygenOrdersHash over the DKG
// orders the generated ones came from. Generated plus Imported is the
// number of loaded keys, the ones keys_hash covers. A proof that shows
// Imported 0 shows that no loaded key came from outside a TEE.
type KeyOrigin struct {
	Generated  uint32 `json:"generated"`
	Imported   uint32 `json:"imported"`
	OrdersHash Root   `json:"orders_hash"`
}

// KeygenOrdersContext is the context of KeygenOrdersHash, an entry of the
// registry in backend/setupwire (CtxKeygenOrders).
const KeygenOrdersContext = "signer-keygen-orders-v1"

// KeygenOrdersHash is the key origin's hash of the DKG orders that made the
// generated keys:
//
//	SHA-256(len(ctx):u16 || ctx || n:u32 || order_hash[32] x n)
//
// with the n distinct order hashes in ascending byte order. No order (no
// generated key) gives 32 zero bytes, not the hash of an empty list.
func KeygenOrdersHash(orders [][32]byte) Root {
	orders = slices.Clone(orders)
	slices.SortFunc(orders, func(a, b [32]byte) int { return bytes.Compare(a[:], b[:]) })
	orders = slices.Compact(orders)
	if len(orders) == 0 {
		return Root{}
	}
	h := sha256.New()
	h.Write(binary.BigEndian.AppendUint16(nil, uint16(len(KeygenOrdersContext))))
	h.Write([]byte(KeygenOrdersContext))
	h.Write(binary.BigEndian.AppendUint32(nil, uint32(len(orders))))
	for _, o := range orders {
		h.Write(o[:])
	}
	return Root(h.Sum(nil))
}

// KeyReleaseContext is the context of KeyReleaseHash, an entry of the
// registry in backend/setupwire (CtxKeyRelease).
const KeyReleaseContext = "signer-key-release-v1"

// The platform byte of KeyReleaseHash: the numbers of the setup's private
// part. GCP and dev have no key release self-check, so their runners leave
// key_release_hash zero.
const (
	KeyReleaseNitro uint8 = 1
	KeyReleaseAzure uint8 = 2
)

// KeyReleaseHash is the setup state's key_release_hash: what the runner
// read at start about the key that releases its sealing key, so a
// verifier sees whether that key's policy is locked
// (docs/attestation-statement.md, section 5):
//
//	SHA-256(len(ctx):u16 || ctx || platform:u8 || {len(field):u32 || field})
//
// with the fields of that platform in their fixed order. A flag field is
// one byte, 0 or 1.
func KeyReleaseHash(platform uint8, fields ...[]byte) Root {
	h := sha256.New()
	h.Write(binary.BigEndian.AppendUint16(nil, uint16(len(KeyReleaseContext))))
	h.Write([]byte(KeyReleaseContext))
	h.Write([]byte{platform})
	for _, f := range fields {
		h.Write(binary.BigEndian.AppendUint32(nil, uint32(len(f))))
		h.Write(f)
	}
	return Root(h.Sum(nil))
}

// SetupStateLen is the size of a SetupState's encoding.
const SetupStateLen = 32 + 2*(8+32+8+32+8) + 32 + (1 + 32 + 8) + 32 + (4 + 4 + 32)

// AppendSetupState appends the fixed-size encoding of s:
//
//	setup_hash[32]
//	locked: version:u64 hash[32] pending_version:u64 pending_hash[32] pending_effective_at:u64
//	open:   the same
//	approver_set_hash[32] order_kind:u8 order_hash[32] order_act_at:u64 key_release_hash[32]
//	key_origin: generated_keys:u32 imported_keys:u32 keygen_orders_hash[32]
func AppendSetupState(b []byte, s *SetupState) []byte {
	be := binary.BigEndian
	b = append(b, s.SetupHash[:]...)
	for _, g := range []*ConfigGroup{&s.Locked, &s.Open} {
		b = be.AppendUint64(b, g.Version)
		b = append(b, g.Hash[:]...)
		b = be.AppendUint64(b, g.Pending.Version)
		b = append(b, g.Pending.Hash[:]...)
		b = be.AppendUint64(b, g.Pending.EffectiveAt)
	}
	b = append(b, s.ApproverSetHash[:]...)
	b = append(b, s.Order.Kind)
	b = append(b, s.Order.Hash[:]...)
	b = be.AppendUint64(b, s.Order.ActAt)
	b = append(b, s.KeyReleaseHash[:]...)
	b = be.AppendUint32(b, s.KeyOrigin.Generated)
	b = be.AppendUint32(b, s.KeyOrigin.Imported)
	return append(b, s.KeyOrigin.OrdersHash[:]...)
}

// ParseSetupState reads an encoding of exactly SetupStateLen bytes. It
// refuses a pending update at or below the active version, an empty one
// with a hash or time, and an order of an unknown kind.
func ParseSetupState(b []byte) (SetupState, error) {
	var s SetupState
	if len(b) != SetupStateLen {
		return s, fmt.Errorf("setup state: %d bytes, want %d", len(b), SetupStateLen)
	}
	be := binary.BigEndian
	take := func(n int) []byte { v := b[:n]; b = b[n:]; return v }
	copy(s.SetupHash[:], take(32))
	for _, g := range []*ConfigGroup{&s.Locked, &s.Open} {
		g.Version = be.Uint64(take(8))
		copy(g.Hash[:], take(32))
		g.Pending.Version = be.Uint64(take(8))
		copy(g.Pending.Hash[:], take(32))
		g.Pending.EffectiveAt = be.Uint64(take(8))
		p := g.Pending
		if p.Version == 0 && (p.Hash != Root{} || p.EffectiveAt != 0) || p.Version != 0 && p.Version <= g.Version {
			return SetupState{}, errors.New("setup state: a pending update that is neither empty nor above the active version")
		}
	}
	copy(s.ApproverSetHash[:], take(32))
	s.Order.Kind = take(1)[0]
	copy(s.Order.Hash[:], take(32))
	s.Order.ActAt = be.Uint64(take(8))
	copy(s.KeyReleaseHash[:], take(32))
	s.KeyOrigin.Generated = be.Uint32(take(4))
	s.KeyOrigin.Imported = be.Uint32(take(4))
	copy(s.KeyOrigin.OrdersHash[:], take(32))
	if s.Order.Kind > 2 || s.Order.Kind == 0 && (s.Order.Hash != Root{} || s.Order.ActAt != 0) {
		return SetupState{}, fmt.Errorf("setup state: order of kind %d", s.Order.Kind)
	}
	return s, nil
}

// userDataHash starts a user data hash: the context, length-prefixed as in
// the setupwire registry, then the nonce, length-prefixed.
func userDataHash(context string, nonce []byte) hash.Hash {
	h := sha256.New()
	h.Write(binary.BigEndian.AppendUint16(nil, uint16(len(context))))
	h.Write([]byte(context))
	h.Write(binary.BigEndian.AppendUint16(nil, uint16(len(nonce))))
	h.Write(nonce)
	return h
}

// IdentityUserData is what the runner binds into the platform document of
// an IDENTITY response: one 32-byte hash over the context, the nonce, the
// setup state and the keys. Every variable-length field is length-prefixed.
func IdentityUserData(nonce []byte, id *Identity) []byte {
	return identityUserData(IdentityContext, nonce, id)
}

func identityUserData(context string, nonce []byte, id *Identity) []byte {
	h := userDataHash(context, nonce)
	h.Write(AppendSetupState(nil, &id.State))
	put16 := func(v int) { h.Write(binary.BigEndian.AppendUint16(nil, uint16(v))) }
	put16(int(id.ImportKEM))
	put16(int(id.ImportKDF))
	put16(int(id.ImportAEAD))
	put16(len(id.ImportKey))
	h.Write(id.ImportKey)
	put16(len(id.TLSKeyHash))
	h.Write(id.TLSKeyHash)
	return h.Sum(nil)
}

// KeysHash is the hash of the loaded keys that ATTEST binds: sha256 over
// pubkey and share_pubkey of each key, sorted by pubkey.
func KeysHash(keys []ValidatorKey) [32]byte {
	keys = slices.Clone(keys)
	slices.SortFunc(keys, func(a, b ValidatorKey) int { return bytes.Compare(a.Pubkey[:], b.Pubkey[:]) })
	h := sha256.New()
	for _, k := range keys {
		h.Write(k.Pubkey[:])
		h.Write(k.SharePubkey[:])
	}
	return [32]byte(h.Sum(nil))
}

// AttestUserData is what the runner binds into the platform document of an
// ATTEST response: one 32-byte hash over the context, the nonce, the setup
// state and the hash of the loaded keys (KeysHash).
func AttestUserData(nonce []byte, s *SetupState, keysHash [32]byte) []byte {
	h := userDataHash(AttestContext, nonce)
	h.Write(AppendSetupState(nil, s))
	h.Write(keysHash[:])
	return h.Sum(nil)
}

// MAARuntimeData is the runtime data an Azure runner sends to MAA for user
// data (IdentityUserData): the JSON object {"signer-runner-identity":"<hex>"},
// byte for byte. The runner sends runtime data to MAA with dataType JSON, so
// it must be JSON; the SNP report data is the SHA-256 of these exact bytes,
// which a verifier recomputes (attest.MAAOptions.RuntimeData).
func MAARuntimeData(userData []byte) []byte {
	return []byte(`{"signer-runner-identity":"` + hex.EncodeToString(userData) + `"}`)
}

// SealedImportRequest loads a share that the dealer encrypted with HPKE to
// the runner's attested import key (Identity.ImportKey). Every field but
// Sealed is bound into the HPKE associated data, so the host cannot change
// them in transit.
type SealedImportRequest struct {
	Pubkey      Pubkey // validator (account) key
	SharePubkey Pubkey // public key of the share inside Sealed; the runner checks it
	Index       uint64 // validator index or IndexUnknown
	Interchange *Watermark
	Sealed      []byte // enc_len:u16 enc ciphertext (package sealedimport)
	// Order is a signed import order (package importorder) that names
	// Pubkey. A runner with a setup refuses a sealed import without one.
	Order []byte
	// The split the share comes from, as the order names it: threshold T
	// of N, this share's index (x coordinate), and the T public commitments
	// of the polynomial, Commitments[0] being Pubkey. With an order they
	// are required.
	T, N, ShareIndex uint8
	Commitments      []Pubkey
}

// Watermark is an EIP-3076 minimal-strategy summary for one validator:
// nothing at or below these values may be signed.
type Watermark struct {
	BlockSlot      uint64 `json:"block_slot"`
	SourceEpoch    uint64 `json:"source_epoch"`
	TargetEpoch    uint64 `json:"target_epoch"`
	HasBlock       bool   `json:"has_block"`
	HasAttestation bool   `json:"has_attestation"`
}

// ImportShareRequest loads a share into the backend. This is a test
// shortcut: the secret crosses the channel in plaintext. Only a debug build
// of the runner (-tags debugimport) has it, and only on the dev platform
// with -allow-import; a release runner answers it as an unknown message
// type. Cloud runners take SealedImportRequest instead.
type ImportShareRequest struct {
	Pubkey Pubkey   // validator (account) key
	Secret [32]byte // share secret, big endian scalar
	Index  uint64   // validator index or IndexUnknown
	// Interchange, if set, raises the slashing watermark to these EIP-3076 maxima.
	Interchange *Watermark
}

// Backend is what the Dirk fork calls. Implementations are safe for
// concurrent use.
type Backend interface {
	PublicKeys(ctx context.Context) ([]ValidatorKey, error)
	// Sign returns a partial signature, or a *RefusedError when slashing
	// protection or policy says no.
	Sign(ctx context.Context, req SignRequest) (Signature, error)
	// Attest returns an attestation document that binds nonce.
	Attest(ctx context.Context, nonce []byte) (*Attestation, error)
	Health(ctx context.Context) (*Health, error)
	Close() error
}
