// Package platform holds the hooks a runner needs from the secure
// environment it runs in. Each platform (dev, nitro, gcp, azure) fills a
// Platform with its own implementations.
package platform

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/lidofinance/tee-signer/governance/setupwire"
	"github.com/lidofinance/tee-signer/signer-protocol"
)

// ErrNotFound is returned by Store.Get for a missing key.
var ErrNotFound = errors.New("platform: not found")

// ErrNotAuthentic is returned by Keys.OpenKey when the blob was not made by
// NewKey of this platform's key release with this aad: someone else made
// it, it was changed, or it belongs to another purpose or signer. Any other
// error (the key service is down, access refused) is not this one, so a
// caller can tell a forged blob from a key release it cannot reach.
var ErrNotAuthentic = errors.New("platform: wrapped key does not open under this key release")

// Sealer encrypts data so that only this measured program on this
// platform, with this setup, can decrypt it: its key comes from key release
// with setup_hash (Options.SetupHash). aad binds the blob to its purpose
// and key.
type Sealer interface {
	Seal(plaintext, aad []byte) ([]byte, error)
	Unseal(blob, aad []byte) ([]byte, error)
}

// Store is persistence outside the secure boundary. Assume the host can
// read, delete, replay and roll back anything in it; it cannot forge
// sealed blobs. Put returns only once the value is durable.
type Store interface {
	Get(key string) ([]byte, error)
	Put(key string, val []byte) error
	List(prefix string) ([]string, error)
}

// Clock is the time source the signer core and the restart rule use.
type Clock interface {
	Now() (time.Time, error)
	// Source names the clock, e.g. "system", "anchored(https-date x3)".
	Source() string
	// Trusted is true only if the design says the host cannot move it.
	Trusted() bool
}

// Keys makes 32-byte secrets wrapped by the platform's attested key release
// and opens them again. Unlike Sealer it needs no local state: a runner of
// the same image that lost its state directory opens what an earlier
// process made. Only the attested runner can make a blob that opens, so a
// blob that opens was made by it (or by whoever controls key release). The
// mark log keeps its signing keys this way (runner/markstore).
type Keys interface {
	// NewKey returns a fresh random key and its wrapped form, bound to aad.
	NewKey(ctx context.Context, aad []byte) (key, blob []byte, err error)
	// OpenKey returns the key of blob. ErrNotAuthentic means the blob was
	// not made by NewKey with this aad under this key release.
	OpenKey(ctx context.Context, blob, aad []byte) ([]byte, error)
}

// SealerKeys is Keys on a Sealer whose key comes from key release without
// local state (Azure: derived from the released key and setup_hash; dev: a
// public key).
type SealerKeys struct{ Sealer Sealer }

func (s SealerKeys) NewKey(_ context.Context, aad []byte) ([]byte, []byte, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, nil, err
	}
	blob, err := s.Sealer.Seal(key, aad)
	if err != nil {
		return nil, nil, err
	}
	return key, blob, nil
}

func (s SealerKeys) OpenKey(_ context.Context, blob, aad []byte) ([]byte, error) {
	key, err := s.Sealer.Unseal(blob, aad)
	if err != nil || len(key) != 32 {
		return nil, ErrNotAuthentic
	}
	return key, nil
}

// Attester produces an attestation document that binds userData.
type Attester interface {
	Attest(ctx context.Context, nonce, userData []byte) (*backend.Attestation, error)
}

// Platform bundles the hooks.
type Platform struct {
	Name     string
	Sealer   Sealer
	Store    Store
	Clock    Clock
	Attester Attester
	// HTTPClient reaches the outside world (KMS, time sources). Nitro
	// enclaves have no network, so there it dials through vsock-proxy.
	// nil means http.DefaultClient.
	HTTPClient *http.Client
	// Dial opens the NTS clock's connections (runner/clock.NTS, build tag
	// nts): TCP for NTS-KE and UDP for NTP. A Nitro enclave has no network,
	// so there TCP goes through vsock-proxy and UDP through the parent's
	// relay (runner/udprelay). nil means net.Dialer.
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
	// Close releases platform resources (devices, sessions). May be nil.
	Close func() error
	// RecordCredentials, if set, signs requests to the clone guard's record
	// store (DynamoDB on AWS). They must be credentials the host does not
	// hold. May be nil.
	RecordCredentials func(ctx context.Context) (Credentials, error)
	// StorageToken, if set, returns an OAuth bearer token for the platform's
	// object store, for the mark log (runner/markstore): on GCP the
	// federated token of the attested workload, on Azure the managed
	// identity's token for https://storage.azure.com/. Only the attested
	// runner can get it. expires is when the token expires, zero when the
	// platform does not say (GCP); the mark log's token cache refreshes by
	// it. May be nil.
	StorageToken func(ctx context.Context) (token string, expires time.Time, err error)
	// ManagementToken, if set, returns an OAuth bearer token for the cloud's
	// management plane. Azure only: the managed identity's token for
	// https://management.azure.com/, with which the mark log reads its
	// container's immutability policy (the lock check). expires as for
	// StorageToken. May be nil.
	ManagementToken func(ctx context.Context) (token string, expires time.Time, err error)
	// Keys wraps keys under the platform's key release, independent of
	// local state (the mark log's signing keys). May be nil on a platform
	// that cannot run the mark log.
	Keys Keys
	// ReportExit, if set, hands the runner's fatal error line (the one it
	// prints to stderr) to the host before the runner exits, for a platform
	// whose console nobody sees (Nitro: the host agent's EXIT). Only that
	// line goes this way: the host is not trusted.
	ReportExit func(text string)
	// SelfImage, if set, returns this runner's own image as an
	// allowed_image_measurements entry, from the attestation evidence its
	// key release used (ImageSeen): GCP the image digest, Azure the CCE
	// policy hash, Nitro PCR0 to PCR2. The runner checks it against the
	// allowed list in force (server.ImageGate). nil: a platform without an
	// image kind (dev), which protects nothing.
	SelfImage func(ctx context.Context) (setupwire.Image, error)
	// KeyRule is what the constructor read about the rule of the key that
	// releases the sealing key (Options.ReadKeyRule), before the key
	// release: key_release_hash and the lock. GCP and dev give
	// backend.KeyLockNone. nil: nothing read (the flag path, or a platform
	// without the read).
	KeyRule *KeyRule
}

// KeyRule is the rule of the key that releases the sealing key, as the
// runner read it inside the TEE: on AWS the KMS key policy and key
// metadata, on Azure the Key Vault key's release policy and flags.
type KeyRule struct {
	// Hash is key_release_hash (backend.KeyReleaseHash,
	// research/setup-phase.md section 4); zero when unread or none.
	Hash [32]byte
	Lock backend.KeyLock
	// Why says what keeps the rule open, or why it was not read.
	Why string
	// NoService: the platform has no key release service at all (dev), so
	// there is no rule to lock or to accept.
	NoService bool
}

// KeyRuleTimeout bounds the read of the key rule at start.
const KeyRuleTimeout = time.Minute

// ReadKeyRule reads the key rule with read before the constructor releases
// any key, and applies the mainnet rule (docs/protocol.md, "Key rule
// lock"): with Mainnet set, a rule that is not locked, or one the runner
// cannot read, stops the start, so nothing is sealed under a key whose
// rule someone can still change. A platform without a lock (GCP) passes
// only when the setup accepts that (CheckKeyRule). Off mainnet a failed
// read gives KeyLockUnread and the start goes on, as before. On the flag
// path (no setup_hash) nothing is read: nil.
func (o Options) ReadKeyRule(ctx context.Context, read func(context.Context) (KeyRule, error)) (*KeyRule, error) {
	if o.SetupHash == ([32]byte{}) {
		return nil, nil
	}
	ctx, cancel := context.WithTimeout(ctx, KeyRuleTimeout)
	defer cancel()
	r, err := read(ctx)
	if err != nil {
		r = KeyRule{Lock: backend.KeyLockUnread, Why: err.Error()}
	}
	if err := o.CheckKeyRule(&r); err != nil {
		return nil, err
	}
	return &r, nil
}

// NoLock is the key rule read of a platform whose key release service has
// no lock on the key's rule (GCP): KeyLockNone with why, and a zero
// key_release_hash.
func NoLock(why string) func(context.Context) (KeyRule, error) {
	return func(context.Context) (KeyRule, error) { return KeyRule{Lock: backend.KeyLockNone, Why: why}, nil }
}

// NoKeyRelease is the key rule read of a platform without a key release
// service (dev): KeyLockNone with NoService set.
func NoKeyRelease(why string) func(context.Context) (KeyRule, error) {
	return func(context.Context) (KeyRule, error) {
		return KeyRule{Lock: backend.KeyLockNone, Why: why, NoService: true}, nil
	}
}

// CheckKeyRule is the mainnet rule on a rule already read: with Mainnet
// set, KeyLockLocked passes, KeyLockNone passes only as CheckNoLock
// allows, and the rest stop the start. nil counts as unread.
func (o Options) CheckKeyRule(r *KeyRule) error {
	if !o.Mainnet {
		return nil
	}
	if r == nil {
		r = &KeyRule{Lock: backend.KeyLockUnread, Why: "the platform read no key rule"}
	}
	switch r.Lock {
	case backend.KeyLockLocked:
		return nil
	case backend.KeyLockNone:
		return o.CheckNoLock(r)
	case backend.KeyLockUnread:
		return fmt.Errorf("mainnet: the runner cannot read the rule of the key that releases its sealing key, and does not start unless it sees the rule locked: %s", r.Why)
	default:
		return fmt.Errorf("mainnet: the rule of the key that releases the sealing key is not locked, and the runner does not start: %s", r.Why)
	}
}

// CheckNoLock is the mainnet rule for a key rule without a lock (T-124): GCP Cloud KMS has no lock on a key's IAM bindings,
// so a GCP runner starts on mainnet only when its setup accepts that
// (sealing_key_release.no_lock_accepted, Options.NoLockAccepted). The dev
// platform (no key release service, NoService) has no real attestation
// either: it never starts on mainnet, whatever the setup accepts. Single-node GCP signers are refused apart from
// this (setupwire.CheckThresholdOn).
func (o Options) CheckNoLock(r *KeyRule) error {
	if r.NoService {
		return fmt.Errorf("mainnet: the dev platform has no real attestation and no key release service, so a mainnet runner does not start on it; run aws, azure or gcp (%s)", r.Why)
	}
	if o.NoLockAccepted {
		return nil
	}
	return fmt.Errorf("mainnet: the platform has no lock on the rule of the key that releases the sealing key (%s), "+
		"and the setup does not accept that (sealing_key_release.no_lock_accepted = true); the runner does not start", r.Why)
}

// DurableFunc wraps the platform's local store in a durable copy outside
// the host (runner/statestore) and restores the local store from it first.
// p carries what the copy needs: Store (the local store), Keys,
// StorageToken, RecordCredentials and HTTPClient; its Sealer is not yet set.
// The platform uses the returned store from then on.
type DurableFunc func(ctx context.Context, p *Platform) (Store, error)

// Credentials are AWS-style access keys.
type Credentials struct {
	AccessKeyID, SecretAccessKey, SessionToken string
	Expires                                    time.Time // zero: does not expire
}

// Options are the settings a platform constructor gets from the command line.
type Options struct {
	StateDir string            // local state directory (dev, or a host-mounted volume)
	Params   map[string]string // --platform-opt key=value pairs
	// SetupHash is the signer's setup_hash; zero on the flag path without a
	// setup. Every key-release call carries it (research/setup-phase.md in
	// the threshold-signer-poc repo, section 4): the sealing key and the keys of
	// Keys differ per setup, so a runner of the same image with another
	// setup, even under the same key-release key, opens nothing this one
	// sealed or wrapped.
	SetupHash [32]byte
	// Durable, if set, is called once the key release works and before the
	// sealing key is read from the store (-state-store). The platforms whose
	// local state can vanish on a restart call it: azure, gcp and dev.
	Durable DurableFunc
	// Mainnet is set when the setup's chain is mainnet
	// (setupwire.IsMainnet): ReadKeyRule then refuses a key rule that is
	// not locked or not readable.
	Mainnet bool
	// NoLockAccepted is the setup's sealing_key_release.no_lock_accepted
	// (GCP only): on mainnet a key rule without a lock passes
	// (CheckNoLock).
	NoLockAccepted bool
}

// UseDurable calls o.Durable if set and returns the store to use.
func (o Options) UseDurable(ctx context.Context, p *Platform) (Store, error) {
	if o.Durable == nil {
		return p.Store, nil
	}
	return o.Durable(ctx, p)
}

// Param returns Params[key] or def.
func (o Options) Param(key, def string) string {
	if v, ok := o.Params[key]; ok && v != "" {
		return v
	}
	return def
}
