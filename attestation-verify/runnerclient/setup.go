package runnerclient

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/remote"
)

// The setup pins (research/setup-phase.md in the threshold-signer-poc repo, section
// 11). Every verifier this package builds runs them after the platform
// check, on the setup state of the verified identity. The
// Dirk fork's adapter, cloud-import (again on the identity it seals each
// share to), proof-check, share-import and the key generation peers
// (runner/keygen, a policy participant's attestation) build their verifier
// here, so all of them refuse the same runners:
//
//   - With setup_sha256, a runner whose setup_hash differs is refused.
//   - Without it, a runner that reports a setup is refused, unless
//     allow_unpinned_setup (tests with the dev verifier only). A runner on
//     the flag path (no setup: setup_hash is the SHA-256 of its -config
//     file and every other field is zero) is accepted, as before setups.
//   - With min_locked_version or min_open_version, a runner whose effective
//     version of that group is lower is refused. That keeps shares away
//     from a runner whose host brought back an older config state (section
//     5 of the design, S6).
//   - With key_release_sha256, a runner whose key_release_hash differs is
//     refused (T-125): its sealing key is released under another rule than
//     the one the operator reviewed, or it read none. With mainnet set, an
//     azure-maa or aws-nitro client needs it; gcp-cs never does.

// setupPins are the setup settings, checked.
type setupPins struct {
	pin                backend.Root
	pinned             bool
	minLocked, minOpen uint64
	allowUnpinned      bool
	keyRelease         backend.Root // zero: not pinned
}

func (a *Attestation) setupPins() (*setupPins, error) {
	p := &setupPins{minLocked: a.MinLockedVersion, minOpen: a.MinOpenVersion, allowUnpinned: a.AllowUnpinnedSetup}
	if a.SetupSHA256 != "" {
		b, err := hex.DecodeString(strings.TrimPrefix(strings.ToLower(a.SetupSHA256), "0x"))
		if err != nil || len(b) != 32 {
			return nil, errors.New("attestation.setup_sha256: want 64 hex digits, the setup_sha256 that setup-tool prints")
		}
		p.pin, p.pinned = backend.Root(b), true
	}
	if a.KeyReleaseSHA256 != "" {
		b, err := hex.DecodeString(strings.TrimPrefix(strings.ToLower(a.KeyReleaseSHA256), "0x"))
		switch {
		case err != nil || len(b) != 32:
			return nil, errors.New("attestation.key_release_sha256: want 64 hex digits, the key_release_hash of the key rule you reviewed")
		case backend.Root(b) == backend.Root{}:
			return nil, errors.New("attestation.key_release_sha256: zero is the hash of a rule not read (or GCP, which has none); pin the hash of a rule")
		case !p.pinned:
			return nil, errors.New("attestation.key_release_sha256: needs setup_sha256, since the key rule is read per setup")
		}
		p.keyRelease = backend.Root(b)
	}
	// On mainnet the key rule of an Azure or Nitro runner must be the one
	// the operator reviewed. GCP has no
	// lock and no rule hash to pin.
	if a.Mainnet && p.keyRelease == (backend.Root{}) && (a.Verifier == VerifierAzureMAA || a.Verifier == VerifierAWSNitro) {
		return nil, fmt.Errorf("attestation: mainnet: an %s runner needs key_release_sha256, the key_release_hash of the key rule you reviewed", a.Verifier)
	}
	switch {
	case !p.pinned && p.minLocked != 0:
		return nil, errors.New("attestation.min_locked_version: needs setup_sha256, since versions count within one setup")
	case !p.pinned && p.minOpen != 0:
		return nil, errors.New("attestation.min_open_version: needs setup_sha256, since versions count within one setup")
	case p.allowUnpinned && p.pinned:
		return nil, errors.New("attestation.allow_unpinned_setup: not with setup_sha256; pin the setup or allow unpinned ones, not both")
	case p.allowUnpinned && a.Verifier != VerifierDev:
		return nil, fmt.Errorf("attestation.allow_unpinned_setup: for tests with the dev verifier only, not %q", a.Verifier)
	}
	return p, nil
}

// after returns a verifier that runs v and then checks the setup state of
// the identity v accepted.
func (p *setupPins) after(v remote.VerifyFunc, now func() time.Time) remote.VerifyFunc {
	return func(ctx context.Context, nonce []byte, id *backend.Identity) error {
		if err := v(ctx, nonce, id); err != nil {
			return err
		}
		return p.check(&id.State, now())
	}
}

func (p *setupPins) check(s *backend.SetupState, now time.Time) error {
	switch {
	case p.pinned && s.SetupHash != p.pin:
		return fmt.Errorf("runnerclient: the runner's setup_hash %s is not the pinned setup_sha256 %s", rootHex(s.SetupHash), rootHex(p.pin))
	case !p.pinned && !FlagPath(s) && !p.allowUnpinned:
		return fmt.Errorf("runnerclient: the runner reports setup %s and no setup_sha256 is pinned; pin the hash of the setup you built", rootHex(s.SetupHash))
	case p.keyRelease != (backend.Root{}) && s.KeyReleaseHash != p.keyRelease:
		return fmt.Errorf("runnerclient: the runner's key_release_hash %s is not the pinned key_release_sha256 %s", rootHex(s.KeyReleaseHash), rootHex(p.keyRelease))
	}
	if v := EffectiveVersion(s.Locked, now); v < p.minLocked {
		return fmt.Errorf("runnerclient: the runner's locked config is at version %d, below min_locked_version %d", v, p.minLocked)
	}
	if v := EffectiveVersion(s.Open, now); v < p.minOpen {
		return fmt.Errorf("runnerclient: the runner's open config is at version %d, below min_open_version %d", v, p.minOpen)
	}
	return nil
}

// FlagPath reports whether s is the state of a runner without a setup: its
// setup_hash is the SHA-256 of its -config file and every other field is
// zero. A runner with a setup always has the hashes of both groups.
func FlagPath(s *backend.SetupState) bool {
	return *s == backend.SetupState{SetupHash: s.SetupHash}
}

// unixNow is now in whole Unix seconds, 0 before 1970.
func unixNow(now time.Time) uint64 { return uint64(max(now.Unix(), 0)) }

// Waiting reports whether g has a pending update whose effective activation
// time is still ahead of now.
func Waiting(g backend.ConfigGroup, now time.Time) bool {
	return g.Pending.Version != 0 && g.Pending.EffectiveAt > unixNow(now)
}

// EffectiveVersion is the version of g in force at now. IDENTITY reports
// the newest mark record, and that still shows an update as pending after
// its effective activation time, while the runner applies it from that time
// on. So a pending update counts once its time has passed.
func EffectiveVersion(g backend.ConfigGroup, now time.Time) uint64 {
	if g.Pending.Version != 0 && !Waiting(g, now) {
		return g.Pending.Version
	}
	return g.Version
}

// CheckPending refuses a state in which a locked update waits for its
// effective activation time, or an order is pending. cloud-import runs it
// on the identity of each share unless the operator passes -allow-pending
// (research/setup-phase.md, section 11): a share sent now stays under the
// approvers, allowed images or handover target that the update or order
// brings in.
func CheckPending(s *backend.SetupState, now time.Time) error {
	if p := s.Locked.Pending; Waiting(s.Locked, now) {
		return fmt.Errorf("a locked config update is pending: version %d (sha256 %s), effective at %s",
			p.Version, rootHex(p.Hash), UnixTime(p.EffectiveAt))
	}
	if o := s.Order; o.Kind != 0 {
		return fmt.Errorf("a %s order is pending (sha256 %s), acting at %s", OrderKind(o.Kind), rootHex(o.Hash), UnixTime(o.ActAt))
	}
	return nil
}

// OrderKind names the kind of a pending order: "handover" (1) or "dkg" (2).
func OrderKind(k uint8) string {
	switch k {
	case 0:
		return "none"
	case 1:
		return "handover"
	case 2:
		return "dkg"
	}
	return fmt.Sprintf("kind %d", k)
}

// UnixTime writes Unix seconds as RFC 3339 UTC, or as the plain number
// past the year 9999 (a saturated sum of the runner).
func UnixTime(sec uint64) string {
	const lastSecondOf9999 = 253402300799
	if sec > lastSecondOf9999 {
		return fmt.Sprintf("unix %d", sec)
	}
	return time.Unix(int64(sec), 0).UTC().Format(time.RFC3339)
}

func rootHex(r backend.Root) string { return hex.EncodeToString(r[:]) }

// SetupLog is the setup state as key and value pairs for log/slog, with
// full hex hashes. For a runner with a setup: setup_sha256, per group
// <group>_version and <group>_sha256, <group>_effective_version when a
// pending update is in force at now, <group>_pending_version,
// <group>_pending_sha256 and <group>_pending_effective_at for a pending
// update, approver_set_sha256, and order, order_sha256 and order_act_at for
// a pending order, key_release_sha256 when set, and the key origin:
// generated_keys, imported_keys and keygen_orders_sha256 when set. For a
// runner on the flag path: setup_sha256 and flag_path true.
func SetupLog(s *backend.SetupState, now time.Time) []any {
	out := []any{"setup_sha256", rootHex(s.SetupHash)}
	if FlagPath(s) {
		return append(out, "flag_path", true)
	}
	for _, g := range []struct {
		name string
		g    backend.ConfigGroup
	}{{"locked", s.Locked}, {"open", s.Open}} {
		out = append(out, g.name+"_version", g.g.Version, g.name+"_sha256", rootHex(g.g.Hash))
		if e := EffectiveVersion(g.g, now); e != g.g.Version {
			out = append(out, g.name+"_effective_version", e)
		}
		if p := g.g.Pending; p.Version != 0 {
			out = append(out, g.name+"_pending_version", p.Version, g.name+"_pending_sha256", rootHex(p.Hash),
				g.name+"_pending_effective_at", UnixTime(p.EffectiveAt))
		}
	}
	out = append(out, "approver_set_sha256", rootHex(s.ApproverSetHash))
	if o := s.Order; o.Kind != 0 {
		out = append(out, "order", OrderKind(o.Kind), "order_sha256", rootHex(o.Hash), "order_act_at", UnixTime(o.ActAt))
	}
	if s.KeyReleaseHash != (backend.Root{}) {
		out = append(out, "key_release_sha256", rootHex(s.KeyReleaseHash))
	}
	out = append(out, "generated_keys", s.KeyOrigin.Generated, "imported_keys", s.KeyOrigin.Imported)
	if s.KeyOrigin.OrdersHash != (backend.Root{}) {
		out = append(out, "keygen_orders_sha256", rootHex(s.KeyOrigin.OrdersHash))
	}
	return out
}

// DescribeSetup is SetupLog as one line of key=value pairs, for tools that
// print it.
func DescribeSetup(s *backend.SetupState, now time.Time) string {
	kv := SetupLog(s, now)
	parts := make([]string, 0, len(kv)/2)
	for i := 0; i+1 < len(kv); i += 2 {
		parts = append(parts, fmt.Sprintf("%v=%v", kv[i], kv[i+1]))
	}
	return strings.Join(parts, " ")
}
