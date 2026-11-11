package setupwire

import (
	"bytes"
	"cmp"
	"errors"
	"fmt"
	"slices"

	"github.com/lidofinance/tee-signer/signer-protocol"
)

// Change rules of config updates (setup format 6). Each changed field of
// an update gets a class:
//
//   - tightening: the signer does less. It comes into force with the usual
//     signature count (approvals_needed) and no wait.
//   - loosening: the signer does more. Usual count, then the change delay
//     (Wait).
//   - break-glass: three loosening changes (adding an image measurement,
//     time_policy from NTS to NTP, raising either time_policy bound) may
//     also come into force with no wait when every active approver signs.
//     The normal path, usual count and wait, stays open for them.
//
// One more fast path: emergency approver removal. An update that removes
// one approver and makes no other loosening change comes into force with no
// wait when every active approver except the removed one signs.
//
// Every other loosening change has only the normal path. In particular
// adding, replacing or reordering approvers always waits.
//
// Some changes that do less still wait, as a loosening does, because the
// usual count could otherwise stop the cluster at once with no way back
// but a change that waits: any change of approvals_needed or
// change_delay_seconds, up or down (raised to every approver and the
// longest delay, governance freezes), and an update that leaves
// allowed_image_measurements empty (no runner may sign). The other
// approvers then have the change delay to replace the update.
//
// Where 0 or an empty list turns a check off, moving to it loosens and
// moving away from it tightens (tightenLimit): builder_registration_max_
// future_seconds (0 turns the core's check off, signer-core policy.c) and
// deposit_policy.allowed_deposit_amounts (unused yet; empty may come to
// mean any amount). The other locked fields were checked against the core
// and the runner: an empty allowed list (images, fee recipients,
// BuilderRequestAuth roots) refuses everything, gas limits are a plain
// range, bare_root_domains 0 allows no domain, change_delay_seconds 0 is
// the shortest delay and absent is the build default, which ChangeDelay
// compares, and the time_policy bounds are never 0 (1000 ms, the largest
// sample bound, is the loosest and compares as such).
//
// The open group never waits. Adding entries to revoked_client_certs is
// fast with the usual count. Dropping one undoes a revocation, for
// example to make room under MaxRevokedClientCerts or once a certificate
// has expired: it needs every active approver and no wait (PathBreakGlass),
// and with fewer signers Decide refuses the update. The minimum number of
// time servers is the runner's check, since it needs the image's catalog.
//
// The runner's config Accept calls Decide for every update it has not
// seen (tee-signer/server, Updates.Accept).

// ChangeClass is the class of a changed field.
type ChangeClass uint8

const (
	ChangeTighten    ChangeClass = 1
	ChangeLoosen     ChangeClass = 2
	ChangeBreakGlass ChangeClass = 3 // loosening, with the all-approvers fast path too
	ChangeOpen       ChangeClass = 4 // a field of the open group, which never waits
)

var changeClassNames = []string{ChangeTighten: "tightening", ChangeLoosen: "loosening", ChangeBreakGlass: "break-glass", ChangeOpen: "open"}

func (c ChangeClass) String() string { return enumName(changeClassNames, uint8(c)) }

// FieldChange is one changed leaf of a group and its class.
type FieldChange struct {
	Field string // the leaf name
	Class ChangeClass
}

// Path is the way an update comes into force.
type Path uint8

const (
	// PathNormal: approvals_needed signatures. The update waits Wait when
	// a change loosens, and comes into force at once when every change
	// tightens.
	PathNormal Path = 1
	// PathBreakGlass: every active approver signed and every loosening
	// change is break-glass. No wait.
	PathBreakGlass Path = 2
	// PathEmergencyRemoval: the update removes one approver, every active
	// approver except that one signed, and no other change loosens. No
	// wait.
	PathEmergencyRemoval Path = 3
)

var pathNames = []string{PathNormal: "normal", PathBreakGlass: "break-glass", PathEmergencyRemoval: "emergency-removal"}

func (p Path) String() string { return enumName(pathNames, uint8(p)) }

// Decision is what the change rules make of a signed update.
type Decision struct {
	Changes []FieldChange // the changed leaves, in leaf order
	Path    Path
	// Wait is W of step 7: Wait for a loosening update on the normal path,
	// else 0.
	Wait uint64
	// Removed is the position in the active set of the approver an
	// emergency removal removes, -1 on the other paths.
	Removed int
}

// Loosens reports whether a change loosens, break-glass changes included.
func (d *Decision) Loosens() bool { return loosens(d.Changes) }

func loosens(cs []FieldChange) bool {
	return slices.ContainsFunc(cs, func(c FieldChange) bool { return c.Class == ChangeLoosen || c.Class == ChangeBreakGlass })
}

// Decide checks a signed update against the values in force and picks its
// path and wait. active is the locked group in force, open the open group
// in force (needed for an open update only). It runs Verify first, so the
// usual signature count holds on every path; a fast path needs more
// signers on top. It is for the runner's config Accept, in place of
// Verify and Wait for an update the runner has not seen, and for the
// tools, to tell the approvers how soon an update can come into force.
//
// The fastest path the signatures allow wins: no wait when every change
// tightens, else emergency removal, else break-glass, else the normal
// path with Wait. h is what the signer's state says about earlier updates:
// within one change delay after an approver removal, break-glass is not a
// path (History.BreakGlassHeld).
func (u *Update) Decide(c *Chain, active *Locked, open *Open, h History) (Decision, error) {
	if err := u.Verify(&active.Approvers); err != nil {
		return Decision{}, err
	}
	b := &u.Body
	d := Decision{Path: PathNormal, Removed: -1}
	held, until := h.BreakGlassHeld(c, active)
	if b.Group == GroupOpen {
		if open == nil {
			return Decision{}, errors.New("update: the open values in force are unknown")
		}
		d.Changes = ClassifyOpen(open, b.Open)
		if d.Loosens() {
			// A dropped revocation: every active approver, no delay path.
			if len(u.Approvals) != len(active.Approvers.Keys) {
				return Decision{}, fmt.Errorf("update: open: dropping an entry of revoked_client_certs needs every approver in force (%d), %d signed",
					len(active.Approvers.Keys), len(u.Approvals))
			}
			if held {
				return Decision{}, fmt.Errorf("update: open: dropping an entry of revoked_client_certs is break-glass, which waits until %d, one change delay after the approver removal in force at %d",
					until, h.RemovedAt)
			}
			d.Path = PathBreakGlass
		}
		return d, nil
	}
	d.Changes = ClassifyLocked(active, b.Locked)
	if !d.Loosens() {
		return d, nil
	}
	signed := map[uint8]bool{}
	for _, a := range u.Approvals {
		signed[a.Position] = true
	}
	if i, ok := EmergencyRemoval(active, b.Locked, d.Changes); ok {
		all := true
		for p := range active.Approvers.Keys {
			if p != i && !signed[uint8(p)] {
				all = false
			}
		}
		if all {
			d.Path, d.Removed = PathEmergencyRemoval, i
			return d, nil
		}
	}
	if BreakGlassOnly(d.Changes) && len(signed) == len(active.Approvers.Keys) && !held {
		d.Path = PathBreakGlass
		return d, nil
	}
	d.Wait = Wait(c, active, b)
	return d, nil
}

// History is what the signer's state says about earlier updates, for
// Decide. The runner keeps it in its mark log records
// (markstore.ConfigState). A tool that does not know it passes the zero
// value, and may then name a faster path than the runner takes.
type History struct {
	// RemovedAt is the effective time of the newest locked update in force
	// that removed one approver (RemovesOne, on any path), 0 for none.
	RemovedAt uint64
	// Now is the trusted time of the check.
	Now uint64
}

// BreakGlassHeld reports whether break-glass is not a path at h.Now, and
// until when: within one change delay of active (ChangeDelayOn) after the
// approver removal at h.RemovedAt. With approvals_needed = n-1, every
// approver but one is the usual count, so k keys could remove the one
// honest approver at once; the smaller set is then every approver, and
// break-glass would skip every wait. The delay gives the removed approver
// the time to react that a loosening change gives. A locked break-glass
// change then takes the normal path and waits; an open one (a dropped
// revocation), which has no other path, is refused.
func (h History) BreakGlassHeld(c *Chain, active *Locked) (bool, uint64) {
	if h.RemovedAt == 0 {
		return false, 0
	}
	until := SatAdd(h.RemovedAt, active.ChangeDelayOn(c))
	return h.Now < until, until
}

// RemovesOne reports whether next's approvers are prev's with one removed
// and no other change loosens: an emergency removal in shape, whatever path
// it took. The runner records the effective time of each such update in
// force (History.RemovedAt).
func RemovesOne(prev, next *Locked) bool {
	_, ok := EmergencyRemoval(prev, next, ClassifyLocked(prev, next))
	return ok
}

// BreakGlassOnly reports whether cs loosens and every loosening change in
// it is break-glass.
func BreakGlassOnly(cs []FieldChange) bool {
	return loosens(cs) && !slices.ContainsFunc(cs, func(c FieldChange) bool { return c.Class == ChangeLoosen })
}

// EmergencyRemoval reports whether next, with changes cs from active,
// qualifies for emergency removal: its approvers are those of active with
// one removed and the others in their order, and approvers is the only
// loosening change (approvals_needed is not lowered). i is the position of
// the removed approver in active.
func EmergencyRemoval(active, next *Locked, cs []FieldChange) (i int, ok bool) {
	ak, nk := active.Approvers.Keys, next.Approvers.Keys
	if len(nk) != len(ak)-1 {
		return -1, false
	}
	i = 0
	for i < len(nk) && nk[i] == ak[i] {
		i++
	}
	if !slices.Equal(nk[i:], ak[i+1:]) {
		return -1, false
	}
	for _, c := range cs {
		if c.Field != "approvers" && c.Class != ChangeTighten {
			return -1, false
		}
	}
	return i, true
}

// leafBytes is the value of each field, in leaf order.
func leafBytes(fs []field) [][]byte {
	out := make([][]byte, len(fs))
	for i, f := range fs {
		w := &writer{}
		f.write(w)
		out[i] = w.b
	}
	return out
}

// ClassifyLocked lists the leaves of next that differ from active, with
// their class. A field without a rule below counts as loosening.
func ClassifyLocked(active, next *Locked) []FieldChange {
	fs := active.fields()
	a, n := leafBytes(fs), leafBytes(next.fields())
	var out []FieldChange
	for i, f := range fs {
		if !bytes.Equal(a[i], n[i]) {
			out = append(out, FieldChange{f.name, lockedClass(f.name, active, next)})
		}
	}
	return out
}

// lockedClass is the class of a change of field name from active to next;
// the caller knows the field changed.
func lockedClass(name string, a, n *Locked) ChangeClass {
	switch name {
	case "approvals_needed", "change_delay_seconds":
		// Up or down: raised at once by the usual count, they would freeze
		// governance (see the package comment).
		return ChangeLoosen
	case "allowed_image_measurements":
		if !subset(n.AllowedImageMeasurements, a.AllowedImageMeasurements, compareImages) {
			return ChangeBreakGlass
		}
		if len(n.AllowedImageMeasurements) == 0 {
			// No image left: no runner signs.
			return ChangeLoosen
		}
		return ChangeTighten
	case "allowed_fee_recipients":
		return tightenIf(subset(n.AllowedFeeRecipients, a.AllowedFeeRecipients, func(x, y backend.Address) int { return bytes.Compare(x[:], y[:]) }))
	case "builder_gas_limit_min":
		return tightenIf(n.BuilderGasLimitMin > a.BuilderGasLimitMin)
	case "builder_gas_limit_max":
		return tightenIf(n.BuilderGasLimitMax < a.BuilderGasLimitMax)
	case "builder_registration_max_future_seconds":
		return tightenLimit(a.BuilderRegistrationMaxFutureSeconds, n.BuilderRegistrationMaxFutureSeconds)
	case "allow_unverified_nonslashable_signing":
		return tightenIf(!n.AllowUnverifiedNonslashableSigning)
	case "bare_root_domains":
		return tightenIf(n.BareRootDomains&^a.BareRootDomains == 0)
	case "allowed_builder_request_auth_data_roots":
		return tightenIf(subset(n.AllowedBuilderRequestAuthDataRoots, a.AllowedBuilderRequestAuthDataRoots, compareRoots))
	case "time_policy":
		return timePolicyClass(&a.TimePolicy, &n.TimePolicy)
	case "deposit_policy":
		ad, nd := &a.DepositPolicy, &n.DepositPolicy
		return tightenIf(ad.MinActivationBalance == nd.MinActivationBalance && ad.MaxEffectiveBalance == nd.MaxEffectiveBalance &&
			subset(nd.WithdrawalCredentials, ad.WithdrawalCredentials, compareRoots) &&
			tighterList(ad.AllowedDepositAmounts, nd.AllowedDepositAmounts))
	}
	// approvers (a removal has its own path, EmergencyRemoval),
	// slot_time_changes, exit_policy and any field added later.
	return ChangeLoosen
}

// timePolicyClass: NTP to NTS and lower bounds tighten; NTS to NTP and
// higher bounds are break-glass. A change with parts of both kinds is
// break-glass.
func timePolicyClass(a, n *TimePolicy) ChangeClass {
	looser := n.Protocol == ClockNTP && a.Protocol != ClockNTP ||
		n.MaxBoundMs > a.MaxBoundMs || n.MaxSampleBoundMs > a.MaxSampleBoundMs
	if looser {
		return ChangeBreakGlass
	}
	return ChangeTighten
}

// ClassifyOpen lists the leaves of next that differ from active. Each is
// ChangeOpen, except revoked_client_certs when it drops an entry of active:
// ChangeBreakGlass, which Decide lets in only with every active approver.
func ClassifyOpen(active, next *Open) []FieldChange {
	fs := active.fields()
	a, n := leafBytes(fs), leafBytes(next.fields())
	var out []FieldChange
	for i, f := range fs {
		if bytes.Equal(a[i], n[i]) {
			continue
		}
		c := ChangeOpen
		if f.name == "revoked_client_certs" && !subset(active.RevokedClientCerts, next.RevokedClientCerts, compare32) {
			c = ChangeBreakGlass
		}
		out = append(out, FieldChange{f.name, c})
	}
	return out
}

// tightenLimit classes a change of a limit where 0 turns the check off: a
// lower non-zero limit, or one where there was none, tightens; 0 from a
// limit, or a higher limit, loosens.
func tightenLimit(a, n uint64) ChangeClass {
	return tightenIf(n != 0 && (a == 0 || n < a))
}

// tighterList reports whether sorted list n is no looser than a, for a
// list where empty means no limit: n is not empty, and a is empty or n is
// a subset of a; or both are empty.
func tighterList(a, n []uint64) bool {
	if len(n) == 0 {
		return len(a) == 0
	}
	return len(a) == 0 || subset(n, a, cmp.Compare[uint64])
}

func tightenIf(ok bool) ChangeClass {
	if ok {
		return ChangeTighten
	}
	return ChangeLoosen
}

// subset reports whether every entry of sorted list x is in sorted list y.
func subset[T any](x, y []T, cmp func(a, b T) int) bool {
	for _, v := range x {
		if _, ok := slices.BinarySearchFunc(y, v, cmp); !ok {
			return false
		}
	}
	return true
}

func compareRoots(a, b backend.Root) int { return bytes.Compare(a[:], b[:]) }
func compare32(a, b [32]byte) int        { return bytes.Compare(a[:], b[:]) }
