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
// lowering change_delay_seconds or approvals_needed, and adding, replacing
// or reordering approvers, always wait.
//
// The open group never waits. Its one rule here is that
// revoked_client_certs only grows. The minimum number of time servers is
// the runner's check, since it needs the image's catalog.
//
// The runner's config Accept does not call Decide yet: it still checks
// with Verify and waits Wait for every locked update, the slower path.

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
// path with Wait.
func (u *Update) Decide(c *Chain, active *Locked, open *Open) (Decision, error) {
	if err := u.Verify(&active.Approvers); err != nil {
		return Decision{}, err
	}
	b := &u.Body
	d := Decision{Path: PathNormal, Removed: -1}
	if b.Group == GroupOpen {
		if open == nil {
			return Decision{}, errors.New("update: the open values in force are unknown")
		}
		cs, err := ClassifyOpen(open, b.Open)
		if err != nil {
			return Decision{}, err
		}
		d.Changes = cs
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
	if BreakGlassOnly(d.Changes) && len(signed) == len(active.Approvers.Keys) {
		d.Path = PathBreakGlass
		return d, nil
	}
	d.Wait = Wait(c, active, b)
	return d, nil
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
	case "approvals_needed":
		return tightenIf(n.Approvers.ApprovalsNeeded > a.Approvers.ApprovalsNeeded)
	case "change_delay_seconds":
		// Equal delays with another presence count as loosening: the
		// default is the build's, not the setup's.
		return tightenIf(n.ChangeDelay() > a.ChangeDelay())
	case "allowed_image_measurements":
		if subset(n.AllowedImageMeasurements, a.AllowedImageMeasurements, compareImages) {
			return ChangeTighten
		}
		return ChangeBreakGlass
	case "allowed_fee_recipients":
		return tightenIf(subset(n.AllowedFeeRecipients, a.AllowedFeeRecipients, func(x, y backend.Address) int { return bytes.Compare(x[:], y[:]) }))
	case "builder_gas_limit_min":
		return tightenIf(n.BuilderGasLimitMin > a.BuilderGasLimitMin)
	case "builder_gas_limit_max":
		return tightenIf(n.BuilderGasLimitMax < a.BuilderGasLimitMax)
	case "builder_registration_max_future_seconds":
		return tightenIf(n.BuilderRegistrationMaxFutureSeconds < a.BuilderRegistrationMaxFutureSeconds)
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
			subset(nd.AllowedDepositAmounts, ad.AllowedDepositAmounts, cmp.Compare[uint64]))
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

// ClassifyOpen lists the leaves of next that differ from active, each
// ChangeOpen. It refuses an update that drops an entry of
// revoked_client_certs: a revocation cannot be undone. (The plan allows
// dropping an entry once its certificate has expired; that needs a proof
// of the expiry, which no update carries yet.)
func ClassifyOpen(active, next *Open) ([]FieldChange, error) {
	for _, h := range active.RevokedClientCerts {
		if _, ok := slices.BinarySearchFunc(next.RevokedClientCerts, h, compare32); !ok {
			return nil, fmt.Errorf("update: open: revoked_client_certs drops %x; a revocation cannot be undone", h[:8])
		}
	}
	fs := active.fields()
	a, n := leafBytes(fs), leafBytes(next.fields())
	var out []FieldChange
	for i, f := range fs {
		if !bytes.Equal(a[i], n[i]) {
			out = append(out, FieldChange{f.name, ChangeOpen})
		}
	}
	return out, nil
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
