package setupwire

import (
	"testing"

	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/buildchain"
)

// prodSet is setWith on a prod chain, with the build's default change
// delay.
func prodSet(t *testing.T, n, k int) *Setup {
	t.Helper()
	s := setWith(t, n, k)
	s.Chain.GenesisForkVersion = backend.Version{9, 9, 9, 9} // no row of the chain table
	s.Locked.ChangeDelaySeconds = nil
	if !s.Chain.Prod() {
		t.Fatal("not a prod chain")
	}
	return s
}

// rv-dko.2: the images minimum binds a threshold of approvers too. Route
// A: 3 of 5 rotate to their own 3 keys (a loosening, one change delay) and
// are then every approver. Route B: 2 of 3 remove the third at once. In
// both, break-glass adds no image until the new set has been in force for
// the images wait; the other break-glass kinds keep their rule, and the
// normal path does not change.
func TestDecideImageAfterApproverChange(t *testing.T) {
	s5 := prodSet(t, 5, 3)
	own := prodSet(t, 3, 3)
	s2 := prodSet(t, 2, 2)
	delay := own.Locked.ChangeDelayOn(&own.Chain)
	images := max(delay, ImagesMinTimeLock)
	if buildchain.Prod && (delay != 172800 || images != 604800) {
		t.Fatalf("mainnet build: change delay %d, images wait %d", delay, images)
	}
	if delay >= images {
		t.Fatalf("change delay %d is not below the images wait %d", delay, images)
	}

	// Route A, step 1: the rotation takes the normal path and is no removal.
	rot := changeBody(s5, func(l *Locked) { l.Approvers = own.Locked.Approvers.clone() })
	d, err := signedUpdate(t, s5, rot, []byte{0, 1, 2}, []byte{1, 2, 3}).Decide(&s5.Chain, &s5.Locked, &s5.Open, History{})
	if err != nil || d.Path != PathNormal || d.Wait != delay || RemovesOne(&s5.Locked, rot.Locked) {
		t.Fatalf("rotation to the signers' own keys: %+v, %v", d, err)
	}

	const at = 1_800_000_000
	rotated := func(now uint64) History { return History{ApproversAt: at, Now: now} }
	removed := func(now uint64) History { return History{RemovedAt: at, ApproversAt: at, Now: now} }
	ntp := func(l *Locked) { l.TimePolicy.Protocol = ClockNTP }
	bound := func(l *Locked) { l.TimePolicy.MaxBoundMs = 200 }
	for _, c := range []struct {
		name    string
		s       *Setup
		mutate  func(l *Locked)
		signers []byte
		h       History
		path    Path
		wait    uint64
	}{
		// Route A, step 2: the 3 are every approver.
		{"A: image right after the rotation", own, addImage, []byte{0, 1, 2}, rotated(at), PathNormal, images},
		{"A: image one change delay after the rotation", own, addImage, []byte{0, 1, 2}, rotated(at + delay), PathNormal, images},
		{"A: image a second before the images wait", own, addImage, []byte{0, 1, 2}, rotated(at + images - 1), PathNormal, images},
		{"A: image after the images wait", own, addImage, []byte{0, 1, 2}, rotated(at + images), PathBreakGlass, 0},
		{"A: image and NTP right after the rotation", own, func(l *Locked) { addImage(l); ntp(l) }, []byte{0, 1, 2}, rotated(at), PathNormal, images},
		// The other break-glass kinds wait only after a removal.
		{"A: NTS to NTP right after the rotation", own, ntp, []byte{0, 1, 2}, rotated(at), PathBreakGlass, 0},
		{"A: bound raised right after the rotation", own, bound, []byte{0, 1, 2}, rotated(at), PathBreakGlass, 0},
		{"A: tightening right after the rotation", own, func(l *Locked) { l.AllowedFeeRecipients = nil }, []byte{0, 1, 2}, rotated(at), PathNormal, 0},
		// Route B.
		{"B: image one change delay after the removal", s2, addImage, []byte{0, 1}, removed(at + delay), PathNormal, images},
		{"B: image a second before the images wait", s2, addImage, []byte{0, 1}, removed(at + images - 1), PathNormal, images},
		{"B: image after the images wait", s2, addImage, []byte{0, 1}, removed(at + images), PathBreakGlass, 0},
		{"B: NTS to NTP within the change delay", s2, ntp, []byte{0, 1}, removed(at + delay - 1), PathNormal, delay},
		{"B: NTS to NTP one change delay after the removal", s2, ntp, []byte{0, 1}, removed(at + delay), PathBreakGlass, 0},
		// A caller that knows the removal time only: a removal changes the set.
		{"B: image, removal time only", s2, addImage, []byte{0, 1}, History{RemovedAt: at, Now: at + delay}, PathNormal, images},
		// The normal path: the usual count waits the images wait, as before.
		{"image by 3 of 5, no history", s5, addImage, []byte{0, 1, 2}, History{Now: at}, PathNormal, images},
		{"image by 3 of 5 after the images wait", s5, addImage, []byte{0, 1, 2}, rotated(at + images), PathNormal, images},
		{"image by every approver, no history", s5, addImage, []byte{0, 1, 2, 3, 4}, History{Now: at}, PathBreakGlass, 0},
	} {
		u := signedUpdate(t, c.s, changeBody(c.s, c.mutate), c.signers, nil)
		d, err := u.Decide(&c.s.Chain, &c.s.Locked, &c.s.Open, c.h)
		if err != nil || d.Path != c.path || d.Wait != c.wait {
			t.Errorf("%s: path %s, wait %d, %v; want %s, %d", c.name, d.Path, d.Wait, err, c.path, c.wait)
		}
	}

	// A dropped revocation is no image: no wait after a rotation.
	prev, _ := own.GroupHash(GroupOpen)
	o := own.Open
	o.RevokedClientCerts = o.RevokedClientCerts[1:]
	drop := signedUpdate(t, own, UpdateBody{Group: GroupOpen, Version: 1, PrevHash: prev, ActivateAt: at, Open: &o}, []byte{0, 1, 2}, nil)
	if d, err := drop.Decide(&own.Chain, &own.Locked, &own.Open, rotated(at)); err != nil || d.Path != PathBreakGlass {
		t.Errorf("revocation drop right after the rotation: %+v, %v", d, err)
	}
}
