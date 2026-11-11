package setupwire

import (
	"bytes"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/lidofinance/tee-signer/signer-protocol"
)

// cloneLocked copies l, lists included, so a change to the copy leaves l.
func cloneLocked(l Locked) Locked {
	l.Approvers = l.Approvers.clone()
	if l.ChangeDelaySeconds != nil {
		l.ChangeDelaySeconds = u64p(*l.ChangeDelaySeconds)
	}
	l.AllowedImageMeasurements = slices.Clone(l.AllowedImageMeasurements)
	l.AllowedFeeRecipients = slices.Clone(l.AllowedFeeRecipients)
	l.SlotTimeChanges = slices.Clone(l.SlotTimeChanges)
	l.AllowedBuilderRequestAuthDataRoots = slices.Clone(l.AllowedBuilderRequestAuthDataRoots)
	l.DepositPolicy.WithdrawalCredentials = slices.Clone(l.DepositPolicy.WithdrawalCredentials)
	l.DepositPolicy.AllowedDepositAmounts = slices.Clone(l.DepositPolicy.AllowedDepositAmounts)
	return l
}

// changeBody is a locked update of s with the values in force changed by
// mutate.
func changeBody(s *Setup, mutate func(l *Locked)) UpdateBody {
	l := cloneLocked(s.Locked)
	mutate(&l)
	prev, _ := s.GroupHash(GroupLocked)
	return UpdateBody{Group: GroupLocked, Version: 1, PrevHash: prev, ActivateAt: 1_800_000_000, Locked: &l}
}

func addImage(l *Locked) {
	l.AllowedImageMeasurements = append(l.AllowedImageMeasurements, Image{Kind: ImageGCP, Measurement: bytes.Repeat([]byte{0x33}, 32)})
}

// One case per change rule: each changes one field and gets one class.
func TestClassifyLocked(t *testing.T) {
	base := samples(t)["setup-nitro"].Locked
	ntp := cloneLocked(base)
	ntp.TimePolicy.Protocol = ClockNTP
	k3 := cloneLocked(base)
	k3.Approvers.ApprovalsNeeded = 3
	unverified := cloneLocked(base)
	unverified.AllowUnverifiedNonslashableSigning = true
	delay := cloneLocked(base)
	delay.ChangeDelaySeconds = u64p(100) // below MaxTimeLock of every build
	noHorizon := cloneLocked(base)
	noHorizon.BuilderRegistrationMaxFutureSeconds = 0
	noAmounts := cloneLocked(base)
	noAmounts.DepositPolicy.AllowedDepositAmounts = nil
	cases := []struct {
		name   string
		from   Locked
		mutate func(l *Locked)
		field  string
		want   ChangeClass
	}{
		{"image removed", base, func(l *Locked) { l.AllowedImageMeasurements = l.AllowedImageMeasurements[1:] }, "allowed_image_measurements", ChangeTighten},
		{"image added", base, addImage, "allowed_image_measurements", ChangeBreakGlass},
		{"image replaced", base, func(l *Locked) { l.AllowedImageMeasurements[0].Measurement = bytes.Repeat([]byte{0x12}, 144) }, "allowed_image_measurements", ChangeBreakGlass},
		{"NTP to NTS", ntp, func(l *Locked) { l.TimePolicy.Protocol = ClockNTS }, "time_policy", ChangeTighten},
		{"NTS to NTP", base, func(l *Locked) { l.TimePolicy.Protocol = ClockNTP }, "time_policy", ChangeBreakGlass},
		{"max bound lowered", base, func(l *Locked) { l.TimePolicy.MaxBoundMs = 50 }, "time_policy", ChangeTighten},
		{"max bound raised", base, func(l *Locked) { l.TimePolicy.MaxBoundMs = 150 }, "time_policy", ChangeBreakGlass},
		{"sample bound lowered", base, func(l *Locked) { l.TimePolicy.MaxSampleBoundMs = 100 }, "time_policy", ChangeTighten},
		{"sample bound raised", base, func(l *Locked) { l.TimePolicy.MaxSampleBoundMs = 1000 }, "time_policy", ChangeBreakGlass},
		{"fee recipient removed", base, func(l *Locked) { l.AllowedFeeRecipients = l.AllowedFeeRecipients[:1] }, "allowed_fee_recipients", ChangeTighten},
		{"fee recipient added", base, func(l *Locked) { l.AllowedFeeRecipients = append(l.AllowedFeeRecipients, backend.Address{0x45}) }, "allowed_fee_recipients", ChangeLoosen},
		{"approvals_needed raised", base, func(l *Locked) { l.Approvers.ApprovalsNeeded = 3 }, "approvals_needed", ChangeTighten},
		{"approvals_needed lowered", k3, func(l *Locked) { l.Approvers.ApprovalsNeeded = 2 }, "approvals_needed", ChangeLoosen},
		{"change delay raised", delay, func(l *Locked) { l.ChangeDelaySeconds = u64p(200) }, "change_delay_seconds", ChangeTighten},
		{"change delay lowered", delay, func(l *Locked) { l.ChangeDelaySeconds = u64p(10) }, "change_delay_seconds", ChangeLoosen},
		{"change delay to the default", base, func(l *Locked) { l.ChangeDelaySeconds = u64p(DefaultTimeLock) }, "change_delay_seconds", ChangeLoosen},
		{"approver added", k3, func(l *Locked) { l.Approvers.Keys = append(l.Approvers.Keys, approverPub(4)) }, "approvers", ChangeLoosen},
		{"approver removed", base, func(l *Locked) { l.Approvers.Keys = l.Approvers.Keys[:2] }, "approvers", ChangeLoosen},
		{"approvers reordered", base, func(l *Locked) { slices.Reverse(l.Approvers.Keys) }, "approvers", ChangeLoosen},
		{"gas min raised", base, func(l *Locked) { l.BuilderGasLimitMin++ }, "builder_gas_limit_min", ChangeTighten},
		{"gas min lowered", base, func(l *Locked) { l.BuilderGasLimitMin-- }, "builder_gas_limit_min", ChangeLoosen},
		{"gas max lowered", base, func(l *Locked) { l.BuilderGasLimitMax-- }, "builder_gas_limit_max", ChangeTighten},
		{"gas max raised", base, func(l *Locked) { l.BuilderGasLimitMax++ }, "builder_gas_limit_max", ChangeLoosen},
		{"registration horizon lowered", base, func(l *Locked) { l.BuilderRegistrationMaxFutureSeconds-- }, "builder_registration_max_future_seconds", ChangeTighten},
		{"registration horizon raised", base, func(l *Locked) { l.BuilderRegistrationMaxFutureSeconds++ }, "builder_registration_max_future_seconds", ChangeLoosen},
		{"unverified signing off", unverified, func(l *Locked) { l.AllowUnverifiedNonslashableSigning = false }, "allow_unverified_nonslashable_signing", ChangeTighten},
		{"unverified signing on", base, func(l *Locked) { l.AllowUnverifiedNonslashableSigning = true }, "allow_unverified_nonslashable_signing", ChangeLoosen},
		{"bare root domain removed", base, func(l *Locked) { l.BareRootDomains = 1 << 2 }, "bare_root_domains", ChangeTighten},
		{"bare root domain added", base, func(l *Locked) { l.BareRootDomains |= 1 << 5 }, "bare_root_domains", ChangeLoosen},
		{"slot time change", base, func(l *Locked) { l.SlotTimeChanges = []SlotTimeChange{{Epoch: 9, SecondsPerSlot: 4}} }, "slot_time_changes", ChangeLoosen},
		{"auth root removed", base, func(l *Locked) { l.AllowedBuilderRequestAuthDataRoots = nil }, "allowed_builder_request_auth_data_roots", ChangeTighten},
		{"auth root added", base, func(l *Locked) {
			l.AllowedBuilderRequestAuthDataRoots = append(l.AllowedBuilderRequestAuthDataRoots, backend.Root{0x53})
		}, "allowed_builder_request_auth_data_roots", ChangeLoosen},
		{"credential removed", base, func(l *Locked) { l.DepositPolicy.WithdrawalCredentials = l.DepositPolicy.WithdrawalCredentials[1:] }, "deposit_policy", ChangeTighten},
		{"deposit amount removed", base, func(l *Locked) { l.DepositPolicy.AllowedDepositAmounts = l.DepositPolicy.AllowedDepositAmounts[1:] }, "deposit_policy", ChangeTighten},
		{"credential added", base, func(l *Locked) {
			l.DepositPolicy.WithdrawalCredentials = append(l.DepositPolicy.WithdrawalCredentials, credentials(0x02, 0x43))
		}, "deposit_policy", ChangeLoosen},
		{"balance changed", base, func(l *Locked) { l.DepositPolicy.MaxEffectiveBalance-- }, "deposit_policy", ChangeLoosen},
		// 0 turns the core's registration horizon check off.
		{"registration horizon 3600 to 0", base, func(l *Locked) { l.BuilderRegistrationMaxFutureSeconds = 0 }, "builder_registration_max_future_seconds", ChangeLoosen},
		{"registration horizon 0 to 3600", noHorizon, func(l *Locked) { l.BuilderRegistrationMaxFutureSeconds = 3600 }, "builder_registration_max_future_seconds", ChangeTighten},
		// An empty allowed_deposit_amounts may come to mean any amount.
		{"deposit amounts emptied", base, func(l *Locked) { l.DepositPolicy.AllowedDepositAmounts = nil }, "deposit_policy", ChangeLoosen},
		{"deposit amounts from empty", noAmounts, func(l *Locked) { l.DepositPolicy.AllowedDepositAmounts = []uint64{32 * eth} }, "deposit_policy", ChangeTighten},
	}
	for _, c := range cases {
		next := cloneLocked(c.from)
		c.mutate(&next)
		if err := next.Check(); err != nil {
			t.Fatalf("%s: the changed group: %v", c.name, err)
		}
		got := ClassifyLocked(&c.from, &next)
		want := []FieldChange{{c.field, c.want}}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s: got %v, want %v", c.name, got, want)
		}
	}
	if got := ClassifyLocked(&base, &base); got != nil {
		t.Errorf("no change: got %v", got)
	}
	// A field without a rule (exit_policy here; Check refuses the value)
	// counts as loosening.
	next := cloneLocked(base)
	next.ExitPolicy.StakeCapPerDay = 1
	if got := ClassifyLocked(&base, &next); !reflect.DeepEqual(got, []FieldChange{{"exit_policy", ChangeLoosen}}) {
		t.Errorf("exit_policy: got %v", got)
	}
	// Two fields, each with its class, in leaf order.
	next = cloneLocked(base)
	addImage(&next)
	next.BuilderGasLimitMax--
	want := []FieldChange{{"allowed_image_measurements", ChangeBreakGlass}, {"builder_gas_limit_max", ChangeTighten}}
	if got := ClassifyLocked(&base, &next); !reflect.DeepEqual(got, want) {
		t.Errorf("two fields: got %v, want %v", got, want)
	}
}

// The open group never waits; dropping a revocation is break-glass.
func TestClassifyOpen(t *testing.T) {
	base := sampleOpen()
	for name, c := range map[string]struct {
		mutate func(o *Open)
		field  string
	}{
		"revocation added":    {func(o *Open) { o.RevokedClientCerts = append(o.RevokedClientCerts, [32]byte{0x73}) }, "revoked_client_certs"},
		"time server added":   {func(o *Open) { o.TimeServers = append(o.TimeServers, "sth2") }, "time_servers"},
		"time server dropped": {func(o *Open) { o.TimeServers = o.TimeServers[1:] }, "time_servers"},
		"fork added":          {func(o *Open) { o.ForkSchedule = append(o.ForkSchedule, Fork{Epoch: 30}) }, "fork_schedule"},
	} {
		next := base
		next.RevokedClientCerts = slices.Clone(base.RevokedClientCerts)
		next.TimeServers = slices.Clone(base.TimeServers)
		next.ForkSchedule = slices.Clone(base.ForkSchedule)
		c.mutate(&next)
		if err := next.Check(); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got := ClassifyOpen(&base, &next); !reflect.DeepEqual(got, []FieldChange{{c.field, ChangeOpen}}) {
			t.Errorf("%s: got %v", name, got)
		}
	}
	next := base
	next.RevokedClientCerts = base.RevokedClientCerts[1:]
	if got := ClassifyOpen(&base, &next); !reflect.DeepEqual(got, []FieldChange{{"revoked_client_certs", ChangeBreakGlass}}) {
		t.Errorf("revocation dropped: got %v", got)
	}
}

// setWith is the nitro sample with n approvers (keys 1 to n) and
// approvals_needed k.
func setWith(t *testing.T, n, k int) *Setup {
	s := samples(t)["setup-nitro"]
	s.Locked.Approvers = ApproverSet{ApprovalsNeeded: uint8(k)}
	for i := range n {
		s.Locked.Approvers.Keys = append(s.Locked.Approvers.Keys, approverPub(byte(i+1)))
	}
	return s
}

// Decide picks the path and the wait from the changes and the signers.
func TestDecide(t *testing.T) {
	s3 := setWith(t, 3, 2)
	s5 := setWith(t, 5, 3)
	s5k4 := setWith(t, 5, 4)
	normal := s3.Locked.ChangeDelayOn(&s3.Chain)
	images := max(normal, ImagesMinTimeLock)
	drop := func(i int) func(l *Locked) {
		return func(l *Locked) { l.Approvers.Keys = slices.Delete(l.Approvers.Keys, i, i+1) }
	}
	cases := []struct {
		name    string
		s       *Setup
		mutate  func(l *Locked)
		signers []byte // positions in the active set
		newKeys []byte // key seeds of the new set, for a rotation
		path    Path
		wait    uint64
		removed int
	}{
		{"tightening, usual count", s3, func(l *Locked) { l.AllowedFeeRecipients = nil }, []byte{0, 1}, nil, PathNormal, 0, -1},
		{"no change", s3, func(l *Locked) {}, []byte{0, 1}, nil, PathNormal, 0, -1},
		{"approvals_needed raised", s3, func(l *Locked) { l.Approvers.ApprovalsNeeded = 3 }, []byte{0, 1}, []byte{1, 2, 3}, PathNormal, 0, -1},
		{"loosening, usual count", s3, func(l *Locked) { l.BuilderGasLimitMax++ }, []byte{0, 1}, nil, PathNormal, normal, -1},
		{"loosening, every approver", s3, func(l *Locked) { l.BuilderGasLimitMax++ }, []byte{0, 1, 2}, nil, PathNormal, normal, -1},
		{"image added, usual count", s3, addImage, []byte{0, 2}, nil, PathNormal, images, -1},
		{"image added, every approver", s3, addImage, []byte{0, 1, 2}, nil, PathBreakGlass, 0, -1},
		{"NTS to NTP, every approver", s3, func(l *Locked) { l.TimePolicy.Protocol = ClockNTP }, []byte{0, 1, 2}, nil, PathBreakGlass, 0, -1},
		{"NTS to NTP, usual count", s3, func(l *Locked) { l.TimePolicy.Protocol = ClockNTP }, []byte{1, 2}, nil, PathNormal, normal, -1},
		{"bound raised, every approver", s3, func(l *Locked) { l.TimePolicy.MaxBoundMs = 200 }, []byte{0, 1, 2}, nil, PathBreakGlass, 0, -1},
		{"break-glass and a tightening, every approver", s3, func(l *Locked) {
			addImage(l)
			l.AllowedFeeRecipients = nil
		}, []byte{0, 1, 2}, nil, PathBreakGlass, 0, -1},
		{"break-glass with another loosening", s3, func(l *Locked) {
			addImage(l)
			l.BuilderGasLimitMax++
		}, []byte{0, 1, 2}, nil, PathNormal, images, -1},
		{"break-glass, one approver short", s5, addImage, []byte{0, 1, 2, 3}, nil, PathNormal, images, -1},
		{"emergency removal", s3, drop(1), []byte{0, 2}, []byte{1, 3}, PathEmergencyRemoval, 0, 1},
		{"emergency removal of the last", s5, drop(4), []byte{0, 1, 2, 3}, []byte{1, 2, 3, 4}, PathEmergencyRemoval, 0, 4},
		{"emergency removal signed by the removed one too", s3, drop(0), []byte{0, 1, 2}, []byte{2, 3}, PathEmergencyRemoval, 0, 0},
		{"emergency removal and a tightening", s3, func(l *Locked) {
			drop(2)(l)
			l.AllowedFeeRecipients = nil
		}, []byte{0, 1}, []byte{1, 2}, PathEmergencyRemoval, 0, 2},
		{"removal with the usual count only", s5, drop(4), []byte{0, 1, 2}, []byte{1, 2, 3, 4}, PathNormal, normal, -1},
		{"removal with a loosening", s3, func(l *Locked) {
			drop(1)(l)
			l.BuilderGasLimitMax++
		}, []byte{0, 2}, []byte{1, 3}, PathNormal, normal, -1},
		{"removal lowering approvals_needed", s5k4, func(l *Locked) {
			drop(4)(l)
			l.Approvers.ApprovalsNeeded = 3
		}, []byte{0, 1, 2, 3}, []byte{1, 2, 3, 4}, PathNormal, normal, -1},
		{"two removed", s5, func(l *Locked) { l.Approvers.Keys = l.Approvers.Keys[:3] }, []byte{0, 1, 2}, []byte{1, 2, 3}, PathNormal, normal, -1},
		{"approver added, every approver", s3, func(l *Locked) {
			l.Approvers.Keys = append(l.Approvers.Keys, approverPub(4))
			l.Approvers.ApprovalsNeeded = 3
		},
			[]byte{0, 1, 2}, []byte{1, 2, 3, 4}, PathNormal, normal, -1},
		{"approver replaced, every approver", s3, func(l *Locked) { l.Approvers.Keys[2] = approverPub(4) },
			[]byte{0, 1, 2}, []byte{1, 2, 4}, PathNormal, normal, -1},
		{"approvals_needed lowered, every approver", s5k4, func(l *Locked) { l.Approvers.ApprovalsNeeded = 3 },
			[]byte{0, 1, 2, 3, 4}, []byte{1, 2, 3, 4, 5}, PathNormal, normal, -1},
		{"registration horizon off, every approver", s3, func(l *Locked) { l.BuilderRegistrationMaxFutureSeconds = 0 }, []byte{0, 1, 2}, nil, PathNormal, normal, -1},
		{"change delay lowered, every approver", s3, func(l *Locked) { l.ChangeDelaySeconds = u64p(60) }, []byte{0, 1, 2}, nil, PathNormal, normal, -1},
	}
	for _, c := range cases {
		u := signedUpdate(t, c.s, changeBody(c.s, c.mutate), c.signers, c.newKeys)
		d, err := u.Decide(&c.s.Chain, &c.s.Locked, &c.s.Open)
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if d.Path != c.path || d.Wait != c.wait || d.Removed != c.removed {
			t.Errorf("%s: path %s, wait %d, removed %d; want %s, %d, %d (changes %v)", c.name, d.Path, d.Wait, d.Removed, c.path, c.wait, c.removed, d.Changes)
		}
	}
	// Every path needs the usual count first: one approver alone fails.
	u := signedUpdate(t, s3, changeBody(s3, addImage), []byte{0}, nil)
	if _, err := u.Decide(&s3.Chain, &s3.Locked, &s3.Open); err == nil || !strings.Contains(err.Error(), "approvals_needed is 2") {
		t.Errorf("one signature: %v", err)
	}
}

// An open update never waits; one that drops a revocation is refused.
func TestDecideOpen(t *testing.T) {
	s := samples(t)["setup-nitro"]
	prev, _ := s.GroupHash(GroupOpen)
	body := func(mutate func(o *Open)) UpdateBody {
		o := s.Open
		o.RevokedClientCerts = slices.Clone(o.RevokedClientCerts)
		o.TimeServers = slices.Clone(o.TimeServers)
		mutate(&o)
		return UpdateBody{Group: GroupOpen, Version: 1, PrevHash: prev, ActivateAt: 1_800_000_000, Open: &o}
	}
	u := signedUpdate(t, s, body(func(o *Open) {
		o.TimeServers = nil
		o.RevokedClientCerts = append(o.RevokedClientCerts, [32]byte{0x7f})
	}), []byte{0, 1}, nil)
	d, err := u.Decide(&s.Chain, &s.Locked, &s.Open)
	want := []FieldChange{{"revoked_client_certs", ChangeOpen}, {"time_servers", ChangeOpen}}
	if err != nil || d.Path != PathNormal || d.Wait != 0 || !reflect.DeepEqual(d.Changes, want) {
		t.Fatalf("open: %+v, %v", d, err)
	}
	// Dropping a revocation (to make room under the cap, say): every
	// approver, no wait; the usual count is refused.
	drop := body(func(o *Open) { o.RevokedClientCerts = o.RevokedClientCerts[1:] })
	u = signedUpdate(t, s, drop, []byte{0, 1, 2}, nil)
	d, err = u.Decide(&s.Chain, &s.Locked, &s.Open)
	if err != nil || d.Path != PathBreakGlass || d.Wait != 0 || !reflect.DeepEqual(d.Changes, []FieldChange{{"revoked_client_certs", ChangeBreakGlass}}) {
		t.Fatalf("revocation dropped by every approver: %+v, %v", d, err)
	}
	short := signedUpdate(t, s, drop, []byte{0, 2}, nil)
	if _, err := short.Decide(&s.Chain, &s.Locked, &s.Open); err == nil || !strings.Contains(err.Error(), "needs every approver in force (3), 2 signed") {
		t.Fatalf("revocation dropped with the usual count: %v", err)
	}
	if _, err := u.Decide(&s.Chain, &s.Locked, nil); err == nil {
		t.Fatal("open update without the open values in force")
	}
}
