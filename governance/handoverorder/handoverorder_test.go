package handoverorder

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lidofinance/tee-signer/governance/setupwire"
)

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

// approverKey is test approver i of setupwire's samples (a fixed seed).
func approverKey(i byte) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{i}, 32))
}

func pub(k ed25519.PrivateKey) [32]byte { return [32]byte(k.Public().(ed25519.PublicKey)) }

// sampleSetup is setupwire's golden Nitro setup: approvers 1 to 3 with
// k = 2, a nitro image of 0x11 bytes and an azure one of 0xaa bytes allowed.
func sampleSetup(t testing.TB) *setupwire.Setup {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "governance", "setupwire", "testdata", "setup-nitro.bin"))
	if err != nil {
		t.Fatal(err)
	}
	return must(setupwire.DecodeSetup(raw))
}

var sourceHash = [32]byte{0x51}

// sampleBody hands a nitro source over to an azure target whose image is
// on the sample list.
func sampleBody(s *setupwire.Setup) Body {
	return Body{ClusterID: s.ClusterID, ChainHash: s.Chain.Hash(), NotAfter: 1_800_000_000,
		Source: Runner{Name: "signer-2", SetupHash: sourceHash, Verifier: VerifierNitro,
			Image: bytes.Repeat([]byte{0x12}, 144), NitroPCR3: [48]byte{0x33}},
		Target: Runner{Name: "signer-2b", SetupHash: [32]byte{0x52}, Verifier: VerifierAzure,
			Image: bytes.Repeat([]byte{0xaa}, 32), MAAHost: "sharedneu.neu.attest.azure.net", Compliance: ComplianceUVM}}
}

// signed signs body with the approvers at these positions of the sample
// set (approver i+1 at position i).
func signed(t testing.TB, body Body, positions ...byte) *Order {
	t.Helper()
	enc := must(body.Encode())
	o := &Order{Body: body}
	for _, p := range positions {
		o.Approvals = append(o.Approvals, setupwire.Approval{Position: p, Signature: SignBody(approverKey(p+1), enc)})
	}
	return o
}

func TestRoundTrip(t *testing.T) {
	s := sampleSetup(t)
	gcp := sampleBody(s)
	gcp.Target = Runner{Name: "signer-3b", SetupHash: [32]byte{0x53}, Verifier: VerifierGCP,
		Image: bytes.Repeat([]byte{0x77}, 32), GCPAudience: "signer-runner-identity", GCPHWModels: []string{"GCP_AMD_SEV"},
		GCPIssuer: "https://confidentialcomputing.googleapis.com", GCPServiceAccount: "signer@p.iam.gserviceaccount.com", GCPProjectID: "p"}
	dev := sampleBody(s)
	dev.Source = Runner{Name: "dev-1", SetupHash: sourceHash, Verifier: VerifierDev}
	dev.Target = Runner{Name: "dev-1b", SetupHash: [32]byte{0x54}, Verifier: VerifierDev}
	for _, b := range []Body{sampleBody(s), gcp, dev} {
		raw := must(b.Encode())
		back, err := DecodeBody(raw)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(must(back.Encode()), raw) {
			t.Fatal("body does not round-trip")
		}
		o := signed(t, b, 0, 2)
		sraw := must(o.Encode())
		ob, err := Decode(sraw)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(must(ob.Encode()), sraw) || len(ob.Approvals) != 2 || ob.Approvals[1].Position != 2 {
			t.Fatal("signed order does not round-trip")
		}
		if !IsBody(raw) || IsOrder(raw) || !IsOrder(sraw) || IsBody(sraw) {
			t.Fatal("kind bytes")
		}
		if _, err := b.Format(); err != nil {
			t.Fatal(err)
		}
		text := string(must(o.Format()))
		for _, want := range []string{"source.setup_sha256 = 0x51", "target.name = " + b.Target.Name, "approver_signature = 2 0x"} {
			if !strings.Contains(text, want) {
				t.Fatalf("human form lacks %q:\n%s", want, text)
			}
		}
	}
}

// The hash is over the body only: signatures do not change it, and it is
// under the handover order's context, not the DKG order's.
func TestHash(t *testing.T) {
	s := sampleSetup(t)
	b := sampleBody(s)
	raw := must(b.Encode())
	if Hash(raw) != must(b.Hash()) || Hash(raw) != setupwire.CtxHandoverOrder.Hash(raw) {
		t.Fatal("hash")
	}
	if Hash(raw) == setupwire.CtxImportOrder.Hash(raw) {
		t.Fatal("the handover order hash is the DKG order's")
	}
}

func TestVerify(t *testing.T) {
	s := sampleSetup(t)
	set := &s.Locked.Approvers
	body := sampleBody(s)
	if err := signed(t, body, 0, 1).Verify(set); err != nil {
		t.Fatal(err)
	}
	// One approver only: approvals_needed is 2.
	if err := signed(t, body, 1).Verify(set); err == nil || !strings.Contains(err.Error(), "approvals_needed is 2") {
		t.Fatalf("one approver: %v", err)
	}
	// The same approver twice is refused by the layout.
	o := signed(t, body, 1, 1)
	if err := o.Verify(set); err == nil || !strings.Contains(err.Error(), "one per approver") {
		t.Fatalf("one approver twice: %v", err)
	}
	if _, err := o.Encode(); err == nil {
		t.Fatal("encoded an order with one approver twice")
	}
	o = signed(t, body, 0, 1)
	o.Approvals[1].Signature[0] ^= 1
	if err := o.Verify(set); err == nil || !strings.Contains(err.Error(), "does not verify") {
		t.Fatalf("bad signature: %v", err)
	}
	// Under the DKG order's context: refused.
	enc := must(body.Encode())
	d := &Order{Body: body, Approvals: []setupwire.Approval{
		{Position: 0, Signature: setupwire.SignApproval(approverKey(1), setupwire.CtxImportOrder, false, enc)},
		{Position: 1, Signature: setupwire.SignApproval(approverKey(2), setupwire.CtxImportOrder, false, enc)}}}
	if err := d.Verify(set); err == nil {
		t.Fatal("an order signed under the DKG order context verified")
	}
	// A rotated set: the old set's signatures count for nothing.
	rot := &setupwire.ApproverSet{Keys: [][32]byte{pub(approverKey(4)), pub(approverKey(5)), pub(approverKey(6))}, ApprovalsNeeded: 2}
	if err := signed(t, body, 0, 1).Verify(rot); err == nil {
		t.Fatal("an order of the old set verified under the new one")
	}
	two := &setupwire.ApproverSet{Keys: set.Keys[:2], ApprovalsNeeded: 2}
	if err := signed(t, body, 0, 2).Verify(two); err == nil || !strings.Contains(err.Error(), "the set in force has 2") {
		t.Fatalf("a position outside the set: %v", err)
	}
}

func TestScope(t *testing.T) {
	s := sampleSetup(t)
	b := sampleBody(s)
	if err := b.Matches(s, sourceHash); err != nil {
		t.Fatal(err)
	}
	if err := b.Matches(s, [32]byte{0x52}); err == nil || !strings.Contains(err.Error(), "its source") {
		t.Fatalf("another source: %v", err)
	}
	other := *s
	other.ClusterID[5] ^= 1
	if err := b.Matches(&other, sourceHash); err == nil || !strings.Contains(err.Error(), "cluster_id") {
		t.Fatalf("other cluster: %v", err)
	}
	other = *s
	other.Chain.GenesisTime++
	if err := b.Matches(&other, sourceHash); err == nil || !strings.Contains(err.Error(), "chain") {
		t.Fatalf("other chain: %v", err)
	}
	if err := b.CheckImage(s.Locked.AllowedImageMeasurements, false); err != nil {
		t.Fatal(err)
	}
	b.Target.Image = bytes.Repeat([]byte{0xab}, 32)
	if err := b.CheckImage(s.Locked.AllowedImageMeasurements, false); err == nil || !strings.Contains(err.Error(), "not on the allowed-images list") {
		t.Fatalf("image not allowed: %v", err)
	}
	// The source's image is the target's business, not the list's.
	b = sampleBody(s)
	b.Source.Image = bytes.Repeat([]byte{0x99}, 144)
	if err := b.CheckImage(s.Locked.AllowedImageMeasurements, false); err != nil {
		t.Fatal(err)
	}
	b.Target = Runner{Name: "dev-1b", SetupHash: [32]byte{0x54}, Verifier: VerifierDev}
	if err := b.CheckImage(s.Locked.AllowedImageMeasurements, false); err == nil || !strings.Contains(err.Error(), "dev runner") {
		t.Fatalf("dev target on a cloud runner: %v", err)
	}
	if err := b.CheckImage(nil, true); err != nil {
		t.Fatal(err)
	}
}

func TestWait(t *testing.T) {
	l := sampleSetup(t).Locked
	zero, long := uint64(0), uint64(setupwire.MaxTimeLock)
	for _, c := range []struct {
		lock      *uint64
		want, dev uint64
	}{
		{&zero, setupwire.ImagesMinTimeLock, 0},
		{nil, max(setupwire.DefaultTimeLock, setupwire.ImagesMinTimeLock), setupwire.DefaultTimeLock},
		{&long, setupwire.MaxTimeLock, setupwire.MaxTimeLock},
	} {
		l.ChangeDelaySeconds = c.lock
		if w := Wait(&l, false); w != c.want {
			t.Errorf("time lock %v: wait %d, want %d", c.lock, w, c.want)
		}
		if w := Wait(&l, true); w != c.dev {
			t.Errorf("time lock %v on dev: wait %d, want %d", c.lock, w, c.dev)
		}
	}
}

func TestChecks(t *testing.T) {
	s := sampleSetup(t)
	cases := []struct {
		want   string
		change func(b *Body)
	}{
		{"cluster_id is zero", func(b *Body) { b.ClusterID = [32]byte{} }},
		{"not_after is 0", func(b *Body) { b.NotAfter = 0 }},
		{"target: setup_sha256 is zero", func(b *Body) { b.Target.SetupHash = [32]byte{} }},
		{"source: setup_sha256 is zero", func(b *Body) { b.Source.SetupHash = [32]byte{} }},
		{"same setup_sha256", func(b *Body) { b.Target.SetupHash = b.Source.SetupHash }},
		{"target: name", func(b *Body) { b.Target.Name = "has space" }},
		{"target: image is 31 bytes", func(b *Body) { b.Target.Image = b.Target.Image[:31] }},
		{"source: aws-nitro needs PCR3", func(b *Body) { b.Source.NitroPCR3 = [48]byte{} }},
		{"target: compliance status", func(b *Body) { b.Target.Compliance = 0 }},
		{"target: nitro settings", func(b *Body) { b.Target.NitroPCR3 = [48]byte{1} }},
	}
	for _, c := range cases {
		b := sampleBody(s)
		c.change(&b)
		if _, err := b.Encode(); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v", c.want, err)
		}
	}
}

// The decoders refuse anything but the one encoding: other kinds and
// versions, short input, trailing bytes, caps, values the rules refuse.
func TestDecodeStrict(t *testing.T) {
	s := sampleSetup(t)
	body := sampleBody(s)
	raw := must(body.Encode())
	sraw := must(signed(t, body, 0, 1).Encode())
	mut := func(b []byte, f func([]byte) []byte) []byte { return f(bytes.Clone(b)) }
	bad := map[string][]byte{
		"empty":            nil,
		"kind":             mut(raw, func(b []byte) []byte { b[0] = 'D'; return b }),
		"version":          mut(raw, func(b []byte) []byte { b[1] = 2; return b }),
		"short":            raw[:len(raw)-1],
		"trailing":         append(bytes.Clone(raw), 0),
		"zero cluster":     mut(raw, func(b []byte) []byte { copy(b[2:34], make([]byte, 32)); return b }),
		"verifier":         mut(raw, func(b []byte) []byte { b[2+32+32+8+1+len("signer-2")+32] = 9; return b }),
		"too big":          make([]byte, MaxSize+1),
		"order as a body":  sraw,
		"pcr8 flag 2":      mut(raw, func(b []byte) []byte { b[2+32+32+8+1+len("signer-2")+32+1+144+48] = 2; return b }),
		"name length past": mut(raw, func(b []byte) []byte { b[2+32+32+8] = 0xff; return b }),
	}
	for name, b := range bad {
		if _, err := DecodeBody(b); err == nil {
			t.Errorf("body %s decoded", name)
		}
	}
	badOrder := map[string][]byte{
		"empty":          nil,
		"body as order":  raw,
		"kind":           mut(sraw, func(b []byte) []byte { b[0] = 'O'; return b }),
		"version":        mut(sraw, func(b []byte) []byte { b[1] = 0; return b }),
		"trailing":       append(bytes.Clone(sraw), 0),
		"short":          sraw[:len(sraw)-1],
		"body length":    mut(sraw, func(b []byte) []byte { binary.BigEndian.PutUint32(b[2:], uint32(len(raw)+1)); return b }),
		"huge length":    mut(sraw, func(b []byte) []byte { binary.BigEndian.PutUint32(b[2:], 1<<31); return b }),
		"sig count":      mut(sraw, func(b []byte) []byte { b[6+len(raw)] = 9; return b }),
		"no signature":   mut(sraw[:6+len(raw)+1], func(b []byte) []byte { b[6+len(raw)] = 0; return b }),
		"positions down": mut(sraw, func(b []byte) []byte { b[6+len(raw)+1], b[6+len(raw)+66] = 1, 0; return b }),
		"position 8":     mut(sraw, func(b []byte) []byte { b[6+len(raw)+66] = 8; return b }),
	}
	for name, b := range badOrder {
		if _, err := Decode(b); err == nil {
			t.Errorf("order %s decoded", name)
		}
	}
}

func TestState(t *testing.T) {
	st := &State{Outcome: Known, Status: Done, Hash: [32]byte{7}, Arrived: 10, ActAt: 430, NotAfter: 43_210, Why: "why"}
	back, err := DecodeState(st.Encode())
	if err != nil || *back != *st {
		t.Fatalf("%+v %v", back, err)
	}
	long := *st
	long.Why = strings.Repeat("x", MaxWhy+10)
	if back, err := DecodeState(long.Encode()); err != nil || len(back.Why) != MaxWhy {
		t.Fatalf("long reason: %v", err)
	}
	enc := st.Encode()
	for name, b := range map[string][]byte{
		"short":    enc[:StateLen-1],
		"trailing": append(bytes.Clone(enc), 'x'),
		"outcome":  append([]byte{3}, enc[1:]...),
		"status":   append([]byte{1, 6}, enc[2:]...),
	} {
		if _, err := DecodeState(b); err == nil {
			t.Errorf("%s decoded", name)
		}
	}
	for s := Pending; s <= Done; s++ {
		if strings.HasPrefix(s.String(), "status") {
			t.Errorf("status %d has no name", s)
		}
	}
}

// A hash-then-sign signature counts like a direct one; one made under
// another kind's hashed context does not.
func TestHashedSignature(t *testing.T) {
	s := sampleSetup(t)
	set := &s.Locked.Approvers
	body := sampleBody(s)
	enc := must(body.Encode())
	o := &Order{Body: body, Approvals: []setupwire.Approval{
		{Position: 0, Signature: SignBodyHashed(approverKey(1), enc)},
		{Position: 1, Signature: SignBody(approverKey(2), enc)}}}
	if err := o.Verify(set); err != nil {
		t.Fatalf("hashed and direct: %v", err)
	}
	o.Approvals[0].Signature = setupwire.SignApproval(approverKey(1), setupwire.CtxImportOrder, true, enc)
	if err := o.Verify(set); err == nil || !strings.Contains(err.Error(), "does not verify") {
		t.Fatalf("hashed under the DKG order context: %v", err)
	}
}

// A runner hands over only to a runner on its own cloud: each platform
// takes its own verifier's target and refuses the other three.
func TestCheckSameCloud(t *testing.T) {
	for _, p := range []setupwire.Platform{setupwire.PlatformNitro, setupwire.PlatformAzure, setupwire.PlatformGCP, setupwire.PlatformDev} {
		want, ok := VerifierOf(p)
		if !ok {
			t.Fatalf("platform %s has no verifier", p)
		}
		for v := VerifierNitro; v <= VerifierDev; v++ {
			r := &Runner{Name: "t", Verifier: v}
			err := r.CheckSameCloud(p)
			if v == want {
				if err != nil {
					t.Errorf("%s to %s: %v", p, v, err)
				}
				continue
			}
			if err == nil || !strings.Contains(err.Error(), "only between runners on the same cloud") {
				t.Errorf("%s to %s: %v, want the same-cloud refusal", p, v, err)
			}
		}
	}
	if err := (&Runner{Verifier: VerifierDev}).CheckSameCloud(0); err == nil {
		t.Error("an unknown source platform passed")
	}
}
