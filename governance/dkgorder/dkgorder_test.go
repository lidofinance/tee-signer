package dkgorder

import (
	"bytes"
	"crypto/ed25519"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/lidofinance/tee-signer/governance/setupwire"
)

var update = flag.Bool("update", false, "rewrite the golden files in testdata")

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

// approverKey is test approver i of setupwire's samples: a key from a fixed
// seed, so signatures are the same on every run.
func approverKey(i byte) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{i}, 32))
}

func pub(k ed25519.PrivateKey) [32]byte { return [32]byte(k.Public().(ed25519.PublicKey)) }

// opKey is a valid Ed25519 public key for an operator key.
func opKey(i byte) [32]byte { return pub(approverKey(0x80 + i)) }

// sampleSetup is setupwire's golden Nitro setup: approvers 1 to 3 with k =
// 2, a nitro image of 0x11 bytes and an azure one of 0xaa bytes allowed.
func sampleSetup(t testing.TB) *setupwire.Setup {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "setupwire", "testdata", "setup-nitro.bin"))
	if err != nil {
		t.Fatal(err)
	}
	return must(setupwire.DecodeSetup(raw))
}

// sampleBody is an order over the three cloud verifiers, for the setup's
// cluster and chain. The nitro and azure images are on the sample allowed
// list; the gcp one is not.
func sampleBody(s *setupwire.Setup, path Path) Body {
	pcr8 := [48]byte{0x88}
	b := Body{ClusterID: s.ClusterID, ChainHash: s.Chain.Hash(), Label: "lane-" + path.String(), Path: path,
		Threshold: 2, NotAfter: 1_800_000_000,
		Participants: []Participant{
			{Name: "aws-1", SetupHash: [32]byte{0x51}, OperatorKey: opKey(1), Verifier: VerifierNitro,
				Image: bytes.Repeat([]byte{0x11}, 144), NitroPCR3: [48]byte{0x33}, NitroPCR8: &pcr8},
			{Name: "azure-2", SetupHash: [32]byte{0x52}, OperatorKey: opKey(2), Verifier: VerifierAzure,
				Image: bytes.Repeat([]byte{0xaa}, 32), MAAHost: "sharedneu.neu.attest.azure.net", Compliance: ComplianceUVM},
			{Name: "gcp-3", SetupHash: [32]byte{0x53}, OperatorKey: opKey(3), Verifier: VerifierGCP,
				Image: bytes.Repeat([]byte{0x77}, 32), GCPAudience: "signer-runner-identity",
				GCPHWModels: []string{"GCP_AMD_SEV", "GCP_INTEL_TDX"}, GCPIssuer: "https://confidentialcomputing.googleapis.com",
				GCPServiceAccount: "signer@p.iam.gserviceaccount.com", GCPProjectID: "p"},
		}}
	if path == PathCharon {
		b.CharonENRs = []string{"enr:-node-1", "enr:-node-2", "enr:-node-3"}
	}
	return b
}

// signed signs body with the approvers at these positions of the sample set
// (approver i+1 at position i).
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
	for _, path := range []Path{PathDirk, PathCharon} {
		o := signed(t, sampleBody(s, path), 0, 2)
		raw := must(o.Encode())
		got, err := Decode(raw)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		if !reflect.DeepEqual(got, o) {
			t.Fatalf("%s: decoded %+v, want %+v", path, got, o)
		}
		if err := got.Verify(&s.Locked.Approvers); err != nil {
			t.Fatalf("%s: verify: %v", path, err)
		}
		if err := got.Body.Matches(s); err != nil {
			t.Fatal(err)
		}
		text := must(o.Format())
		p, err := Parse("order", text)
		if err != nil || !reflect.DeepEqual(p, o) {
			t.Fatalf("%s: human form does not read back: %v\n%s", path, err, text)
		}
		body := must(o.Body.Encode())
		b, err := DecodeBody(body)
		if err != nil || !reflect.DeepEqual(*b, o.Body) {
			t.Fatalf("%s: body: %v", path, err)
		}
		pb, err := ParseBody("body", must(o.Body.Format()))
		if err != nil || !reflect.DeepEqual(*pb, o.Body) {
			t.Fatalf("%s: body text: %v", path, err)
		}
		if h, _ := o.Body.Hash(); h != Hash(body) || h != setupwire.CtxDKGOrder.Hash(body) {
			t.Fatal("order hash is not over the body under signer-dkg-order-v1")
		}
		if !IsOrder(raw) || !IsBody(body) || IsOrder(body) || IsBody(raw) {
			t.Fatal("kind bytes")
		}
	}
}

// The hash names the body only: other signatures over the same body keep
// it, any change of the body changes it.
func TestHashIsTheBody(t *testing.T) {
	s := sampleSetup(t)
	a := signed(t, sampleBody(s, PathDirk), 0, 1)
	b := signed(t, sampleBody(s, PathDirk), 1, 2)
	ha, _ := a.Body.Hash()
	hb, _ := b.Body.Hash()
	if ha != hb {
		t.Fatal("two signings of one body have different hashes")
	}
	c := sampleBody(s, PathDirk)
	c.Participants[0].SetupHash[31] = 1
	if hc, _ := c.Hash(); hc == ha {
		t.Fatal("another setup_sha256 keeps the order hash")
	}
}

func TestVerify(t *testing.T) {
	s := sampleSetup(t)
	set := &s.Locked.Approvers
	body := sampleBody(s, PathCharon)
	if err := signed(t, body, 0).Verify(set); err == nil || !strings.Contains(err.Error(), "approvals_needed is 2") {
		t.Fatalf("too few approvers: %v", err)
	}
	o := signed(t, body, 0, 1)
	o.Approvals[1].Signature[0] ^= 1
	if err := o.Verify(set); err == nil || !strings.Contains(err.Error(), "does not verify") {
		t.Fatalf("bad signature: %v", err)
	}
	// Signed under the config update context: refused.
	enc := must(body.Encode())
	u := &Order{Body: body, Approvals: []setupwire.Approval{
		{Position: 0, Signature: [64]byte(ed25519.Sign(approverKey(1), setupwire.CtxConfigUpdate.Message(enc)))},
		{Position: 1, Signature: [64]byte(ed25519.Sign(approverKey(2), setupwire.CtxConfigUpdate.Message(enc)))}}}
	if err := u.Verify(set); err == nil {
		t.Fatal("an order signed under the config update context verified")
	}
	// A rotated set: the old signatures count for nothing.
	rot := &setupwire.ApproverSet{Keys: [][32]byte{pub(approverKey(4)), pub(approverKey(5)), pub(approverKey(6))}, ApprovalsNeeded: 2}
	if err := signed(t, body, 0, 1).Verify(rot); err == nil {
		t.Fatal("an order of the old set verified under the new one")
	}
	two := &setupwire.ApproverSet{Keys: set.Keys[:2], ApprovalsNeeded: 2}
	if err := signed(t, body, 0, 1).Verify(two); err != nil {
		t.Fatal(err)
	}
	if err := signed(t, body, 0, 2).Verify(two); err == nil || !strings.Contains(err.Error(), "the set in force has 2") {
		t.Fatalf("a position outside the set: %v", err)
	}
}

// Scope: cluster, chain, the runner's own setup, the images in force.
func TestScope(t *testing.T) {
	s := sampleSetup(t)
	body := sampleBody(s, PathDirk)
	other := *s
	other.ClusterID[5] ^= 1
	if err := body.Matches(&other); err == nil || !strings.Contains(err.Error(), "cluster_id") {
		t.Fatalf("other cluster: %v", err)
	}
	other = *s
	other.Chain.GenesisTime++
	if err := body.Matches(&other); err == nil || !strings.Contains(err.Error(), "chain") {
		t.Fatalf("other chain: %v", err)
	}
	if i, ok := body.Position([32]byte{0x52}); !ok || i != 1 {
		t.Fatalf("position %d %v", i, ok)
	}
	if _, ok := body.Position([32]byte{0x59}); ok {
		t.Fatal("a setup the order does not name has a position")
	}
	if err := body.CheckImages(s.Locked.AllowedImageMeasurements, false); err == nil || !strings.Contains(err.Error(), "gcp-3") {
		t.Fatalf("image not allowed: %v", err)
	}
	allowed := append(s.Locked.AllowedImageMeasurements, setupwire.Image{Kind: setupwire.ImageGCP, Measurement: bytes.Repeat([]byte{0x77}, 32)})
	if err := body.CheckImages(allowed, false); err != nil {
		t.Fatal(err)
	}
	// A dev participant has no image: only a dev runner takes it.
	dev := body
	dev.Participants = append([]Participant(nil), body.Participants...)
	dev.Participants[2] = Participant{Name: "dev-3", SetupHash: [32]byte{0x53}, OperatorKey: opKey(3), Verifier: VerifierDev}
	if err := dev.CheckImages(allowed, false); err == nil || !strings.Contains(err.Error(), "dev runner") {
		t.Fatalf("dev participant on a cloud runner: %v", err)
	}
	if err := dev.CheckImages(allowed, true); err != nil {
		t.Fatal(err)
	}
}

func TestWait(t *testing.T) {
	l := sampleSetup(t).Locked
	zero, long := uint64(0), uint64(setupwire.MaxTimeLock)
	for _, c := range []struct {
		lock *uint64
		want uint64
	}{{&zero, setupwire.ImagesMinTimeLock}, {nil, setupwire.ImagesMinTimeLock}, {&long, setupwire.MaxTimeLock}} {
		l.ChangeDelaySeconds = c.lock
		if w := Wait(&l); w != c.want {
			t.Errorf("time lock %v: wait %d, want %d", c.lock, w, c.want)
		}
	}
}

func TestChecks(t *testing.T) {
	s := sampleSetup(t)
	for _, c := range []struct {
		want string
		edit func(b *Body)
	}{
		{"cluster_id is zero", func(b *Body) { b.ClusterID = [32]byte{} }},
		{"label", func(b *Body) { b.Label = "a lane" }},
		{"path 3", func(b *Body) { b.Path = 3 }},
		{"not_after is 0", func(b *Body) { b.NotAfter = 0 }},
		{"1 participants", func(b *Body) { b.Participants = b.Participants[:1] }},
		{"threshold 1 of 3", func(b *Body) { b.Threshold = 1 }},
		{"threshold 4 of 3", func(b *Body) { b.Threshold = 4 }},
		{"name \"aws-1\" repeats", func(b *Body) { b.Participants[1].Name = "aws-1" }},
		{"setup_sha256 repeats", func(b *Body) { b.Participants[2].SetupHash = b.Participants[0].SetupHash }},
		{"operator_key repeats", func(b *Body) { b.Participants[2].OperatorKey = b.Participants[1].OperatorKey }},
		{"setup_sha256 is zero", func(b *Body) { b.Participants[0].SetupHash = [32]byte{} }},
		{"operator_key", func(b *Body) { b.Participants[0].OperatorKey = [32]byte{1} }},
		{"needs PCR3", func(b *Body) { b.Participants[0].NitroPCR3 = [48]byte{} }},
		{"debug-mode enclave", func(b *Body) { b.Participants[0].Image = make([]byte, 144) }},
		{"image is 32 bytes, verifier aws-nitro takes 144", func(b *Body) { b.Participants[0].Image = make([]byte, 32) }},
		{"azure settings does not apply", func(b *Body) { b.Participants[0].MAAHost = "x.attest.azure.net" }},
		{"compliance status 3", func(b *Body) { b.Participants[1].Compliance = 3 }},
		{"maa_host", func(b *Body) { b.Participants[1].MAAHost = "x.net/path" }},
		{"gcp_hwmodels must be sorted", func(b *Body) { b.Participants[2].GCPHWModels = []string{"B", "A"} }},
		{"0 gcp_hwmodels", func(b *Body) { b.Participants[2].GCPHWModels = nil }},
		{"gcp_issuer: want an https URL", func(b *Body) { b.Participants[2].GCPIssuer = "http://x" }},
		{"gcp_project_id", func(b *Body) { b.Participants[2].GCPProjectID = "" }},
		{"verifier 9", func(b *Body) { b.Participants[2].Verifier = 9 }},
		{"charon_enrs are for the charon path", func(b *Body) { b.CharonENRs = []string{"enr:-a"} }},
		{"charon_enrs lists 2 nodes for 3", func(b *Body) { b.Path, b.CharonENRs = PathCharon, []string{"enr:-a", "enr:-b"} }},
		{"charon_enrs 2 is not an ENR", func(b *Body) { b.Path, b.CharonENRs = PathCharon, []string{"enr:-a", "x", "enr:-c"} }},
		{"charon_enrs 3 repeats", func(b *Body) { b.Path, b.CharonENRs = PathCharon, []string{"enr:-a", "enr:-b", "enr:-a"} }},
		{"charon_enrs 1 is not an ENR", func(b *Body) {
			b.Path, b.CharonENRs = PathCharon, []string{"enr:" + strings.Repeat("x", MaxENR), "enr:-b", "enr:-c"}
		}},
	} {
		b := sampleBody(s, PathDirk)
		b.Participants = append([]Participant(nil), b.Participants...)
		c.edit(&b)
		if _, err := b.Encode(); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: got %v", c.want, err)
		}
	}
	// An ENR above 255 characters is fine.
	b := sampleBody(s, PathCharon)
	b.CharonENRs[0] = "enr:" + strings.Repeat("x", 600)
	if _, err := Decode(must(signed(t, b, 0, 1).Encode())); err != nil {
		t.Fatal(err)
	}
}

// The decoder refuses what the encoder would not write.
func TestDecodeStrict(t *testing.T) {
	s := sampleSetup(t)
	o := signed(t, sampleBody(s, PathCharon), 0, 1)
	raw := must(o.Encode())
	body := must(o.Body.Encode())
	n := len(raw)
	swapped := append(append(bytes.Clone(raw[:n-2*65]), raw[n-65:]...), raw[n-2*65:n-65]...)
	for name, b := range map[string][]byte{
		"trailing byte":   append(bytes.Clone(raw), 0),
		"truncated":       raw[:n-1],
		"body as order":   body,
		"wrong version":   append([]byte{kindOrder, 2}, raw[2:]...),
		"update kind":     append([]byte{'U'}, raw[1:]...),
		"no signature":    append(bytes.Clone(raw[:n-1-2*65]), 0),
		"signatures down": swapped,
	} {
		if _, err := Decode(b); err == nil {
			t.Errorf("%s: decoded", name)
		}
	}
	write := func(b Body) []byte {
		w := &writer{}
		b.write(w)
		return w.b
	}
	bad := sampleBody(s, PathDirk)
	bad.Participants = append([]Participant(nil), bad.Participants...)
	bad.Participants[2].GCPHWModels = []string{"GCP_INTEL_TDX", "GCP_AMD_SEV"}
	if _, err := DecodeBody(write(bad)); err == nil || !strings.Contains(err.Error(), "sorted") {
		t.Fatalf("unsorted hwmodels: %v", err)
	}
	bad = sampleBody(s, PathDirk)
	bad.Participants = append([]Participant(nil), bad.Participants...)
	bad.Participants[0] = Participant{Name: "x", SetupHash: [32]byte{1}, OperatorKey: opKey(9), Verifier: 7}
	if _, err := DecodeBody(write(bad)); err == nil || !strings.Contains(err.Error(), "unknown verifier 7") {
		t.Fatalf("unknown verifier: %v", err)
	}
	enc := write(sampleBody(s, PathDirk))
	enc[len(enc)-1] = 1 // enr_count 1 on the dirk path, then no bytes
	if _, err := DecodeBody(enc); err == nil {
		t.Fatal("an ENR count past the end decoded")
	}
}

func TestHumanRefusals(t *testing.T) {
	s := sampleSetup(t)
	text := string(must(signed(t, sampleBody(s, PathDirk), 0, 1).Format()))
	for _, c := range []struct{ edit, want string }{
		{"participant_1.maa_host = x.attest.azure.net\n", "does not apply to verifier aws-nitro"},
		{"participant_2.image = gcp 0x" + strings.Repeat("77", 32) + "\n", "set again"},
		{"participant_4.name = extra\n", "participant_4.setup_sha256 is missing"},
		{"charon_enrs = enr:-a\n", "charon_enrs are for the charon path"},
		{"Label = x\n", "keys are lower case"},
		{"extra = 1\n", "unknown key \"extra\""},
	} {
		if _, err := Parse("order", []byte(text+c.edit)); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%q: got %v", c.edit, err)
		}
	}
	wrongKind := strings.Replace(text, "participant_2.image = azure", "participant_2.image = gcp", 1)
	if _, err := Parse("order", []byte(wrongKind)); err == nil || !strings.Contains(err.Error(), "verifier azure-maa takes azure") {
		t.Errorf("image kind of another verifier: %v", err)
	}
}

// The vectors in testdata match the code and read back to each other: the
// .conf parses to the .bin, the .bin formats to the .conf.
func TestGolden(t *testing.T) {
	s := sampleSetup(t)
	files := map[string][]byte{}
	var hashes strings.Builder
	for _, path := range []Path{PathDirk, PathCharon} {
		name := "order-" + path.String()
		o := signed(t, sampleBody(s, path), 0, 1)
		files[name+".bin"] = must(o.Encode())
		files[name+".conf"] = must(o.Format())
		h, _ := o.Body.Hash()
		fmt.Fprintf(&hashes, "%s order_hash %x\n", name, h)
	}
	files["hashes.txt"] = []byte(hashes.String())
	for name, want := range files {
		p := filepath.Join("testdata", name)
		if *update {
			if err := os.WriteFile(p, want, 0o644); err != nil {
				t.Fatal(err)
			}
			continue
		}
		got, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("%v (run with -update to make it)", err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("%s differs from what the code makes", name)
		}
		if base, ok := strings.CutSuffix(name, ".bin"); ok {
			conf, _ := os.ReadFile(filepath.Join("testdata", base+".conf"))
			d, err := Decode(got)
			if err != nil {
				t.Fatal(err)
			}
			pd, err := Parse(base+".conf", conf)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(must(d.Format()), conf) || !bytes.Equal(must(pd.Encode()), got) {
				t.Errorf("%s and %s.conf do not read back to each other", name, base)
			}
		}
	}
}

func FuzzDecode(f *testing.F) {
	paths, _ := filepath.Glob(filepath.Join("testdata", "order-*.bin"))
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		o, err := Decode(b)
		if err != nil {
			return
		}
		if again, err := o.Encode(); err != nil || !bytes.Equal(again, b) {
			t.Fatalf("decoded order does not encode back: %v", err)
		}
		text, err := o.Format()
		if err != nil {
			t.Fatal(err)
		}
		p, err := Parse("fuzz", text)
		if err != nil || !reflect.DeepEqual(p, o) {
			t.Fatalf("human form does not read back: %v\n%s", err, text)
		}
	})
}

// A hash-then-sign signature counts like a direct one; one made under
// another kind's hashed context does not.
func TestHashedSignature(t *testing.T) {
	s := sampleSetup(t)
	set := &s.Locked.Approvers
	body := sampleBody(s, PathCharon)
	enc := must(body.Encode())
	o := &Order{Body: body, Approvals: []setupwire.Approval{
		{Position: 0, Signature: SignBody(approverKey(1), enc)},
		{Position: 1, Signature: SignBodyHashed(approverKey(2), enc)}}}
	if err := o.Verify(set); err != nil {
		t.Fatalf("direct and hashed: %v", err)
	}
	o.Approvals[0].Signature = SignBodyHashed(approverKey(1), enc)
	if err := o.Verify(set); err != nil {
		t.Fatalf("both hashed: %v", err)
	}
	o.Approvals[1].Signature = setupwire.SignApproval(approverKey(2), setupwire.CtxImportOrder, true, enc)
	if err := o.Verify(set); err == nil || !strings.Contains(err.Error(), "does not verify") {
		t.Fatalf("hashed under the import order context: %v", err)
	}
}

// A GCP signer never runs a single-node DKG (t = n = 1), on any chain
// (setupwire.CheckThresholdOn); other platforms keep the threshold rule.
func TestSingleNodeOnGCP(t *testing.T) {
	s := sampleSetup(t)
	body := sampleBody(s, PathDirk)
	body.Threshold, body.Participants = 1, body.Participants[:1]
	if err := body.Matches(s); err != nil {
		t.Fatalf("1 of 1 on %s: %v", s.Platform.Platform, err)
	}
	gcp := *s
	gcp.Platform.Platform = setupwire.PlatformGCP
	if err := body.Matches(&gcp); err == nil || !strings.Contains(err.Error(), "single-node") {
		t.Fatalf("1 of 1 on gcp: %v", err)
	}
}
