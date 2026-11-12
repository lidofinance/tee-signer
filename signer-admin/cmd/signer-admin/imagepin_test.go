package main

import (
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/governance/importorder"
	"github.com/lidofinance/tee-signer/governance/setupwire"
	"github.com/lidofinance/tee-signer/signer-admin/fakerunner"
	cloud "github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/wire"
	wireadmin "github.com/lidofinance/tee-signer/signer-protocol/wire/admin"
)

// nitroPins is the nitro_pcrs setting of an image whose PCR0 to PCR2 are
// all the byte b.
func nitroPins(b string) map[string]string {
	v := strings.Repeat(b, 48)
	return map[string]string{"0": v, "1": v, "2": v}
}

// imagePinFixture is the nitro signer of ownImageCluster alone in a
// cluster.json, with a fake runner at its address and a shares file. The
// fake runner answers with the dev document, so a connection that gets
// past the image check fails at the Nitro verifier.
type imagePinFixture struct {
	f      *ownImageFixture
	m      *member
	r      *fakerunner.Runner
	cl     string
	setup  string
	shares string
	cert   string
	key    string
}

func newImagePinFixture(t *testing.T) *imagePinFixture {
	t.Helper()
	f := ownImageCluster(t)
	m := f.members[1]
	if m.setup.Platform.Platform != setupwire.PlatformNitro {
		t.Fatalf("%s is on %s, want nitro", m.name, m.setup.Platform.Platform)
	}
	p := &imagePinFixture{f: f, m: m, r: fakerunner.StartSetup(t, m.setupRaw), setup: filepath.Join(f.dir, "setups", m.name+".setup")}
	p.cert, p.key = p.r.ClientFiles(t, t.TempDir())
	p.cl = f.clusterJSON(t, []*member{m})
	pk, shares, _ := split(t, f.dir, 2, 3, []string{m.name, "y", "z"})
	p.shares = filepath.Join(f.dir, "shares.txt")
	if err := os.WriteFile(p.shares, fmt.Appendf(nil, "%s 7 0x%x\n", pk, shares[0].Secret), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// writeConn writes the member's cloud.json with the aws-nitro verifier and
// the given attestation settings on top.
func (p *imagePinFixture) writeConn(t *testing.T, att map[string]any) {
	t.Helper()
	a := map[string]any{"verifier": "aws-nitro", "setup_sha256": hex.EncodeToString(p.m.setupHash[:])}
	for k, v := range att {
		a[k] = v
	}
	writeJSONFile(t, p.m.cloudPath, map[string]any{
		"address": p.r.Addr(), "client_cert": p.cert, "client_key": p.key, "attestation": a,
	})
}

// requests is the number of requests the fake runner got.
func (p *imagePinFixture) requests() int {
	return p.r.Seen(wire.TypeIdentity) + p.r.Seen(wire.TypeHealth)
}

// signLocked drafts a locked update with images for the cluster after the
// setup's version 0, signs it with two approvers and writes it to the
// updates folder of the cluster.json as name.signed.
func (p *imagePinFixture) signLocked(t *testing.T, name, images string) {
	t.Helper()
	f := p.f
	body := filepath.Join(f.dir, name+".bin")
	c := &cluster{updates: filepath.Join(f.dir, "updates"), members: f.members}
	b := &setupwire.UpdateBody{Group: setupwire.GroupLocked, Locked: f.locked(images)}
	if err := writeDraft(c, f.states(t, f.members), b, 0, body, nil, io.Discard); err != nil {
		t.Fatalf("draft %s: %v", name, err)
	}
	var sigs []string
	for _, k := range f.keys[:2] {
		mustTool(t, "sign", "-key", k.file, "-expect-sha256", expectOf(t, body), body)
		sigs = append(sigs, fmt.Sprintf("%s.%s.sig", body, k.pub[2:10]))
	}
	if err := os.MkdirAll(c.updates, 0o755); err != nil {
		t.Fatal(err)
	}
	mustTool(t, append([]string{"assemble", "-out", filepath.Join(c.updates, name+".signed"), body}, sigs...)...)
}

// Every command that reads a member, and import -conn, refuses a
// cloud.json whose pin no allowed_image_measurements of the cluster lists,
// before any request reaches the runner. The listed pin goes on to the
// runner.
func TestDealerRefusesUnlistedImagePin(t *testing.T) {
	p := newImagePinFixture(t)
	p.writeConn(t, map[string]any{"nitro_pcrs": nitroPins("22")})
	const want = "allowed_image_measurements"
	for _, args := range [][]string{
		{"probe", "-cluster", p.cl},
		{"pin", "-cluster", p.cl},
		{"status", "-cluster", p.cl},
		{"import", "-cluster", p.cl, "-signer", p.m.name, "-shares", p.shares},
		{"import", "-conn", p.m.cloudPath, "-setup", p.setup, "-shares", p.shares},
	} {
		wantIn(t, failTool(t, args...), want, "nitro", strings.Repeat("22", 8))
	}
	// -conn without -setup has no list to check against.
	wantIn(t, failTool(t, "import", "-conn", p.m.cloudPath, "-shares", p.shares), "-conn needs -setup")
	if n := p.requests(); n != 0 {
		t.Fatalf("%d requests reached a runner whose pin no list names", n)
	}
	if n := p.r.Seen(wireadmin.TypeImportSealed) + p.r.Seen(wireadmin.TypeImportBatch); n != 0 {
		t.Fatalf("%d sealed shares sent", n)
	}

	// The listed image: the check passes and the Nitro verifier refuses
	// the fake runner's dev document.
	p.writeConn(t, map[string]any{"nitro_pcrs": nitroPins("11")})
	before := p.requests()
	if out := failTool(t, "probe", "-cluster", p.cl); strings.Contains(out, want) {
		t.Fatalf("a listed pin refused:\n%s", out)
	}
	if p.requests() == before {
		t.Fatal("a listed pin did not reach the runner")
	}
}

// orderFor writes a signed import order for the setup target of cluster
// id. The tool reads the order before it dials; the runner would check
// the signature.
func orderFor(t *testing.T, dir string, target, id [32]byte) string {
	t.Helper()
	o := importorder.Order{
		Body: importorder.Body{ClusterID: id, Target: target, NotAfter: 4_000_000_000, T: 2, N: 3, ShareIndex: 1,
			Validators: []importorder.Entry{{Pubkey: cloud.Pubkey{0xa0}, CommitmentsHash: [32]byte{1}}}},
		Approvals: []setupwire.Approval{{Position: 0}},
	}
	raw, err := o.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return writeFile(t, filepath.Join(dir, fmt.Sprintf("order-%x.signed", target[:4])), string(raw))
}

// import -conn binds the share to the -setup file: a cloud verifier needs
// an import order, and the order must name that setup and its cluster.
// cloud.json must pin that setup or none, and a named -updates folder
// must exist.
func TestConnImportNeedsOrderForSetup(t *testing.T) {
	p := newImagePinFixture(t)
	p.writeConn(t, map[string]any{"nitro_pcrs": nitroPins("11")})
	args := func(extra ...string) []string {
		return append([]string{"import", "-conn", p.m.cloudPath, "-setup", p.setup, "-shares", p.shares}, extra...)
	}
	wantIn(t, failTool(t, args()...), "-conn needs -order")
	other := p.f.members[0].setupHash
	missing := filepath.Join(p.f.dir, "no-commitments")
	wantIn(t, failTool(t, args("-order", orderFor(t, p.f.dir, other, p.m.setup.ClusterID), "-commitments", missing)...), "is an import order for setup")
	wantIn(t, failTool(t, args("-order", orderFor(t, p.f.dir, p.m.setupHash, [32]byte{9}), "-commitments", missing)...), "is an import order for setup")
	// The order of this setup passes; the commitments file comes next.
	wantIn(t, failTool(t, args("-order", orderFor(t, p.f.dir, p.m.setupHash, p.m.setup.ClusterID), "-commitments", missing)...), "no-commitments")
	wantIn(t, failTool(t, args("-updates", filepath.Join(p.f.dir, "no-such-folder"))...), "-updates")

	p.writeConn(t, map[string]any{"nitro_pcrs": nitroPins("11"), "setup_sha256": hex.EncodeToString(other[:])})
	wantIn(t, failTool(t, args()...), "pins setup_sha256 "+hex.EncodeToString(other[:])+" already")
	if n := p.requests(); n != 0 {
		t.Fatalf("%d requests reached the runner", n)
	}
}

// A signed locked update in the updates folder that lists the 0x22 image
// and drops 0x11: 0x22 counts once the update's activate_at plus the
// push slack has passed, and 0x11 counts until its activate_at. So push, which
// saves the update in the folder, does not lock out a member still on
// 0x11 while it pushes to the others.
func TestImagePinFollowsUpdates(t *testing.T) {
	p := newImagePinFixture(t)
	p.signLocked(t, "locked-v1", otherNitro(t))
	updates := filepath.Join(p.f.dir, "updates")
	const want = "allowed_image_measurements"

	p.writeConn(t, map[string]any{"nitro_pcrs": nitroPins("22")})
	wantIn(t, failTool(t, "probe", "-cluster", p.cl), want, "activate_at has not passed")
	wantIn(t, failTool(t, "import", "-conn", p.m.cloudPath, "-setup", p.setup, "-updates", updates, "-shares", p.shares), "activate_at has not passed")
	if n := p.requests(); n != 0 {
		t.Fatalf("%d requests reached a runner whose image is still pending", n)
	}

	// Two members after push saved the update: the nitro one still on the
	// dropped image, and the azure one, whose image the update keeps.
	azure := p.f.members[0]
	azure.updates = updates
	writeJSONFile(t, azure.cloudPath, map[string]any{"address": "tcp:127.0.0.1:1", "client_cert": "c.pem", "client_key": "k.pem",
		"attestation": map[string]any{"verifier": "azure-maa", "maa_host": "sharedneu.neu.attest.azure.net", "cce_policy_sha256": strings.Repeat("aa", 32)}})
	p.writeConn(t, map[string]any{"nitro_pcrs": nitroPins("11")})
	for _, m := range []*member{p.m, azure} {
		if _, err := memberConn(m); err != nil {
			t.Fatalf("%s before the update's time: %v", m.name, err)
		}
	}

	later := time.Now().Add(30 * 24 * time.Hour)
	now = func() time.Time { return later }
	t.Cleanup(func() { now = time.Now })
	if _, err := memberConn(azure); err != nil {
		t.Fatalf("azure after the update's time: %v", err)
	}
	wantIn(t, failTool(t, "probe", "-cluster", p.cl), want, "locked version 1", strings.Repeat("11", 8))
	if n := p.requests(); n != 0 {
		t.Fatal("a pin of a dropped image reached the runner")
	}
	p.writeConn(t, map[string]any{"nitro_pcrs": nitroPins("22")})
	for _, args := range [][]string{
		{"probe", "-cluster", p.cl},
		{"import", "-conn", p.m.cloudPath, "-setup", p.setup, "-updates", updates, "-shares", p.shares},
	} {
		if out := failTool(t, args...); strings.Contains(out, want) {
			t.Fatalf("a pin the update lists refused after its time:\n%s", out)
		}
	}
	if p.requests() == 0 {
		t.Fatal("a pin the update lists did not reach the runner")
	}
}

// The trust anchor of cloud.json must be the setup's: the verifier of the
// member's platform, the setup's MAA host, Google's key set, the default
// compliance status and mainnet as the chain says. A listed pin with that
// anchor passes.
func TestImagePinAnchor(t *testing.T) {
	f := ownImageCluster(t)
	azure, nitro, gcp := f.members[0], f.members[1], f.members[2]
	azureAtt := map[string]any{"verifier": "azure-maa", "maa_host": "sharedneu.neu.attest.azure.net", "cce_policy_sha256": strings.Repeat("aa", 32)}
	gcpAtt := map[string]any{"verifier": "gcp-cs", "gcp_image_digest": "sha256:" + strings.Repeat("99", 32),
		"gcp_audience": "signer-runner-identity", "gcp_hwmodels": []string{"GCP_AMD_SEV"}}
	nitroAtt := map[string]any{"verifier": "aws-nitro", "nitro_pcrs": nitroPins("11")}
	with := func(base map[string]any, k string, v any) map[string]any {
		out := map[string]any{k: v}
		for bk, bv := range base {
			if bk != k {
				out[bk] = bv
			}
		}
		return out
	}
	for _, tc := range []struct {
		name string
		m    *member
		att  map[string]any
		want string // empty: passes
	}{
		{"azure", azure, azureAtt, ""},
		{"azure MAA host in other case", azure, with(azureAtt, "maa_host", "SharedNEU.neu.attest.azure.net"), ""},
		{"azure other MAA host", azure, with(azureAtt, "maa_host", "evil.example.com"), "maa_host"},
		{"azure MAA host with a port", azure, with(azureAtt, "maa_host", "sharedneu.neu.attest.azure.net:8443"), "maa_host"},
		{"azure pins another setup", azure, with(azureAtt, "setup_sha256", strings.Repeat("ab", 32)), "pins setup_sha256 " + strings.Repeat("ab", 32) + " already"},
		{"azure cvm", azure, with(azureAtt, "compliance_status", "azure-compliant-cvm"), "compliance_status"},
		{"azure unlisted", azure, with(azureAtt, "cce_policy_sha256", strings.Repeat("bb", 32)), "allowed_image_measurements"},
		{"gcp", gcp, gcpAtt, ""},
		{"gcp own issuer", gcp, with(gcpAtt, "gcp_issuer", "https://evil.example.com"), "gcp_issuer"},
		{"gcp own key set", gcp, with(gcpAtt, "gcp_jwks_file", "keys.json"), "gcp_jwks_file"},
		{"nitro", nitro, nitroAtt, ""},
		{"nitro mainnet", nitro, with(nitroAtt, "mainnet", true), "mainnet"},
		{"nitro verifier on azure", azure, nitroAtt, "on the azure platform"},
		{"dev on nitro", nitro, map[string]any{"verifier": "dev"}, "on the nitro platform"},
	} {
		writeJSONFile(t, tc.m.cloudPath, map[string]any{"address": "tcp:127.0.0.1:1", "client_cert": "c.pem", "client_key": "k.pem", "attestation": tc.att})
		conn, err := memberConn(tc.m)
		switch {
		case tc.want == "" && err != nil:
			t.Fatalf("%s: %v", tc.name, err)
		case tc.want == "" && conn.Attestation.SetupSHA256 != fullHex(tc.m.setupHash):
			t.Fatalf("%s: setup_sha256 %q, want the member's setup pinned", tc.name, conn.Attestation.SetupSHA256)
		case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
			t.Fatalf("%s: %v, want %q", tc.name, err, tc.want)
		}
	}
}

// signer-admin reads the attestation section of cloud.json strictly: a
// misspelled pin key would leave the pin unset or weaker. Fields outside
// it (those of the signing client) stay allowed.
func TestConnAttestationStrict(t *testing.T) {
	p := newImagePinFixture(t)
	p.writeConn(t, map[string]any{"nitro_pcrs": nitroPins("11"), "nitro_pcr": nitroPins("22")})
	wantIn(t, failTool(t, "probe", "-cluster", p.cl), "nitro_pcr", "unknown field")
	if n := p.requests(); n != 0 {
		t.Fatalf("%d requests reached the runner", n)
	}
	writeJSONFile(t, p.m.cloudPath, map[string]any{
		"address": p.r.Addr(), "client_cert": p.cert, "client_key": p.key, "slots_per_epoch": 32,
		"attestation": map[string]any{"verifier": "aws-nitro", "setup_sha256": hex.EncodeToString(p.m.setupHash[:]), "nitro_pcrs": nitroPins("11")},
	})
	if out := failTool(t, "probe", "-cluster", p.cl); strings.Contains(out, "unknown field") {
		t.Fatalf("a field of the signing client refused:\n%s", out)
	}
}
