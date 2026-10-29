package e2e

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/governance/dkgorder"
	"github.com/lidofinance/tee-signer/governance/flavor"
	"github.com/lidofinance/tee-signer/governance/setupwire"
	"github.com/lidofinance/tee-signer/signer-core/core"
	"github.com/lidofinance/tee-signer/signer-core/software"
	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/sealedimport"
	"github.com/lidofinance/tee-signer/tee-signer/handoverorder"
)

// TestE2EHandoverGate is the release gate of the handover (docs/protocol.md,
// "Handover"): every image of this branch must hand its shares to the next
// one. Image N, a dev key generation runner (the build the cloud images
// take, with the dev peer), holds keys and signs; it hands over to image
// N+1 of the same branch through the two tools, under an approvers' order
// that waits its delay; N+1 signs above the mark; then N+1 hands over to
// N+2 the same way, and N+2 signs above its mark. After each step the
// source refuses to sign, also after a restart, and takes no other order.
// Every signature of the three runners goes to a slashing checker.
//
// scripts/handover-gate.sh runs this test, wants it to pass (not skip), and
// writes the stamp the image builds check (scripts/common.sh
// require_handover_gate). It must never skip: it needs only this tree.
//
// HANDOVER_GATE_FROM_BIN, if set, names the runner of image N: a dev key
// generation build of an older tree (a running image's code). Images N+1
// and N+2 are this tree's. It shows that an image of that tree can hand
// over to this one.
//
// Built with -tags testnet, the test runs the testnet flavour's dev key
// generation build (RUNNER_TESTNET_DKG_BIN) instead, and the tools connect
// with allow_testnet_build. scripts/handover-gate.sh runs both flavours.
func TestE2EHandoverGate(t *testing.T) {
	testnet := flavor.Build == flavor.Testnet
	binKey := "dev-dkg"
	if testnet {
		binKey = "dev-testnet-dkg"
	}
	bin := runnerBinary(t, binKey)
	fromBin := os.Getenv("HANDOVER_GATE_FROM_BIN")
	srcTool, tgtTool := filepath.Join(binDir, "handover-source"), filepath.Join(binDir, "handover-target")
	for tool, pkg := range map[string]string{srcTool: "../../signer-admin/cmd/handover-source", tgtTool: "../../signer-admin/cmd/handover-target"} {
		if err := goBuild(tool, pkg, ""); err != nil {
			t.Fatal(err)
		}
	}
	const nKeys = 8
	c := dkgChain(t)
	if testnet {
		// A testnet build takes Hoodi's fork version with Hoodi's root
		// only: a devnet here.
		c = newChain(t)
	}
	dir := t.TempDir()
	caFile, cliCfg := testPKI(t, dir, "gate")
	cert, key := writeClientPair(t, dir, cliCfg)
	var cluster [32]byte
	rand.Read(cluster[:])
	lock := uint64(orderTimeLock)

	// Image N: generation 1.
	s, err := setupwire.DecodeSetup(orderSetupFor(t, c, filepath.Join(dir, "gen1"), caFile, "signer-1", cluster, &lock))
	if err != nil {
		t.Fatal(err)
	}
	s.HandoverGeneration = 1
	writeSetup := func(s *setupwire.Setup, name string) (string, [32]byte) {
		t.Helper()
		raw, err := s.Encode()
		if err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(dir, name+".setup")
		if err := os.WriteFile(p, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		return p, mustSetupHash(t, raw)
	}
	writeConn := func(name, addr string, h [32]byte) string {
		t.Helper()
		p := filepath.Join(dir, name+".json")
		b, _ := json.Marshal(map[string]any{"address": addr, "client_cert": cert, "client_key": key,
			"attestation": map[string]any{"verifier": "dev", "setup_sha256": hex.EncodeToString(h[:])}, "allow_testnet_build": testnet})
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	type gen struct {
		name  string
		setup *setupwire.Setup
		file  string
		hash  [32]byte
		p     *peerProc
		conn  string
	}
	start := func(name string, s *setupwire.Setup) *gen {
		t.Helper()
		g := &gen{name: name, setup: s}
		g.file, g.hash = writeSetup(s, name)
		addr := fmt.Sprintf("tcp:127.0.0.1:%d", freePort(t))
		b := bin
		if name == "gen1" && fromBin != "" {
			b = fromBin
		}
		g.p = startPeerAt(t, b, name, filepath.Join(dir, name), g.file, addr)
		g.conn = writeConn(name, addr, g.hash)
		return g
	}
	cur := start("gen1", s)
	if h, err := cur.p.cl.Health(ctx); err != nil || flavor.FromVersion(h.Version) != flavor.Build {
		t.Fatalf("gen1 HEALTH: %v %+v, want the %s flavour", err, h, flavor.Build)
	}

	// Keys: sealed imports under import orders of k approvers.
	var keys []backend.Pubkey
	for i := range nKeys {
		sk, _ := software.NewSecret()
		pk, _ := core.PubkeyOf(sk)
		req := &backend.SealedImportRequest{Pubkey: pk, SharePubkey: pk, Index: uint64(10 + i),
			Order: importOrder(t, s, cur.hash, pk, 1, 1, 1, []backend.Pubkey{pk}), T: 1, N: 1, ShareIndex: 1, Commitments: []backend.Pubkey{pk}}
		if req.Sealed, err = sealedimport.Seal(devIdentity(t, cur.p.cl), req, &sk); err != nil {
			t.Fatal(err)
		}
		if _, err := adminOf(cur.p.cl).ImportSealed(ctx, req); err != nil {
			t.Fatal(err)
		}
		keys = append(keys, pk)
	}

	check := &slashCheck{atts: map[slashKey][]slashAtt{}, blks: map[slashKey]map[uint64]backend.Root{}}
	// signAll signs an attestation of the current epoch for every key on g,
	// and returns how many it signed.
	signAll := func(g *gen) int {
		e := c.stableEpoch(t)
		n := 0
		for _, pk := range keys {
			data := att(e-1, e, byte(e))
			root, _ := c.cfg.SigningRoot(data)
			if _, err := g.p.cl.Sign(ctx, c.req(pk, data)); err == nil {
				check.add(0, pk, data, root, g.name)
				n++
			}
		}
		return n
	}
	// signs waits until g signs every key in one epoch (its restart floor
	// and the handed-over mark behind it).
	signs := func(g *gen, what string) {
		t.Helper()
		deadline := time.Now().Add(30 * epochSecs * time.Second)
		for signAll(g) != nKeys {
			if time.Now().After(deadline) {
				t.Fatalf("%s: %s does not sign every key", g.name, what)
			}
			c.waitEpoch(t, c.epochNow()+1)
		}
	}
	signs(cur, "after the import")

	for step := 2; step <= 3; step++ {
		// Image N+1: the source's setup with handover_generation one higher,
		// version 0 of both groups equal to the source's config in force
		// (no update was pushed, so the setup's), new salts, its own stores.
		ns, err := setupwire.DecodeSetup(mustRead(t, cur.file))
		if err != nil {
			t.Fatal(err)
		}
		ns.HandoverGeneration++
		salts, err := setupwire.NewPolicySalts(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		ns.PolicySalts = salts
		gdir := filepath.Join(dir, fmt.Sprintf("gen%d", step))
		ns.Platform.SlashingLogStore = setupwire.Store{Dir: filepath.Join(gdir, "marks")}
		ns.Platform.EncryptedStateStore = &setupwire.Store{Dir: filepath.Join(gdir, "state-copy")}
		next := start(fmt.Sprintf("gen%d", step), ns)
		if k, _ := next.p.cl.PublicKeys(ctx); len(k) != 0 {
			t.Fatalf("%s holds keys at start", next.name)
		}

		hb := handoverorder.Body{ClusterID: cluster, ChainHash: s.Chain.Hash(), NotAfter: uint64(time.Now().Add(12 * time.Hour).Unix()),
			Source: handoverorder.Runner{Name: cur.name, SetupHash: cur.hash, Verifier: dkgorder.VerifierDev},
			Target: handoverorder.Runner{Name: next.name, SetupHash: next.hash, Verifier: dkgorder.VerifierDev}}
		orderFile := filepath.Join(dir, next.name+".order")
		if err := os.WriteFile(orderFile, signHandoverOrder(t, hb), 0o600); err != nil {
			t.Fatal(err)
		}
		idFile, pages := filepath.Join(dir, next.name+"-identity.json"), filepath.Join(dir, next.name+"-pages")
		// A source hands over only to a target reserved for its order
		// (handover-target identity -order).
		if _, err := runTool(t, tgtTool, "identity", "-conn", next.conn, "-setup", next.file, "-order", orderFile, "-out", idFile); err != nil {
			t.Fatal(err)
		}
		source := func(extra ...string) (string, error) {
			return runTool(t, srcTool, append([]string{"-conn", cur.conn, "-order", orderFile, "-identity", idFile, "-out", pages}, extra...)...)
		}
		// The order waits its delay; the source signs on meanwhile.
		if out, err := source(); err == nil || !strings.Contains(out, "waits") {
			t.Fatalf("step %d: handover-source inside the wait: %v", step, err)
		}
		signs(cur, "inside the order's wait")
		time.Sleep(time.Duration(lock+1) * time.Second)
		if out, err := source(); err == nil || !strings.Contains(out, "-go") {
			t.Fatalf("step %d: handover-source without -go: %v", step, err)
		}
		if _, err := source("-go"); err != nil {
			t.Fatalf("step %d: handover-source: %v", step, err)
		}
		out, err := runTool(t, tgtTool, "import", "-conn", next.conn, "-order", orderFile, "-pages", pages)
		if err != nil || !strings.Contains(out, fmt.Sprintf("holds %d of %d", nKeys, nKeys)) || !strings.Contains(out, "done true") {
			t.Fatalf("step %d: import: %v\n%s", step, err, out)
		}

		// The source signs nothing after its tombstone, also after a
		// restart, and takes no other order.
		pk := keys[0]
		e := c.epochNow()
		if _, err := cur.p.cl.Sign(ctx, c.req(pk, att(e, e+1, 0xee))); err == nil {
			t.Fatalf("step %d: %s signed after its tombstone", step, cur.name)
		}
		cur.p.restart(t)
		if _, err := cur.p.cl.Sign(ctx, c.req(pk, att(e, e+1, 0xee))); err == nil {
			t.Fatalf("step %d: %s signed after a restart past its tombstone", step, cur.name)
		}
		other := hb
		other.Target.SetupHash = [32]byte{0x77}
		if _, err := adminOf(cur.p.cl).HandoverOrder(ctx, signHandoverOrder(t, other)); err == nil {
			t.Fatalf("step %d: %s took a second order after its tombstone", step, cur.name)
		}
		// The target refuses what the source signed up to the mark, then
		// signs above it.
		if last, ok := check.lastAtt(0, pk); ok {
			if _, err := next.p.cl.Sign(ctx, c.req(pk, att(last.source, last.target, 0xef))); err == nil {
				t.Fatalf("step %d: %s signed a double vote of %s's target %d", step, next.name, cur.name, last.target)
			}
		}
		signs(next, "above the handed-over mark")
		// N+1 restarts and signs from its own stored shares and log.
		next.p.restart(t)
		signs(next, "after a restart")
		t.Logf("step %d: %s handed %d keys to %s; the source refuses, the target signs above the mark", step, cur.name, nKeys, next.name)
		cur = next
	}
	if len(check.bad) > 0 {
		t.Fatalf("slashing checker: %d violations, first %s", len(check.bad), check.bad[0])
	}
	t.Logf("handover gate: gen1 -> gen2 -> gen3, %d signatures checked, no double vote or surround", check.sigs)
}

// signHandoverOrder is b signed by approvers 1 and 2.
func signHandoverOrder(t *testing.T, b handoverorder.Body) []byte {
	t.Helper()
	enc, err := b.Encode()
	if err != nil {
		t.Fatal(err)
	}
	o := handoverorder.Order{Body: b}
	for _, id := range []byte{1, 2} {
		o.Approvals = append(o.Approvals, setupwire.Approval{Position: id - 1, Signature: handoverorder.SignBody(configApprover(id), enc)})
	}
	raw, err := o.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
