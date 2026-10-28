// Package e2e starts real runner processes and drives them through the
// remote backend over TCP, a unix socket and (if the kernel allows)
// vsock. Chain time is compressed: 1-second slots, 2 slots per epoch.
//
// There is one runner binary per cloud (runner/platforms.go, and
// scripts/build-runner.sh builds them). Each test uses the binary its
// platform needs. A variable names the binary to test; when it is unset the
// test builds the binary itself, with the tags in runnerBuilds below.
//
//	RUNNER_BIN=/path/to/runner-dev            the dev release build
//	RUNNER_DEBUG_BIN=/path/to/runner-dev-debugimport
//	                                          the dev debug build (-tags debugimport) for the
//	                                          tests that load shares in plain text; default
//	                                          RUNNER_BIN-debugimport when RUNNER_BIN is set
//	RUNNER_AWS_BIN, RUNNER_AZURE_BIN, RUNNER_GCP_BIN
//	                                          the release builds of the clouds (start-up refusals)
//	RUNNER_AWS_DEBUG_BIN                      the debug build with the nitro and dev platforms
//	                                          (vsock tests, which need -tags platform_aws)
//	RUNNER_AZURE_DEBUG_BIN                    the Azure debug build
//	RUNNER_GCP_DEBUG_BIN                      the GCP debug build (Google endpoints at a test URL)
//	RUNNER_WRAPPER=qemu-aarch64               run the binaries through this (arm64 on x86_64)
//
// Tests that need plaintext IMPORT_SHARE (newRunner) run the dev debug build;
// the rest (newRunnerArgs) run the dev release build. The vsock tests are in
// vsock_test.go, built with -tags platform_aws, and run on the AWS debug
// build with the dev platform: the dev build has no vsock.
package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/signer-core/core"
	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/remote"
)

const (
	secondsPerSlot = 1
	slotsPerEpoch  = 2
	epochSecs      = secondsPerSlot * slotsPerEpoch
)

var shareImportBin, binDir string

// runnerBuilds are the runner binaries the tests use: the variable that names
// one, and the build tags that make it (scripts/build-runner.sh uses the same).
var runnerBuilds = map[string]struct{ env, tags string }{
	"dev":         {"RUNNER_BIN", "platform_dev"},
	"dev-debug":   {"RUNNER_DEBUG_BIN", "platform_dev,debugimport"},
	"aws":         {"RUNNER_AWS_BIN", "platform_aws,nts"},
	"aws-debug":   {"RUNNER_AWS_DEBUG_BIN", "platform_aws,platform_dev,debugimport,nts"},
	"azure":       {"RUNNER_AZURE_BIN", "platform_azure,nts"},
	"azure-debug": {"RUNNER_AZURE_DEBUG_BIN", "platform_azure,debugimport,nts"},
	"gcp":         {"RUNNER_GCP_BIN", "platform_gcp,nts"},
	"gcp-debug":   {"RUNNER_GCP_DEBUG_BIN", "platform_gcp,debugimport,nts"},
	"dev-dkg":     {"RUNNER_DKG_BIN", "platform_dev,peerselect,peer_dev"},
	// The testnet builds (testnet_test.go, -tags testnet).
	"dev-testnet":     {"RUNNER_TESTNET_BIN", "platform_dev,testnet"},
	"dev-testnet-dkg": {"RUNNER_TESTNET_DKG_BIN", "platform_dev,testnet,peerselect,peer_dev"},
}

var (
	binMu sync.Mutex
	bins  = map[string]string{}
)

// goBuild builds pkg (relative to this directory) into out.
func goBuild(out, pkg string, tags string) error {
	args := []string{"build"}
	if tags != "" {
		args = append(args, "-tags", tags)
	}
	// pkg is a folder of a module of this repo: build it there, with the
	// go.mod of that module.
	abs, err := filepath.Abs(out)
	if err != nil {
		return err
	}
	cmd := exec.Command("go", append(args, "-o", abs, ".")...)
	cmd.Dir = pkg
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	return cmd.Run()
}

// runnerBinary returns the path of the runner binary for a key of
// runnerBuilds: the variable if it is set, else a build made here.
func runnerBinary(t *testing.T, key string) string {
	t.Helper()
	binMu.Lock()
	defer binMu.Unlock()
	if p, ok := bins[key]; ok {
		return p
	}
	b, ok := runnerBuilds[key]
	if !ok {
		t.Fatalf("no runner build %q", key)
	}
	p := os.Getenv(b.env)
	if p == "" && key == "dev-debug" && os.Getenv("RUNNER_BIN") != "" {
		p = os.Getenv("RUNNER_BIN") + "-debugimport"
	}
	if p == "" {
		p = filepath.Join(binDir, "runner-"+key)
		if err := goBuild(p, "../../tee-signer", b.tags); err != nil {
			t.Fatalf("build runner-%s (-tags %s): %v (or set %s)", key, b.tags, err, b.env)
		}
	}
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("no runner-%s at %s: %v (set %s)", key, p, err, b.env)
	}
	bins[key] = p
	return p
}

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "runner-e2e-")
	if err != nil {
		panic(err)
	}
	binDir = dir
	// The dealer tool always runs natively.
	shareImportBin = filepath.Join(dir, "share-import")
	if err := goBuild(shareImportBin, "../../signer-admin/cmd/share-import", ""); err != nil {
		fmt.Fprintln(os.Stderr, "build ../cmd/share-import:", err)
		os.RemoveAll(dir)
		os.Exit(1)
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

// chain is the test chain: genesis 1000 epochs ago.
type chain struct {
	cfg  core.Config
	path string
}

func newChain(t *testing.T) chain {
	now := uint64(time.Now().Unix())
	cfg := core.DevConfig(now-1000*epochSecs, secondsPerSlot, slotsPerEpoch)
	cfg.Forks = nil // keep one fork version
	raw, _ := json.MarshalIndent(cfg, "", "  ")
	p := filepath.Join(t.TempDir(), "chain.json")
	if err := os.WriteFile(p, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return chain{cfg: cfg, path: p}
}

func (c chain) epochNow() uint64 { return c.cfg.EpochAt(uint64(time.Now().Unix())) }

// req is a SIGN request for m with the domain this chain gives it, as a
// client on the runner's fork sends it.
func (c chain) req(pk backend.Pubkey, m backend.Message) backend.SignRequest {
	d, _ := c.cfg.MessageDomain(m)
	return backend.SignRequest{Pubkey: pk, Message: m, Domain: d}
}

// waitEpoch sleeps until the wall-clock epoch is at least e and we are at
// least 300 ms past a second boundary, so runner and test agree.
func (c chain) waitEpoch(t *testing.T, e uint64) {
	t.Helper()
	for {
		now := time.Now()
		if c.cfg.EpochAt(uint64(now.Unix())) >= e && now.Nanosecond() > 300e6 && now.Nanosecond() < 800e6 {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// stableEpoch returns the current epoch, first waiting out an epoch boundary.
func (c chain) stableEpoch(t *testing.T) uint64 {
	t.Helper()
	for {
		now := time.Now()
		into := (uint64(now.Unix()) - c.cfg.GenesisTime) % epochSecs
		if into < epochSecs-1 && now.Nanosecond() > 200e6 && now.Nanosecond() < 700e6 {
			return c.cfg.EpochAt(uint64(now.Unix()))
		}
		time.Sleep(50 * time.Millisecond)
	}
}

type runner struct {
	t        *testing.T
	name     string
	bin      string // one of the binaries of runnerBuilds
	args     []string
	stateDir string
	logPath  string
	cmd      *exec.Cmd
	log      *os.File
}

func freePort(t *testing.T) int {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// newRunner makes a dev runner from the debug build that also accepts
// plaintext imports.
func newRunner(t *testing.T, name string, c chain, listen string, extra ...string) *runner {
	return newRunnerOn(t, runnerBinary(t, "dev-debug"), name, c, listen, append([]string{"-allow-import"}, extra...)...)
}

// newRunnerArgs makes a dev runner from the release build with exactly the
// given extra flags.
func newRunnerArgs(t *testing.T, name string, c chain, listen string, extra ...string) *runner {
	return newRunnerOn(t, runnerBinary(t, "dev"), name, c, listen, extra...)
}

// newRunnerOn makes a runner on the dev platform from the binary bin, with
// exactly the given extra flags.
func newRunnerOn(t *testing.T, bin, name string, c chain, listen string, extra ...string) *runner {
	dir := t.TempDir()
	r := &runner{t: t, name: name, bin: bin, stateDir: filepath.Join(dir, "state"), logPath: filepath.Join(dir, name+".log")}
	r.args = append([]string{"-platform", "dev", "-config", c.path, "-state-dir", r.stateDir,
		"-listen", listen}, extra...)
	t.Cleanup(func() {
		r.stop()
		if t.Failed() {
			b, _ := os.ReadFile(r.logPath)
			t.Logf("---- %s log ----\n%s", name, b)
		}
	})
	return r
}

// runnerCmd runs bin with args, through RUNNER_WRAPPER if set.
func runnerCmd(bin string, args ...string) *exec.Cmd {
	if w := os.Getenv("RUNNER_WRAPPER"); w != "" {
		return exec.Command(w, append([]string{bin}, args...)...)
	}
	return exec.Command(bin, args...)
}

func (r *runner) start(extra ...string) {
	r.t.Helper()
	f, err := os.OpenFile(r.logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		r.t.Fatal(err)
	}
	r.cmd = runnerCmd(r.bin, append(append([]string{}, r.args...), extra...)...)
	r.cmd.Stdout, r.cmd.Stderr = f, f
	r.log = f
	if err := r.cmd.Start(); err != nil {
		r.t.Fatal(err)
	}
}

func (r *runner) stop() {
	if r.cmd == nil || r.cmd.Process == nil {
		return
	}
	_ = r.cmd.Process.Signal(syscall.SIGTERM)
	done := make(chan struct{})
	go func() { r.cmd.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		r.cmd.Process.Kill()
		<-done
	}
	r.log.Close()
	r.cmd = nil
}

func (r *runner) logText() string {
	b, _ := os.ReadFile(r.logPath)
	return string(b)
}

func waitReady(t *testing.T, b backend.Backend) *backend.Health {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		h, err := b.Health(ctx)
		cancel()
		if err == nil && h.Ready {
			return h
		}
		if time.Now().After(deadline) {
			t.Fatalf("runner not ready: %v", err)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func client(t *testing.T, addr string) *remote.Client {
	c, err := remote.New(addr, remote.WithTimeout(30*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func att(source, target uint64, tag byte) *backend.AttestationData {
	return &backend.AttestationData{Slot: target * slotsPerEpoch, BeaconBlockRoot: backend.Root{tag},
		Source: backend.Checkpoint{Epoch: source, Root: backend.Root{0x51}},
		Target: backend.Checkpoint{Epoch: target, Root: backend.Root{0x52}}}
}

func wantRefused(t *testing.T, err error, code backend.Status) *backend.RefusedError {
	t.Helper()
	var r *backend.RefusedError
	if !errors.As(err, &r) || r.Code != code {
		t.Fatalf("want %v, got %v", code, err)
	}
	return r
}

var ctx = context.Background()

// TestE2E is the main scenario from the task: three runners hold shares of
// one 3-of-5 key; the first serves TCP and a unix socket.
func TestE2E(t *testing.T) {
	c := newChain(t)
	sk, _ := core.NewSecret()
	pk, _ := core.PubkeyOf(sk)
	shares, err := core.Split(sk, 3, 5)
	if err != nil {
		t.Fatal(err)
	}
	const index = 9 // not on the exit allowlist {7}

	sock := filepath.Join(t.TempDir(), "a.sock")
	tcpA := fmt.Sprintf("tcp:127.0.0.1:%d", freePort(t))
	a := newRunner(t, "runner-a", c, tcpA+",unix:"+sock, "-persist-repeat-root=true")
	a.start()
	viaTCP, viaUnix := client(t, tcpA), client(t, "unix:"+sock)
	var others []*remote.Client
	var otherRunners []*runner
	for _, name := range []string{"runner-b", "runner-c"} {
		addr := fmt.Sprintf("tcp:127.0.0.1:%d", freePort(t))
		r := newRunner(t, name, c, addr)
		r.start()
		others = append(others, client(t, addr))
		otherRunners = append(otherRunners, r)
	}
	h := waitReady(t, viaUnix)
	for _, o := range others {
		waitReady(t, o)
	}
	// Repeat roots are off by default (runner-b and runner-c); runner-a
	// turns them on for the restart below.
	if !strings.Contains(a.logText(), "persist_repeat_root=true") {
		t.Fatal("runner-a: no persist_repeat_root=true in its start line")
	}
	for _, r := range otherRunners {
		if !strings.Contains(r.logText(), "persist_repeat_root=false") {
			t.Fatalf("%s: no persist_repeat_root=false in its start line (the default)", r.name)
		}
	}
	t.Logf("runner-a ready: platform=%s restart_mode=%s clock=%s", h.Platform, h.RestartMode, h.ClockSource)
	// The system clock: the time in milliseconds, no NTS state.
	if h.NTS != nil || h.ClockUnixMS == 0 || h.ClockUnixMS/1000 != h.ClockUnix {
		t.Fatalf("health clock: nts %+v, clock_unix_ms %d, clock_unix %d", h.NTS, h.ClockUnixMS, h.ClockUnix)
	}

	// Import share 1 over TCP, shares 2 and 3 into the other runners.
	e0 := c.stableEpoch(t)
	backends := []*remote.Client{viaTCP, others[0], others[1]}
	for i, b := range backends {
		k, err := adminOf(b).ImportShare(ctx, backend.ImportShareRequest{Pubkey: pk, Secret: shares[i].Secret, Index: index})
		if err != nil {
			t.Fatal(err)
		}
		want, _ := core.PubkeyOf(shares[i].Secret)
		if k.SharePubkey != want || k.Pubkey != pk {
			t.Fatalf("share %d: keys differ", i+1)
		}
	}
	keys, err := viaUnix.PublicKeys(ctx)
	if err != nil || len(keys) != 1 || keys[0].Pubkey != pk {
		t.Fatalf("public keys over unix socket: %+v %v", keys, err)
	}
	t.Logf("imported shares 1-3 at epoch %d; floor at import = %d (margin max_epochs_ahead + 1 = 2)", e0, e0+2)

	// Sign one attestation on all three, over TCP (a) and TCP (b, c).
	// e0+4 leaves room for a floor of e0+3 if an import crossed an epoch.
	e1 := e0 + 4
	c.waitEpoch(t, e1)
	data := att(e1-1, e1, 0xa1)
	root, _ := c.cfg.SigningRoot(data)
	var sigs []backend.Signature
	for i, b := range backends {
		sig, err := b.Sign(ctx, c.req(pk, data))
		if err != nil {
			t.Fatalf("share %d: %v", i+1, err)
		}
		sp, _ := core.PubkeyOf(shares[i].Secret)
		if !core.Verify(sp, root, sig) {
			t.Fatalf("share %d: partial signature does not verify under its share key", i+1)
		}
		sigs = append(sigs, sig)
	}
	full, err := core.RecoverSignature([]uint64{1, 2, 3}, sigs)
	if err != nil {
		t.Fatal(err)
	}
	if !core.Verify(pk, root, full) {
		t.Fatal("recovered signature does not verify under the validator key")
	}
	t.Logf("epoch %d: attestation source=%d target=%d signed by 3 runners; partials verify; recovered 3-of-5 signature verifies under the validator key (blst)", e1, e1-1, e1)

	// A validator client retry: the same attestation again on every runner
	// gives the same partials, so the same recovered signature.
	var again []backend.Signature
	for i, b := range backends {
		sig, err := b.Sign(ctx, c.req(pk, att(e1-1, e1, 0xa1)))
		if err != nil {
			t.Fatalf("share %d: exact repeat refused: %v", i+1, err)
		}
		if sig != sigs[i] {
			t.Fatalf("share %d: exact repeat gave another signature", i+1)
		}
		again = append(again, sig)
	}
	if full2, _ := core.RecoverSignature([]uint64{1, 2, 3}, again); full2 != full {
		t.Fatal("recovered signature of the repeat differs")
	}
	t.Logf("exact repeat of the attestation on 3 runners: same partial signatures, same recovered signature")

	// Double vote over the unix socket.
	_, err = viaUnix.Sign(ctx, c.req(pk, att(e1-1, e1, 0xa2)))
	r := wantRefused(t, err, backend.StatusSlashTarget)
	t.Logf("double vote for target %d refused: %v", e1, r)

	// Exit for a validator not on the allowlist.
	_, err = viaTCP.Sign(ctx, c.req(pk, &backend.VoluntaryExit{Epoch: e1, ValidatorIndex: index}))
	r = wantRefused(t, err, backend.StatusPolicyExit)
	t.Logf("voluntary exit refused: %v", r)

	// Block and a RANDAO root over the unix socket.
	blk := &backend.BeaconBlockHeader{Slot: e1*slotsPerEpoch + 1, ProposerIndex: index, BodyRoot: backend.Root{0xb0}}
	sig, err := viaUnix.Sign(ctx, c.req(pk, blk))
	if err != nil {
		t.Fatal(err)
	}
	broot, _ := c.cfg.SigningRoot(blk)
	sp1, _ := core.PubkeyOf(shares[0].Secret)
	if !core.Verify(sp1, broot, sig) {
		t.Fatal("block partial signature")
	}
	blkAgain := *blk
	if sig2, err := viaTCP.Sign(ctx, c.req(pk, &blkAgain)); err != nil || sig2 != sig {
		t.Fatalf("exact repeat of the block: %v", err)
	}
	other := *blk
	other.BodyRoot = backend.Root{0xb1}
	_, err = viaTCP.Sign(ctx, c.req(pk, &other))
	wantRefused(t, err, backend.StatusSlashBlock)
	t.Logf("block slot %d: exact repeat signed again (same signature), other body root refused", blk.Slot)
	randao := &backend.RootMessage{Type: backend.RootRandaoReveal, Epoch: e1,
		ObjectRoot: backend.HashTreeRootUint64(e1), Domain: c.cfg.Domain(backend.DomainRandao, e1)}
	sig, err = viaUnix.Sign(ctx, c.req(pk, randao))
	if err != nil {
		t.Fatal(err)
	}
	if rroot, _ := c.cfg.SigningRoot(randao); !core.Verify(sp1, rroot, sig) {
		t.Fatal("RANDAO partial signature")
	}
	wrong := *randao
	wrong.Domain = c.cfg.Domain(backend.DomainAggregateAndProof, e1)
	_, err = viaUnix.Sign(ctx, c.req(pk, &wrong))
	wantRefused(t, err, backend.StatusDomainMismatch)
	// A bare selection proof root is unverified: refused with
	// allow_unverified_nonslashable off.
	sel := &backend.RootMessage{Type: backend.RootAggregationSlot, Epoch: e1,
		ObjectRoot: backend.HashTreeRootUint64(e1 * slotsPerEpoch), Domain: c.cfg.Domain(backend.DomainSelectionProof, e1)}
	_, err = viaUnix.Sign(ctx, c.req(pk, sel))
	wantRefused(t, err, backend.StatusPolicyDomain)
	t.Logf("block slot %d and RANDAO root signed over the unix socket; RANDAO with a wrong domain and a bare selection proof root refused", blk.Slot)
	// The typed selection proof carries the caller's domain too: one from a
	// caller on another fork version is refused, the runner's own signs.
	tsel := &backend.SelectionProof{Slot: e1 * slotsPerEpoch}
	stale := c.req(pk, tsel)
	stale.Domain = backend.ComputeDomain(backend.DomainSelectionProof, backend.Version{0x09, 0, 0, 1}, c.cfg.GenesisValidatorsRoot)
	_, err = viaTCP.Sign(ctx, stale)
	wantRefused(t, err, backend.StatusDomainMismatch)
	sig, err = viaTCP.Sign(ctx, c.req(pk, tsel))
	if troot, _ := c.cfg.SigningRoot(tsel); err != nil || !core.Verify(sp1, troot, sig) {
		t.Fatalf("typed selection proof with the runner's domain: %v", err)
	}
	t.Logf("typed selection proof with another fork's domain refused, with the runner's domain signed")

	// Attestation document binds the nonce.
	nonce := []byte("e2e-nonce-0123456789")
	doc, err := viaUnix.Attest(ctx, nonce)
	if err != nil || doc.Platform != "dev" || len(doc.UserData) != 32 || !bytes.Contains(doc.Document, []byte(`"user_data"`)) {
		t.Fatalf("attest: %+v %v", doc, err)
	}

	// Restart runner-a: shares come back from the sealed store, the floor
	// moves to the restart epoch + 2.
	a.stop()
	viaTCP.Close()
	viaUnix.Close()
	e2 := c.stableEpoch(t)
	a.start()
	h = waitReady(t, viaUnix)
	if h.Validators != 1 {
		t.Fatalf("after restart: %d validators", h.Validators)
	}
	t.Logf("runner-a restarted at epoch %d, share reloaded from sealed storage", e2)
	// persist_repeat_root (on for runner-a): the roots of the last vote and
	// block were stored with each signature, so a validator client retry
	// after the restart signs, with the same partial signature. Another
	// root at that target is still refused by the floor.
	sig, err = viaTCP.Sign(ctx, c.req(pk, att(e1-1, e1, 0xa1)))
	if err != nil || sig != sigs[0] {
		t.Fatalf("exact repeat after restart: want the same signature, got %v (same %v)", err, sig == sigs[0])
	}
	if sig2, err := viaTCP.Sign(ctx, c.req(pk, &blkAgain)); err != nil {
		t.Fatalf("exact repeat of the block after restart: %v", err)
	} else if bsig, _ := c.cfg.SigningRoot(blk); !core.Verify(sp1, bsig, sig2) {
		t.Fatal("block repeat after restart does not verify")
	}
	_, err = viaTCP.Sign(ctx, c.req(pk, att(e1-1, e1, 0xa2)))
	if r := wantRefused(t, err, backend.StatusSlashSource); !strings.Contains(r.Detail, "restart floor") {
		t.Fatalf("other root at target %d after restart: want a floor refusal, got %v", e1, r)
	}
	t.Logf("after restart: exact repeats of the last attestation and block signed again (repeat roots from the sealed store); another root at target %d refused by the floor", e1)
	var floor uint64
	// Source below the floor, then source and target at E+1. (E+2 is past
	// the clock horizon until epoch E+1, and below the floor after.)
	for _, m := range []*backend.AttestationData{att(e2, e2+1, 0xa3), att(e2+1, e2+1, 0xa3)} {
		_, err = viaTCP.Sign(ctx, c.req(pk, m))
		var rr *backend.RefusedError
		if !errors.As(err, &rr) || !rr.Code.IsSlashing() || !strings.Contains(rr.Detail, "restart floor") {
			t.Fatalf("target %d after restart: want a floor refusal, got %v", m.Target.Epoch, err)
		}
		if _, err := fmt.Sscanf(rr.Detail[strings.Index(rr.Detail, "floor epoch"):], "floor epoch %d", &floor); err != nil {
			t.Fatal(err)
		}
		t.Logf("after restart: source=%d target=%d refused: %v", m.Source.Epoch, m.Target.Epoch, rr)
	}
	if floor != e2+2 {
		t.Logf("note: the runner read epoch %d at load (slow start), floor %d", floor-2, floor)
	}
	e3 := floor + 1
	c.waitEpoch(t, e3)
	data = att(e3-1, e3, 0xa4)
	sig, err = viaTCP.Sign(ctx, c.req(pk, data))
	if err != nil {
		t.Fatalf("epoch %d after restart: %v", e3, err)
	}
	root, _ = c.cfg.SigningRoot(data)
	if !core.Verify(sp1, root, sig) {
		t.Fatal("post-restart signature")
	}
	t.Logf("epoch %d: first attestation after the restart signed and verified (targets <= %d were refused)", e3, floor)
	if !strings.Contains(a.logText(), "restart floor") {
		t.Fatal("runner log does not mention the floor")
	}
}

// TestE2EClockSkewBreaksFloor shows the dependency on the clock: a host
// that runs the clock ahead, then restarts the runner with the right time,
// gets two different votes for one target.
func TestE2EClockSkewBreaksFloor(t *testing.T) {
	c := newChain(t)
	sk, _ := core.NewSecret()
	pk, _ := core.PubkeyOf(sk)
	addr := fmt.Sprintf("tcp:127.0.0.1:%d", freePort(t))
	r := newRunner(t, "runner-skew", c, addr)
	// 4 epochs: more than the floor's spare epoch, so the attack still works.
	skew := 4 * epochSecs * time.Second
	r.start("-platform-opt", "clock_offset="+skew.String())
	cl := client(t, addr)
	waitReady(t, cl)
	e0 := c.stableEpoch(t)
	if _, err := adminOf(cl).ImportShare(ctx, backend.ImportShareRequest{Pubkey: pk, Secret: sk, Index: 7}); err != nil {
		t.Fatal(err)
	}
	// The runner believes it is epoch e0+4; floor e0+6, ceiling e0+5.
	// Wait two epochs so the ceiling passes the floor: target e0+7.
	c.waitEpoch(t, e0+2)
	e := c.stableEpoch(t)
	victim := e + 5
	first := att(victim-1, victim, 0x01)
	if _, err := cl.Sign(ctx, c.req(pk, first)); err != nil {
		t.Fatalf("signing ahead with the skewed clock: %v", err)
	}
	t.Logf("clock +%v: signed target %d while the real epoch was %d", skew, victim, e)

	r.stop()
	cl.Close()
	r.start() // honest clock now
	waitReady(t, cl)
	c.waitEpoch(t, victim-1)
	second := att(victim-1, victim, 0x02)
	sig2, err := cl.Sign(ctx, c.req(pk, second))
	if err != nil {
		t.Fatalf("expected the double vote to be signed (documents the limit), got %v", err)
	}
	r1, _ := c.cfg.SigningRoot(first)
	r2, _ := c.cfg.SigningRoot(second)
	if r1 == r2 || !core.Verify(pk, r2, sig2) {
		t.Fatal("setup error")
	}
	t.Logf("restart with honest clock: signed a second, different vote for target %d -> slashable double vote", victim)
}

// TestE2EHTTPSDateIgnoresHostClock repeats the skew attack with the
// anchored HTTPS-date clock: the host-set system clock is 1 hour ahead,
// the runner ignores it, and a vote 4 epochs ahead is refused. Needs
// network; runs only with E2E_NETWORK=1.
func TestE2EHTTPSDateIgnoresHostClock(t *testing.T) {
	if os.Getenv("E2E_NETWORK") != "1" {
		t.Skip("set E2E_NETWORK=1 to run (needs HTTPS to public sites)")
	}
	c := newChain(t)
	addr := fmt.Sprintf("tcp:127.0.0.1:%d", freePort(t))
	r := newRunner(t, "runner-httpsdate", c, addr, "-platform-opt", "clock_offset=1h",
		"-clock", "https-date", "-clock-urls", "https://www.cloudflare.com/,https://www.google.com/,https://github.com/",
		"-clock-interval", "2s", "-clock-max-age", "20s")
	r.start()
	cl := client(t, addr)
	h := waitReady(t, cl)
	off := int64(h.ClockUnix) - time.Now().Unix()
	if h.NTS != nil || h.ClockUnixMS/1000 != h.ClockUnix {
		t.Fatalf("https-date clock: nts %+v, clock_unix_ms %d, clock_unix %d", h.NTS, h.ClockUnixMS, h.ClockUnix)
	}
	if off < -30 || off > 30 || !h.ClockTrusted {
		t.Fatalf("clock %d s off system time (system clock is +1h for the runner's dev platform), trusted=%v", off, h.ClockTrusted)
	}
	t.Logf("runner clock %s: %+d s from real time although the dev platform clock is +1h", h.ClockSource, off)
	sk, _ := core.NewSecret()
	pk, _ := core.PubkeyOf(sk)
	if _, err := adminOf(cl).ImportShare(ctx, backend.ImportShareRequest{Pubkey: pk, Secret: sk, Index: 7}); err != nil {
		t.Fatal(err)
	}
	e := c.stableEpoch(t)
	_, err := cl.Sign(ctx, c.req(pk, att(e+3, e+4, 1)))
	rr := wantRefused(t, err, backend.StatusPolicyFuture)
	t.Logf("vote 4 epochs ahead refused: %v", rr)
}
