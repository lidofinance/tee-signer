//go:build nonprod

package e2e

// The non-prod builds (signer-protocol/buildchain) on dev runners. Run
// these tests on their own and with the tags:
//
//	go test -tags nonprod,chain_ci_test -timeout 20m -run TestE2ENonProd -v ./e2e
//
// The tags make this test binary's setupwire constants the short waits of
// the non-prod builds too, so the waits below are the ones the runners
// use. Nothing fakes a clock: the runners read the host's.

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/attestation-verify/runnerclient"
	"github.com/lidofinance/tee-signer/governance/runnerchain"
	"github.com/lidofinance/tee-signer/governance/setupwire"
	"github.com/lidofinance/tee-signer/platform/setup"
	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/buildchain"
	"github.com/lidofinance/tee-signer/signer-protocol/remote"
	wireadmin "github.com/lidofinance/tee-signer/signer-protocol/wire/admin"
)

// chainSetup is the dev sample setup (setupForTest) on the chain with
// these genesis values, its stores in dir.
func chainSetup(t *testing.T, dir, caFile, fork, root string) []byte {
	t.Helper()
	s, err := setupwire.DecodeSetup(setupForTest(t, dir, caFile))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := hex.Decode(s.Chain.GenesisForkVersion[:], []byte(fork)); err != nil {
		t.Fatal(err)
	}
	if _, err := hex.Decode(s.Chain.GenesisValidatorsRoot[:], []byte(root)); err != nil {
		t.Fatal(err)
	}
	raw, err := s.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// TestE2ENonProdChains: each non-prod runner starts on its own chain only,
// from a setup file and from SIGNER_SETUP: the hoodi build on Hoodi with
// its exact genesis values, the devnet build on a devnet, the ci-test build
// on the ci-test chain. Each refuses mainnet (file and SIGNER_SETUP), the
// other builds' chains and a public network's fork version with another
// root, and the flag path. A started one reports its chain;
// attestation-verify/runnerclient refuses it unless allow_chain_build names that chain.
func TestE2ENonProdChains(t *testing.T) {
	if runnerchain.Build.Prod() {
		t.Fatal("run with -tags nonprod,chain_<name>")
	}
	dir := t.TempDir()
	caFile, cliCfg := testPKI(t, dir, "nonprod")
	devnetRoot := sha256.Sum256([]byte("a kurtosis devnet"))
	devnet := hex.EncodeToString(devnetRoot[:])
	const (
		hoodiRoot   = "212f13fc4df078b6cb7db228f1c8307566dcecf900867401a92023d7ba99cb5f"
		mainnetRoot = "4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95"
		ciTestRoot  = "535276eb9690335cc5e4cb926858a79ece25caaf930a7dfad44757c8b7bef420"
	)
	type tc struct {
		build            runnerchain.Chain
		name, fork, root string
		env              bool   // the setup in SIGNER_SETUP, not in a file
		want             string // "": starts
	}
	var cases []tc
	for _, b := range []runnerchain.Chain{runnerchain.Hoodi, runnerchain.Devnet, runnerchain.CITest} {
		refused := "a " + string(b) + " build runs on"
		own := map[runnerchain.Chain]tc{
			runnerchain.Hoodi:  {b, "hoodi", "10000910", hoodiRoot, false, refused},
			runnerchain.Devnet: {b, "kurtosis devnet", "10000038", devnet, false, refused},
			runnerchain.CITest: {b, "ci-test", "00000001", ciTestRoot, false, refused},
		}
		for c, x := range own {
			if c == b {
				x.want = ""
				cases = append(cases, x)
				x.name, x.env = x.name+" in SIGNER_SETUP", true
			}
			cases = append(cases, x)
		}
		cases = append(cases,
			tc{b, "mainnet", "00000000", mainnetRoot, false, "chain mainnet"},
			tc{b, "mainnet in SIGNER_SETUP", "00000000", mainnetRoot, true, "chain mainnet"},
			tc{b, "mainnet fork version, another root", "00000000", devnet, false, "a prod chain"},
			tc{b, "gnosis", "00000064", "f5dcb5564e829aab27264b9becd5dfaa017085611224cb3036f573368dbb9d47", false, "chain gnosis"},
		)
		if b != runnerchain.Hoodi {
			cases = append(cases, tc{b, "hoodi fork version, another root", "10000910", devnet, false, "hoodi has fork version 0x10000910"})
		}
	}
	for i, c := range cases {
		bin := runnerBinary(t, "dev-"+string(c.build))
		c.name = string(c.build) + " build, " + c.name
		cdir := filepath.Join(dir, fmt.Sprint(i))
		if err := os.MkdirAll(cdir, 0o700); err != nil {
			t.Fatal(err)
		}
		raw := chainSetup(t, cdir, caFile, c.fork, c.root)
		addr := fmt.Sprintf("tcp:127.0.0.1:%d", freePort(t))
		args := []string{"-platform", "dev", "-state-dir", filepath.Join(cdir, "state"), "-listen", addr}
		var env []string
		if c.env {
			args = append(args, "-setup", "platform")
			env = []string{setup.EnvVar + "=" + b64(raw)}
		} else {
			p := filepath.Join(cdir, "setup.bin")
			if err := os.WriteFile(p, raw, 0o600); err != nil {
				t.Fatal(err)
			}
			args = append(args, "-setup", "file:"+p)
		}
		cmd := runnerCmd(bin, args...)
		var out bytes.Buffer
		cmd.Stdout, cmd.Stderr, cmd.Env = &out, &out, append(os.Environ(), env...)
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		if c.want != "" {
			select {
			case err := <-done:
				if err == nil || !strings.Contains(out.String(), c.want) {
					t.Errorf("%s: exit %v, want a refusal with %q:\n%s", c.name, err, c.want, out.String())
				}
			case <-time.After(30 * time.Second):
				cmd.Process.Kill()
				<-done
				t.Errorf("%s: still running after 30 s, want a refusal", c.name)
			}
			continue
		}
		cl, err := newTLSClient(addr, cliCfg, remote.DevVerifier, remote.WithTimeout(5*time.Second))
		if err != nil {
			t.Fatal(err)
		}
		h := waitReady(t, cl)
		if runnerchain.FromVersion(h.Version) != c.build {
			t.Errorf("%s: HEALTH version %q", c.name, h.Version)
		}
		if !c.env {
			checkRunnerclientBuild(t, dir, addr, cliCfg, mustSetupHash(t, raw), c.build)
		}
		cl.Close()
		cmd.Process.Kill()
		<-done
		if !strings.Contains(out.String(), "0.1.0+"+string(c.build)) {
			t.Errorf("%s: the start log does not name the version:\n%s", c.name, out.String())
		}
	}

	// The flag path has no setup, so no chain to check.
	chainFile := newChain(t).path
	for _, b := range []runnerchain.Chain{runnerchain.Hoodi, runnerchain.Devnet, runnerchain.CITest} {
		cmd := runnerCmd(runnerBinary(t, "dev-"+string(b)), "-platform", "dev", "-state-dir", filepath.Join(dir, "flags-"+string(b)), "-listen",
			fmt.Sprintf("tcp:127.0.0.1:%d", freePort(t)), "-config", chainFile)
		out, err := cmd.CombinedOutput()
		if err == nil || !strings.Contains(string(out), "starts with a setup only") {
			t.Errorf("%s build, flag path: %v\n%s", b, err, out)
		}
	}
	t.Logf("non-prod runners: each started on its own chain (file and SIGNER_SETUP) and refused mainnet (file and SIGNER_SETUP), the other builds' chains, a public fork version with another root, Gnosis and the flag path")
}

// checkRunnerclientBuild connects to the non-prod runner at addr with
// attestation-verify/runnerclient: without allow_chain_build, with another chain's,
// and with its own.
func checkRunnerclientBuild(t *testing.T, dir, addr string, cliCfg *tls.Config, setupHash [32]byte, build runnerchain.Chain) {
	t.Helper()
	cert, key := writeClientPair(t, dir, cliCfg)
	conn := runnerclient.Connection{Address: addr, ClientCert: cert, ClientKey: key,
		Attestation: runnerclient.Attestation{Verifier: runnerclient.VerifierDev, SetupSHA256: hex.EncodeToString(setupHash[:])}}
	health := func() (*backend.Health, error) {
		cl, err := conn.New(runnerclient.WithTimeout(5 * time.Second))
		if err != nil {
			t.Fatal(err)
		}
		defer cl.Close()
		return cl.Health(ctx)
	}
	want := "the runner is a " + string(build) + " build"
	if _, err := health(); err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("runnerclient without allow_chain_build: %v", err)
	}
	other := runnerchain.Devnet
	if build == other {
		other = runnerchain.Hoodi
	}
	conn.AllowChainBuild = string(other)
	if _, err := health(); err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("runnerclient with allow_chain_build %s: %v", other, err)
	}
	conn.AllowChainBuild = string(build)
	h, err := health()
	if err != nil {
		t.Fatalf("runnerclient with allow_chain_build %s: %v", build, err)
	}
	t.Logf("runnerclient: refused the %s runner without allow_chain_build and with %s, took it with %s (version %s)", build, other, build, h.Version)
}

// TestE2ENonProdImagesUpdateWaits: a ci-test runner on the ci-test chain,
// with a setup that names no time lock, so the image default holds: 2
// minutes in a non-prod build, 48 hours in the mainnet build. An
// allowed-images update waits the images minimum instead, 7 minutes (7
// days in the mainnet build): that wait is what keeps a new image from
// being trusted the moment its update arrives. The update is sent at the
// start; it stays pending across a restart and past the time lock, and
// comes into force after its 7 minutes. attestation-verify/runnerclient refuses the
// runner without allow_chain_build and takes it with the setting.
func TestE2ENonProdImagesUpdateWaits(t *testing.T) {
	if runnerchain.Build.Prod() {
		t.Fatal("run with -tags nonprod,chain_<name>")
	}
	if setupwire.DefaultTimeLock != buildchain.ShortTimeLock || setupwire.ImagesMinTimeLock != buildchain.ShortImagesMinTimeLock {
		t.Fatal("this test binary does not have the non-prod constants")
	}
	c := newChain(t) // the ci-test chain: software.DevConfig's fork version and root
	dir := t.TempDir()
	caFile, cliCfg := testPKI(t, dir, "waits")
	var cluster [32]byte
	rand.Read(cluster[:])
	raw := devSetupFor(t, c, filepath.Join(dir, "signer-1"), caFile, "signer-1", cluster, nil)
	s, err := setupwire.DecodeSetup(raw)
	if err != nil {
		t.Fatal(err)
	}
	if s.Locked.ChangeDelaySeconds != nil {
		t.Fatal("the setup names a time lock")
	}
	setupFile := filepath.Join(dir, "signer-1.setup")
	if err := os.WriteFile(setupFile, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	addr := fmt.Sprintf("tcp:127.0.0.1:%d", freePort(t))
	p := startPeerAt(t, runnerBinary(t, "dev-ci-test"), "signer-1", filepath.Join(dir, "signer-1"), setupFile, addr)
	if h, err := p.cl.Health(ctx); err != nil || runnerchain.FromVersion(h.Version) != runnerchain.CITest {
		t.Fatalf("HEALTH: %v %+v, want the ci-test build", err, h)
	}
	checkRunnerclientBuild(t, dir, addr, cliCfg, mustSetupHash(t, raw), runnerchain.CITest)

	// The allowed-images update: the locked group gains a GCP image.
	timeLock, imagesMin := uint64(setupwire.DefaultTimeLock), uint64(setupwire.ImagesMinTimeLock)
	lh, _ := s.GroupHash(setupwire.GroupLocked)
	next := s.Locked
	img := make([]byte, 32)
	rand.Read(img)
	next.AllowedImageMeasurements = []setupwire.Image{{Kind: setupwire.ImageGCP, Measurement: img}}
	ub := &setupwire.UpdateBody{ClusterID: s.ClusterID, ChainHash: s.Chain.Hash(), Group: setupwire.GroupLocked, Version: 1,
		PrevHash: lh, ActivateAt: uint64(time.Now().Unix()), Locked: &next, Salts: e2eSalts(t, setupwire.NumLockedLeaves)}
	updHash, _ := ub.Hash()
	sent := time.Now()
	before := uint64(sent.Unix())
	outcome, st, err := sendConfigUpdate(t, addr, cliCfg, signConfigUpdate(t, ub, 1, 2))
	if err != nil || outcome != wireadmin.ConfigAccepted {
		t.Fatalf("allowed-images update: %d %v", outcome, err)
	}
	pend := st.Locked.Pending
	if pend.Version != 1 || pend.Hash != updHash || pend.EffectiveAt < before+imagesMin || pend.EffectiveAt > before+imagesMin+2 {
		t.Fatalf("update pending %+v, sent at %d, want effective %d s later", pend, before, imagesMin)
	}
	effective := pend.EffectiveAt
	t.Logf("sent the allowed-images update: effective in %d s (7 days in the mainnet build), past the setup's %d s time lock", effective-before, timeLock)

	// Still pending, with the same time, after a restart: the wait is in
	// the mark log, not in memory.
	p.restart(t)
	stillPending := func(when string) {
		t.Helper()
		st := devIdentity(t, p.cl).State.Locked
		if st.Version != 0 || st.Pending.Version != 1 || st.Pending.Hash != updHash || st.Pending.EffectiveAt != effective {
			t.Fatalf("locked group %+v %s, want version 0 with the update pending as sent (effective at %d)", st, when, effective)
		}
	}
	stillPending("after a restart")
	// Past the time lock the update still waits: the images minimum is
	// the longer wait.
	sleepUntil(t, before+timeLock+1)
	stillPending("past the time lock")
	sleepUntil(t, effective-5)
	stillPending("5 s before its time")
	deadline := time.Unix(int64(effective)+30, 0)
	for devIdentity(t, p.cl).State.Locked != (backend.ConfigGroup{Version: 1, Hash: updHash}) {
		if time.Now().After(deadline) {
			t.Fatal("the allowed-images update did not come into force")
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Logf("the allowed-images update came into force %v after sending (images minimum %d s), having waited past the %d s time lock and a restart",
		time.Since(sent).Round(time.Second), imagesMin, timeLock)
}

// sleepUntil waits until the Unix second at, logging the wait.
func sleepUntil(t *testing.T, at uint64) {
	t.Helper()
	d := time.Until(time.Unix(int64(at), 0))
	if d <= 0 {
		return
	}
	t.Logf("waiting %v", d.Round(time.Second))
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	<-ctx.Done()
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }
