//go:build testnet

package e2e

// The testnet build (backend/buildflavor) on dev runners. Run these tests on
// their own and with the tag, as make testnet-test does:
//
//	go test -tags testnet -timeout 20m -run TestE2ETestnet -v ./e2e
//
// The tag makes this test binary's setupwire constants the testnet
// build's too, so the waits below are the ones the runners use. Nothing
// fakes a clock: the runners read the host's.

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
	"github.com/lidofinance/tee-signer/governance/flavor"
	"github.com/lidofinance/tee-signer/governance/setupwire"
	"github.com/lidofinance/tee-signer/platform/setup"
	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/buildflavor"
	"github.com/lidofinance/tee-signer/signer-protocol/remote"
	wireadmin "github.com/lidofinance/tee-signer/signer-protocol/wire/admin"
)

// testnetChainSetup is the dev sample setup (setupForTest) on the chain
// with these genesis values, its stores in dir.
func testnetChainSetup(t *testing.T, dir, caFile, fork, root string) []byte {
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

// TestE2ETestnetChains: a testnet runner starts on a devnet and on Hoodi,
// Sepolia and Chiado with their exact genesis values, from a setup file and
// from SIGNER_SETUP. It refuses mainnet, Gnosis, Holesky and LUKSO, Hoodi's
// fork version with another root, and the flag path. A started one reports
// its flavour; attest/runnerclient refuses it unless allow_testnet_build.
func TestE2ETestnetChains(t *testing.T) {
	if flavor.Build != flavor.Testnet {
		t.Fatal("run with -tags testnet")
	}
	dir := t.TempDir()
	caFile, cliCfg := testPKI(t, dir, "testnet")
	devnetRoot := sha256.Sum256([]byte("a kurtosis devnet"))
	devnet := hex.EncodeToString(devnetRoot[:])
	cases := []struct {
		name, fork, root string
		env              bool   // the setup in SIGNER_SETUP, not in a file
		want             string // "": starts
	}{
		{"kurtosis devnet", "10000038", devnet, false, ""},
		{"hoodi", "10000910", "212f13fc4df078b6cb7db228f1c8307566dcecf900867401a92023d7ba99cb5f", false, ""},
		{"hoodi in SIGNER_SETUP", "10000910", "212f13fc4df078b6cb7db228f1c8307566dcecf900867401a92023d7ba99cb5f", true, ""},
		{"sepolia", "90000069", "d8ea171f3c94aea21ebc42a1ed61052acf3f9209c00e4efbaaddac09ed9b8078", false, ""},
		{"chiado", "0000006f", "9d642dac73058fbf39c0ae41ab1e34e4d889043cb199851ded7095bc99eb4c1e", false, ""},
		{"hoodi fork version, another root", "10000910", devnet, false, "hoodi has fork version 0x10000910"},
		{"mainnet", "00000000", "4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95", false, "chain mainnet"},
		{"mainnet in SIGNER_SETUP", "00000000", "4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95", true, "chain mainnet"},
		{"gnosis", "00000064", "f5dcb5564e829aab27264b9becd5dfaa017085611224cb3036f573368dbb9d47", false, "chain gnosis"},
		{"holesky", "01017000", "9143aa7c615a7f7115e2b6aac319c03529df8242ae705fba9df39b79c59fa8b1", false, "chain holesky"},
		{"lukso", "42000001", "a27edd68cde5c396f499157945d062a010308ce5ed5719a6b1e12ad2a51b97e6", false, "chain lukso"},
	}
	bin := runnerBinary(t, "dev-testnet")
	for i, c := range cases {
		cdir := filepath.Join(dir, fmt.Sprint(i))
		if err := os.MkdirAll(cdir, 0o700); err != nil {
			t.Fatal(err)
		}
		raw := testnetChainSetup(t, cdir, caFile, c.fork, c.root)
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
		if flavor.FromVersion(h.Version) != flavor.Testnet {
			t.Errorf("%s: HEALTH version %q", c.name, h.Version)
		}
		if c.name == "hoodi" {
			checkRunnerclientFlavor(t, dir, addr, cliCfg, mustSetupHash(t, raw))
		}
		cl.Close()
		cmd.Process.Kill()
		<-done
		if !strings.Contains(out.String(), "0.1.0+testnet") {
			t.Errorf("%s: the start log does not name the version:\n%s", c.name, out.String())
		}
	}

	// The flag path has no setup, so no chain to check.
	chainFile := newChain(t).path
	cmd := runnerCmd(bin, "-platform", "dev", "-state-dir", filepath.Join(dir, "flags"), "-listen",
		fmt.Sprintf("tcp:127.0.0.1:%d", freePort(t)), "-config", chainFile)
	out, err := cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(out), "starts with a setup only") {
		t.Errorf("flag path: %v\n%s", err, out)
	}
	t.Logf("testnet runner: started on a devnet, Hoodi (file and SIGNER_SETUP), Sepolia and Chiado; refused Hoodi's fork version with another root, mainnet (file and SIGNER_SETUP), Gnosis, Holesky, LUKSO and the flag path")
}

// checkRunnerclientFlavor connects to the testnet runner at addr with
// attest/runnerclient, without and with allow_testnet_build.
func checkRunnerclientFlavor(t *testing.T, dir, addr string, cliCfg *tls.Config, setupHash [32]byte) {
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
	if _, err := health(); err == nil || !strings.Contains(err.Error(), "the runner is a testnet build") {
		t.Fatalf("runnerclient without allow_testnet_build: %v", err)
	}
	conn.AllowTestnetBuild = true
	h, err := health()
	if err != nil {
		t.Fatalf("runnerclient with allow_testnet_build: %v", err)
	}
	t.Logf("runnerclient: refused the testnet runner without allow_testnet_build, took it with the setting (version %s)", h.Version)
}

// TestE2ETestnetImagesUpdateWaits: a testnet runner on a devnet, with a
// setup that names no time lock, so the image default holds: 2 minutes in
// a testnet build, 48 hours in the default build. An allowed-images update
// waits the images minimum instead, 7 minutes (7 days in the default
// build): that wait is what keeps a new image from being trusted the
// moment its update arrives. The update is sent at the start; it stays
// pending across a restart and past the time lock, and comes into force
// after its 7 minutes. attest/runnerclient refuses the runner without
// allow_testnet_build and takes it with the setting.
func TestE2ETestnetImagesUpdateWaits(t *testing.T) {
	if flavor.Build != flavor.Testnet {
		t.Fatal("run with -tags testnet")
	}
	if setupwire.DefaultTimeLock != buildflavor.TestnetFlavorTimeLock || setupwire.ImagesMinTimeLock != buildflavor.TestnetFlavorImagesMinTimeLock {
		t.Fatal("this test binary does not have the testnet constants")
	}
	c := newChain(t) // a devnet: software.DevConfig's fork version and root
	dir := t.TempDir()
	caFile, cliCfg := testPKI(t, dir, "waits")
	var cluster [32]byte
	rand.Read(cluster[:])
	raw := orderSetupFor(t, c, filepath.Join(dir, "signer-1"), caFile, "signer-1", cluster, nil)
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
	p := startPeerAt(t, runnerBinary(t, "dev-testnet"), "signer-1", filepath.Join(dir, "signer-1"), setupFile, addr)
	if h, err := p.cl.Health(ctx); err != nil || flavor.FromVersion(h.Version) != flavor.Testnet {
		t.Fatalf("HEALTH: %v %+v, want the testnet flavour", err, h)
	}
	checkRunnerclientFlavor(t, dir, addr, cliCfg, mustSetupHash(t, raw))

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
	t.Logf("sent the allowed-images update: effective in %d s (7 days in the default build), past the setup's %d s time lock", effective-before, timeLock)

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
