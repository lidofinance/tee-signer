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
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/attestation-verify/runnerclient"
	"github.com/lidofinance/tee-signer/governance/dkgorder"
	"github.com/lidofinance/tee-signer/governance/flavor"
	"github.com/lidofinance/tee-signer/governance/setupwire"
	"github.com/lidofinance/tee-signer/platform/setup"
	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/buildflavor"
	"github.com/lidofinance/tee-signer/signer-protocol/dkgmsg"
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

// TestE2ETestnetWaits: three testnet key generation runners on a devnet,
// with setups that name no time lock, so the image default holds: 2
// minutes in a testnet build, 48 hours in the default build. An
// allowed-images update waits the images minimum, 7 minutes (7 days in the
// default build); a DKG order on the dev platform waits the time lock, 2
// minutes (48 hours; on a cloud the images minimum, 7 days). Both are sent
// at the start; the order acts and makes a key after its 2 minutes, while
// the update is still pending; the update comes into force after its 7.
func TestE2ETestnetWaits(t *testing.T) {
	if flavor.Build != flavor.Testnet {
		t.Fatal("run with -tags testnet")
	}
	if setupwire.DefaultTimeLock != buildflavor.TestnetFlavorTimeLock || setupwire.ImagesMinTimeLock != buildflavor.TestnetFlavorImagesMinTimeLock {
		t.Fatal("this test binary does not have the testnet constants")
	}
	c := newChain(t) // a devnet: software.DevConfig's fork version and root
	k := newOrderClusterWith(t, c, orderOpts{bin: "dev-testnet-dkg", testnet: true})
	for i, cl := range k.clients {
		h, err := cl.Health(ctx)
		if err != nil || flavor.FromVersion(h.Version) != flavor.Testnet {
			t.Fatalf("runner %d HEALTH: %v %+v", i+1, err, h)
		}
	}
	// The coordinator, through attest/runnerclient, refuses these runners
	// without allow_testnet_build.
	conns := make([]coordConn, len(k.conns))
	copy(conns, k.conns)
	for i := range conns {
		conns[i].AllowTestnet = false
		conns[i].Attestation = json.RawMessage(fmt.Sprintf(`{"verifier":"dev","setup_sha256":"%s"}`, hex.EncodeToString(k.setupHashes[i][:])))
	}
	pre := filepath.Join(k.dir, "operator-keys-no-allow.json")
	b, _ := json.Marshal(map[string]any{"runners": conns})
	if err := os.WriteFile(pre, b, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, log, err := k.coord(t, "operator-keys", "-config", pre); err == nil || !strings.Contains(log, "the runner is a testnet build") {
		t.Fatalf("operator-keys without allow_testnet_build: %v\n%s", err, log)
	}

	raw, _ := os.ReadFile(k.setups[0])
	s, err := setupwire.DecodeSetup(raw)
	if err != nil {
		t.Fatal(err)
	}
	if s.Locked.ChangeDelaySeconds != nil {
		t.Fatal("the setups name a time lock")
	}
	timeLock, imagesMin := uint64(setupwire.DefaultTimeLock), uint64(setupwire.ImagesMinTimeLock)

	// The allowed-images update: the locked group gains a GCP image.
	lh, _ := s.GroupHash(setupwire.GroupLocked)
	next := s.Locked
	img := make([]byte, 32)
	_, _ = rand.Read(img)
	next.AllowedImageMeasurements = []setupwire.Image{{Kind: setupwire.ImageGCP, Measurement: img}}
	ub := &setupwire.UpdateBody{ClusterID: s.ClusterID, ChainHash: s.Chain.Hash(), Group: setupwire.GroupLocked, Version: 1,
		PrevHash: lh, ActivateAt: uint64(time.Now().Unix()), Locked: &next, Salts: e2eSalts(t, setupwire.NumLockedLeaves)}
	updHash, _ := ub.Hash()
	signedUpdate := signConfigUpdate(t, ub, 1, 2)
	// The DKG order of the Dirk lane.
	body := k.orderBody(t, "testnet-waits", dkgorder.PathDirk, nil)
	signedOrder := signOrderBody(t, body, 1, 3)
	enc, _ := body.Encode()
	orderHash := dkgorder.Hash(enc)

	sent := time.Now()
	var effective, actAt uint64
	for i, addr := range k.addrs {
		before := uint64(time.Now().Unix())
		outcome, st, err := sendConfigUpdate(t, addr, k.cliCfg, signedUpdate)
		if err != nil || outcome != wireadmin.ConfigAccepted {
			t.Fatalf("runner %d: allowed-images update: %d %v", i+1, outcome, err)
		}
		p := st.Locked.Pending
		if p.Version != 1 || p.Hash != updHash || p.EffectiveAt < before+imagesMin || p.EffectiveAt > before+imagesMin+2 {
			t.Fatalf("runner %d: update pending %+v, sent at %d, want effective %d s later", i+1, p, before, imagesMin)
		}
		effective = max(effective, p.EffectiveAt)
		before = uint64(time.Now().Unix())
		ost, err := adminOf(k.clients[i]).DKGOrder(ctx, signedOrder)
		if err != nil || ost.Status != dkgmsg.OrderPending || ost.ActAt < before+timeLock || ost.ActAt > before+timeLock+2 {
			t.Fatalf("runner %d: order %+v %v, sent at %d, want it to act %d s later", i+1, ost, err, before, timeLock)
		}
		actAt = max(actAt, ost.ActAt)
	}
	t.Logf("sent the allowed-images update (effective in %d s; 7 days in the default build) and the DKG order (acts in %d s; 48 h in the default build) to 3 runners",
		effective-uint64(sent.Unix()), actAt-uint64(sent.Unix()))

	// Before its time the order makes nothing.
	_, err = adminOf(k.clients[0]).InOrder(orderHash).DKGHello(ctx, &dkgmsg.HelloRequest{Nonce: bytes.Repeat([]byte{1}, 32), Count: 1})
	if r := wantRefused(t, err, backend.StatusNotReady); !strings.Contains(r.Detail, "waits until") {
		t.Fatalf("hello while the order waits: %v", r)
	}
	sleepUntil(t, actAt+1)
	cfg := k.useOrder(t, "testnet-waits", signedOrder)
	out := k.keygenWith(t, cfg, 1, filepath.Join(k.dir, "testnet-result.json"))
	if len(out.Validators) != 1 {
		t.Fatalf("keygen: %+v", out)
	}
	orderDone := time.Since(sent)
	// The update is still pending: its wait is longer.
	for i, cl := range k.clients {
		st := devIdentity(t, cl).State.Locked
		if st.Version != 0 || st.Pending.Version != 1 {
			t.Fatalf("runner %d: locked group %+v %v after sending, want the update still pending", i+1, st, time.Since(sent))
		}
	}
	t.Logf("the order acted: 1 key made %v after sending; the allowed-images update still pending", orderDone.Round(time.Second))

	sleepUntil(t, effective-5)
	for i, cl := range k.clients {
		if st := devIdentity(t, cl).State.Locked; st.Version != 0 {
			t.Fatalf("runner %d: locked version %d 5 s before the update's time", i+1, st.Version)
		}
	}
	deadline := time.Unix(int64(effective)+30, 0)
	for i, cl := range k.clients {
		for devIdentity(t, cl).State.Locked != (backend.ConfigGroup{Version: 1, Hash: updHash}) {
			if time.Now().After(deadline) {
				t.Fatalf("runner %d: the allowed-images update did not come into force", i+1)
			}
			time.Sleep(500 * time.Millisecond)
		}
	}
	t.Logf("the allowed-images update came into force on 3 runners %v after sending (images minimum %d s)",
		time.Since(sent).Round(time.Second), imagesMin)
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
