package e2e

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/signer-core/core"
	"github.com/lidofinance/tee-signer/signer-core/threshold"
	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/tee-signer/charonlock"
)

// TestE2ECharonLock: the Charon path, offline. Three DKG runners make two
// keys, in two sessions, for a Charon cluster of 3 nodes, threshold 2. The ENRs come from
// stock `charon create enr`; the coordinator gets the deposits and builder
// registrations signed by the runners and every runner's signature over
// the lock hash it computes; each node adds its signature with its ENR key;
// then stock `charon run` v1.11.0 loads the lock on each node, with its
// verification on and an internal mock beacon node, and refuses a lock with
// one changed node signature.
//
// It needs Docker and the local image: CHARON_IMAGE=obolnetwork/charon:v1.11.0@sha256:...
// Its containers have no network (--network none), carry the test's own
// names and are removed by the test.
func TestE2ECharonLock(t *testing.T) {
	image := os.Getenv("CHARON_IMAGE")
	if image == "" {
		t.Skip("CHARON_IMAGE not set")
	}
	c := dkgChain(t)
	k := newDKGCluster(t, c)
	tag := make([]byte, 4)
	_, _ = rand.Read(tag)
	prefix := "c1-dkg-test-" + hex.EncodeToString(tag)

	// One ENR per node, made by stock charon on that node's folder.
	var enrs []string
	for i := range 3 {
		dir := filepath.Join(k.dir, fmt.Sprintf("node%d", i))
		if err := os.MkdirAll(dir, 0o777); err != nil {
			t.Fatal(err)
		}
		_ = os.Chmod(dir, 0o777)
		out, err := exec.Command("docker", "run", "--rm", "--network", "none", "--user", fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid()),
			"-v", dir+":/data", image, "create", "enr", "--data-dir", "/data").CombinedOutput()
		if err != nil {
			t.Fatalf("charon create enr: %v\n%s", err, out)
		}
		for _, line := range strings.Split(string(out), "\n") {
			if strings.HasPrefix(line, "enr:") {
				enrs = append(enrs, strings.TrimSpace(line))
			}
		}
	}
	if len(enrs) != 3 {
		t.Fatalf("got %d ENRs", len(enrs))
	}
	enrJSON, _ := json.Marshal(enrs)
	k.usePolicy(t, k.policy(`,"setup":{"path":"charon","withdrawal_address":"`+withdrawal+`","deposit_amounts_gwei":[32000000000],"charon_enrs":`+string(enrJSON)+`}`))
	// Two key generation sessions of one key each, in one lock: a lock may
	// hold several whole sessions (a session makes at most 64 keys).
	var results []string
	out := &dkgOutput{Threshold: 2}
	for s := 1; s <= 2; s++ {
		o := k.keygen(t, 1)
		p := filepath.Join(k.dir, fmt.Sprintf("result-%d.json", s))
		if err := os.Rename(filepath.Join(k.dir, "dkg-result.json"), p); err != nil {
			t.Fatal(err)
		}
		results = append(results, p)
		out.Validators = append(out.Validators, o.Validators...)
	}
	result := strings.Join(results, ",")
	checkKeys(t, k, out, 2)

	cluster := map[string]any{"name": "c1-tee-dkg", "fork_version": fmt.Sprintf("0x%x", hoodiFork[:]), "fee_recipient": feeHex(c),
		"gas_limit": 60_000_000, "registration_timestamp": hoodiGenesis}
	cb, _ := json.Marshal(cluster)
	clusterFile := filepath.Join(k.dir, "cluster.json")
	if err := os.WriteFile(clusterFile, cb, 0o600); err != nil {
		t.Fatal(err)
	}
	lockFile := filepath.Join(k.dir, "cluster-lock.json")
	if _, log, err := k.coord(t, "charon-lock", "-config", k.config, "-result", result,
		"-cluster", clusterFile, "-out", lockFile); err != nil {
		t.Fatalf("charon-lock: %v\n%s", err, log)
	}
	// A second lock is refused: every runner closed setup for these keys.
	if _, _, err := k.coord(t, "charon-lock", "-config", k.config, "-result", result,
		"-cluster", clusterFile, "-out", lockFile+".2"); err == nil {
		t.Fatal("a second lock after setup closed was signed")
	}

	// Each node signs with its ENR key, in its own folder.
	_, nodeSign := tools(t)
	for i := range 3 {
		cmd := exec.Command(nodeSign, "-lock", lockFile, "-key", filepath.Join(k.dir, fmt.Sprintf("node%d", i), "charon-enr-private-key"))
		msg, err := cmd.CombinedOutput()
		t.Logf("charon-node-sign node%d: %s", i, strings.TrimSpace(string(msg)))
		if err != nil {
			t.Fatal(err)
		}
	}
	if msg, err := exec.Command(nodeSign, "-lock", lockFile, "-verify").CombinedOutput(); err != nil {
		t.Fatalf("verify: %v\n%s", err, msg)
	} else {
		t.Logf("charon-node-sign -verify: %s", strings.TrimSpace(string(msg)))
	}
	// The lock's deposits, checked offline as before sending them.
	checked := filepath.Join(k.dir, "deposit-data.json")
	if _, log, err := k.coord(t, "check-deposits", "-config", k.config, "-policy", filepath.Join(k.dir, "policy.json"), "-result", result,
		"-lock", lockFile, "-fork-version", fmt.Sprintf("%x", hoodiFork[:]), "-out", checked); err != nil {
		t.Fatalf("check-deposits -lock: %v\n%s", err, log)
	}
	var deps []struct {
		Pubkey string `json:"pubkey"`
		Amount uint64 `json:"amount"`
	}
	if b, _ := os.ReadFile(checked); json.Unmarshal(b, &deps) != nil || len(deps) != 2 || deps[0].Amount != 32_000_000_000 {
		t.Fatalf("checked deposits of the lock: %+v", deps)
	}
	t.Log("check-deposits -lock: the lock's 2 deposits pass (Charon's checks, the result's keys, the policy's credentials, 32 ETH)")
	raw, _ := os.ReadFile(lockFile)
	l, err := charonlock.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if l.Definition.Threshold != 2 || len(l.Definition.Operators) != 3 || len(l.Validators) != 2 {
		t.Fatal("lock shape")
	}
	for v, val := range out.Validators {
		for i, s := range val.PublicShares {
			if "0x"+hex.EncodeToString(l.Validators[v].PubShares[i]) != s {
				t.Fatalf("validator %d share %d is not at its position", v, i+1)
			}
		}
	}

	// Signer shim settings for each node.
	shims := filepath.Join(k.dir, "shims")
	if _, log, err := k.coord(t, "charon-shims", "-config", k.config, "-result", result,
		"-chain", c.path, "-out-dir", shims); err != nil {
		t.Fatalf("charon-shims: %v\n%s", err, log)
	}
	for i := range 3 {
		var cloud struct {
			Address  string `json:"address"`
			Accounts string `json:"accounts"`
		}
		b, _ := os.ReadFile(filepath.Join(shims, fmt.Sprintf("node%d", i), "cloud.json"))
		if err := json.Unmarshal(b, &cloud); err != nil || cloud.Address != k.addrs[i] {
			t.Fatalf("node%d cloud.json: %v %s", i, err, b)
		}
		for _, f := range []string{"shim.yml", "accounts.json"} {
			if _, err := os.Stat(filepath.Join(shims, fmt.Sprintf("node%d", i), f)); err != nil {
				t.Fatal(err)
			}
		}
	}
	t.Log("signer shim settings written: node<i>/shim.yml, cloud.json (runner i+1, the policy's attestation settings), accounts.json (its share key)")
	if shimBin := os.Getenv("SHIM_BIN"); shimBin != "" {
		shimSigns(t, k, c, out, shims, shimBin)
	} else {
		t.Log("SHIM_BIN not set: the shims were not started")
	}

	// Stock charon run on each node, verification on.
	runCharon := func(name, dir string) *exec.Cmd {
		args := []string{"run", "--rm", "--name", name, "--network", "none", "--user", fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid()),
			"-v", dir + ":/data", image, "run", "--lock-file", "/data/cluster-lock.json",
			"--private-key-file", "/data/charon-enr-private-key", "--simnet-beacon-mock", "--p2p-relays", "",
			"--validator-api-address", "0.0.0.0:3600", "--monitoring-address", "0.0.0.0:3620", "--log-format", "console"}
		return exec.Command("docker", args...)
	}
	t.Cleanup(func() {
		for i := range 4 {
			_ = exec.Command("docker", "rm", "-f", fmt.Sprintf("%s-node%d", prefix, i)).Run()
		}
	})
	type started struct {
		cmd *exec.Cmd
		out *bytes.Buffer
	}
	var nodes []started
	for i := range 3 {
		dir := filepath.Join(k.dir, fmt.Sprintf("node%d", i))
		if err := os.WriteFile(filepath.Join(dir, "cluster-lock.json"), raw, 0o644); err != nil {
			t.Fatal(err)
		}
		cmd := runCharon(fmt.Sprintf("%s-node%d", prefix, i), dir)
		var buf bytes.Buffer
		cmd.Stdout, cmd.Stderr = &buf, &buf
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		nodes = append(nodes, started{cmd, &buf})
	}
	time.Sleep(20 * time.Second)
	for i, n := range nodes {
		alive := exec.Command("docker", "inspect", "-f", "{{.State.Running}}", fmt.Sprintf("%s-node%d", prefix, i))
		state, _ := alive.Output()
		_ = exec.Command("docker", "stop", "-t", "5", fmt.Sprintf("%s-node%d", prefix, i)).Run()
		_ = n.cmd.Wait()
		log := n.out.String()
		if strings.TrimSpace(string(state)) != "true" || charonMarkers(log) == "" {
			t.Fatalf("charon run on node%d: running=%s\n%s", i, state, tail(log, 40))
		}
		t.Logf("charon run node%d, lock verification on: still running after 20 s; log lines: %s", i, charonMarkers(log))
	}

	// One changed node signature: charon run refuses the lock.
	bad := filepath.Join(k.dir, "node3")
	_ = os.MkdirAll(bad, 0o777)
	_ = os.Chmod(bad, 0o777)
	l.NodeSignatures[1][10] ^= 1
	badRaw, _ := l.Marshal()
	if err := os.WriteFile(filepath.Join(bad, "cluster-lock.json"), badRaw, 0o644); err != nil {
		t.Fatal(err)
	}
	key0, _ := os.ReadFile(filepath.Join(k.dir, "node0", "charon-enr-private-key"))
	if err := os.WriteFile(filepath.Join(bad, "charon-enr-private-key"), key0, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := runCharon(prefix+"-node3", bad)
	done := make(chan []byte, 1)
	go func() { b, _ := cmd.CombinedOutput(); done <- b }()
	select {
	case b := <-done:
		line := firstMatch(string(b), " erro ", " fatal", " crit ", "error:")
		if strings.Contains(string(b), "Lock file loaded") || line == "" {
			t.Fatalf("charon run on a lock with a changed node signature:\n%s", tail(string(b), 20))
		}
		t.Logf("charon run refuses a lock with one changed node signature and exits: %s", line)
	case <-time.After(60 * time.Second):
		t.Fatal("charon run kept running on a lock with a changed node signature")
	}
}

func tail(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

func firstMatch(s string, subs ...string) string {
	for _, line := range strings.Split(s, "\n") {
		for _, sub := range subs {
			if strings.Contains(strings.ToLower(line), sub) {
				return strings.TrimSpace(line)
			}
		}
	}
	return ""
}

// charonMarkers picks the line that shows Charon loaded the lock, which it
// logs after its hash and signature checks.
func charonMarkers(log string) string {
	var out []string
	for _, line := range strings.Split(log, "\n") {
		if strings.Contains(line, "Lock file loaded") {
			out = append(out, strings.TrimSpace(line))
		}
	}
	return strings.Join(out, " | ")
}

// shimSigns starts the signer shims of nodes 0 and 2 (threshold-signer-poc
// gateway/cmd/signer-shim built with -tags shim,dirkfork,cloudremote) from
// the settings charon-shims wrote: each lists its node's share keys, signs
// an attestation as a validator client asks it to (Web3Signer API), and the
// two partial signatures combine to a signature under the validator key.
func shimSigns(t *testing.T, k *dkgCluster, c chain, out *dkgOutput, shims, shimBin string) {
	t.Helper()
	e := c.stableEpoch(t) + 4
	c.waitEpoch(t, e)
	data := att(e-1, e, 0xc1)
	root, _ := c.cfg.SigningRoot(data)
	gk := pubkeyHex(t, out.Validators[0].Pubkey)
	g := fmt.Sprintf("0x%x", c.cfg.GenesisForkVersion[:])
	body := map[string]any{
		"type": "ATTESTATION",
		"fork_info": map[string]any{
			"fork":                    map[string]string{"previous_version": g, "current_version": g, "epoch": "0"},
			"genesis_validators_root": fmt.Sprintf("0x%x", c.cfg.GenesisValidatorsRoot[:]),
		},
		"attestation": map[string]any{
			"slot": fmt.Sprint(data.Slot), "index": "0", "beacon_block_root": fmt.Sprintf("0x%x", data.BeaconBlockRoot[:]),
			"source": map[string]string{"epoch": fmt.Sprint(data.Source.Epoch), "root": fmt.Sprintf("0x%x", data.Source.Root[:])},
			"target": map[string]string{"epoch": fmt.Sprint(data.Target.Epoch), "root": fmt.Sprintf("0x%x", data.Target.Root[:])},
		},
	}
	var ids []uint64
	var sigs []backend.Signature
	for _, i := range []int{0, 2} {
		dir := filepath.Join(shims, fmt.Sprintf("node%d", i))
		for _, f := range []string{"client.pem", "client-key.pem"} {
			b, _ := os.ReadFile(filepath.Join(k.dir, f))
			if err := os.WriteFile(filepath.Join(dir, f), b, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		port := freePort(t)
		yml, _ := os.ReadFile(filepath.Join(dir, "shim.yml"))
		yml = []byte(strings.Replace(string(yml), "listen: 127.0.0.1:29220", fmt.Sprintf("listen: 127.0.0.1:%d", port), 1))
		if err := os.WriteFile(filepath.Join(dir, "shim.yml"), yml, 0o600); err != nil {
			t.Fatal(err)
		}
		logf, _ := os.Create(filepath.Join(dir, "shim.log"))
		cmd := exec.Command(shimBin, "-config", filepath.Join(dir, "shim.yml"))
		cmd.Stdout, cmd.Stderr = logf, logf
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait(); logf.Close() })
		addr := fmt.Sprintf("http://127.0.0.1:%d", port)
		var keys []string
		for deadline := time.Now().Add(20 * time.Second); time.Now().Before(deadline); time.Sleep(200 * time.Millisecond) {
			if resp, err := http.Get(addr + "/api/v1/eth2/publicKeys"); err == nil {
				_ = json.NewDecoder(resp.Body).Decode(&keys)
				resp.Body.Close()
				if len(keys) > 0 {
					break
				}
			}
		}
		want := map[string]bool{out.Validators[0].PublicShares[i]: true, out.Validators[1].PublicShares[i]: true}
		if len(keys) != 2 || !want[keys[0]] || !want[keys[1]] {
			lg, _ := os.ReadFile(filepath.Join(dir, "shim.log"))
			t.Fatalf("node%d shim lists %v, want its two share keys\n%s", i, keys, lg)
		}
		raw, _ := json.Marshal(body)
		req, _ := http.NewRequest(http.MethodPost, addr+"/api/v1/eth2/sign/"+out.Validators[0].PublicShares[i], bytes.NewReader(raw))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		var sr struct {
			Signature string `json:"signature"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&sr)
		resp.Body.Close()
		sb, _ := hex.DecodeString(strings.TrimPrefix(sr.Signature, "0x"))
		var sig backend.Signature
		copy(sig[:], sb)
		if resp.StatusCode != http.StatusOK || !core.Verify(pubkeyHex(t, out.Validators[0].PublicShares[i]), root, sig) {
			t.Fatalf("node%d shim sign: status %d, signature does not verify under the share key", i, resp.StatusCode)
		}
		ids, sigs = append(ids, uint64(i+1)), append(sigs, sig)
	}
	full, err := threshold.RecoverSignature(ids, sigs)
	if err != nil || !core.Verify(gk, root, full) {
		t.Fatal("the two shims' partial signatures do not combine under the validator key")
	}
	t.Logf("signer shims (cloudremote) of nodes 0 and 2: each lists its node's 2 share keys; epoch %d attestation signed through each, partials combine under the validator key", e)
}
