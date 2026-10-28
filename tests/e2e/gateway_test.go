package e2e

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/signer-core/core"
	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/remote"
)

// TestE2EGateway: a validator client's Web3Signer requests through the
// gateway (gateway/cmd/gateway) to three dev runners over mutual TLS.
// Each runner holds one share of a 2-of-3 key. The gateway checks each
// runner's attestation on every new connection, sends each request to all
// three, checks the partial signatures, combines two and returns the
// validator signature. The test checks every signature under the
// validator key against the signing root the signer core computes. The
// signers are listed in another order than their share indices, so the
// gateway must find the indices from the share keys.
func TestE2EGateway(t *testing.T) {
	c := newChain(t)
	dir := t.TempDir()
	roles := rolePKI(t, dir, "gw", 24*time.Hour, 24*time.Hour)
	certFile, keyFile := writeSigningPair(t, dir, roles.signing)

	sk, _ := core.NewSecret()
	pk, _ := core.PubkeyOf(sk)
	shares, err := core.Split(sk, 2, 3)
	if err != nil {
		t.Fatal(err)
	}
	const index = 9 // the validator index the shares are bound to
	e0 := c.stableEpoch(t)
	var runners []*runner
	var addrs []string
	for i := range shares {
		addr := fmt.Sprintf("tcp:127.0.0.1:%d", freePort(t))
		r := newRunnerArgs(t, fmt.Sprintf("gw-runner-%d", i+1), c, addr, "-tls-client-ca", roles.caFile)
		r.start()
		cl, err := newTLSClient(addr, roles.signing, remote.DevVerifier, remote.WithTimeout(10*time.Second))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { cl.Close() })
		waitReady(t, cl)
		sp, _ := core.PubkeyOf(shares[i].Secret)
		if _, err := adminOf(cl).ImportShareSealed(ctx, backend.ImportShareRequest{Pubkey: pk, Secret: shares[i].Secret, Index: index},
			sp, remote.DevVerifier); err != nil {
			t.Fatalf("import share %d: %v", i+1, err)
		}
		runners, addrs = append(runners, r), append(addrs, addr)
	}
	t.Logf("3 dev runners with mutual TLS, shares 1 to 3 of a 2-of-3 key imported sealed")

	// The gateway lists the signers as 3, 1, 2.
	order := []int{2, 0, 1}
	var nodes strings.Builder
	for _, i := range order {
		fmt.Fprintf(&nodes, "    - {name: gw-runner-%d, address: %q, attestation: {verifier: dev}}\n", i+1, addrs[i])
	}
	listen := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	cfg := fmt.Sprintf(`listen: %s
chain:
  preset: mainnet
  slots_per_epoch: %d
  genesis_fork_version: "%#x"
  genesis_validators_root: "%#x"
signers:
  client_cert: %s
  client_key: %s
  timeout: 5s
  nodes:
%spolicy:
  fee_recipient_allowlist: ["0x1111111111111111111111111111111111111111"]
`, listen, slotsPerEpoch, c.cfg.GenesisForkVersion[:], c.cfg.GenesisValidatorsRoot[:], certFile, keyFile, nodes.String())
	gw := startGateway(t, dir, cfg, listen)
	url := "http://" + listen

	var keys []string
	getJSON(t, url+"/api/v1/eth2/publicKeys", &keys)
	if len(keys) != 1 || keys[0] != fmt.Sprintf("%#x", pk[:]) {
		t.Fatalf("public keys %v", keys)
	}
	if n := strings.Count(gw.logText(), "signer attested"); n < 3 {
		t.Fatalf("%d attested connections at start, want 3:\n%s", n, gw.logText())
	}

	forkInfo := fmt.Sprintf(`"fork_info":{"fork":{"previous_version":"%#x","current_version":"%#x","epoch":"0"},"genesis_validators_root":"%#x"}`,
		c.cfg.GenesisForkVersion[:], c.cfg.GenesisForkVersion[:], c.cfg.GenesisValidatorsRoot[:])
	sign := func(body string) (int, backend.Signature, string) {
		t.Helper()
		code, out := postJSON(t, url+"/api/v1/eth2/sign/"+fmt.Sprintf("%#x", pk[:]), body)
		var sig backend.Signature
		if code == http.StatusOK {
			var reply struct {
				Signature string `json:"signature"`
			}
			if err := json.Unmarshal([]byte(out), &reply); err != nil {
				t.Fatalf("reply %q: %v", out, err)
			}
			if err := sig.UnmarshalText([]byte(reply.Signature)); err != nil {
				t.Fatalf("signature %q: %v", reply.Signature, err)
			}
		}
		return code, sig, out
	}
	mustSign := func(what, body string, m backend.Message) backend.Signature {
		t.Helper()
		code, sig, out := sign(body)
		if code != http.StatusOK {
			t.Fatalf("%s: %d %s\n%s", what, code, out, gw.logText())
		}
		root, err := c.cfg.SigningRoot(m)
		if err != nil {
			t.Fatal(err)
		}
		if !core.Verify(pk, root, sig) {
			t.Fatalf("%s: the gateway's signature does not verify under the validator key", what)
		}
		return sig
	}
	attBody := func(a *backend.AttestationData) string {
		return fmt.Sprintf(`{"type":"ATTESTATION",%s,"attestation":{"slot":"%d","index":"%d","beacon_block_root":"%#x",`+
			`"source":{"epoch":"%d","root":"%#x"},"target":{"epoch":"%d","root":"%#x"}}}`, forkInfo, a.Slot, a.Index,
			a.BeaconBlockRoot[:], a.Source.Epoch, a.Source.Root[:], a.Target.Epoch, a.Target.Root[:])
	}

	e1 := e0 + 4
	c.waitEpoch(t, e1)
	data := att(e1-1, e1, 0xa1)
	attSig := mustSign("attestation", attBody(data), data)
	t.Logf("epoch %d: ATTESTATION through the gateway: 2-of-3 signature verifies under the validator key", e1)

	blk := &backend.BeaconBlockHeader{Slot: e1*slotsPerEpoch + 1, ProposerIndex: index, ParentRoot: backend.Root{0xb1},
		StateRoot: backend.Root{0xb2}, BodyRoot: backend.Root{0xb3}}
	mustSign("block", fmt.Sprintf(`{"type":"BLOCK_V2",%s,"beacon_block":{"version":"BELLATRIX","block_header":{"slot":"%d",`+
		`"proposer_index":"%d","parent_root":"%#x","state_root":"%#x","body_root":"%#x"}}}`, forkInfo, blk.Slot, blk.ProposerIndex,
		blk.ParentRoot[:], blk.StateRoot[:], blk.BodyRoot[:]), blk)
	t.Logf("BLOCK_V2 (header) through the gateway: signature verifies")

	// An aggregator: the selection proof, then the aggregate with it.
	slot := e1 * slotsPerEpoch
	proof := mustSign("selection proof", fmt.Sprintf(`{"type":"AGGREGATION_SLOT",%s,"aggregation_slot":{"slot":"%d"}}`, forkInfo, slot),
		&backend.SelectionProof{Slot: slot})
	aggBody := func(proof backend.Signature) string {
		return fmt.Sprintf(`{"type":"AGGREGATE_AND_PROOF",%s,"aggregate_and_proof":{"aggregator_index":"%d","aggregate":`+
			`{"aggregation_bits":"0x03","data":{"slot":"%d","index":"0","beacon_block_root":"%#x","source":{"epoch":"%d","root":"%#x"},`+
			`"target":{"epoch":"%d","root":"%#x"}},"signature":"%#x"},"selection_proof":"%#x"}}`, forkInfo, index, data.Slot,
			data.BeaconBlockRoot[:], data.Source.Epoch, data.Source.Root[:], data.Target.Epoch, data.Target.Root[:], attSig[:], proof[:])
	}
	mustSign("aggregate", aggBody(proof), &backend.AggregateAndProof{Form: backend.AggregatePhase0,
		SSZ: phase0AggregateSSZ(index, proof, []byte{0x03}, data, attSig)})
	t.Logf("AGGREGATION_SLOT and AGGREGATE_AND_PROOF through the gateway: signatures verify")
	if code, _, out := sign(aggBody(attSig)); code != http.StatusPreconditionFailed {
		t.Fatalf("aggregate with a selection proof that is not one: %d %s", code, out)
	}
	t.Logf("aggregate whose selection proof does not verify: 412 (the signers refuse it)")

	// Slashing protection is the signers': a double vote is refused.
	if code, _, out := sign(attBody(att(e1-1, e1, 0xa2))); code != http.StatusPreconditionFailed {
		t.Fatalf("double vote: %d %s", code, out)
	}
	if !strings.Contains(gw.logText(), "SC_ERR_SLASH_TARGET") {
		t.Fatalf("no slashing refusal in the gateway log:\n%s", gw.logText())
	}
	t.Logf("double vote for target %d: 412", e1)

	// One signer down: the other two sign. Two down: no signature.
	runners[0].stop()
	c.waitEpoch(t, e1+1)
	data2 := att(e1, e1+1, 0xa3)
	mustSign("attestation with one signer down", attBody(data2), data2)
	t.Logf("epoch %d: gw-runner-1 stopped, the other two sign", e1+1)
	runners[1].stop()
	c.waitEpoch(t, e1+2)
	if code, _, out := sign(attBody(att(e1+1, e1+2, 0xa4))); code != http.StatusInternalServerError {
		t.Fatalf("two signers down: %d %s", code, out)
	}
	t.Logf("epoch %d: two signers stopped: 500, no signature", e1+2)

	// The first runner comes back with a new TLS key: the gateway attests
	// the new connection and signs again, once the runner's restart floor
	// has passed (a new target each epoch).
	before := strings.Count(gw.logText(), "signer attested")
	runners[0].start()
	for target := e1 + 3; ; target++ {
		c.waitEpoch(t, target)
		code, sig, out := sign(attBody(att(target-1, target, 0xa5)))
		if code == http.StatusOK {
			root, _ := c.cfg.SigningRoot(att(target-1, target, 0xa5))
			if !core.Verify(pk, root, sig) {
				t.Fatal("signature after the restart does not verify")
			}
			t.Logf("epoch %d: gw-runner-1 restarted (new TLS key), attested again, signs with gw-runner-3", target)
			break
		}
		if target > e1+12 {
			t.Fatalf("no signature after gw-runner-1 restarted: %d %s\n%s", code, out, gw.logText())
		}
	}
	if after := strings.Count(gw.logText(), "signer attested"); after <= before {
		t.Fatalf("no new attested connection after the restart")
	}
}

// writeSigningPair writes the client certificate chain and key of cfg
// itself (writeClientPair writes its admin twin).
func writeSigningPair(t *testing.T, dir string, cfg *tls.Config) (certFile, keyFile string) {
	t.Helper()
	pair := cfg.Certificates[0]
	var chain []byte
	for _, der := range pair.Certificate {
		chain = append(chain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	key, err := x509.MarshalPKCS8PrivateKey(pair.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	certFile, keyFile = filepath.Join(dir, "gateway.pem"), filepath.Join(dir, "gateway-key.pem")
	if err := os.WriteFile(certFile, chain, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certFile, keyFile
}

type gatewayProc struct {
	cmd     *exec.Cmd
	logPath string
}

func (g *gatewayProc) logText() string {
	b, _ := os.ReadFile(g.logPath)
	return string(b)
}

// startGateway builds the gateway, starts it with cfg and waits until it
// answers on listen.
func startGateway(t *testing.T, dir, cfg, listen string) *gatewayProc {
	t.Helper()
	bin := filepath.Join(binDir, "gateway")
	binMu.Lock()
	if _, err := os.Stat(bin); err != nil {
		if err := goBuild(bin, "../../gateway/cmd/gateway", ""); err != nil {
			binMu.Unlock()
			t.Fatalf("build the gateway: %v", err)
		}
	}
	binMu.Unlock()
	cfgPath := filepath.Join(dir, "gateway.yml")
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	g := &gatewayProc{logPath: filepath.Join(dir, "gateway.log")}
	f, err := os.Create(g.logPath)
	if err != nil {
		t.Fatal(err)
	}
	g.cmd = exec.Command(bin, "-config", cfgPath)
	g.cmd.Stdout, g.cmd.Stderr = f, f
	if err := g.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = g.cmd.Process.Signal(syscall.SIGTERM)
		_ = g.cmd.Wait()
		f.Close()
		if t.Failed() {
			t.Logf("---- gateway log ----\n%s", g.logText())
		}
	})
	deadline := time.Now().Add(60 * time.Second)
	for {
		resp, err := http.Get("http://" + listen + "/upcheck")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return g
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("gateway not up:\n%s", g.logText())
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func getJSON(t *testing.T, url string, v any) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(v); err != nil {
		t.Fatal(err)
	}
}

// postJSON sends a sign request as a validator client does.
func postJSON(t *testing.T, url, body string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// phase0AggregateSSZ is the SSZ of a phase0 AggregateAndProof, for the
// signer core to hash.
func phase0AggregateSSZ(aggregator uint64, proof backend.Signature, bits []byte, d *backend.AttestationData, sig backend.Signature) []byte {
	le := binary.LittleEndian
	var data []byte
	data = le.AppendUint64(data, d.Slot)
	data = le.AppendUint64(data, d.Index)
	data = append(data, d.BeaconBlockRoot[:]...)
	data = le.AppendUint64(data, d.Source.Epoch)
	data = append(data, d.Source.Root[:]...)
	data = le.AppendUint64(data, d.Target.Epoch)
	data = append(data, d.Target.Root[:]...)
	att := le.AppendUint32(nil, uint32(4+len(data)+len(sig)))
	att = append(append(append(att, data...), sig[:]...), bits...)
	out := le.AppendUint64(nil, aggregator)
	out = le.AppendUint32(out, 8+4+96)
	return append(append(out, proof[:]...), att...)
}
