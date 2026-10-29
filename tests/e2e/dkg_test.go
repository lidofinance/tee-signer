package e2e

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/signer-core/core"
	"github.com/lidofinance/tee-signer/signer-core/dkgmath"
	"github.com/lidofinance/tee-signer/signer-core/software"
	"github.com/lidofinance/tee-signer/signer-core/threshold"
	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/dkgmsg"
	"github.com/lidofinance/tee-signer/signer-protocol/remote"
	"github.com/lidofinance/tee-signer/tee-signer/charonlock"
)

// Key generation among three dev runners of the key generation build
// (runner-dev-dkg-dev: platform dev, peer verifier dev), with the
// coordinator binary, as an operator would run it.

var (
	toolOnce sync.Once
	coordBin string
	nodeBin  string
	toolErr  error
)

// tools builds dkg-coordinator and charon-node-sign (its own module).
func tools(t *testing.T) (string, string) {
	t.Helper()
	toolOnce.Do(func() {
		coordBin = filepath.Join(binDir, "dkg-coordinator")
		if toolErr = goBuild(coordBin, "../../signer-admin/cmd/dkg-coordinator", ""); toolErr != nil {
			return
		}
		nodeBin = filepath.Join(binDir, "charon-node-sign")
		cmd := exec.Command("go", "build", "-o", nodeBin, "./cmd/charon-node-sign")
		cmd.Dir = "../../signer-admin"
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
		toolErr = cmd.Run()
	})
	if toolErr != nil {
		t.Fatalf("build tools: %v", toolErr)
	}
	return coordBin, nodeBin
}

// hoodiFork is the genesis fork version of a network Charon knows, so the
// lock test can run stock charon on it without testnet flags.
var hoodiFork = backend.Version{0x10, 0x00, 0x09, 0x10}

const hoodiGenesis = 1742213400

// dkgChain is the test chain with Hoodi's genesis fork version.
func dkgChain(t *testing.T) chain {
	t.Helper()
	now := uint64(time.Now().Unix())
	cfg := software.DevConfig(now-1000*epochSecs, secondsPerSlot, slotsPerEpoch)
	cfg.Forks = nil
	cfg.GenesisForkVersion = hoodiFork
	raw, _ := json.MarshalIndent(cfg, "", "  ")
	p := filepath.Join(t.TempDir(), "chain.json")
	if err := os.WriteFile(p, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return chain{cfg: cfg, path: p}
}

func feeHex(c chain) string { return fmt.Sprintf("0x%x", c.cfg.FeeRecipients[0][:]) }

const withdrawal = "0x8943545177806ed17b9f23f0a21ee5948ecaa776"

// writeClientPair writes the client certificate (with its intermediate)
// and key of cfg's admin twin as PEM files: the tools that read them
// (dkg-coordinator, the handover tools, signer-admin) send admin messages.
func writeClientPair(t *testing.T, dir string, cfg *tls.Config) (string, string) {
	t.Helper()
	c := adminConfig(cfg).Certificates[0]
	keyDER, err := x509.MarshalPKCS8PrivateKey(c.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, key := filepath.Join(dir, "client.pem"), filepath.Join(dir, "client-key.pem")
	var chain []byte
	for _, der := range c.Certificate {
		chain = append(chain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	if err := os.WriteFile(cert, chain, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(key, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return cert, key
}

type dkgCluster struct {
	chain   chain
	dir     string
	runners []*runner
	addrs   []string
	clients []*remote.Client
	caFile  string
	keys    []string // operator keys
	config  string   // coordinator config with the policy
	// Runners with setups (dkg_order_test.go): each one's setup file and
	// setup_hash, and the coordinator connections without attestation.
	setups      []string
	setupHashes []backend.Root
	conns       []coordConn
	cliCfg      *tls.Config // the client certificate of the runners' CA
}

type coordConn struct {
	Address     string          `json:"address"`
	ClientCert  string          `json:"client_cert"`
	ClientKey   string          `json:"client_key"`
	Attestation json.RawMessage `json:"attestation,omitempty"`
	// AllowTestnet is allow_testnet_build: the runners are testnet builds.
	AllowTestnet bool `json:"allow_testnet_build,omitempty"`
}

// newDKGCluster starts three DKG runners with mutual TLS and no policy,
// reads their operator keys with the coordinator, and writes the
// coordinator config.
func newDKGCluster(t *testing.T, c chain) *dkgCluster {
	t.Helper()
	k := &dkgCluster{chain: c, dir: t.TempDir()}
	var cliCfg *tls.Config
	k.caFile, cliCfg = testPKI(t, k.dir, "dkg")
	cert, key := writeClientPair(t, k.dir, cliCfg)
	var conns []coordConn
	for i := range 3 {
		addr := fmt.Sprintf("tcp:127.0.0.1:%d", freePort(t))
		r := newRunnerOn(t, runnerBinary(t, "dev-dkg"), fmt.Sprintf("runner%d", i+1), c, addr, "-tls-client-ca", k.caFile)
		r.start()
		cl, err := newTLSClient(addr, cliCfg, remote.DevVerifier, remote.WithTimeout(30*time.Second))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { cl.Close() })
		waitReady(t, cl)
		k.runners, k.addrs, k.clients = append(k.runners, r), append(k.addrs, addr), append(k.clients, cl)
		conns = append(conns, coordConn{addr, cert, key, json.RawMessage(`{"verifier":"dev"}`), false})
	}
	pre := filepath.Join(k.dir, "operator-keys.json")
	b, _ := json.Marshal(map[string]any{"runners": conns})
	if err := os.WriteFile(pre, b, 0o600); err != nil {
		t.Fatal(err)
	}
	out, log, err := k.coord(t, "operator-keys", "-config", pre)
	if err != nil {
		t.Fatalf("operator-keys: %v\n%s", err, log)
	}
	var got []struct {
		Address     string `json:"address"`
		OperatorKey string `json:"operator_key"`
	}
	if err := json.Unmarshal(out, &got); err != nil || len(got) != 3 {
		t.Fatalf("operator-keys output: %v\n%s", err, out)
	}
	for i, g := range got {
		if g.Address != k.addrs[i] || len(g.OperatorKey) != 64 {
			t.Fatalf("operator key %d: %+v", i, g)
		}
		k.keys = append(k.keys, g.OperatorKey)
	}
	for i := range conns {
		conns[i].Attestation = nil
	}
	b, _ = json.Marshal(map[string]any{"policy": "policy.json", "runners": conns})
	k.config = filepath.Join(k.dir, "coordinator.json")
	if err := os.WriteFile(k.config, b, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Logf("3 DKG runners up with mutual TLS; operator keys read over attested connections: %s..., %s..., %s...", k.keys[0][:12], k.keys[1][:12], k.keys[2][:12])
	return k
}

// policy is the cluster's policy with setup appended (",\"setup\":{...}" or "").
func (k *dkgCluster) policy(setup string) string {
	var b strings.Builder
	b.WriteString(`{"version":1,"threshold":2,"participants":[`)
	for i, key := range k.keys {
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, "\n {\"name\":\"op%d\",\"operator_key\":\"%s\",\"attestation\":{\"verifier\":\"dev\"}}", i+1, key)
	}
	b.WriteString("]" + setup + "}\n")
	return b.String()
}

// usePolicy writes each runner's policy file (policies[i], or policies[0]
// for all) and restarts the runners with it; the coordinator gets the first.
func (k *dkgCluster) usePolicy(t *testing.T, policies ...string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(k.dir, "policy.json"), []byte(policies[0]), 0o600); err != nil {
		t.Fatal(err)
	}
	for i, r := range k.runners {
		pol := policies[0]
		if i < len(policies) {
			pol = policies[i]
		}
		p := filepath.Join(k.dir, fmt.Sprintf("policy-runner%d.json", i+1))
		if err := os.WriteFile(p, []byte(pol), 0o600); err != nil {
			t.Fatal(err)
		}
		r.stop()
		r.start("-dkg-policy", p)
		waitReady(t, k.clients[i])
	}
}

// coord runs the coordinator; the output is stdout, the log stderr.
func (k *dkgCluster) coord(t *testing.T, args ...string) ([]byte, string, error) {
	t.Helper()
	bin, _ := tools(t)
	if args[0] != "accounts" {
		args = append(args, "-platform", "dev")
	}
	cmd := exec.Command(bin, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	start := time.Now()
	err := cmd.Run()
	t.Logf("dkg-coordinator %s (%v):\n%s", args[0], time.Since(start).Round(time.Millisecond), stderr.String())
	return stdout.Bytes(), stderr.String(), err
}

type dkgOutput struct {
	Session    string `json:"session"`
	Transcript string `json:"transcript"`
	Threshold  int    `json:"threshold"`
	Validators []struct {
		Pubkey       string   `json:"pubkey"`
		PublicShares []string `json:"public_shares"`
	} `json:"validators"`
	Confirmations []string `json:"confirmations"`
}

func (k *dkgCluster) keygen(t *testing.T, count int) *dkgOutput {
	t.Helper()
	outFile := filepath.Join(k.dir, "dkg-result.json")
	if _, log, err := k.coord(t, "keygen", "-config", k.config, "-count", fmt.Sprint(count), "-out", outFile); err != nil {
		t.Fatalf("keygen: %v\n%s", err, log)
	}
	b, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatal(err)
	}
	var out dkgOutput
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	return &out
}

// forgedResultRefused (TKGARTIFACT-01): a result the coordinator made of
// its own keys, consistent and with deposits signed under them, under the
// same policy. check-deposits asks the runners and refuses it: none holds
// those keys.
func forgedResultRefused(t *testing.T, k *dkgCluster, wc backend.Root) {
	t.Helper()
	var res map[string]any
	if err := json.Unmarshal(mustReadFile(t, filepath.Join(k.dir, "dkg-result.json")), &res); err != nil {
		t.Fatal(err)
	}
	s, err := software.NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	sh, err := software.Split(s, 2, 3)
	if err != nil {
		t.Fatal(err)
	}
	pk, _ := core.PubkeyOf(s)
	var shares []string
	for _, x := range sh {
		p, _ := core.PubkeyOf(x.Secret)
		shares = append(shares, fmt.Sprintf("0x%x", p[:]))
	}
	res["validators"] = []map[string]any{{"pubkey": fmt.Sprintf("0x%x", pk[:]), "public_shares": shares}}
	forged := filepath.Join(k.dir, "forged-result.json")
	b, _ := json.Marshal(res)
	if err := os.WriteFile(forged, b, 0o600); err != nil {
		t.Fatal(err)
	}
	const amount = 32_000_000_000
	root := charonlock.DepositSigningRoot(pk, wc, amount, hoodiFork)
	sig, err := dkgmath.Sign(&s, root[:])
	if err != nil {
		t.Fatal(err)
	}
	deps := filepath.Join(k.dir, "forged-deposits.json")
	db, _ := json.Marshal([]map[string]any{{"pubkey": hex.EncodeToString(pk[:]), "withdrawal_credentials": hex.EncodeToString(wc[:]),
		"amount": amount, "signature": hex.EncodeToString(sig[:])}})
	if err := os.WriteFile(deps, db, 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(k.dir, "forged-checked.json")
	_, log, err := k.coord(t, "check-deposits", "-config", k.config, "-policy", filepath.Join(k.dir, "policy.json"),
		"-result", forged, "-deposits", deps, "-fork-version", fmt.Sprintf("%x", hoodiFork[:]), "-out", out)
	if err == nil || !strings.Contains(log, "runner 1 (op1): does not hold validator 0") {
		t.Fatalf("check-deposits took a result of keys no runner holds: %v\n%s", err, log)
	}
	if _, err := os.Stat(out); err == nil {
		t.Fatal("check-deposits wrote the funding file of a forged result")
	}
	t.Log("check-deposits: a consistent result of the coordinator's own keys, with deposits signed by them, is refused: no runner holds them")
}

func mustReadFile(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func pubkeyHex(t *testing.T, s string) backend.Pubkey {
	t.Helper()
	b, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
	var pk backend.Pubkey
	if err != nil || len(b) != len(pk) {
		t.Fatalf("bad key %q", s)
	}
	copy(pk[:], b)
	return pk
}

var hex64 = regexp.MustCompile(`[0-9a-fA-F]{64,}`)

func mustHex(b []byte) []byte {
	out, err := hex.DecodeString(string(b))
	if err != nil {
		panic(err)
	}
	return out
}

// scanForShares looks in the runners' logs and state folders for any
// 32-byte value, either byte order, whose public key is a public share or a
// validator key of the run: as hex in every file, and raw in every file. It
// needs only the public result.
func scanForShares(t *testing.T, k *dkgCluster, out *dkgOutput) {
	t.Helper()
	needles := map[backend.Pubkey]string{}
	for v, val := range out.Validators {
		needles[pubkeyHex(t, val.Pubkey)] = fmt.Sprintf("validator %d key", v)
		for i, s := range val.PublicShares {
			needles[pubkeyHex(t, s)] = fmt.Sprintf("validator %d share %d", v, i+1)
		}
	}
	hit := func(b []byte) string {
		for _, le := range []bool{false, true} {
			var s [32]byte
			copy(s[:], b)
			if le {
				for i := range 16 {
					s[i], s[31-i] = s[31-i], s[i]
				}
			}
			if pk, err := core.PubkeyOf(s); err == nil {
				if what, ok := needles[pk]; ok {
					return what
				}
			}
		}
		return ""
	}
	files, bytesScanned := 0, 0
	for _, r := range k.runners {
		for _, root := range []string{r.logPath, r.stateDir} {
			_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
				if err != nil || !d.Type().IsRegular() {
					return nil
				}
				data, err := os.ReadFile(p)
				if err != nil {
					return nil
				}
				files++
				bytesScanned += len(data)
				for _, run := range hex64.FindAll(data, -1) {
					for off := 0; off+64 <= len(run); off += 2 {
						if what := hit(mustHex(run[off : off+64])); what != "" {
							t.Fatalf("%s: %s as hex", p, what)
						}
					}
				}
				for off := 0; off+32 <= len(data); off++ {
					if what := hit(data[off : off+32]); what != "" {
						t.Fatalf("%s: %s raw at %d", p, what, off)
					}
				}
				return nil
			})
		}
	}
	// Control: the scanner finds a planted value in both forms and orders.
	ctl, _ := software.NewSecret()
	cpk, _ := core.PubkeyOf(ctl)
	needles[cpk] = "control"
	rev := ctl
	for i := range 16 {
		rev[i], rev[31-i] = rev[31-i], rev[i]
	}
	text := []byte("x=" + hex.EncodeToString(rev[:]) + " ")
	if hit(ctl[:]) != "control" || hit(rev[:]) != "control" || hit(mustHex(hex64.Find(text))) != "control" {
		t.Fatal("scanner misses a planted value")
	}
	t.Logf("no share in %d log and state files (%d bytes), hex and raw, both byte orders (a planted control is found)", files, bytesScanned)
}

func checkKeys(t *testing.T, k *dkgCluster, out *dkgOutput, count int) {
	t.Helper()
	for i, c := range k.clients {
		keys, err := c.PublicKeys(ctx)
		if err != nil || len(keys) != count {
			t.Fatalf("runner %d: %d keys, %v", i+1, len(keys), err)
		}
		for _, key := range keys {
			found := false
			for _, v := range out.Validators {
				if pubkeyHex(t, v.Pubkey) == key.Pubkey {
					found = true
					if pubkeyHex(t, v.PublicShares[i]) != key.SharePubkey || key.Index != backend.IndexUnknown {
						t.Fatalf("runner %d holds a share other than x = %d", i+1, i+1)
					}
				}
			}
			if !found {
				t.Fatalf("runner %d holds an unknown key", i+1)
			}
		}
	}
}

const dirkSetup = `,"setup":{"path":"dirk","withdrawal_address":"` + withdrawal + `","deposit_amounts_gwei":[32000000000]}`

// TestE2EDKG: the Dirk path. Three runners make two keys; each holds the
// share at its position; any two sign for the validator key; the shares
// survive a restart sealed; the deposits are threshold signatures of the
// runners; each participant gets its accounts file.
func TestE2EDKG(t *testing.T) {
	k := newDKGCluster(t, dkgChain(t))
	k.usePolicy(t, k.policy(dirkSetup))
	const count = 2
	out := k.keygen(t, count)
	if out.Threshold != 2 || len(out.Validators) != count || len(out.Confirmations) != 3 {
		t.Fatalf("output: %+v", out)
	}
	checkKeys(t, k, out, count)
	t.Logf("3 runners, 2 of 3: %d keys, every runner holds the share at its position", count)

	// Any two runners sign an attestation for the first key.
	gk := pubkeyHex(t, out.Validators[0].Pubkey)
	e := k.chain.stableEpoch(t) + 4
	k.chain.waitEpoch(t, e)
	data := att(e-1, e, 0xd1)
	root, _ := k.chain.cfg.SigningRoot(data)
	sigs := make([]backend.Signature, 3)
	var err error
	for i, c := range k.clients {
		if sigs[i], err = c.Sign(ctx, k.chain.req(gk, data)); err != nil {
			t.Fatalf("runner %d sign: %v", i+1, err)
		}
	}
	for _, pick := range [][]int{{0, 1}, {0, 2}, {1, 2}} {
		full, err := threshold.RecoverSignature([]uint64{uint64(pick[0] + 1), uint64(pick[1] + 1)}, []backend.Signature{sigs[pick[0]], sigs[pick[1]]})
		if err != nil || !core.Verify(gk, root, full) {
			t.Fatalf("runners %v: combined signature does not verify under the validator key", pick)
		}
	}
	t.Logf("epoch %d: every pair of runners combines to an attestation signature under the validator key", e)

	// Deposits: threshold signatures of the runners, checked here too.
	depFile := filepath.Join(k.dir, "deposit-data.json")
	if _, log, err := k.coord(t, "deposits", "-config", k.config, "-result", filepath.Join(k.dir, "dkg-result.json"),
		"-fork-version", fmt.Sprintf("%x", hoodiFork[:]), "-network-name", "hoodi", "-out", depFile); err != nil {
		t.Fatalf("deposits: %v\n%s", err, log)
	}
	var deps []struct {
		Pubkey                string `json:"pubkey"`
		WithdrawalCredentials string `json:"withdrawal_credentials"`
		Amount                uint64 `json:"amount"`
		Signature             string `json:"signature"`
		DepositDataRoot       string `json:"deposit_data_root"`
	}
	b, _ := os.ReadFile(depFile)
	if err := json.Unmarshal(b, &deps); err != nil || len(deps) != count {
		t.Fatalf("deposit data: %v %s", err, b)
	}
	addr, _ := charonlock.Address(withdrawal)
	wc := charonlock.WithdrawalCredentials(addr, true)
	for _, d := range deps {
		pk := pubkeyHex(t, d.Pubkey)
		sigB, _ := hex.DecodeString(d.Signature)
		var sig backend.Signature
		copy(sig[:], sigB)
		if d.WithdrawalCredentials != hex.EncodeToString(wc[:]) || d.Amount != 32_000_000_000 ||
			!core.Verify(pk, charonlock.DepositSigningRoot(pk, wc, d.Amount, hoodiFork), sig) {
			t.Fatalf("deposit for %s does not verify", d.Pubkey[:12])
		}
		dr := charonlock.DepositDataRoot(pk, wc, d.Amount, sig)
		if d.DepositDataRoot != hex.EncodeToString(dr[:]) {
			t.Fatal("deposit_data_root does not recompute")
		}
	}
	// Setup is closed after the policy's only amount: a second run is refused.
	if _, _, err := k.coord(t, "deposits", "-config", k.config, "-result", filepath.Join(k.dir, "dkg-result.json"),
		"-fork-version", fmt.Sprintf("%x", hoodiFork[:]), "-out", depFile+".2"); err == nil {
		t.Fatal("second deposit run after setup closed succeeded")
	}
	t.Logf("deposits: %d, 0x02 credentials, 32 ETH, each a 2-of-3 signature of the runners under the validator key; setup then closed", len(deps))

	// The offline check before sending: the coordinator's output passes, the
	// same file with one credentials byte changed does not.
	checkArgs := func(in, out string) []string {
		return []string{"check-deposits", "-config", k.config, "-policy", filepath.Join(k.dir, "policy.json"), "-result", filepath.Join(k.dir, "dkg-result.json"),
			"-deposits", in, "-fork-version", fmt.Sprintf("%x", hoodiFork[:]), "-out", out}
	}
	if _, log, err := k.coord(t, checkArgs(depFile, depFile+".checked")...); err != nil {
		t.Fatalf("check-deposits: %v\n%s", err, log)
	}
	raw, _ := os.ReadFile(depFile)
	bad := bytes.Replace(raw, []byte(`"withdrawal_credentials": "02`), []byte(`"withdrawal_credentials": "01`), 1)
	if err := os.WriteFile(depFile+".bad", bad, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, log, err := k.coord(t, checkArgs(depFile+".bad", depFile+".bad.checked")...); err == nil || !strings.Contains(log, "withdrawal credentials") {
		t.Fatalf("check-deposits took 0x01 credentials: %v\n%s", err, log)
	}
	t.Log("check-deposits: the runners' deposits pass; with 0x01 credentials in place of the policy's 0x02 the file is refused")
	forgedResultRefused(t, k, wc)

	// Accounts files for the Dirk fork, one per participant.
	if _, log, err := k.coord(t, "accounts", "-result", filepath.Join(k.dir, "dkg-result.json"), "-wallet", "Generated",
		"-endpoints", "dirk1:9091,dirk2:9091,dirk3:9091", "-out-dir", k.dir); err != nil {
		t.Fatalf("accounts: %v\n%s", err, log)
	}
	for i := range 3 {
		var f struct {
			Accounts []struct {
				PubKey             string            `json:"pubkey"`
				SharePubKey        string            `json:"share_pubkey"`
				SigningThreshold   int               `json:"signing_threshold"`
				ParticipantPubKeys map[string]string `json:"participant_pubkeys"`
			} `json:"accounts"`
		}
		b, _ := os.ReadFile(filepath.Join(k.dir, fmt.Sprintf("accounts-%d.json", i+1)))
		if err := json.Unmarshal(b, &f); err != nil || len(f.Accounts) != count {
			t.Fatalf("accounts-%d.json: %v", i+1, err)
		}
		for v, a := range f.Accounts {
			if a.PubKey != out.Validators[v].Pubkey || a.SharePubKey != out.Validators[v].PublicShares[i] ||
				a.SigningThreshold != 2 || a.ParticipantPubKeys[fmt.Sprint(i+1)] != a.SharePubKey {
				t.Fatalf("accounts-%d.json account %d", i+1, v)
			}
		}
	}
	t.Log("accounts-1..3.json: each participant's share key, all participants' share keys, threshold 2")

	// Restart runner 2: its shares load from sealed storage.
	k.runners[1].stop()
	k.runners[1].start("-dkg-policy", filepath.Join(k.dir, "policy-runner2.json"))
	waitReady(t, k.clients[1])
	keys, err := k.clients[1].PublicKeys(ctx)
	if err != nil || len(keys) != count {
		t.Fatalf("after restart: %d keys, %v", len(keys), err)
	}
	// Repeat roots are off by default, so the restart floor refuses the
	// same attestation again.
	_, err = k.clients[1].Sign(ctx, k.chain.req(gk, data))
	if r := wantRefused(t, err, backend.StatusSlashSource); !strings.Contains(r.Detail, "restart floor") {
		t.Fatalf("after restart: want a floor refusal of the repeat, got %v", r)
	}
	t.Log("runner 2 restarted: both shares loaded from sealed storage; the repeat of the attestation is refused by the restart floor (repeat roots off)")

	// A second commit with the published confirmations changes nothing.
	q := &dkgmsg.CommitRequest{}
	sess, _ := hex.DecodeString(strings.TrimPrefix(out.Session, "0x"))
	copy(q.Session[:], sess)
	for _, h := range out.Confirmations {
		b, _ := hex.DecodeString(strings.TrimPrefix(h, "0x"))
		c, err := dkgmsg.DecodeConfirm(b)
		if err != nil {
			t.Fatal(err)
		}
		q.Confirms = append(q.Confirms, c)
	}
	if keys, err := adminOf(k.clients[0]).DKGCommit(ctx, q); err != nil || len(keys) != count {
		t.Fatalf("repeated commit: %d keys, %v", len(keys), err)
	}
	scanForShares(t, k, out)
}

// TestE2EDKGRefusals: a runner on another policy file stops the run before
// any runner deals; a runner without the peer verifier a policy names does
// not start; builds without key generation answer UNSUPPORTED.
func TestE2EDKGRefusals(t *testing.T) {
	k := newDKGCluster(t, dkgChain(t))
	pol := k.policy("")
	k.usePolicy(t, pol, pol, pol+" ")
	outFile := filepath.Join(k.dir, "dkg-result.json")
	_, log, err := k.coord(t, "keygen", "-config", k.config, "-count", "1", "-out", outFile)
	if err == nil || !strings.Contains(log, "runner 3: hello names policy") {
		t.Fatalf("run with a runner on another policy: %v\n%s", err, log)
	}
	for i, c := range k.clients {
		if keys, _ := c.PublicKeys(ctx); len(keys) != 0 {
			t.Fatalf("runner %d holds keys", i+1)
		}
		_, err := adminOf(c).DKGDeal(ctx, [][]byte{{1}})
		wantRefused(t, err, backend.StatusNotReady)
	}
	hellos := make([][]byte, 3)
	for i, c := range k.clients {
		if hellos[i], err = adminOf(c).DKGHello(ctx, &dkgmsg.HelloRequest{Nonce: bytes.Repeat([]byte{1}, 32), Count: 1}); err != nil {
			t.Fatal(err)
		}
	}
	for i := range 2 {
		_, err := adminOf(k.clients[i]).DKGDeal(ctx, hellos)
		if r := wantRefused(t, err, backend.StatusBadKey); !strings.Contains(r.Detail, "participant 3 (op3): another policy") {
			t.Fatalf("runner %d: %v", i+1, r)
		}
	}
	t.Log("runner 3 on a policy file one byte longer: the coordinator stops before dealing; runners 1 and 2 refuse its hello on their own")

	// A policy that names aws-nitro for a runner built with the dev peer
	// only: the runner does not start.
	pcr := strings.Repeat("ab", 48)
	nitro := strings.Replace(pol, `"attestation":{"verifier":"dev"}}]`,
		`"attestation":{"verifier":"aws-nitro","nitro_pcrs":{"0":"`+pcr+`","1":"`+pcr+`","2":"`+pcr+`","3":"`+pcr+`"}}}]`, 1)
	np := filepath.Join(k.dir, "policy-nitro.json")
	if err := os.WriteFile(np, []byte(nitro), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := runnerCmd(runnerBinary(t, "dev-dkg"), "-platform", "dev", "-config", k.chain.path, "-state-dir", t.TempDir(),
		"-listen", fmt.Sprintf("tcp:127.0.0.1:%d", freePort(t)), "-dkg-policy", np)
	msg, err := cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(msg), `verifier "aws-nitro" is not built into this runner`) {
		t.Fatalf("runner without peer_aws and a policy naming aws-nitro: %v\n%s", err, msg)
	}
	t.Logf("runner without peer_aws, policy naming aws-nitro: refused at start: %s", strings.TrimSpace(string(msg)))

	// The default dev build has no key generation at all.
	sock := filepath.Join(t.TempDir(), "r.sock")
	plain := newRunnerArgs(t, "no-dkg", k.chain, "unix:"+sock)
	plain.start()
	pc := client(t, "unix:"+sock)
	waitReady(t, pc)
	_, err = adminOf(pc).DKGHello(ctx, &dkgmsg.HelloRequest{Nonce: bytes.Repeat([]byte{1}, 32), Count: 1})
	wantRefused(t, err, backend.StatusUnsupported)
	if !strings.Contains(plain.logText(), "runner started") || strings.Contains(plain.logText(), "operator key") {
		t.Fatal("default build log")
	}
	t.Log("default dev build (no peer tags): DKG_HELLO is an unknown message")
}
