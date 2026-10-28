package e2e

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/governance/dkgorder"
	"github.com/lidofinance/tee-signer/governance/setupwire"
	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/dkgmsg"
	"github.com/lidofinance/tee-signer/signer-protocol/remote"
	"github.com/lidofinance/tee-signer/tee-signer/charonlock"
)

// Key generation among three dev runners with setups, under approver-signed
// DKG orders (research/setup-phase.md in the threshold-signer-poc repo, section 10):
// no policy file, the orders come over the wire, the same three runners
// make the keys of a Dirk fork lane and of a Charon lane.

// orderTimeLock is the setups' time lock: on the dev platform an order
// waits it out (a cloud runner waits the images minimum, a week).
const orderTimeLock = 2

// orderSetupFor is a dev setup of signer name in cluster for chain c: the
// chain and safety values of c, the CA of caFile, the stores in dir, the
// config approvers 1 to 3 with k = 2, the time lock timeLock (nil: none
// named, the image default), compounding credentials to withdrawal and
// 32 ETH deposits.
func orderSetupFor(t *testing.T, c chain, dir, caFile, name string, cluster [32]byte, timeLock *uint64) []byte {
	t.Helper()
	sample, err := os.ReadFile(filepath.Join("..", "..", "governance", "setupwire", "testdata", "setup-dev.bin"))
	if err != nil {
		t.Fatal(err)
	}
	s, err := setupwire.DecodeSetup(sample)
	if err != nil {
		t.Fatal(err)
	}
	cfg := c.cfg
	s.SignerName, s.ClusterID = name, cluster
	s.Chain = setupwire.Chain{GenesisValidatorsRoot: cfg.GenesisValidatorsRoot, GenesisForkVersion: cfg.GenesisForkVersion,
		GenesisTime: cfg.GenesisTime, SecondsPerSlot: cfg.SecondsPerSlot, SlotsPerEpoch: cfg.SlotsPerEpoch,
		Preset: setupwire.PresetMainnet, VoluntaryExitForkVersion: cfg.VoluntaryExitForkVersion}
	s.Safety = setupwire.Safety{MaxSignEpochsAheadOfClock: cfg.MaxEpochsAhead, SlashingMarkPrewrite: setupwire.SlashingMarkPrewrite{
		BlockSlots: cfg.CommitAhead.BlockSlots, SourceEpochs: cfg.CommitAhead.SourceEpochs, TargetEpochs: cfg.CommitAhead.TargetEpochs}}
	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		t.Fatal(err)
	}
	blk, _ := pem.Decode(caPEM)
	p := &s.Platform
	p.AllowedClientCA, s.MaxKeys = [][]byte{blk.Bytes}, 64
	p.SlashingLogStore = setupwire.Store{Dir: filepath.Join(dir, "marks")}
	p.EncryptedStateStore = &setupwire.Store{Dir: filepath.Join(dir, "state-copy")}
	l := &s.Locked
	l.Approvers = setupwire.ApproverSet{ApprovalsNeeded: 2}
	for id := byte(1); id <= 3; id++ {
		l.Approvers.Keys = append(l.Approvers.Keys, [32]byte(configApprover(id).Public().(ed25519.PublicKey)))
	}
	l.ChangeDelaySeconds, l.AllowedImageMeasurements = timeLock, nil
	l.AllowedFeeRecipients = slices.SortedFunc(slices.Values(cfg.FeeRecipients), func(a, b backend.Address) int { return bytes.Compare(a[:], b[:]) })
	l.BuilderGasLimitMin, l.BuilderGasLimitMax, l.BuilderRegistrationMaxFutureSeconds = cfg.GasLimitMin, cfg.GasLimitMax, cfg.RegistrationMaxFutureSeconds
	l.ExitAllowedValidators = slices.Sorted(slices.Values(cfg.ExitAllowlist))
	addr, _ := charonlock.Address(withdrawal)
	l.WithdrawalCredentials = charonlock.WithdrawalCredentials(addr, true)
	l.AllowedDepositAmounts = []uint64{32_000_000_000}
	s.Open = setupwire.Open{}
	for _, f := range cfg.Forks {
		s.Open.ForkSchedule = append(s.Open.ForkSchedule, setupwire.Fork{Epoch: f.Epoch, Version: f.Version})
	}
	raw, err := s.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// orderOpts are the runners and setups of an order cluster.
type orderOpts struct {
	bin      string  // the runnerBuilds key of the runners
	timeLock *uint64 // the setups' time lock; nil: the image default
	testnet  bool    // the runners are testnet builds: the coordinator allows them
	// maxValidators, if set, replaces the setups' max_validators (64).
	maxValidators uint32
}

// newOrderCluster starts three key generation runners with setups of one
// cluster and mutual TLS, and reads their operator keys with the
// coordinator, each runner pinned to its setup. The setups' time lock is
// orderTimeLock.
func newOrderCluster(t *testing.T, c chain) *dkgCluster {
	t.Helper()
	lock := uint64(orderTimeLock)
	return newOrderClusterWith(t, c, orderOpts{bin: "dev-dkg", timeLock: &lock})
}

func newOrderClusterWith(t *testing.T, c chain, o orderOpts) *dkgCluster {
	t.Helper()
	k := &dkgCluster{chain: c, dir: t.TempDir()}
	var cliCfg *tls.Config
	k.caFile, cliCfg = testPKI(t, k.dir, "dkg")
	k.cliCfg = cliCfg
	cert, key := writeClientPair(t, k.dir, cliCfg)
	var cluster [32]byte
	_, _ = rand.Read(cluster[:])
	var conns []coordConn
	for i := range 3 {
		name := fmt.Sprintf("signer-%d", i+1)
		dir := filepath.Join(k.dir, name)
		raw := orderSetupFor(t, c, dir, k.caFile, name, cluster, o.timeLock)
		if o.maxValidators != 0 {
			s, err := setupwire.DecodeSetup(raw)
			if err != nil {
				t.Fatal(err)
			}
			s.MaxKeys = o.maxValidators
			if raw, err = s.Encode(); err != nil {
				t.Fatal(err)
			}
		}
		setupFile := filepath.Join(k.dir, name+".setup")
		if err := os.WriteFile(setupFile, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		h, _ := setupwire.SetupHash(raw)
		addr := fmt.Sprintf("tcp:127.0.0.1:%d", freePort(t))
		r := &runner{t: t, name: name, bin: runnerBinary(t, o.bin), stateDir: filepath.Join(dir, "state"),
			logPath: filepath.Join(dir, name+".log")}
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		r.args = []string{"-platform", "dev", "-setup", "file:" + setupFile, "-state-dir", r.stateDir, "-listen", addr}
		t.Cleanup(func() {
			r.stop()
			if t.Failed() {
				b, _ := os.ReadFile(r.logPath)
				t.Logf("---- %s log ----\n%s", name, b)
			}
		})
		r.start()
		cl, err := newTLSClient(addr, cliCfg, remote.DevVerifier, remote.WithTimeout(30*time.Second))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { cl.Close() })
		waitReady(t, cl)
		k.runners, k.addrs, k.clients = append(k.runners, r), append(k.addrs, addr), append(k.clients, cl)
		k.setups, k.setupHashes = append(k.setups, setupFile), append(k.setupHashes, h)
		att := fmt.Sprintf(`{"verifier":"dev","setup_sha256":"%x"}`, h)
		conns = append(conns, coordConn{addr, cert, key, json.RawMessage(att), o.testnet})
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
		OperatorKey string `json:"operator_key"`
	}
	if err := json.Unmarshal(out, &got); err != nil || len(got) != 3 {
		t.Fatalf("operator-keys output: %v\n%s", err, out)
	}
	for _, g := range got {
		k.keys = append(k.keys, g.OperatorKey)
	}
	for i := range conns {
		conns[i].Attestation = nil
	}
	k.conns = conns
	t.Logf("3 key generation runners with setups of cluster %x up; operator keys read over connections pinned to each setup", cluster[:4])
	return k
}

// orderBody is the cluster's order for path, every participant with the dev
// verifier and its setup pinned.
func (k *dkgCluster) orderBody(t *testing.T, label string, path dkgorder.Path, enrs []string) dkgorder.Body {
	t.Helper()
	raw, _ := os.ReadFile(k.setups[0])
	s, err := setupwire.DecodeSetup(raw)
	if err != nil {
		t.Fatal(err)
	}
	b := dkgorder.Body{ClusterID: s.ClusterID, ChainHash: s.Chain.Hash(), Label: label, Path: path, Threshold: 2,
		NotAfter: uint64(time.Now().Add(24 * time.Hour).Unix()), CharonENRs: enrs}
	for i, key := range k.keys {
		op, _ := hex.DecodeString(key)
		b.Participants = append(b.Participants, dkgorder.Participant{Name: fmt.Sprintf("signer-%d", i+1),
			SetupHash: k.setupHashes[i], OperatorKey: [32]byte(op), Verifier: dkgorder.VerifierDev})
	}
	return b
}

// signOrderBody signs b by the config approvers ids (approver id at
// position id-1).
func signOrderBody(t *testing.T, b dkgorder.Body, ids ...byte) []byte {
	t.Helper()
	enc, err := b.Encode()
	if err != nil {
		t.Fatal(err)
	}
	o := &dkgorder.Order{Body: b}
	for _, id := range ids {
		o.Approvals = append(o.Approvals, setupwire.Approval{Position: id - 1, Signature: dkgorder.SignBody(configApprover(id), enc)})
	}
	raw, err := o.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// useOrder writes the signed order, a coordinator config that names it
// (with runner 1's setup as the locked group) and pushes it to every
// runner, waiting until each has it in force. It returns the config.
func (k *dkgCluster) useOrder(t *testing.T, name string, signed []byte) string {
	t.Helper()
	of := filepath.Join(k.dir, name+".order")
	if err := os.WriteFile(of, signed, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(k.dir, name+"-coordinator.json")
	b, _ := json.Marshal(map[string]any{"order": of, "locked": k.setups[0], "runners": k.conns})
	if err := os.WriteFile(cfg, b, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, log, err := k.coord(t, "push-order", "-config", cfg, "-wait", "30s"); err != nil {
		t.Fatalf("push-order %s: %v\n%s", name, err, log)
	}
	return cfg
}

// keygenWith makes count keys under the coordinator config cfg and moves the
// result to out.
func (k *dkgCluster) keygenWith(t *testing.T, cfg string, count int, out string) *dkgOutput {
	t.Helper()
	if _, log, err := k.coord(t, "keygen", "-config", cfg, "-count", fmt.Sprint(count), "-out", out); err != nil {
		t.Fatalf("keygen: %v\n%s", err, log)
	}
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var o dkgOutput
	if err := json.Unmarshal(b, &o); err != nil {
		t.Fatal(err)
	}
	return &o
}

// TestE2EDKGOrders: three dev runners with setups take two approver-signed
// DKG orders, a Dirk fork lane and a Charon lane. Each order waits out the
// setups' time lock (IDENTITY shows it pending), then makes its own keys:
// two for the Dirk lane with their deposits, two in two sessions for the
// Charon lane with a lock over both sessions. Deposits pass the offline
// check against the order and the setups' locked group. Without a setup
// signer's approval, for another setup, or as plain DKG messages, nothing
// happens. With CHARON_IMAGE stock charon run loads the lock; with
// SHIM_BIN two signer shims sign through the runners.
func TestE2EDKGOrders(t *testing.T) {
	c := dkgChain(t)
	k := newOrderCluster(t, c)

	// Refusals first. Plain DKG messages: this runner wants orders.
	_, err := adminOf(k.clients[0]).DKGHello(ctx, &dkgmsg.HelloRequest{Nonce: bytes.Repeat([]byte{1}, 32), Count: 1})
	if r := wantRefused(t, err, backend.StatusUnsupported); !strings.Contains(r.Detail, "DKG orders") {
		t.Fatalf("plain hello: %v", r)
	}
	dirkBody := k.orderBody(t, "dirk-lanes", dkgorder.PathDirk, nil)
	_, err = adminOf(k.clients[0]).DKGOrder(ctx, signOrderBody(t, dirkBody, 1))
	if r := wantRefused(t, err, backend.StatusBadRequest); !strings.Contains(r.Detail, "approvals_needed is 2") {
		t.Fatalf("one approver: %v", r)
	}
	other := dirkBody
	other.Participants = slices.Clone(dirkBody.Participants)
	other.Participants[0].SetupHash = backend.Root{0xee}
	_, err = adminOf(k.clients[0]).DKGOrder(ctx, signOrderBody(t, other, 1, 2))
	if r := wantRefused(t, err, backend.StatusBadRequest); !strings.Contains(r.Detail, "not one of its participants") {
		t.Fatalf("another setup: %v", r)
	}
	t.Log("refused: plain DKG_HELLO (this runner takes orders), an order signed by one approver, an order naming another setup")

	// The Dirk lane's order: pending for the time lock, shown in IDENTITY.
	dirkSigned := signOrderBody(t, dirkBody, 1, 3)
	st, err := adminOf(k.clients[1]).DKGOrder(ctx, dirkSigned)
	if err != nil || st.Status != dkgmsg.OrderPending || st.Position != 1 {
		t.Fatalf("first push: %+v %v", st, err)
	}
	enc, _ := dirkBody.Encode()
	dirkHash := dkgorder.Hash(enc)
	if id := devIdentity(t, k.clients[1]); id.State.Order.Kind != 2 || id.State.Order.Hash != dirkHash || id.State.Order.ActAt != st.ActAt {
		t.Fatalf("IDENTITY order slot %+v", id.State.Order)
	}
	_, err = adminOf(k.clients[1]).InOrder(dirkHash).DKGHello(ctx, &dkgmsg.HelloRequest{Nonce: bytes.Repeat([]byte{1}, 32), Count: 1})
	if r := wantRefused(t, err, backend.StatusNotReady); !strings.Contains(r.Detail, "waits until") {
		t.Fatalf("hello while pending: %v", r)
	}
	t.Logf("dirk order %x pending on runner 2 until %d (time lock %d s), IDENTITY shows it", dirkHash[:6], st.ActAt, orderTimeLock)
	dirkCfg := k.useOrder(t, "dirk", dirkSigned)
	if id := devIdentity(t, k.clients[1]); id.State.Order != (backend.Order{}) {
		t.Fatalf("IDENTITY order slot after the order acted: %+v", id.State.Order)
	}

	dirkResult := filepath.Join(k.dir, "dirk-result.json")
	dirk := k.keygenWith(t, dirkCfg, 2, dirkResult)
	if len(dirk.Validators) != 2 || dirk.Threshold != 2 {
		t.Fatalf("dirk result %+v", dirk)
	}
	checkKeys(t, k, dirk, 2)
	keyOrigin := func(i int, want backend.KeyOrigin) {
		t.Helper()
		if got := devIdentity(t, k.clients[i]).State.KeyOrigin; got != want {
			t.Fatalf("runner %d: IDENTITY key origin %+v, want %+v", i+1, got, want)
		}
	}
	for i := range k.clients {
		keyOrigin(i, backend.KeyOrigin{Generated: 2, OrdersHash: backend.KeygenOrdersHash([][32]byte{dirkHash})})
	}
	t.Log("IDENTITY key origin on every runner: 2 generated, 0 imported, under the dirk order")
	fork := fmt.Sprintf("%x", hoodiFork[:])
	depFile := filepath.Join(k.dir, "dirk-deposits.json")
	if _, log, err := k.coord(t, "deposits", "-config", dirkCfg, "-result", dirkResult, "-fork-version", fork, "-out", depFile); err != nil {
		t.Fatalf("deposits: %v\n%s", err, log)
	}
	check := func(args ...string) (string, error) {
		_, log, err := k.coord(t, append([]string{"check-deposits", "-config", dirkCfg, "-order", filepath.Join(k.dir, "dirk.order"), "-locked", k.setups[0],
			"-fork-version", fork}, args...)...)
		return log, err
	}
	if log, err := check("-result", dirkResult, "-deposits", depFile, "-out", depFile+".checked"); err != nil {
		t.Fatalf("check-deposits: %v\n%s", err, log)
	}
	raw, _ := os.ReadFile(depFile)
	bad := bytes.Replace(raw, []byte(`"withdrawal_credentials": "02`), []byte(`"withdrawal_credentials": "01`), 1)
	_ = os.WriteFile(depFile+".bad", bad, 0o600)
	if log, err := check("-result", dirkResult, "-deposits", depFile+".bad", "-out", depFile+".bad.checked"); err == nil || !strings.Contains(log, "withdrawal credentials") {
		t.Fatalf("check-deposits took 0x01 credentials: %v\n%s", err, log)
	}
	t.Log("dirk lane: 2 keys, deposits signed with the setups' locked credentials (0x02) and 32 ETH; check-deposits passes them and refuses 0x01")

	// The Charon lane's order on the same runners. Real ENRs with the image.
	image := os.Getenv("CHARON_IMAGE")
	enrs := []string{"enr:-test-1", "enr:-test-2", "enr:-test-3"}
	if image != "" {
		enrs = charonENRs(t, k, image)
	}
	charonBody := k.orderBody(t, "charon", dkgorder.PathCharon, enrs)
	charonCfg := k.useOrder(t, "charon", signOrderBody(t, charonBody, 2, 3))
	var results []string
	charon := &dkgOutput{Threshold: 2}
	for s := 1; s <= 2; s++ {
		p := filepath.Join(k.dir, fmt.Sprintf("charon-result-%d.json", s))
		o := k.keygenWith(t, charonCfg, 1, p)
		results, charon.Validators = append(results, p), append(charon.Validators, o.Validators...)
	}
	result := strings.Join(results, ",")
	for i, cl := range k.clients {
		keys, err := cl.PublicKeys(ctx)
		if err != nil || len(keys) != 4 {
			t.Fatalf("runner %d: %d keys, %v", i+1, len(keys), err)
		}
	}
	// A Dirk key is not the Charon order's: its deposit is refused there.
	gk := pubkeyHex(t, dirk.Validators[0].Pubkey)
	addr, _ := charonlock.Address(withdrawal)
	q := &dkgmsg.SetupRequest{Kind: dkgmsg.SetupDeposit, Deposit: &dkgmsg.Deposit{Pubkey: gk,
		WithdrawalCredentials: charonlock.WithdrawalCredentials(addr, true), Amount: 32_000_000_000}}
	enc, _ = charonBody.Encode()
	charonHash := dkgorder.Hash(enc)
	bothOrders := backend.KeyOrigin{Generated: 4, OrdersHash: backend.KeygenOrdersHash([][32]byte{dirkHash, charonHash})}
	for i := range k.clients {
		keyOrigin(i, bothOrders)
	}
	_, err = adminOf(k.clients[0]).InOrder(charonHash).DKGSetupSign(ctx, q)
	if r := wantRefused(t, err, backend.StatusPolicyPubkey); !strings.Contains(r.Detail, "another policy") {
		t.Fatalf("dirk key under the charon order: %v", r)
	}
	t.Log("charon lane on the same runners: 2 keys in 2 sessions; each runner holds 4 keys; a dirk key's deposit is refused under the charon order")

	cluster := map[string]any{"name": "c1-tee-dkg-order", "fork_version": "0x" + fork, "fee_recipient": feeHex(c),
		"gas_limit": 60_000_000, "registration_timestamp": hoodiGenesis}
	cb, _ := json.Marshal(cluster)
	clusterFile := filepath.Join(k.dir, "cluster.json")
	_ = os.WriteFile(clusterFile, cb, 0o600)
	lockFile := filepath.Join(k.dir, "cluster-lock.json")
	if _, log, err := k.coord(t, "charon-lock", "-config", charonCfg, "-result", result, "-cluster", clusterFile, "-out", lockFile); err != nil {
		t.Fatalf("charon-lock: %v\n%s", err, log)
	}
	checked := filepath.Join(k.dir, "lock-deposits.json")
	if _, log, err := k.coord(t, "check-deposits", "-config", charonCfg, "-order", filepath.Join(k.dir, "charon.order"), "-locked", k.setups[0],
		"-result", result, "-lock", lockFile, "-fork-version", fork, "-out", checked); err != nil {
		t.Fatalf("check-deposits -lock: %v\n%s", err, log)
	}
	t.Log("charon lock over 2 sessions signed by every runner; its deposits pass check-deposits against the order and the locked group")

	shims := filepath.Join(k.dir, "shims")
	if _, log, err := k.coord(t, "charon-shims", "-config", charonCfg, "-result", result, "-chain", c.path, "-out-dir", shims); err != nil {
		t.Fatalf("charon-shims: %v\n%s", err, log)
	}
	var cloud struct {
		Attestation struct {
			SetupSHA256 string `json:"setup_sha256"`
		} `json:"attestation"`
	}
	b, _ := os.ReadFile(filepath.Join(shims, "node1", "cloud.json"))
	if err := json.Unmarshal(b, &cloud); err != nil || cloud.Attestation.SetupSHA256 != hex.EncodeToString(k.setupHashes[1][:]) {
		t.Fatalf("node1 cloud.json does not pin runner 2's setup: %s", b)
	}
	if shimBin := os.Getenv("SHIM_BIN"); shimBin != "" {
		shimSigns(t, k, c, charon, shims, shimBin)
	} else {
		t.Log("SHIM_BIN not set: the shims were not started")
	}
	if image != "" {
		charonRunsLock(t, k, image, lockFile)
	} else {
		t.Log("CHARON_IMAGE not set: charon run was not tried")
	}

	// Restart runner 3: the orders and keys come back, no new wait.
	k.runners[2].stop()
	k.runners[2].start()
	waitReady(t, k.clients[2])
	st, err = adminOf(k.clients[2]).DKGOrder(ctx, dirkSigned)
	if err != nil || st.Outcome != dkgmsg.OrderKnown || st.Status != dkgmsg.OrderActive {
		t.Fatalf("after a restart: %+v %v", st, err)
	}
	if keys, err := k.clients[2].PublicKeys(ctx); err != nil || len(keys) != 4 {
		t.Fatalf("after a restart: %d keys, %v", len(keys), err)
	}
	keyOrigin(2, bothOrders)
	t.Log("runner 3 restarted: both orders known with their arrival, active; its 4 shares loaded, all 4 counted as generated under the two orders")
	scanForShares(t, k, &dkgOutput{Validators: append(slices.Clone(dirk.Validators), charon.Validators...)})
}

// charonENRs makes one ENR per node with stock charon, in node<i>/ of the
// cluster's folder.
func charonENRs(t *testing.T, k *dkgCluster, image string) []string {
	t.Helper()
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
	return enrs
}

// charonRunsLock adds each node's signature to the lock and runs stock
// charon on each node, verification on: each must load the lock and keep
// running.
func charonRunsLock(t *testing.T, k *dkgCluster, image, lockFile string) {
	t.Helper()
	_, nodeSign := tools(t)
	for i := range 3 {
		if msg, err := exec.Command(nodeSign, "-lock", lockFile, "-key", filepath.Join(k.dir, fmt.Sprintf("node%d", i), "charon-enr-private-key")).CombinedOutput(); err != nil {
			t.Fatalf("charon-node-sign node%d: %v\n%s", i, err, msg)
		}
	}
	raw, _ := os.ReadFile(lockFile)
	tag := make([]byte, 4)
	_, _ = rand.Read(tag)
	prefix := "c1-dkg-order-test-" + hex.EncodeToString(tag)
	t.Cleanup(func() {
		for i := range 3 {
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
		cmd := exec.Command("docker", "run", "--rm", "--name", fmt.Sprintf("%s-node%d", prefix, i), "--network", "none",
			"--user", fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid()), "-v", dir+":/data", image, "run",
			"--lock-file", "/data/cluster-lock.json", "--private-key-file", "/data/charon-enr-private-key", "--simnet-beacon-mock",
			"--p2p-relays", "", "--validator-api-address", "0.0.0.0:3600", "--monitoring-address", "0.0.0.0:3620", "--log-format", "console")
		var buf bytes.Buffer
		cmd.Stdout, cmd.Stderr = &buf, &buf
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		nodes = append(nodes, started{cmd, &buf})
	}
	time.Sleep(20 * time.Second)
	for i, n := range nodes {
		state, _ := exec.Command("docker", "inspect", "-f", "{{.State.Running}}", fmt.Sprintf("%s-node%d", prefix, i)).Output()
		_ = exec.Command("docker", "stop", "-t", "5", fmt.Sprintf("%s-node%d", prefix, i)).Run()
		_ = n.cmd.Wait()
		log := n.out.String()
		if strings.TrimSpace(string(state)) != "true" || charonMarkers(log) == "" {
			t.Fatalf("charon run on node%d: running=%s\n%s", i, state, tail(log, 40))
		}
		t.Logf("charon run node%d, lock verification on: still running after 20 s; %s", i, charonMarkers(log))
	}
}
