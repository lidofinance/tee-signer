package e2e

import (
	"bytes"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/governance/setupwire"
	"github.com/lidofinance/tee-signer/signer-core/software"
	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/remote"
)

// Helpers of the handover gate (handover_gate_test.go): runners with
// setups, the tools' client files, and a slashing checker.

// hoodiFork is the genesis fork version of Hoodi, a network that is not
// mainnet, so the setups below run under the testnet rules of the default
// build.
var hoodiFork = backend.Version{0x10, 0x00, 0x09, 0x10}

// hoodiChain is the test chain with Hoodi's genesis fork version.
func hoodiChain(t *testing.T) chain {
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

const withdrawal = "0x8943545177806ed17b9f23f0a21ee5948ecaa776"

// writeClientPair writes the client certificate (with its intermediate)
// and key of cfg's admin twin as PEM files: the tools that read them (the
// handover tools, signer-admin) send admin messages.
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

// orderTimeLock is the setups' time lock: on the dev platform an order
// waits it out (a cloud runner waits the images minimum, a week).
const orderTimeLock = 2

// orderSetupFor is a single-mode dev setup (setup-dev-single) of signer
// name in cluster for chain c: the chain and safety values of c, the CA of
// caFile, the stores in dir, the config approvers 1 to 3 with k = 2, the
// time lock timeLock (nil: none named, the image default), compounding
// credentials to withdrawal and 32 ETH deposits.
func orderSetupFor(t *testing.T, c chain, dir, caFile, name string, cluster [32]byte, timeLock *uint64) []byte {
	t.Helper()
	sample, err := os.ReadFile(filepath.Join("..", "..", "governance", "setupwire", "testdata", "setup-dev-single.bin"))
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
	// Compounding (0x02) withdrawal credentials to the address.
	addr, err := hex.DecodeString(strings.TrimPrefix(withdrawal, "0x"))
	if err != nil || len(addr) != 20 {
		t.Fatalf("withdrawal address: %v", err)
	}
	l.WithdrawalCredentials = backend.Root{0x02}
	copy(l.WithdrawalCredentials[12:], addr)
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

// slashCheck is the slashing checker: per signer position and validator,
// every message each runner of that position signed. They hold the same
// key, so together they must never sign a double vote, a surround or two
// blocks of one slot.
type slashCheck struct {
	mu   sync.Mutex
	atts map[slashKey][]slashAtt
	blks map[slashKey]map[uint64]backend.Root
	sigs int
	// blocks counts the block signatures among sigs.
	blocks int
	bad    []string
}

type slashKey struct {
	signer int
	pk     backend.Pubkey
}

type slashAtt struct {
	source, target uint64
	root           backend.Root
}

func (c *slashCheck) add(signer int, pk backend.Pubkey, m backend.Message, root backend.Root, who string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sigs++
	k := slashKey{signer, pk}
	switch v := m.(type) {
	case *backend.AttestationData:
		a := slashAtt{v.Source.Epoch, v.Target.Epoch, root}
		for _, o := range c.atts[k] {
			switch {
			case o.target == a.target && o.root != a.root:
				c.bad = append(c.bad, fmt.Sprintf("%s signer %d validator %s: double vote at target %d", who, signer, pk.String()[:12], a.target))
			case o.source < a.source && a.target < o.target, a.source < o.source && o.target < a.target:
				c.bad = append(c.bad, fmt.Sprintf("%s signer %d validator %s: (%d,%d) and (%d,%d) surround", who, signer, pk.String()[:12],
					o.source, o.target, a.source, a.target))
			}
		}
		c.atts[k] = append(c.atts[k], a)
	case *backend.BeaconBlockHeader:
		c.blocks++
		if c.blks[k] == nil {
			c.blks[k] = map[uint64]backend.Root{}
		}
		if o, ok := c.blks[k][v.Slot]; ok && o != root {
			c.bad = append(c.bad, fmt.Sprintf("%s signer %d validator %s: two blocks at slot %d", who, signer, pk.String()[:12], v.Slot))
		}
		c.blks[k][v.Slot] = root
	}
}

// lastAtt is the attestation of the highest target signer signed for pk.
func (c *slashCheck) lastAtt(signer int, pk backend.Pubkey) (slashAtt, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var best slashAtt
	as := c.atts[slashKey{signer, pk}]
	for _, a := range as {
		if a.target > best.target {
			best = a
		}
	}
	return best, len(as) > 0
}

// peerProc is one runner process with its unix socket.
type peerProc struct {
	r    *runner
	addr string // tcp, mutual TLS (the tools)
	sock string // unix, plain (the test)
	cl   *remote.Client
}

// startPeerAt starts a runner with its mutual TLS address addr and a unix
// socket.
func startPeerAt(t *testing.T, bin, name, dir, setupFile, addr string) *peerProc {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	p := &peerProc{addr: addr, sock: "unix:" + filepath.Join(dir, "runner.sock")}
	p.r = &runner{t: t, name: name, bin: bin, stateDir: filepath.Join(dir, "state"), logPath: filepath.Join(dir, name+".log")}
	p.r.args = []string{"-platform", "dev", "-setup", "file:" + setupFile, "-state-dir", p.r.stateDir, "-listen", p.addr + "," + p.sock}
	t.Cleanup(func() {
		p.r.stop()
		b, _ := os.ReadFile(p.r.logPath)
		if d := os.Getenv("HANDOVER_LOG_DIR"); d != "" {
			// The whole log of every runner, kept past the test's folder.
			if err := os.WriteFile(filepath.Join(d, name+".log"), b, 0o600); err != nil {
				t.Log(err)
			}
		}
		if t.Failed() {
			if len(b) > 20000 {
				b = b[len(b)-20000:]
			}
			t.Logf("---- %s log (end) ----\n%s", name, b)
		}
	})
	p.start(t)
	return p
}

// start starts the runner and waits until it answers PUBLIC_KEYS on its
// socket.
func (p *peerProc) start(t *testing.T) {
	t.Helper()
	p.r.start()
	var err error
	if p.cl, err = remote.New(p.sock, remote.WithTimeout(60*time.Second)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { p.cl.Close() })
	deadline := time.Now().Add(30 * time.Second)
	for {
		if _, err = p.cl.PublicKeys(ctx); err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s does not answer: %v", p.r.name, err)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func (p *peerProc) restart(t *testing.T) {
	t.Helper()
	p.r.stop()
	p.cl.Close()
	p.start(t)
}

// runTool runs a tool; its stdout and stderr go to the log.
func runTool(t *testing.T, bin string, args ...string) (string, error) {
	t.Helper()
	cmd := exec.Command(bin, args...)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	start := time.Now()
	err := cmd.Run()
	t.Logf("%s %s (%v):\n%s", filepath.Base(bin), args[0], time.Since(start).Round(time.Millisecond), strings.TrimSpace(out.String()))
	return out.String(), err
}
