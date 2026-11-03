package e2e

import (
	"bytes"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/governance/setupwire"
	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/remote"
)

// Helpers for runners started with a setup and for the tools' client
// files.

const withdrawal = "0x8943545177806ed17b9f23f0a21ee5948ecaa776"

// writeClientPair writes the client certificate (with its intermediate)
// and key of cfg's admin twin as PEM files: the tools that read them
// (signer-admin) send admin messages.
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

// devSetupFor is a single-mode dev setup (setup-dev-single) of signer
// name in cluster for chain c: the chain and safety values of c, the CA of
// caFile, the stores in dir, the config approvers 1 to 3 with k = 2, the
// time lock timeLock (nil: none named, the image default), compounding
// credentials to withdrawal and 32 ETH deposits.
func devSetupFor(t *testing.T, c chain, dir, caFile, name string, cluster [32]byte, timeLock *uint64) []byte {
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
