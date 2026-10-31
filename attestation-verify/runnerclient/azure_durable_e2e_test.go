//go:build !verifierselect

package runnerclient

// The Azure debug runner with the durable state copy
// (slashing-log/docs/durable-state.md): a group restart that loses the
// container's file system. The runner releases its Key Vault key again,
// restores the wrapped sealing key and the sealed share from the state copy
// before the mark log claim, and signs on from the log's mark without a new
// import. HANDOVER has its own tests (tee-signer/server, tests/e2e).
//
//	RUNNER_AZURE_DEBUG_BIN=build/x86_64/bin/runner-azure-debugimport go test -run TestE2EAzureRunnerDurable ./runnerclient

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"syscall"
	"testing"
	"time"

	remoteadmin "github.com/lidofinance/tee-signer/signer-admin/remote/admin"
	"github.com/lidofinance/tee-signer/signer-protocol"
)

func TestE2EAzureRunnerDurable(t *testing.T) {
	bin := os.Getenv("RUNNER_AZURE_DEBUG_BIN")
	if bin == "" {
		t.Skip("set RUNNER_AZURE_DEBUG_BIN to the Azure debug runner (build/<arch>/bin/runner-azure-debugimport)")
	}
	ca := newTestCA(t)
	env := newMAAEnv(t, mainKeySet(t))
	chain, genesis := fastChain(t)
	logDir := t.TempDir()
	hostA := goodHostData

	fakesA := newAzureFakes(t, env, tokenSpec{})
	fakesA.selfIssuer = true
	pool := x509.NewCertPool()
	pool.AddCert(fakesA.tlsCert)
	maaClient := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}, Timeout: 10 * time.Second}

	var sk [32]byte
	var pk backend.Pubkey
	hex.Decode(sk[:], []byte(lostStateSecret))
	hex.Decode(pk[:], []byte(lostStatePubkey))
	epochNow := func() uint64 { return (uint64(time.Now().Unix()) - genesis) / 2 }
	waitEpoch := func(e uint64) {
		for {
			now := time.Now()
			if epochNow() >= e && now.Nanosecond() > 300e6 && now.Nanosecond() < 800e6 {
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
	vote := func(source, target uint64, tag byte) *backend.AttestationData {
		return &backend.AttestationData{Slot: target * 2, BeaconBlockRoot: backend.Root{tag},
			Source: backend.Checkpoint{Epoch: source, Root: backend.Root{0x51}},
			Target: backend.Checkpoint{Epoch: target, Root: backend.Root{0x52}}}
	}
	// connect is a client with a signing certificate; admin is one with an
	// admin certificate, for the import message
	// (docs/protocol.md, "Client roles").
	dial := func(r azureRunner, hostData string, admin bool) *Client {
		cert, key := ca.issue(t, t.TempDir(), "client", time.Time{})
		if admin {
			cert, key = ca.issueAdmin(t, t.TempDir(), "admin")
		}
		c := Connection{Address: r.addr, ClientCert: cert, ClientKey: key,
			Attestation: Attestation{Verifier: VerifierAzureMAA, MAAHost: hostPort(fakesA.maa), CCEPolicySHA256: hostData,
				SetupSHA256: configPin(t, chain)}}
		cl, err := c.New(WithHTTPClient(maaClient), WithTimeout(15*time.Second))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { cl.Close() })
		return cl
	}
	connect := func(r azureRunner, hostData string) *Client { return dial(r, hostData, false) }
	admin := func(r azureRunner, hostData string) *remoteadmin.Client {
		return remoteadmin.Wrap(dial(r, hostData, true).Client)
	}
	sign := func(cl *Client, m backend.Message) error {
		_, err := cl.Sign(ctx, backend.SignRequest{Pubkey: pk, Message: m, Domain: fastChainAttester()})
		return err
	}
	stop := func(r azureRunner) {
		r.cmd.Process.Signal(syscall.SIGTERM)
		select {
		case <-r.done:
		case <-time.After(10 * time.Second):
			t.Fatal("the runner did not stop")
		}
	}
	stateA := filepath.Join(t.TempDir(), "state")
	flagsA := []string{"-config", chain, "-state-dir", stateA, "-mark-store", "file:" + logDir, "-mark-signer", "signer-1",
		"-state-store", "file:" + logDir}

	// Group A: import, sign, lose the file system, come back with the share.
	a := waitListening(t, launchAzureRunner(t, bin, ca, fakesA, flagsA...))
	cl := connect(a, hostA)
	if _, err := admin(a, hostA).ImportShareSealed(ctx, backend.ImportShareRequest{Pubkey: pk, Secret: sk, Index: 7}, pk, cl.Verify); err != nil {
		t.Fatal(err)
	}
	e0 := epochNow() + 3 // above the restart floor (clock epoch + 2)
	s0 := e0 - 1
	for e := e0; e < e0+2; e++ {
		waitEpoch(e)
		if err := sign(cl, vote(s0, e, 0x10)); err != nil {
			t.Fatalf("group A, target %d: %v", e, err)
		}
	}
	stop(a)
	if err := os.RemoveAll(stateA); err != nil {
		t.Fatal(err)
	}
	a = waitListening(t, launchAzureRunner(t, bin, ca, fakesA, flagsA...))
	cl = connect(a, hostA)
	h, err := cl.Health(ctx)
	if err != nil || h.Validators != 1 {
		log, _ := os.ReadFile(a.logPath)
		t.Fatalf("after the file system was lost: %+v %v, want the share back from the state copy:\n%s", h, err, log)
	}
	e1 := epochNow() + 3
	waitEpoch(e1)
	if err := sign(cl, vote(s0-1, e1, 0x30)); err == nil {
		t.Fatal("after the restart a vote with a source below the log's signed")
	}
	if err := sign(cl, vote(s0, e1, 0x20)); err != nil {
		t.Fatalf("after the restart, target %d: %v", e1, err)
	}
	log, _ := os.ReadFile(a.logPath)
	if !regexp.MustCompile(`state copy: newest commit.*restored=[1-9]`).Match(log) {
		t.Fatalf("no restore line:\n%s", log)
	}
	t.Logf("file system lost: the share came back from the state copy, health %q", h.Record)
}
