package e2e

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/governance/importorder"
	"github.com/lidofinance/tee-signer/governance/setupwire"
	"github.com/lidofinance/tee-signer/signer-core/core"
	"github.com/lidofinance/tee-signer/signer-core/software"
	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/remote"
	"github.com/lidofinance/tee-signer/signer-protocol/sealedimport"
	"github.com/lidofinance/tee-signer/signer-protocol/wire"
	wireadmin "github.com/lidofinance/tee-signer/signer-protocol/wire/admin"
	"github.com/lidofinance/tee-signer/slashing-log"
)

// configApprover is test approver id: a key from a fixed seed.
func configApprover(id byte) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{id}, 32))
}

// importOrder is an import order to the runner of setup s (hash), for
// pk from a t-of-n split whose commitments are commitments, share index
// idx, signed by approvers 1 and 2 (configApprover).
func importOrder(t *testing.T, s *setupwire.Setup, hash [32]byte, pk backend.Pubkey, tt, n, idx uint8, commitments []backend.Pubkey) []byte {
	t.Helper()
	b := importorder.Body{ClusterID: s.ClusterID, ChainHash: s.Chain.Hash(), Target: hash, NotAfter: uint64(time.Now().Unix()) + 3600,
		T: tt, N: n, ShareIndex: idx, Validators: []importorder.Entry{{Pubkey: pk, CommitmentsHash: importorder.CommitmentsHash(commitments)}}}
	enc, err := b.Encode()
	if err != nil {
		t.Fatal(err)
	}
	o := importorder.Order{Body: b}
	for _, id := range []byte{1, 2} {
		o.Approvals = append(o.Approvals, setupwire.Approval{Position: id - 1, Signature: importorder.SignBody(configApprover(id), enc)})
	}
	raw, err := o.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// signConfigUpdate signs body by approvers 1 and 2 of ids (positions 0 and
// 1 of the set), or by the approvers of ids at positions 0 on.
func signConfigUpdate(t *testing.T, body *setupwire.UpdateBody, ids ...byte) []byte {
	t.Helper()
	u := setupwire.Update{Body: *body}
	for pos, id := range ids {
		sig, err := body.Sign(configApprover(id))
		if err != nil {
			t.Fatal(err)
		}
		u.Approvals = append(u.Approvals, setupwire.Approval{Position: uint8(pos), Signature: sig})
	}
	raw, err := u.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// e2eSalts are n fresh salts for an update body.
func e2eSalts(t *testing.T, n int) setupwire.Salts {
	t.Helper()
	s, err := setupwire.NewSalts(rand.Reader, n)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// mustSetupHash is setup_hash of the encoded setup raw.
func mustSetupHash(t *testing.T, raw []byte) [32]byte {
	t.Helper()
	h, err := setupwire.SetupHash(raw)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// sendConfigUpdate sends CONFIG_UPDATE over mutual TLS with the client
// certificate of cliCfg. The runner's own certificate is not checked here:
// IDENTITY over the attested client checks the runner.
func sendConfigUpdate(t *testing.T, addr string, cliCfg *tls.Config, raw []byte) (uint8, *backend.SetupState, error) {
	t.Helper()
	cfg := adminConfig(cliCfg).Clone()
	cfg.InsecureSkipVerify = true
	conn, err := tls.Dial("tcp", strings.TrimPrefix(addr, "tcp:"), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	p, err := wireadmin.EncodeConfigUpdate(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := wire.WriteFrame(conn, wire.Frame{Type: wireadmin.TypeConfigUpdate, ID: 1, Payload: p}); err != nil {
		t.Fatal(err)
	}
	f, err := wire.ReadFrame(conn)
	if err != nil || f.Type != wireadmin.TypeConfigUpdate|wire.ResponseFlag || f.ID != 1 {
		t.Fatalf("answer %v %d: %v", f.Type, f.ID, err)
	}
	body, err := wire.DecodeResponse(f.Payload)
	if err != nil {
		return 0, nil, err
	}
	return wireadmin.DecodeConfigUpdateResponse(body)
}

// newestRecord parses the newest record of the setup's mark log in dir.
func newestRecord(t *testing.T, dir string, s *setupwire.Setup, hash [32]byte) *markstore.Record {
	t.Helper()
	logDir := filepath.Join(dir, "marks", "marks", hex.EncodeToString(hash[:]), s.SignerName)
	ents, err := os.ReadDir(logDir)
	if err != nil {
		t.Fatal(err)
	}
	var newest string
	for _, e := range ents {
		if !strings.HasPrefix(e.Name(), ".tmp-") && e.Name() > newest {
			newest = e.Name()
		}
	}
	b, err := os.ReadFile(filepath.Join(logDir, newest))
	if err != nil {
		t.Fatal(err)
	}
	r, err := markstore.Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// TestE2EConfigUpdate: a dev runner with a setup takes approver-signed
// config updates over CONFIG_UPDATE. A locked update (a new fee recipient)
// waits out the setup's 3 s time lock, then signs; an open update (a new
// fork) is in force at once. An update with one signature is refused, the
// same update twice is known. The runner writes the record that shows them
// in force, and a restart keeps them.
func TestE2EConfigUpdate(t *testing.T) {
	dir := t.TempDir()
	caFile, cliCfg := testPKI(t, dir, "config")
	s, err := setupwire.DecodeSetup(setupForTest(t, dir, caFile))
	if err != nil {
		t.Fatal(err)
	}
	s.Locked.Approvers = setupwire.ApproverSet{ApprovalsNeeded: 2}
	for id := byte(1); id <= 3; id++ {
		s.Locked.Approvers.Keys = append(s.Locked.Approvers.Keys, [32]byte(configApprover(id).Public().(ed25519.PublicKey)))
	}
	lock := uint64(3)
	s.Locked.ChangeDelaySeconds = &lock
	raw, err := s.Encode()
	if err != nil {
		t.Fatal(err)
	}
	hash, _ := setupwire.SetupHash(raw)
	setupFile := filepath.Join(dir, "setup.bin")
	if err := os.WriteFile(setupFile, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	addr := fmt.Sprintf("tcp:127.0.0.1:%d", freePort(t))
	args := []string{"-platform", "dev", "-state-dir", filepath.Join(dir, "state"), "-listen", addr, "-setup", "file:" + setupFile}
	connect := func() *remote.Client {
		cl, err := newTLSClient(addr, cliCfg, remote.DevVerifier, remote.WithTimeout(5*time.Second))
		if err != nil {
			t.Fatal(err)
		}
		return cl
	}
	first := startSetupRunner(t, filepath.Join(dir, "first.log"), nil, args...)
	cl := connect()
	waitReady(t, cl)

	sk, _ := software.NewSecret()
	pk, _ := core.PubkeyOf(sk)
	req := &backend.SealedImportRequest{Pubkey: pk, SharePubkey: pk, Index: 3,
		Order: importOrder(t, s, hash, pk, 1, 1, 1, []backend.Pubkey{pk}), T: 1, N: 1, ShareIndex: 1, Commitments: []backend.Pubkey{pk}}
	if req.Sealed, err = sealedimport.Seal(devIdentity(t, cl), req, &sk); err != nil {
		t.Fatal(err)
	}
	if _, err := adminOf(cl).ImportSealed(ctx, req); err != nil {
		t.Fatal(err)
	}
	fee := backend.Address{0x55}
	register := func(cl *remote.Client) error {
		m := &backend.ValidatorRegistration{FeeRecipient: fee, GasLimit: 36_000_000, Timestamp: uint64(time.Now().Unix()), Pubkey: pk}
		d := backend.ComputeDomain(backend.DomainApplicationBuilder, s.Chain.GenesisForkVersion, backend.Root{})
		_, err := cl.Sign(ctx, backend.SignRequest{Pubkey: pk, Message: m, Domain: d})
		return err
	}
	wantRefused(t, register(cl), backend.StatusPolicyFeeRecipient)

	// A locked update: pending for the time lock, then in force.
	lh, _ := s.GroupHash(setupwire.GroupLocked)
	lb := &setupwire.UpdateBody{ClusterID: s.ClusterID, ChainHash: s.Chain.Hash(), Group: setupwire.GroupLocked, Version: 1,
		PrevHash: lh, ActivateAt: uint64(time.Now().Unix()), Locked: &s.Locked, Salts: e2eSalts(t, setupwire.NumLockedLeaves)}
	nextLocked := s.Locked
	nextLocked.AllowedFeeRecipients = append(append([]backend.Address(nil), s.Locked.AllowedFeeRecipients...), fee)
	lb.Locked = &nextLocked
	lockedHash, _ := lb.Hash()
	sent := uint64(time.Now().Unix())
	outcome, st, err := sendConfigUpdate(t, addr, cliCfg, signConfigUpdate(t, lb, 1, 2))
	if err != nil || outcome != wireadmin.ConfigAccepted {
		t.Fatalf("locked update: %d %v", outcome, err)
	}
	if p := st.Locked.Pending; p.Version != 1 || p.Hash != lockedHash || p.EffectiveAt < sent+lock || p.EffectiveAt > sent+lock+2 {
		t.Fatalf("locked update pending %+v, sent at %d", p, sent)
	}
	wantRefused(t, register(cl), backend.StatusPolicyFeeRecipient)
	deadline := time.Now().Add(15 * time.Second)
	for devIdentity(t, cl).State.Locked != (backend.ConfigGroup{Version: 1, Hash: lockedHash}) {
		if time.Now().After(deadline) {
			t.Fatal("the locked update did not come into force")
		}
		time.Sleep(200 * time.Millisecond)
	}
	if err := register(cl); err != nil {
		t.Fatalf("after the time lock: %v", err)
	}

	// One signature is not k; the refusal names why.
	lb2 := *lb
	lb2.Version, lb2.PrevHash = 2, lockedHash
	_, _, err = sendConfigUpdate(t, addr, cliCfg, signConfigUpdate(t, &lb2, 1))
	if r := wantRefused(t, err, backend.StatusBadRequest); !strings.Contains(r.Detail, "approvals_needed is 2") {
		t.Fatalf("refusal %q", r.Detail)
	}

	// An open update: a fork 10 epochs ahead, in force at once; the same
	// update again is known.
	oh, _ := s.GroupHash(setupwire.GroupOpen)
	epoch := (uint64(time.Now().Unix()) - s.Chain.GenesisTime) / (s.Chain.SecondsPerSlot * s.Chain.SlotsPerEpoch)
	nextOpen := setupwire.Open{ForkSchedule: append(append([]setupwire.Fork(nil), s.Open.ForkSchedule...),
		setupwire.Fork{Epoch: epoch + 10, Version: backend.Version{0x06, 0, 0, 0x10}}), GloasForkEpoch: s.Open.GloasForkEpoch}
	ob := &setupwire.UpdateBody{ClusterID: s.ClusterID, ChainHash: s.Chain.Hash(), Group: setupwire.GroupOpen, Version: 1,
		PrevHash: oh, ActivateAt: uint64(time.Now().Unix()), Open: &nextOpen, Salts: e2eSalts(t, setupwire.NumOpenLeaves)}
	openHash, _ := ob.Hash()
	openRaw := signConfigUpdate(t, ob, 1, 2)
	outcome, st, err = sendConfigUpdate(t, addr, cliCfg, openRaw)
	if err != nil || outcome != wireadmin.ConfigAccepted || st.Open != (backend.ConfigGroup{Version: 1, Hash: openHash}) {
		t.Fatalf("open update: %d %+v %v", outcome, st, err)
	}
	if outcome, _, err := sendConfigUpdate(t, addr, cliCfg, openRaw); err != nil || outcome != wireadmin.ConfigKnown {
		t.Fatalf("the same update again: %d %v", outcome, err)
	}

	// The runner writes the record that shows both in force.
	deadline = time.Now().Add(10 * time.Second)
	for {
		r := newestRecord(t, dir, s, hash)
		if r.State.Locked.Version == 1 && r.State.Open.Version == 1 && r.State.Locked.Pending == nil && r.State.Open.Pending == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the newest record holds %+v", r.State)
		}
		time.Sleep(200 * time.Millisecond)
	}
	cl.Close()
	first.Process.Signal(syscall.SIGTERM)
	first.Wait()

	// After a restart both are in force, and the fee recipient signs.
	startSetupRunner(t, filepath.Join(dir, "second.log"), nil, args...)
	cl = connect()
	defer cl.Close()
	if h := waitReady(t, cl); h.Validators != 1 {
		t.Fatalf("after the restart: %d validators", h.Validators)
	}
	want := backend.SetupState{SetupHash: hash, Locked: backend.ConfigGroup{Version: 1, Hash: lockedHash},
		Open: backend.ConfigGroup{Version: 1, Hash: openHash}, ApproverSetHash: s.Locked.Approvers.Hash(),
		KeyOrigin: backend.KeyOrigin{Imported: 1}}
	if id := devIdentity(t, cl); id.State != want {
		t.Fatalf("after the restart %+v, want %+v", id.State, want)
	}
	if err := register(cl); err != nil {
		t.Fatalf("after the restart: %v", err)
	}
	log, _ := os.ReadFile(filepath.Join(dir, "first.log"))
	for _, line := range []string{"config update accepted", "config: locked values in force", "config: record shows the config in force", "config update refused"} {
		if !strings.Contains(string(log), line) {
			t.Fatalf("the log lacks %q", line)
		}
	}
	t.Logf("locked update in force after its %d s time lock, open update at once, both kept over a restart", lock)
}
