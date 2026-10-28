package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/signer-core/core"
	"github.com/lidofinance/tee-signer/signer-core/dkgmath"
	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/dkgmsg"
	"github.com/lidofinance/tee-signer/tee-signer/charonlock"
	"github.com/lidofinance/tee-signer/tee-signer/keygen"
)

const (
	testWithdrawal = "0x8943545177806ed17b9f23f0a21ee5948ecaa776"
	thirtyTwo      = uint64(32_000_000_000)
)

var testFork = backend.Version{0x10, 0x00, 0x00, 0x38}

// fixture is a policy, a keygen result and the secrets behind it: what the
// runners would hold, made here in one place for the test only.
type fixture struct {
	dir        string
	policyPath string
	resultPath string
	pol        *keygen.Policy
	res        *Result
	secrets    [][32]byte
	shares     [][]core.Share
	wc         backend.Root
}

func newFixture(t *testing.T, setup string, count int) *fixture {
	t.Helper()
	f := &fixture{dir: t.TempDir()}
	var b strings.Builder
	b.WriteString(`{"version":1,"threshold":2,"participants":[`)
	for i := range 3 {
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, `{"name":"op%d","operator_key":"%s","attestation":{"verifier":"dev"}}`, i+1, strings.Repeat(fmt.Sprintf("%02x", i+1), 32))
	}
	b.WriteString(`],"setup":` + setup + "}\n")
	f.policyPath = filepath.Join(f.dir, "policy.json")
	if err := os.WriteFile(f.policyPath, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	pol, hash, err := keygen.ParsePolicy([]byte(b.String()), "dev")
	if err != nil {
		t.Fatal(err)
	}
	f.pol = pol
	f.wc, _ = pol.WithdrawalCredentials()
	f.res = &Result{PolicySHA256: hex.EncodeToString(hash[:]), Threshold: 2}
	for i := range 3 {
		f.res.Participants = append(f.res.Participants, Participant{Name: fmt.Sprintf("op%d", i+1), ShareID: i + 1})
	}
	for range count {
		s, err := core.NewSecret()
		if err != nil {
			t.Fatal(err)
		}
		sh, err := core.Split(s, 2, 3)
		if err != nil {
			t.Fatal(err)
		}
		pk, _ := core.PubkeyOf(s)
		v := Validator{Pubkey: hex0x(pk[:])}
		for _, x := range sh {
			p, _ := core.PubkeyOf(x.Secret)
			v.PublicShares = append(v.PublicShares, hex0x(p[:]))
		}
		f.secrets, f.shares = append(f.secrets, s), append(f.shares, sh)
		f.res.Validators = append(f.res.Validators, v)
	}
	f.resultPath = filepath.Join(f.dir, "dkg-result.json")
	if err := writeJSON(f.resultPath, f.res); err != nil {
		t.Fatal(err)
	}
	return f
}

// configPath writes a coordinator config with the policy and three
// runners, for the commands that read one.
func (f *fixture) configPath(t *testing.T) string {
	t.Helper()
	p := filepath.Join(f.dir, "coordinator.json")
	cfg := `{"policy":"policy.json","runners":[{"address":"tcp:127.0.0.1:1"},{"address":"tcp:127.0.0.1:2"},{"address":"tcp:127.0.0.1:3"}]}`
	if err := os.WriteFile(p, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// runnersHoldFixture makes check-deposits see runners that hold the
// fixture's shares, each the one at its position, for this test.
func (f *fixture) runnersHoldFixture(t *testing.T) {
	t.Helper()
	held := make([][]backend.ValidatorKey, 3)
	for v := range f.secrets {
		for i, sh := range f.shares[v] {
			p, _ := core.PubkeyOf(sh.Secret)
			held[i] = append(held[i], backend.ValidatorKey{Pubkey: f.pubkey(v), SharePubkey: p, Index: backend.IndexUnknown})
		}
	}
	setRunners(t, func(_ context.Context, cfg *Config, _ *keygen.Policy, res *Result, _ time.Duration) error {
		for i := range cfg.Runners {
			if err := heldBy(res, i, held[i]); err != nil {
				return fmt.Errorf("runner %d: %w", i+1, err)
			}
		}
		return nil
	})
}

func setRunners(t *testing.T, f func(context.Context, *Config, *keygen.Policy, *Result, time.Duration) error) {
	old := checkRunners
	checkRunners = f
	t.Cleanup(func() { checkRunners = old })
}

func (f *fixture) pubkey(v int) backend.Pubkey {
	pk, _ := core.PubkeyOf(f.secrets[v])
	return pk
}

// deposit is validator v's deposit, signed with the validator key.
func (f *fixture) deposit(t *testing.T, v int, wc backend.Root, amount uint64, fork backend.Version) DepositData {
	t.Helper()
	pk := f.pubkey(v)
	root := charonlock.DepositSigningRoot(pk, wc, amount, fork)
	sig, err := dkgmath.Sign(&f.secrets[v], root[:])
	if err != nil {
		t.Fatal(err)
	}
	dr := charonlock.DepositDataRoot(pk, wc, amount, sig)
	return DepositData{Pubkey: hex.EncodeToString(pk[:]), WithdrawalCredentials: hex.EncodeToString(wc[:]), Amount: amount,
		Signature: hex.EncodeToString(sig[:]), DepositDataRoot: hex.EncodeToString(dr[:]), ForkVersion: hex.EncodeToString(fork[:])}
}

func (f *fixture) deposits(t *testing.T) []DepositData {
	var out []DepositData
	for v := range f.secrets {
		out = append(out, f.deposit(t, v, f.wc, thirtyTwo, testFork))
	}
	return out
}

const dirkSetupJSON = `{"path":"dirk","withdrawal_address":"` + testWithdrawal + `","deposit_amounts_gwei":[32000000000]}`

func TestCheckDepositsGood(t *testing.T) {
	f := newFixture(t, dirkSetupJSON, 3)
	in := f.deposits(t)
	// Out of order in, result order out.
	in[0], in[2] = in[2], in[0]
	out, err := checkDeposits(in, f.pol, f.res, testFork, thirtyTwo)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 3 {
		t.Fatalf("%d deposits", len(out))
	}
	for v, d := range out {
		pk := f.pubkey(v)
		if d.Pubkey != hex.EncodeToString(pk[:]) || d.Amount != thirtyTwo || d.ForkVersion != "10000038" {
			t.Fatalf("deposit %d: %+v", v, d)
		}
		if d.WithdrawalCredentials[:2] != "02" || !strings.HasSuffix(d.WithdrawalCredentials, testWithdrawal[2:]) {
			t.Fatalf("deposit %d credentials %s", v, d.WithdrawalCredentials)
		}
		mr := charonlock.DepositMessageRoot(pk, f.wc, thirtyTwo)
		if d.DepositMessageRoot != hex.EncodeToString(mr[:]) || len(d.DepositDataRoot) != 64 {
			t.Fatalf("deposit %d roots", v)
		}
	}
}

func TestCheckDepositsRefusals(t *testing.T) {
	f := newFixture(t, `{"path":"dirk","withdrawal_address":"`+testWithdrawal+`","deposit_amounts_gwei":[32000000000,1000000000]}`, 2)
	other := newFixture(t, dirkSetupJSON, 1)
	addr, _ := charonlock.Address("0x1111111111111111111111111111111111111111")
	otherWC := charonlock.WithdrawalCredentials(addr, true)
	var policyAddr [20]byte
	copy(policyAddr[:], f.wc[12:])
	type change func(in []DepositData) []DepositData
	tests := []struct {
		name   string
		change change
		amount uint64
		want   string
	}{
		{"another withdrawal address", func(in []DepositData) []DepositData {
			in[1] = f.deposit(t, 1, otherWC, thirtyTwo, testFork)
			return in
		}, thirtyTwo, "withdrawal credentials"},
		{"0x01 credentials to the policy's address", func(in []DepositData) []DepositData {
			in[1] = f.deposit(t, 1, charonlock.WithdrawalCredentials(policyAddr, false), thirtyTwo, testFork)
			return in
		}, thirtyTwo, "withdrawal credentials"},
		{"an amount the policy does not allow", func(in []DepositData) []DepositData {
			in[0] = f.deposit(t, 0, f.wc, 31_000_000_000, testFork)
			return in
		}, thirtyTwo, "not among the policy's"},
		{"a check for an amount the policy does not allow", func(in []DepositData) []DepositData { return in }, 2_048_000_000_000, "not among the policy's"},
		{"signed with another fork version", func(in []DepositData) []DepositData {
			in[0] = f.deposit(t, 0, f.wc, thirtyTwo, backend.Version{0x10, 0, 0, 0x39})
			in[0].ForkVersion = ""
			return in
		}, thirtyTwo, "does not verify"},
		{"signature of another key", func(in []DepositData) []DepositData {
			in[0].Signature = in[1].Signature
			in[0].DepositDataRoot = ""
			return in
		}, thirtyTwo, "does not verify"},
		{"a key outside the result", func(in []DepositData) []DepositData {
			return append(in, other.deposit(t, 0, f.wc, thirtyTwo, testFork))
		}, thirtyTwo, "not in the result"},
		{"one key without a deposit", func(in []DepositData) []DepositData { return in[:1] }, thirtyTwo, "no deposit of 32000000000 gwei for validator 1"},
		{"two deposits for one key", func(in []DepositData) []DepositData { return append(in, in[0]) }, thirtyTwo, "a second deposit"},
		{"a deposit_data_root that does not recompute", func(in []DepositData) []DepositData {
			in[0].DepositDataRoot = strings.Repeat("00", 32)
			return in
		}, thirtyTwo, "deposit_data_root"},
		{"a fork_version field of another chain", func(in []DepositData) []DepositData {
			in[0].ForkVersion = "10000039"
			return in
		}, thirtyTwo, "fork_version"},
		{"a short signature", func(in []DepositData) []DepositData {
			in[0].Signature = in[0].Signature[:100]
			return in
		}, thirtyTwo, "want 96 bytes"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := checkDeposits(tc.change(f.deposits(t)), f.pol, f.res, testFork, tc.amount)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
		})
	}
	// Deposits of the policy's other amount are left out, not refused.
	in := append(f.deposits(t), f.deposit(t, 0, f.wc, 1_000_000_000, testFork))
	if out, err := checkDeposits(in, f.pol, f.res, testFork, thirtyTwo); err != nil || len(out) != 2 {
		t.Fatalf("with a 1 ETH deposit too: %d, %v", len(out), err)
	}
}

// buildLock makes a Charon lock of the fixture's keys as charon-lock does:
// deposits and registrations under the validator keys, every share's
// signature over the lock hash.
func buildLock(t *testing.T, f *fixture, withdrawal string, fork backend.Version) *charonlock.Lock {
	t.Helper()
	c := &charonlock.Cluster{Name: "t", UUID: "0194FDC2-FA2F-4CC0-81D3-FF12045B73C8", Timestamp: "2026-10-20T10:00:00Z",
		ENRs: []string{"enr:-a", "enr:-b", "enr:-c"}, Threshold: 2, ForkVersion: fork,
		FeeRecipient: "0x000000000000000000000000000000000000dEaD", WithdrawalAddress: withdrawal, Compounding: true,
		GasLimit: 60_000_000, RegistrationTimestamp: 1_700_000_000}
	gks, shares, err := f.res.Keys()
	if err != nil {
		t.Fatal(err)
	}
	l, err := charonlock.NewLock(c, gks, shares)
	if err != nil {
		t.Fatal(err)
	}
	addr, _ := charonlock.Address(withdrawal)
	wc := charonlock.WithdrawalCredentials(addr, true)
	for v := range gks {
		root := charonlock.DepositSigningRoot(gks[v], wc, thirtyTwo, fork)
		sig, _ := dkgmath.Sign(&f.secrets[v], root[:])
		l.AddDeposit(v, wc, thirtyTwo, sig)
		reg, err := l.RegistrationFor(v, c)
		if err != nil {
			t.Fatal(err)
		}
		rr, err := charonlock.RegistrationSigningRoot(reg, fork)
		if err != nil {
			t.Fatal(err)
		}
		rs, _ := dkgmath.Sign(&f.secrets[v], rr[:])
		l.SetRegistration(v, reg, rs)
	}
	lh, err := l.SetLockHash()
	if err != nil {
		t.Fatal(err)
	}
	var all []backend.Signature
	for v := range gks {
		for _, s := range f.shares[v] {
			sig, _ := dkgmath.Sign(&s.Secret, lh[:])
			all = append(all, sig)
		}
	}
	agg, err := dkgmath.AggregateSignatures(all)
	if err != nil {
		t.Fatal(err)
	}
	l.SignatureAggregate = agg[:]
	if err := l.VerifyBLS(); err != nil {
		t.Fatal(err)
	}
	return l
}

func writeLock(t *testing.T, dir string, l *charonlock.Lock) string {
	t.Helper()
	b, err := l.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, fmt.Sprintf("lock-%d.json", len(b)))
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

const charonSetupJSON = `{"path":"charon","withdrawal_address":"` + testWithdrawal + `","deposit_amounts_gwei":[32000000000],"charon_enrs":["enr:-a","enr:-b","enr:-c"]}`

func TestCheckDepositsFromLock(t *testing.T) {
	f := newFixture(t, charonSetupJSON, 2)
	path := writeLock(t, f.dir, buildLock(t, f, testWithdrawal, testFork))
	in, err := lockDeposits(path, f.pol, f.res, testFork)
	if err != nil {
		t.Fatal(err)
	}
	out, err := checkDeposits(in, f.pol, f.res, testFork, thirtyTwo)
	if err != nil || len(out) != 2 {
		t.Fatalf("%d, %v", len(out), err)
	}

	if _, err := lockDeposits(path, f.pol, f.res, backend.Version{0x10, 0, 0, 0x39}); err == nil || !strings.Contains(err.Error(), "fork version") {
		t.Fatalf("lock of another chain: %v", err)
	}
	// A lock made right for another withdrawal address.
	other := writeLock(t, f.dir, buildLock(t, f, "0x1111111111111111111111111111111111111111", testFork))
	if _, err := lockDeposits(other, f.pol, f.res, testFork); err == nil || !strings.Contains(err.Error(), "withdraws to") {
		t.Fatalf("lock with another withdrawal address: %v", err)
	}
	// A lock of other keys than the result.
	g := newFixture(t, charonSetupJSON, 2)
	foreign := writeLock(t, f.dir, buildLock(t, g, testWithdrawal, testFork))
	if _, err := lockDeposits(foreign, f.pol, f.res, testFork); err == nil || !strings.Contains(err.Error(), "not the result's") {
		t.Fatalf("lock of other keys: %v", err)
	}
	// One changed byte in a deposit signature: Charon's own checks refuse it.
	l := buildLock(t, f, testWithdrawal, testFork)
	l.Validators[1].PartialDepositData[0].Signature[5] ^= 1
	if _, err := lockDeposits(writeLock(t, f.dir, l), f.pol, f.res, testFork); err == nil {
		t.Fatal("lock with a changed deposit signature")
	}
}

// TestCheckDepositsCommand runs the command on files, as up.sh does.
func TestCheckDepositsCommand(t *testing.T) {
	f := newFixture(t, dirkSetupJSON, 2)
	in := filepath.Join(f.dir, "deposits.json")
	if err := writeJSON(in, f.deposits(t)); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(f.dir, "checked.json")
	f.runnersHoldFixture(t)
	args := []string{"-policy", f.policyPath, "-platform", "dev", "-result", f.resultPath, "-deposits", in,
		"-fork-version", "0x10000038", "-network-name", "kurtosis", "-config", f.configPath(t), "-out", out}
	if err := cmdCheckDeposits(args); err != nil {
		t.Fatal(err)
	}
	var got []DepositData
	b, _ := os.ReadFile(out)
	if err := json.Unmarshal(b, &got); err != nil || len(got) != 2 || got[0].NetworkName != "kurtosis" {
		t.Fatalf("%v %s", err, b)
	}
	// The dev verifier is refused off the dev platform.
	gcp := append([]string(nil), args...)
	gcp[3] = "gcp"
	if err := cmdCheckDeposits(gcp); err == nil {
		t.Fatal("dev verifier accepted on gcp")
	}
	// A result made under another policy.
	g := newFixture(t, charonSetupJSON, 2)
	bad := append([]string(nil), args...)
	bad[5] = g.resultPath
	if err := cmdCheckDeposits(bad); err == nil || !strings.Contains(err.Error(), "another policy") {
		t.Fatalf("result of another policy: %v", err)
	}
	// Unknown fields in the deposits file are refused.
	if err := os.WriteFile(in, []byte(`[{"pubkey":"00","extra":1}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := cmdCheckDeposits(args); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("unknown field: %v", err)
	}
}

// Several results read as one: the keys of each in order, the same
// participants and threshold, no key twice.
func TestReadResultSeveral(t *testing.T) {
	a := newFixture(t, dirkSetupJSON, 2)
	b := newFixture(t, dirkSetupJSON, 3) // the same policy bytes, another session
	_, hash, err := keygen.ParsePolicy([]byte(mustRead(t, a.policyPath)), "dev")
	if err != nil {
		t.Fatal(err)
	}
	r, err := readResult(a.resultPath+","+b.resultPath, hash)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Validators) != 5 || r.Validators[2].Pubkey != b.res.Validators[0].Pubkey || r.Session != "" {
		t.Fatalf("merged result: %d keys, session %q", len(r.Validators), r.Session)
	}
	// Deposits of both sessions check as one.
	in := append(a.deposits(t), b.deposits(t)...)
	if out, err := checkDeposits(in, a.pol, r, testFork, thirtyTwo); err != nil || len(out) != 5 {
		t.Fatalf("deposits over two results: %d, %v", len(out), err)
	}
	if _, err := readResult(a.resultPath+","+a.resultPath, hash); err == nil || !strings.Contains(err.Error(), "earlier result") {
		t.Fatalf("one result twice: %v", err)
	}
	b.res.Threshold = 3
	if err := writeJSON(b.resultPath, b.res); err != nil {
		t.Fatal(err)
	}
	if _, err := readResult(a.resultPath+","+b.resultPath, hash); err == nil || !strings.Contains(err.Error(), "threshold") {
		t.Fatalf("another threshold: %v", err)
	}
}

// A lock of 640 validators fits a runner request
// once compact (charon-lock sends it so); indented it does not.
func TestLockOf640FitsCompact(t *testing.T) {
	f := newFixture(t, charonSetupJSON, 640)
	b, err := buildLock(t, f, testWithdrawal, testFork).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	var c bytes.Buffer
	if err := json.Compact(&c, b); err != nil {
		t.Fatal(err)
	}
	if c.Len() > dkgmsg.MaxLock || len(b) <= dkgmsg.MaxLock {
		t.Fatalf("640 validators: %d bytes compact, %d indented, limit %d", c.Len(), len(b), dkgmsg.MaxLock)
	}
	t.Logf("640 validators: %d bytes compact, %d indented, limit %d", c.Len(), len(b), dkgmsg.MaxLock)
}

func mustRead(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
