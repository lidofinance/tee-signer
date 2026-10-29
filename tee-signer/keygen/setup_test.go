package keygen

import (
	"bytes"
	"context"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/lidofinance/tee-signer/platform/dev"
	"github.com/lidofinance/tee-signer/signer-core/core"
	"github.com/lidofinance/tee-signer/signer-core/dkgmath"
	"github.com/lidofinance/tee-signer/signer-core/threshold"
	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/dkgmsg"
	"github.com/lidofinance/tee-signer/tee-signer/charonlock"
	"github.com/lidofinance/tee-signer/tee-signer/keygen/relay"
)

const (
	setupDirk   = `,"setup":{"path":"dirk","withdrawal_address":"0x8943545177806ed17b9f23f0a21ee5948ecaa776","deposit_amounts_gwei":[32000000000]}`
	setupCharon = `,"setup":{"path":"charon","withdrawal_address":"0x8943545177806ed17b9f23f0a21ee5948ecaa776","deposit_amounts_gwei":[32000000000],"charon_enrs":["enr:-test-1","enr:-test-2","enr:-test-3"]}`
)

// A runner whose operator key is not the policy's for its position refuses
// to deal, and its peers refuse its hello.
func TestOperatorKeyBinding(t *testing.T) {
	var stores []*memStore
	var keys [][32]byte
	for range 3 {
		s, k := newStore(t)
		stores, keys = append(stores, s), append(keys, k)
	}
	keys[2] = [32]byte{0xee} // the policy names another key for position 3
	pol := policyFor(keys, 2, "")
	rs := []*testRunner{newTestRunner(t, pol, stores[0]), newTestRunner(t, pol, stores[1]), newTestRunner(t, pol, stores[2])}
	hs := hellos(t, rs, 1)
	_, err := rs[2].DKGDeal(context.Background(), hs)
	wantRefused(t, err, backend.StatusBadKey, "this runner's operator key is not the one the policy names for participant 3 (op3)")
	_, err = rs[0].DKGDeal(context.Background(), hs)
	wantRefused(t, err, backend.StatusBadKey, "participant 3 (op3): operator key is not the one the policy names")
}

func TestOperatorKeySealedAndAttested(t *testing.T) {
	st, k1 := newStore(t)
	again, err := LoadOperatorKeys(dev.NewDevSealer(), st, dev.Attester{})
	if err != nil || again.Public() != k1 {
		t.Fatalf("operator key changed on the second load: %v", err)
	}
	b, err := again.Answer(context.Background(), &dkgmsg.OperatorRequest{Nonce: bytes.Repeat([]byte{5}, 16)}, backend.SetupState{SetupHash: backend.Root{1}}, []byte("tls"))
	if err != nil {
		t.Fatal(err)
	}
	info, err := dkgmsg.DecodeOperatorInfo(b)
	if err != nil {
		t.Fatal(err)
	}
	nonce := info.AttestNonce()
	if info.Key != k1 || !bytes.Equal(info.Identity.Attestation.UserData, backend.DKGOperatorUserData(nonce, info.Identity)) {
		t.Fatal("DKG_OPERATOR answer does not bind the key")
	}
	// A record the host changed does not unseal.
	st.m[operatorKeyName][20] ^= 1
	if _, err := LoadOperatorKeys(dev.NewDevSealer(), st, dev.Attester{}); err == nil {
		t.Fatal("changed operator key record accepted")
	}
}

func setupSign(t *testing.T, r *testRunner, q *dkgmsg.SetupRequest) ([]byte, error) {
	t.Helper()
	b, err := q.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return r.m.SetupSign(context.Background(), b)
}

// combine signs with runners at ids (from 1) and combines the partials.
func combine(t *testing.T, rs []*testRunner, ids []uint64, q *dkgmsg.SetupRequest) backend.Signature {
	t.Helper()
	var sigs []backend.Signature
	for _, id := range ids {
		b, err := setupSign(t, rs[id-1], q)
		if err != nil {
			t.Fatalf("runner %d: %v", id, err)
		}
		var s backend.Signature
		copy(s[:], b)
		sigs = append(sigs, s)
	}
	full, err := threshold.RecoverSignature(ids, sigs)
	if err != nil {
		t.Fatal(err)
	}
	return full
}

func TestSetupDepositDirkPath(t *testing.T) {
	rs := newRunners(t, 3, 2, setupDirk)
	out, err := relay.Run(context.Background(), asRelay(rs), 1, relay.Options{})
	if err != nil {
		t.Fatal(err)
	}
	gk := out.Result.GroupKeys[0]
	addr, _ := charonlock.Address(testWithdrawal)
	wc := charonlock.WithdrawalCredentials(addr, true)
	dep := &dkgmsg.Deposit{Pubkey: gk, WithdrawalCredentials: wc, Amount: 32 * gwei}
	q := &dkgmsg.SetupRequest{Kind: dkgmsg.SetupDeposit, Deposit: dep}

	// Refusals first: none of them closes the setup.
	bad := []struct {
		name string
		d    dkgmsg.Deposit
		want string
	}{
		{"0x01 credentials", dkgmsg.Deposit{Pubkey: gk, WithdrawalCredentials: charonlock.WithdrawalCredentials(addr, false), Amount: 32 * gwei}, "withdrawal credentials are not the policy's"},
		{"other address", dkgmsg.Deposit{Pubkey: gk, WithdrawalCredentials: charonlock.WithdrawalCredentials([20]byte{9}, true), Amount: 32 * gwei}, "withdrawal credentials are not the policy's"},
		{"other amount", dkgmsg.Deposit{Pubkey: gk, WithdrawalCredentials: wc, Amount: 31 * gwei}, "not in the policy"},
		{"not a generated key", dkgmsg.Deposit{Pubkey: out.Result.PublicShares[0][0], WithdrawalCredentials: wc, Amount: 32 * gwei}, "not a key this runner generated"},
	}
	for _, c := range bad {
		_, err := setupSign(t, rs[0], &dkgmsg.SetupRequest{Kind: dkgmsg.SetupDeposit, Deposit: &c.d})
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Fatalf("%s: %v", c.name, err)
		}
	}
	reg := &backend.ValidatorRegistration{FeeRecipient: testFee, GasLimit: 30_000_000, Timestamp: 1, Pubkey: gk}
	_, err = setupSign(t, rs[0], &dkgmsg.SetupRequest{Kind: dkgmsg.SetupRegistration, Registration: reg})
	wantRefused(t, err, backend.StatusUnsupported, "Charon path only")

	// Runners 1 and 3 sign; the combination verifies under the key.
	full := combine(t, rs, []uint64{1, 3}, q)
	if !core.Verify(gk, charonlock.DepositSigningRoot(gk, wc, 32*gwei, testChain.GenesisForkVersion), full) {
		t.Fatal("combined deposit signature does not verify")
	}
	// The policy's only amount is signed: setup is closed on runners 1 and
	// 3, still open on runner 2.
	_, err = setupSign(t, rs[0], q)
	wantRefused(t, err, backend.StatusPolicyPubkey, "setup: closed")
	if _, err := setupSign(t, rs[1], q); err != nil {
		t.Fatalf("runner 2: %v", err)
	}
	assertNoSecrets(t, rs)
}

func testCluster() *charonlock.Cluster {
	return &charonlock.Cluster{
		Name: "c1-test", UUID: "C1-TEST-UUID", Timestamp: "2026-10-17T00:00:00Z",
		ENRs: []string{"enr:-test-1", "enr:-test-2", "enr:-test-3"}, Threshold: 2,
		ForkVersion: testChain.GenesisForkVersion, FeeRecipient: "0x" + hex.EncodeToString(testFee[:]),
		WithdrawalAddress: testWithdrawal, Compounding: true, DepositAmounts: []uint64{32 * gwei},
		GasLimit: 60_000_000, RegistrationTimestamp: testChain.GenesisTime,
	}
}

// buildLock builds a lock for the result with deposits and registrations
// that runners 1 and 2 sign.
func buildLock(t *testing.T, rs []*testRunner, res *dkgmsg.Result, c *charonlock.Cluster) *charonlock.Lock {
	t.Helper()
	l, err := charonlock.NewLock(c, res.GroupKeys, res.PublicShares)
	if err != nil {
		t.Fatal(err)
	}
	addr, _ := charonlock.Address(c.WithdrawalAddress)
	wc := charonlock.WithdrawalCredentials(addr, c.Compounding)
	for v, gk := range res.GroupKeys {
		for _, amount := range c.DepositAmounts {
			sig := combine(t, rs, []uint64{1, 2}, &dkgmsg.SetupRequest{Kind: dkgmsg.SetupDeposit,
				Deposit: &dkgmsg.Deposit{Pubkey: gk, WithdrawalCredentials: wc, Amount: amount}})
			l.AddDeposit(v, wc, amount, sig)
		}
		reg, err := l.RegistrationFor(v, c)
		if err != nil {
			t.Fatal(err)
		}
		l.SetRegistration(v, reg, combine(t, rs, []uint64{1, 2}, &dkgmsg.SetupRequest{Kind: dkgmsg.SetupRegistration, Registration: reg}))
	}
	if _, err := l.SetLockHash(); err != nil {
		t.Fatal(err)
	}
	return l
}

func lockRequest(t *testing.T, l *charonlock.Lock) *dkgmsg.SetupRequest {
	t.Helper()
	b, err := l.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return &dkgmsg.SetupRequest{Kind: dkgmsg.SetupCharonLock, Lock: b}
}

func TestSetupCharonLock(t *testing.T) {
	rs := newRunners(t, 3, 2, setupCharon)
	out, err := relay.Run(context.Background(), asRelay(rs), 2, relay.Options{})
	if err != nil {
		t.Fatal(err)
	}
	res := out.Result
	c := testCluster()
	good := buildLock(t, rs, res, c)
	if err := good.VerifyHashes(); err != nil {
		t.Fatal(err)
	}
	if err := firstErr(good.VerifyShares(), good.VerifyDeposits(), good.VerifyRegistrations()); err != nil {
		t.Fatal(err)
	}

	// Each change below is refused, and none closes the setup.
	rehash := func(l *charonlock.Lock) {
		if err := l.Definition.SetHashes(); err != nil {
			t.Fatal(err)
		}
		if _, err := l.SetLockHash(); err != nil {
			t.Fatal(err)
		}
	}
	clone := func() *charonlock.Lock {
		b, _ := good.Marshal()
		l, err := charonlock.Parse(b)
		if err != nil {
			t.Fatal(err)
		}
		return l
	}
	bad := []struct {
		name   string
		change func(l *charonlock.Lock)
		want   string
	}{
		{"other fork version", func(l *charonlock.Lock) { l.Definition.ForkVersion = charonlock.Hex{1, 2, 3, 4}; rehash(l) }, "fork_version"},
		{"other withdrawal address", func(l *charonlock.Lock) {
			l.Definition.Validators[1].WithdrawalAddress = "0x000000000000000000000000000000000000dead"
			rehash(l)
		}, "validator 1 withdrawal address"},
		{"fee recipient not allowed", func(l *charonlock.Lock) {
			l.Definition.Validators[0].FeeRecipientAddress = "0x000000000000000000000000000000000000beef"
			rehash(l)
		}, "not in the allowlist"},
		{"0x01 credentials", func(l *charonlock.Lock) { l.Definition.Compounding = false; rehash(l) }, "compounding false"},
		{"public shares swapped", func(l *charonlock.Lock) {
			s := l.Validators[0].PubShares
			s[0], s[1] = s[1], s[0]
			rehash(l)
		}, "do not give the validator key"},
		{"lock hash changed", func(l *charonlock.Lock) { l.LockHash[0] ^= 1 }, "lock_hash does not recompute"},
		{"definition hash changed", func(l *charonlock.Lock) { l.Definition.DefinitionHash[0] ^= 1 }, "definition_hash does not recompute"},
		{"operator with an address", func(l *charonlock.Lock) {
			l.Definition.Operators[0].Address = "0x000000000000000000000000000000000000beef"
			rehash(l)
		}, "operator 0 has an address"},
		{"threshold 3", func(l *charonlock.Lock) { l.Definition.Threshold = 3; rehash(l) }, "threshold 3 of 3"},
		{"deposit amount outside the policy", func(l *charonlock.Lock) {
			l.Definition.DepositAmounts = charonlock.GweiList{8 * gwei}
			rehash(l)
		}, "deposit amount 8000000000 gwei is not in the policy"},
		{"bad deposit signature", func(l *charonlock.Lock) {
			l.Validators[1].PartialDepositData[0].Signature = append(charonlock.Hex(nil), l.Validators[0].PartialDepositData[0].Signature...)
			rehash(l)
		}, "deposit 0: signature does not verify"},
		{"registration with another gas limit", func(l *charonlock.Lock) {
			l.Validators[0].BuilderRegistration.Message.GasLimit = 59_000_000
			rehash(l)
		}, "builder registration signature does not verify"},
		{"one of the two keys", func(l *charonlock.Lock) {
			l.Validators = l.Validators[:1]
			l.Definition.Validators = l.Definition.Validators[:1]
			l.Definition.NumValidators = 1
			rehash(l)
		}, "holds 1 of the 2 keys"},
		{"other Charon node", func(l *charonlock.Lock) { l.Definition.Operators[2].ENR = "enr:-someone-else"; rehash(l) },
			"operator 2 is not the Charon node the policy names for participant 3"},
		{"nodes swapped", func(l *charonlock.Lock) {
			o := l.Definition.Operators
			o[0], o[1] = o[1], o[0]
			rehash(l)
		}, "operator 0 is not the Charon node the policy names for participant 1"},
	}
	for _, b := range bad {
		l := clone()
		b.change(l)
		_, err := setupSign(t, rs[0], lockRequest(t, l))
		if err == nil || !strings.Contains(err.Error(), b.want) {
			t.Fatalf("%s: %v", b.name, err)
		}
	}

	// The good lock: every runner signs the lock hash it computes, with each
	// share; the aggregate of all of them verifies as Charon checks it.
	var sigs []backend.Signature
	per := map[backend.Pubkey][]backend.Signature{}
	for i, r := range rs {
		b, err := setupSign(t, r, lockRequest(t, good))
		if err != nil {
			t.Fatalf("runner %d: %v", i+1, err)
		}
		ls, err := dkgmsg.DecodeLockSigned(b)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(ls.LockHash[:], good.LockHash) || len(ls.Signatures) != 2 {
			t.Fatalf("runner %d: lock hash or signature count", i+1)
		}
		for _, s := range ls.Signatures {
			per[s.Pubkey] = append(per[s.Pubkey], s.Signature)
		}
	}
	for _, gk := range res.GroupKeys {
		sigs = append(sigs, per[gk]...)
	}
	agg, err := dkgmath.AggregateSignatures(sigs)
	if err != nil {
		t.Fatal(err)
	}
	good.SignatureAggregate = agg[:]
	if err := good.VerifyBLS(); err != nil {
		t.Fatalf("lock signed by the runners: %v", err)
	}
	// Setup is closed now for both keys.
	_, err = setupSign(t, rs[0], lockRequest(t, good))
	wantRefused(t, err, backend.StatusPolicyPubkey, "closed")
	addr, _ := charonlock.Address(testWithdrawal)
	_, err = setupSign(t, rs[1], &dkgmsg.SetupRequest{Kind: dkgmsg.SetupDeposit, Deposit: &dkgmsg.Deposit{
		Pubkey: res.GroupKeys[0], WithdrawalCredentials: charonlock.WithdrawalCredentials(addr, true), Amount: 32 * gwei}})
	wantRefused(t, err, backend.StatusPolicyPubkey, "closed")
	assertNoSecrets(t, rs)
}

func TestSetupNeedsPolicySection(t *testing.T) {
	rs := threeRunners(t)
	_, err := setupSign(t, rs[0], &dkgmsg.SetupRequest{Kind: dkgmsg.SetupDeposit, Deposit: &dkgmsg.Deposit{}})
	wantRefused(t, err, backend.StatusUnsupported, "no setup section")
	rd := newRunners(t, 3, 2, setupDirk)
	_, err = setupSign(t, rd[0], &dkgmsg.SetupRequest{Kind: dkgmsg.SetupCharonLock, Lock: []byte("{}")})
	wantRefused(t, err, backend.StatusUnsupported, "not charon")
}

func firstErr(errs ...error) error {
	for _, e := range errs {
		if e != nil {
			return e
		}
	}
	return nil
}

// TestSetupCharonLockOverSessions: a lock may hold several whole key
// generation sessions (a session makes at most dkgmsg.MaxValidators keys),
// but never part of one.
func TestSetupCharonLockOverSessions(t *testing.T) {
	rs := newRunners(t, 3, 2, setupCharon)
	a, err := relay.Run(context.Background(), asRelay(rs), 1, relay.Options{})
	if err != nil {
		t.Fatal(err)
	}
	b, err := relay.Run(context.Background(), asRelay(rs), 2, relay.Options{})
	if err != nil {
		t.Fatal(err)
	}
	c := testCluster()
	part := &dkgmsg.Result{GroupKeys: append(append([]backend.Pubkey(nil), a.Result.GroupKeys...), b.Result.GroupKeys[0]),
		PublicShares: append(append([][]backend.Pubkey(nil), a.Result.PublicShares...), b.Result.PublicShares[0])}
	_, err = setupSign(t, rs[0], lockRequest(t, buildLock(t, rs, part, c)))
	if err == nil || !strings.Contains(err.Error(), "holds 1 of the 2 keys of key generation session") {
		t.Fatalf("lock with part of the second session: %v", err)
	}
	both := &dkgmsg.Result{GroupKeys: append(append([]backend.Pubkey(nil), a.Result.GroupKeys...), b.Result.GroupKeys...),
		PublicShares: append(append([][]backend.Pubkey(nil), a.Result.PublicShares...), b.Result.PublicShares...)}
	good := buildLock(t, rs, both, c)
	for i, r := range rs {
		out, err := setupSign(t, r, lockRequest(t, good))
		if err != nil {
			t.Fatalf("runner %d, lock over two sessions: %v", i+1, err)
		}
		ls, err := dkgmsg.DecodeLockSigned(out)
		if err != nil || len(ls.Signatures) != 3 {
			t.Fatalf("runner %d: %v, %d signatures", i+1, err, len(ls.Signatures))
		}
	}
	// Setup is closed for the keys of both sessions.
	_, err = setupSign(t, rs[2], lockRequest(t, good))
	wantRefused(t, err, backend.StatusPolicyPubkey, "closed")
}

// TKGSETUP-01 on the Charon path: a key whose record holds the credentials
// of an earlier deposit signature gets no lock signature for others; the
// lock signature stores the credentials it signed for.
func TestSetupCharonLockKeepsCredentials(t *testing.T) {
	rs := newRunners(t, 3, 2, setupCharon)
	out, err := relay.Run(context.Background(), asRelay(rs), 2, relay.Options{})
	if err != nil {
		t.Fatal(err)
	}
	res := out.Result
	good := buildLock(t, rs, res, testCluster())
	m := rs[0].m
	rec, err := LoadKeyRecord(m.env.Sealer, m.env.Store, res.GroupKeys[1])
	if err != nil {
		t.Fatal(err)
	}
	other := charonlock.WithdrawalCredentials([20]byte{0x42}, true)
	rec.Credentials = other[:]
	if err := m.storeKeyRecord(rec); err != nil {
		t.Fatal(err)
	}
	_, err = setupSign(t, rs[0], lockRequest(t, good))
	wantRefused(t, err, backend.StatusPolicyPubkey, "validator 1")
	if err == nil || !strings.Contains(err.Error(), "since its first deposit signature") {
		t.Fatalf("lock for other credentials: %v", err)
	}
	b, err := setupSign(t, rs[1], lockRequest(t, good))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := dkgmsg.DecodeLockSigned(b); err != nil {
		t.Fatal(err)
	}
	addr, _ := charonlock.Address(testWithdrawal)
	wc := charonlock.WithdrawalCredentials(addr, true)
	for _, gk := range res.GroupKeys {
		rec, err := LoadKeyRecord(rs[1].m.env.Sealer, rs[1].m.env.Store, gk)
		if err != nil || !bytes.Equal(rec.Credentials, wc[:]) {
			t.Fatalf("record after the lock: %+v %v", rec, err)
		}
	}
}
