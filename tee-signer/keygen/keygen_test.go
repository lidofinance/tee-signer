package keygen

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/platform"
	"github.com/lidofinance/tee-signer/platform/dev"
	"github.com/lidofinance/tee-signer/signer-core/core"
	"github.com/lidofinance/tee-signer/signer-core/dkgmath"
	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/dkgmsg"
	"github.com/lidofinance/tee-signer/signer-protocol/remote"
	"github.com/lidofinance/tee-signer/tee-signer/charonlock"
	"github.com/lidofinance/tee-signer/tee-signer/keygen/relay"
)

// memStore is a platform.Store in memory.
type memStore struct {
	mu sync.Mutex
	m  map[string][]byte
}

func (s *memStore) Get(k string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.m[k]
	if !ok {
		return nil, platform.ErrNotFound
	}
	return append([]byte(nil), v...), nil
}

func (s *memStore) Put(k string, v []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[k] = append([]byte(nil), v...)
	return nil
}

func (s *memStore) Delete(k string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, k)
	return nil
}

func (s *memStore) List(prefix string) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for k := range s.m {
		if strings.HasPrefix(k, prefix) {
			out = append(out, k)
		}
	}
	slices.Sort(out)
	return out, nil
}

// testRunner is one runner's key generation with a fake signer. It keeps
// the shares it is given in secrets, so the test can check them; a real
// runner hands them to the signer core.
type testRunner struct {
	m       *Manager
	store   *memStore
	policy  string
	logs    *bytes.Buffer
	mu      sync.Mutex
	keys    []backend.ValidatorKey
	secrets map[backend.Pubkey][32]byte
	orders  map[backend.Pubkey][]byte // NewShare.Order of each added share
	now     time.Time
}

var (
	testFee        = backend.Address{0x11, 0x22}
	testWithdrawal = "0x8943545177806ed17b9f23f0a21ee5948ecaa776"
)

// testChain is the runners' chain config: the dev chain with one allowed
// fee recipient and a gas limit range.
var testChain = func() core.Config {
	c := core.DevConfig(1_700_000_000, 12, 32)
	c.GenesisForkVersion = backend.Version{0x10, 0, 0x09, 0x10}
	c.FeeRecipients = []backend.Address{testFee}
	c.GasLimitMin, c.GasLimitMax = 30_000_000, 60_000_000
	return c
}()

// newStore makes a runner's store holding its operator key.
func newStore(t *testing.T) (*memStore, [32]byte) {
	t.Helper()
	st := &memStore{m: map[string][]byte{}}
	k, err := LoadOperatorKeys(dev.NewDevSealer(), st, dev.Attester{})
	if err != nil {
		t.Fatal(err)
	}
	return st, k.Public()
}

// copyStore is a second store with the same content: a clone of a runner.
func copyStore(s *memStore) *memStore {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := &memStore{m: map[string][]byte{}}
	for k, v := range s.m {
		c.m[k] = slices.Clone(v)
	}
	return c
}

// policyFor is a dev policy with these operator keys; extra is appended
// inside the top-level object (a setup section).
func policyFor(keys [][32]byte, threshold int, extra string) string {
	var b strings.Builder
	fmt.Fprintf(&b, `{"version":1,"threshold":%d,"participants":[`, threshold)
	for i, k := range keys {
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, "\n {\"name\":\"op%d\",\"operator_key\":\"%s\",\"attestation\":{\"verifier\":\"dev\"}}", i+1, hex.EncodeToString(k[:]))
	}
	b.WriteString("]" + extra + "}")
	return b.String()
}

func newTestRunner(t *testing.T, policy string, store *memStore) *testRunner {
	t.Helper()
	return newTestRunnerWithState(t, policy, store, backend.SetupState{})
}

// newTestRunnerWithState is newTestRunner for a runner whose identity
// carries state. The peers' verifiers come from the policy, as the runner
// builds them (setupDKG in runner/dkg_hooks.go).
func newTestRunnerWithState(t *testing.T, policy string, store *memStore, state backend.SetupState) *testRunner {
	t.Helper()
	p, h, err := ParsePolicy([]byte(policy), "dev")
	if err != nil {
		t.Fatal(err)
	}
	ops, err := LoadOperatorKeys(dev.NewDevSealer(), store, dev.Attester{})
	if err != nil {
		t.Fatal(err)
	}
	r := &testRunner{store: store, policy: policy, logs: &bytes.Buffer{}, secrets: map[backend.Pubkey][32]byte{}, now: time.Now()}
	vs := make([]remote.VerifyFunc, len(p.Participants))
	for i := range vs {
		if vs[i], err = p.Participants[i].Attestation.NewVerifier(); err != nil {
			t.Fatal(err)
		}
	}
	r.m, err = New(p, h, Env{
		Platform: "dev", Sealer: dev.NewDevSealer(), Store: store, Attester: dev.Attester{}, State: state,
		TLSKeyHash:  func() []byte { return []byte("tls key hash of this test runner") },
		OperatorKey: ops.Public(),
		Verifiers:   vs,
		Chain:       testChain,
		AddShares:   r.addShares,
		WithShare:   r.withShare,
		Sign:        r.sign,
		Keys: func() []backend.ValidatorKey {
			r.mu.Lock()
			defer r.mu.Unlock()
			return slices.Clone(r.keys)
		},
		Now: func() time.Time { r.mu.Lock(); defer r.mu.Unlock(); return r.now },
		Log: slog.New(slog.NewTextHandler(syncWriter{r}, &slog.HandlerOptions{Level: slog.LevelDebug})),
	})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// newRunners makes n runners with fresh stores and a dev policy that names
// their operator keys.
func newRunners(t *testing.T, n, threshold int, extra string) []*testRunner {
	t.Helper()
	var stores []*memStore
	var keys [][32]byte
	for range n {
		s, k := newStore(t)
		stores, keys = append(stores, s), append(keys, k)
	}
	pol := policyFor(keys, threshold, extra)
	var rs []*testRunner
	for _, s := range stores {
		rs = append(rs, newTestRunner(t, pol, s))
	}
	return rs
}

func (r *testRunner) withShare(pk backend.Pubkey, f func(*[32]byte) error) error {
	r.mu.Lock()
	s, ok := r.secrets[pk]
	r.mu.Unlock()
	if !ok {
		return errors.New("no such share")
	}
	defer clear(s[:])
	return f(&s)
}

// sign plays the signer core for builder registrations: its policy checks
// and the builder domain.
func (r *testRunner) sign(req backend.SignRequest) (backend.Signature, error) {
	m, ok := req.Message.(*backend.ValidatorRegistration)
	if !ok {
		return backend.Signature{}, errors.New("test signer signs registrations only")
	}
	if m.Pubkey != req.Pubkey {
		return backend.Signature{}, &backend.RefusedError{Code: backend.StatusPolicyPubkey}
	}
	if req.Domain != backend.ComputeDomain(backend.DomainApplicationBuilder, testChain.GenesisForkVersion, backend.Root{}) {
		return backend.Signature{}, &backend.RefusedError{Code: backend.StatusDomainMismatch}
	}
	if !slices.Contains(testChain.FeeRecipients, m.FeeRecipient) {
		return backend.Signature{}, &backend.RefusedError{Code: backend.StatusPolicyFeeRecipient}
	}
	if m.GasLimit < testChain.GasLimitMin || m.GasLimit > testChain.GasLimitMax {
		return backend.Signature{}, &backend.RefusedError{Code: backend.StatusPolicyGasLimit}
	}
	root, err := charonlock.RegistrationSigningRoot(m, testChain.GenesisForkVersion)
	if err != nil {
		return backend.Signature{}, err
	}
	var sig backend.Signature
	err = r.withShare(req.Pubkey, func(s *[32]byte) error {
		var err error
		sig, err = dkgmath.Sign(s, root[:])
		return err
	})
	return sig, err
}

type syncWriter struct{ r *testRunner }

func (w syncWriter) Write(p []byte) (int, error) {
	w.r.mu.Lock()
	defer w.r.mu.Unlock()
	return w.r.logs.Write(p)
}

// addShares plays the server (server.AddGeneratedShares): it seals the
// shares, lets store write them with the key records and keeps them only
// if that succeeded.
func (r *testRunner) addShares(shares []NewShare, store func(map[string][]byte) error) ([]backend.ValidatorKey, error) {
	sealed := map[string][]byte{}
	for _, sh := range shares {
		blob, err := dev.NewDevSealer().Seal(sh.Secret[:], append([]byte("test share|"), sh.Pubkey[:]...))
		if err != nil {
			return nil, err
		}
		sealed["shares/"+hex.EncodeToString(sh.Pubkey[:])] = blob
	}
	if err := store(sealed); err != nil {
		return nil, err
	}
	var out []backend.ValidatorKey
	for _, sh := range shares {
		k, err := r.addShare(sh.Pubkey, sh.Secret)
		if err != nil {
			return out, err
		}
		r.mu.Lock()
		if r.orders == nil {
			r.orders = map[backend.Pubkey][]byte{}
		}
		r.orders[sh.Pubkey] = sh.Order
		r.mu.Unlock()
		out = append(out, k)
	}
	return out, nil
}

func (r *testRunner) addShare(pk backend.Pubkey, secret *[32]byte) (backend.ValidatorKey, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	spk, err := core.PubkeyOf(*secret)
	if err != nil {
		return backend.ValidatorKey{}, err
	}
	k := backend.ValidatorKey{Pubkey: pk, SharePubkey: spk, Index: backend.IndexUnknown}
	r.keys = append(r.keys, k)
	r.secrets[pk] = *secret
	return k, nil
}

// The relay.Runner methods go through the same encodings as the wire.

func (r *testRunner) DKGHello(ctx context.Context, q *dkgmsg.HelloRequest) ([]byte, error) {
	b, err := q.Encode()
	if err != nil {
		return nil, err
	}
	if q, err = dkgmsg.DecodeHelloRequest(b); err != nil {
		return nil, err
	}
	return r.m.Hello(ctx, q)
}

func (r *testRunner) DKGDeal(ctx context.Context, hellos [][]byte) ([]byte, error) {
	l, err := dkgmsg.DecodeList(dkgmsg.EncodeList(hellos), dkgmsg.MaxParticipants)
	if err != nil {
		return nil, err
	}
	return r.m.Deal(ctx, l)
}

func (r *testRunner) DKGFinish(ctx context.Context, deals [][]byte) (*dkgmsg.Finished, error) {
	l, err := dkgmsg.DecodeList(dkgmsg.EncodeList(deals), dkgmsg.MaxParticipants)
	if err != nil {
		return nil, err
	}
	f, err := r.m.Finish(ctx, l)
	if err != nil {
		return nil, err
	}
	b, err := f.Encode()
	if err != nil {
		return nil, err
	}
	return dkgmsg.DecodeFinished(b)
}

func (r *testRunner) DKGCommit(ctx context.Context, q *dkgmsg.CommitRequest) ([]backend.ValidatorKey, error) {
	q2, err := dkgmsg.DecodeCommitRequest(q.Encode())
	if err != nil {
		return nil, err
	}
	return r.m.Commit(ctx, q2)
}

func (r *testRunner) DKGAbort(context.Context) error { r.m.Abort(); return nil }

func threeRunners(t *testing.T) []*testRunner { return newRunners(t, 3, 2, "") }

func asRelay(rs []*testRunner) []relay.Runner {
	out := make([]relay.Runner, len(rs))
	for i, r := range rs {
		out[i] = r
	}
	return out
}

var order, _ = new(big.Int).SetString("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 16)

// lagrange0 combines secret shares at the given IDs into f(0).
func lagrange0(ids []uint64, shares [][32]byte) [32]byte {
	acc := new(big.Int)
	for i, xi := range ids {
		num, den := big.NewInt(1), big.NewInt(1)
		for j, xj := range ids {
			if i == j {
				continue
			}
			num.Mul(num, new(big.Int).SetUint64(xj)).Mod(num, order)
			d := new(big.Int).Sub(new(big.Int).SetUint64(xj), new(big.Int).SetUint64(xi))
			den.Mul(den, d.Mod(d, order)).Mod(den, order)
		}
		l := num.Mul(num, new(big.Int).ModInverse(den, order))
		acc.Add(acc, l.Mul(l, new(big.Int).SetBytes(shares[i][:]))).Mod(acc, order)
	}
	var out [32]byte
	acc.FillBytes(out[:])
	return out
}

// needles are the hex forms (both byte orders) of every share, to look
// for in logs and storage.
func needles(rs []*testRunner) [][]byte {
	var out [][]byte
	for _, r := range rs {
		for _, s := range r.secrets {
			le := slices.Clone(s[:])
			slices.Reverse(le)
			out = append(out, slices.Clone(s[:]), le, []byte(hex.EncodeToString(s[:])), []byte(hex.EncodeToString(le)))
		}
	}
	return out
}

func assertNoSecrets(t *testing.T, rs []*testRunner) {
	t.Helper()
	ns := needles(rs)
	if len(ns) == 0 {
		t.Fatal("no shares to look for")
	}
	for i, r := range rs {
		r.mu.Lock()
		logs := r.logs.Bytes()
		for _, n := range ns {
			if bytes.Contains(logs, n) {
				t.Fatalf("runner %d: a share is in the log", i+1)
			}
		}
		r.mu.Unlock()
		r.store.mu.Lock()
		for k, v := range r.store.m {
			for _, n := range ns {
				if bytes.Contains(v, n) {
					t.Fatalf("runner %d: a share is in stored %s in plain form", i+1, k)
				}
			}
		}
		r.store.mu.Unlock()
	}
}

func TestDKGThreeRunners(t *testing.T) {
	rs := threeRunners(t)
	const count = 3
	out, err := relay.Run(context.Background(), asRelay(rs), count, relay.Options{})
	if err != nil {
		t.Fatal(err)
	}
	res := out.Result
	if len(res.GroupKeys) != count || res.Threshold != 2 {
		t.Fatalf("result: %d keys, threshold %d", len(res.GroupKeys), res.Threshold)
	}
	for v, gk := range res.GroupKeys {
		// Each runner holds the share at x = its position, with the public
		// share the result lists there.
		var shares [][32]byte
		for i, r := range rs {
			s, ok := r.secrets[gk]
			if !ok {
				t.Fatalf("runner %d holds no share of validator %d", i+1, v)
			}
			// A policy file names no order, so the share carries none.
			if o, ok := r.orders[gk]; !ok || o != nil {
				t.Fatalf("runner %d: share of validator %d handed over with order %x (known %v)", i+1, v, o, ok)
			}
			pk, _ := core.PubkeyOf(s)
			if pk != res.PublicShares[v][i] {
				t.Fatalf("runner %d: share is not public share %d", i+1, i+1)
			}
			shares = append(shares, s)
		}
		// Any two shares give the key; one does not.
		for _, pick := range [][]int{{0, 1}, {0, 2}, {1, 2}} {
			sk := lagrange0([]uint64{uint64(pick[0] + 1), uint64(pick[1] + 1)}, [][32]byte{shares[pick[0]], shares[pick[1]]})
			if pk, _ := core.PubkeyOf(sk); pk != gk {
				t.Fatalf("validator %d: shares %v do not give the key", v, pick)
			}
		}
		if pk, _ := core.PubkeyOf(shares[0]); pk == gk {
			t.Fatal("one share is the key")
		}
		// Charon v1.11.0's lock check: the shares at x = 1..t give the key,
		// and every further share with the first t-1 gives it too.
		for _, ids := range [][]uint64{{1, 2}, {1, 3}} {
			got, err := core.RecoverPubkey(ids, []backend.Pubkey{res.PublicShares[v][ids[0]-1], res.PublicShares[v][ids[1]-1]})
			if err != nil || got != gk {
				t.Fatalf("validator %d: public shares %v do not recover the key", v, ids)
			}
		}
	}
	for i, r := range rs {
		if len(out.Keys[i]) != count {
			t.Fatalf("runner %d reports %d keys", i+1, len(out.Keys[i]))
		}
		for _, gk := range res.GroupKeys {
			rec, err := LoadKeyRecord(dev.NewDevSealer(), r.store, gk)
			if err != nil {
				t.Fatalf("runner %d: key record: %v", i+1, err)
			}
			if rec.Self != uint16(i+1) || rec.Threshold != 2 || len(rec.PublicShares) != 3 || !bytes.Equal(rec.Transcript, res.Transcript[:]) {
				t.Fatalf("runner %d: key record %+v", i+1, rec)
			}
		}
		p, err := r.m.getPending(res.Session)
		if err != nil || p.State != "committed" || len(p.Shares) != 0 {
			t.Fatalf("runner %d: pending record after commit: %v %+v", i+1, err, p)
		}
	}
	// A second commit changes nothing and reports the same keys.
	keys, err := rs[0].DKGCommit(context.Background(), &dkgmsg.CommitRequest{Session: res.Session, Confirms: out.Confirms})
	if err != nil || len(keys) != count || len(rs[0].keys) != count {
		t.Fatalf("second commit: %v, %d keys", err, len(keys))
	}
	assertNoSecrets(t, rs)
}

// hellos runs HELLO on every runner.
func hellos(t *testing.T, rs []*testRunner, count int) [][]byte {
	t.Helper()
	q := &dkgmsg.HelloRequest{Nonce: bytes.Repeat([]byte{7}, 32), Count: uint16(count)}
	out := make([][]byte, len(rs))
	for i, r := range rs {
		var err error
		if out[i], err = r.DKGHello(context.Background(), q); err != nil {
			t.Fatalf("runner %d hello: %v", i+1, err)
		}
	}
	return out
}

func deals(t *testing.T, rs []*testRunner, hs [][]byte) [][]byte {
	t.Helper()
	out := make([][]byte, len(rs))
	for i, r := range rs {
		var err error
		if out[i], err = r.DKGDeal(context.Background(), hs); err != nil {
			t.Fatalf("runner %d deal: %v", i+1, err)
		}
	}
	return out
}

func wantRefused(t *testing.T, err error, code backend.Status, substr string) {
	t.Helper()
	var r *backend.RefusedError
	if !errors.As(err, &r) || r.Code != code || !strings.Contains(r.Detail, substr) {
		t.Fatalf("got %v, want %v containing %q", err, code, substr)
	}
}

// After a refusal the session is gone: the next round finds none.
func wantNoSession(t *testing.T, r *testRunner) {
	t.Helper()
	_, err := r.DKGFinish(context.Background(), [][]byte{{1}, {2}, {3}})
	wantRefused(t, err, backend.StatusNotReady, "no session")
}

func TestDKGRefusesBadHellos(t *testing.T) {
	cases := []struct {
		name   string
		change func(t *testing.T, rs []*testRunner, hs [][]byte) [][]byte
		code   backend.Status
		want   string
	}{
		{"attestation of other fields", func(t *testing.T, rs []*testRunner, hs [][]byte) [][]byte {
			h, _ := dkgmsg.DecodeHello(hs[2])
			h.Random[0] ^= 1 // the attested nonce no longer matches
			b, _ := h.Encode()
			hs[2] = b
			return hs
		}, backend.StatusBadKey, "participant 3 (op3): attestation does not bind this hello"},
		{"swapped session key", func(t *testing.T, rs []*testRunner, hs [][]byte) [][]byte {
			h, _ := dkgmsg.DecodeHello(hs[2])
			h3, _ := dkgmsg.DecodeHello(hs[0])
			h.Identity.ImportKey = h3.Identity.ImportKey
			b, _ := h.Encode()
			hs[2] = b
			return hs
		}, backend.StatusBadKey, "participant 3 (op3): attestation does not bind this hello"},
		{"repeated peer", func(t *testing.T, rs []*testRunner, hs [][]byte) [][]byte {
			hs[2] = hs[0]
			return hs
		}, backend.StatusBadKey, "participant 3 (op3): operator key is not the one the policy names"},
		{"own hello replaced by a peer's", func(t *testing.T, rs []*testRunner, hs [][]byte) [][]byte {
			hs[1] = hs[0]
			return hs
		}, backend.StatusBadKey, "participant 2 (op2): operator key is not the one the policy names"},
		{"positions swapped", func(t *testing.T, rs []*testRunner, hs [][]byte) [][]byte {
			hs[0], hs[2] = hs[2], hs[0]
			return hs
		}, backend.StatusBadKey, "participant 1 (op1): operator key is not the one the policy names"},
		{"too few", func(t *testing.T, rs []*testRunner, hs [][]byte) [][]byte {
			return hs[:2]
		}, backend.StatusBadRequest, "2 hellos for 3 participants"},
		{"other policy", func(t *testing.T, rs []*testRunner, hs [][]byte) [][]byte {
			// The same participants in a file that differs by one space.
			other := newTestRunner(t, rs[2].policy+" ", copyStore(rs[2].store))
			b, err := other.DKGHello(context.Background(), &dkgmsg.HelloRequest{Nonce: bytes.Repeat([]byte{7}, 32), Count: 2})
			if err != nil {
				t.Fatal(err)
			}
			hs[2] = b
			return hs
		}, backend.StatusBadKey, "participant 3 (op3): another policy"},
		{"other nonce", func(t *testing.T, rs []*testRunner, hs [][]byte) [][]byte {
			b, err := rs[2].DKGHello(context.Background(), &dkgmsg.HelloRequest{Nonce: bytes.Repeat([]byte{8}, 32), Count: 2})
			if err != nil {
				t.Fatal(err)
			}
			hs[2] = b
			return hs
		}, backend.StatusBadKey, "another session"},
		{"garbage", func(t *testing.T, rs []*testRunner, hs [][]byte) [][]byte {
			hs[2] = hs[2][:40]
			return hs
		}, backend.StatusBadRequest, "participant 3"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rs := threeRunners(t)
			hs := c.change(t, rs, hellos(t, rs, 2))
			_, err := rs[1].DKGDeal(context.Background(), hs)
			wantRefused(t, err, c.code, c.want)
			wantNoSession(t, rs[1])
		})
	}
	t.Run("own hello absent", func(t *testing.T) {
		rs := threeRunners(t)
		hs := hellos(t, rs, 2)
		// A clone of runner 2: same operator key, other session keys.
		other := newTestRunner(t, rs[1].policy, copyStore(rs[1].store))
		b, _ := other.DKGHello(context.Background(), &dkgmsg.HelloRequest{Nonce: bytes.Repeat([]byte{7}, 32), Count: 2})
		hs[1] = b
		_, err := rs[1].DKGDeal(context.Background(), hs)
		wantRefused(t, err, backend.StatusBadRequest, "own hello is missing")
	})
}

// The policy pins each participant's setup in its attestation section
// (setup_sha256, research/setup-phase.md section 11; the DKG order of
// phase 2 replaces the policy file). Runners whose hellos carry the pinned
// setups make keys. A hello whose identity carries another setup is refused,
// and so is a runner with a setup that the policy does not pin.
func TestDKGSetupPins(t *testing.T) {
	var stores []*memStore
	var keys [][32]byte
	var states []backend.SetupState
	for i := range 3 {
		s, k := newStore(t)
		stores, keys = append(stores, s), append(keys, k)
		states = append(states, backend.SetupState{SetupHash: backend.Root{0x5e, byte(i + 1)},
			Locked: backend.ConfigGroup{Hash: backend.Root{1}}, Open: backend.ConfigGroup{Hash: backend.Root{2}}, ApproverSetHash: backend.Root{3}})
	}
	// policy pins participant i to pins[i]; an empty pin leaves its
	// attestation section as policyFor writes it.
	policy := func(pins ...string) string {
		pol := policyFor(keys, 2, "")
		for i, pin := range pins {
			if pin == "" {
				continue
			}
			k := `"operator_key":"` + hex.EncodeToString(keys[i][:]) + `","attestation":{"verifier":"dev"`
			pol = strings.Replace(pol, k, k+`,"setup_sha256":"`+pin+`"`, 1)
		}
		return pol
	}
	pinOf := func(r backend.Root) string { return hex.EncodeToString(r[:]) }
	runners := func(pol string) []*testRunner {
		var rs []*testRunner
		for i, s := range stores {
			rs = append(rs, newTestRunnerWithState(t, pol, copyStore(s), states[i]))
		}
		return rs
	}

	good := policy(pinOf(states[0].SetupHash), pinOf(states[1].SetupHash), pinOf(states[2].SetupHash))
	if _, err := relay.Run(context.Background(), asRelay(runners(good)), 1, relay.Options{}); err != nil {
		t.Fatalf("pinned setups: %v", err)
	}
	for name, c := range map[string]struct{ policy, want string }{
		"another setup": {policy(pinOf(states[0].SetupHash), pinOf(states[1].SetupHash), pinOf(backend.Root{0x99})),
			"participant 3 (op3): attestation: runnerclient: the runner's setup_hash 5e03"},
		"setup not pinned": {policy(pinOf(states[0].SetupHash), pinOf(states[1].SetupHash), ""),
			"participant 3 (op3): attestation: runnerclient: the runner reports setup 5e03"},
	} {
		t.Run(name, func(t *testing.T) {
			rs := runners(c.policy)
			_, err := rs[0].DKGDeal(context.Background(), hellos(t, rs, 1))
			wantRefused(t, err, backend.StatusBadKey, c.want)
			wantNoSession(t, rs[0])
		})
	}
}

func TestDKGRefusesBadDeals(t *testing.T) {
	cases := []struct {
		name   string
		change func(ds [][]byte) [][]byte
		want   string
	}{
		{"changed commitment", func(ds [][]byte) [][]byte {
			ds[2] = slices.Clone(ds[2])
			ds[2][1+32+6+10] ^= 1
			return ds
		}, "dealer 3 (op3)"},
		{"swapped order", func(ds [][]byte) [][]byte {
			ds[0], ds[2] = ds[2], ds[0]
			return ds
		}, "dealer 1 (op1): deal of another session, position"},
		{"own deal changed", func(ds [][]byte) [][]byte {
			ds[1] = slices.Clone(ds[1])
			ds[1][len(ds[1])-1] ^= 1
			return ds
		}, "dealer 2 (op2): own deal came back changed"},
		{"bad signature", func(ds [][]byte) [][]byte {
			ds[0] = slices.Clone(ds[0])
			ds[0][len(ds[0])-1] ^= 1
			return ds
		}, "dealer 1 (op1): signature does not verify"},
		{"truncated", func(ds [][]byte) [][]byte {
			ds[0] = ds[0][:100]
			return ds
		}, "dealer 1"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rs := threeRunners(t)
			ds := c.change(deals(t, rs, hellos(t, rs, 2)))
			_, err := rs[1].DKGFinish(context.Background(), ds)
			var r *backend.RefusedError
			if !errors.As(err, &r) || !strings.Contains(r.Detail, c.want) {
				t.Fatalf("got %v, want %q", err, c.want)
			}
			wantNoSession(t, rs[1])
			if ks, _ := rs[1].store.List("dkg/"); len(ks) != 0 {
				t.Fatalf("stored after a refusal: %v", ks)
			}
		})
	}
}

// A dealer with a valid attestation and signature sends runner 1 a share
// that does not match its commitments. Runner 1 refuses and names it;
// runner 2 finishes, but without runner 1's confirmation no runner keeps a
// share.
func TestDKGRogueDealerNoKey(t *testing.T) {
	rs := threeRunners(t)
	one := [32]byte{31: 1}
	rs[2].m.tamperShare = func(recipient uint16, _ int, s *[32]byte) {
		if recipient == 1 {
			*s, _ = dkgmath.ScalarAdd(*s, one)
		}
	}
	out, err := relay.Run(context.Background(), asRelay(rs), 2, relay.Options{})
	if err == nil || out != nil {
		t.Fatal("run with a rogue dealer succeeded")
	}
	if !strings.Contains(err.Error(), "runner 1: backend refused: SC_ERR_BAD_KEY: dkg: dealer 3 (op3): validator 0: share does not match the commitments") {
		t.Fatalf("error: %v", err)
	}
	for i, r := range rs {
		if len(r.keys) != 0 {
			t.Fatalf("runner %d holds keys", i+1)
		}
	}
	// Run by hand to the commit: runners 2 and 3 finish, runner 1 refuses.
	rs = threeRunners(t)
	rs[2].m.tamperShare = func(recipient uint16, _ int, s *[32]byte) {
		if recipient == 1 {
			*s, _ = dkgmath.ScalarAdd(*s, one)
		}
	}
	ds := deals(t, rs, hellos(t, rs, 1))
	if _, err := rs[0].DKGFinish(context.Background(), ds); err == nil {
		t.Fatal("runner 1 accepted the rogue share")
	}
	f2, err := rs[1].DKGFinish(context.Background(), ds)
	if err != nil {
		t.Fatal(err)
	}
	f3, err := rs[2].DKGFinish(context.Background(), ds)
	if err != nil {
		t.Fatal(err)
	}
	// Two of three confirmations, the first repeated: refused.
	q := &dkgmsg.CommitRequest{Session: f2.Result.Session, Confirms: []*dkgmsg.Confirm{f2.Confirm, f2.Confirm, f3.Confirm}}
	_, err = rs[1].DKGCommit(context.Background(), q)
	wantRefused(t, err, backend.StatusBadKey, "confirmation 1 does not verify")
	q.Confirms = q.Confirms[1:]
	_, err = rs[1].DKGCommit(context.Background(), q)
	wantRefused(t, err, backend.StatusBadRequest, "2 confirmations for 3 participants")
	if len(rs[1].keys) != 0 || len(rs[2].keys) != 0 {
		t.Fatal("a runner kept a share without every confirmation")
	}
}

// finishAll runs the rounds up to FINISH by hand and returns each runner's
// result and a copy of each runner's session signing key (test only).
func finishAll(t *testing.T, rs []*testRunner, count int) ([]*dkgmsg.Finished, []ed25519.PrivateKey) {
	t.Helper()
	ds := deals(t, rs, hellos(t, rs, count))
	keys := make([]ed25519.PrivateKey, len(rs))
	for i, r := range rs {
		keys[i] = slices.Clone(r.m.sess.signKey)
	}
	fins := make([]*dkgmsg.Finished, len(rs))
	for i, r := range rs {
		var err error
		if fins[i], err = r.DKGFinish(context.Background(), ds); err != nil {
			t.Fatalf("runner %d finish: %v", i+1, err)
		}
	}
	return fins, keys
}

func confirms(fins []*dkgmsg.Finished) *dkgmsg.CommitRequest {
	q := &dkgmsg.CommitRequest{Session: fins[0].Result.Session}
	for _, f := range fins {
		q.Confirms = append(q.Confirms, f.Confirm)
	}
	return q
}

// A validly signed confirmation of another transcript drops the pending
// result for good.
func TestDKGDisagreementDropsResult(t *testing.T) {
	rs := threeRunners(t)
	fins, signKeys := finishAll(t, rs, 1)
	q := confirms(fins)
	bad := *q.Confirms[2]
	bad.Transcript[0] ^= 1
	copy(bad.Signature[:], ed25519.Sign(signKeys[2], bad.SignedBytes()))
	q.Confirms[2] = &bad
	_, err := rs[0].DKGCommit(context.Background(), q)
	wantRefused(t, err, backend.StatusBadKey, "participant 3 confirmed another transcript")
	_, err = rs[0].DKGCommit(context.Background(), confirms(fins))
	wantRefused(t, err, backend.StatusBadRequest, "was aborted")
	if len(rs[0].keys) != 0 {
		t.Fatal("runner 1 kept a share")
	}
	p, err := rs[0].m.getPending(fins[0].Result.Session)
	if err != nil || p.State != "aborted" || len(p.Shares) != 0 {
		t.Fatalf("pending record: %v %+v", err, p)
	}
}

// A confirmation with a bad signature changes nothing: the good set still
// commits afterwards.
func TestDKGCommitRefusesBadSignature(t *testing.T) {
	rs := threeRunners(t)
	fins, _ := finishAll(t, rs, 1)
	q := confirms(fins)
	bad := *q.Confirms[2]
	bad.Signature[5] ^= 1
	q.Confirms[2] = &bad
	_, err := rs[0].DKGCommit(context.Background(), q)
	wantRefused(t, err, backend.StatusBadKey, "confirmation 3 does not verify")
	if len(rs[0].keys) != 0 {
		t.Fatal("kept a share after a bad confirmation")
	}
	if keys, err := rs[0].DKGCommit(context.Background(), confirms(fins)); err != nil || len(keys) != 1 {
		t.Fatalf("good commit after a bad one: %v", err)
	}
}

// The pending result survives a restart between FINISH and COMMIT.
func TestDKGCommitAfterRestart(t *testing.T) {
	rs := threeRunners(t)
	fins, _ := finishAll(t, rs, 2)
	restarted := newTestRunner(t, rs[0].policy, rs[0].store)
	keys, err := restarted.DKGCommit(context.Background(), confirms(fins))
	if err != nil || len(keys) != 2 {
		t.Fatalf("commit after restart: %v, %d keys", err, len(keys))
	}
	for v, gk := range fins[0].Result.GroupKeys {
		pk, _ := core.PubkeyOf(restarted.secrets[gk])
		if pk != fins[0].Result.PublicShares[v][0] {
			t.Fatal("restarted runner loaded another share")
		}
	}
}

func TestDKGSessionLimits(t *testing.T) {
	t.Run("expired", func(t *testing.T) {
		rs := threeRunners(t)
		hs := hellos(t, rs, 1)
		rs[0].mu.Lock()
		rs[0].now = rs[0].now.Add(SessionTTL + time.Second)
		rs[0].mu.Unlock()
		_, err := rs[0].DKGDeal(context.Background(), hs)
		wantRefused(t, err, backend.StatusNotReady, "session older than")
		wantNoSession(t, rs[0])
	})
	t.Run("new hello ends the session", func(t *testing.T) {
		rs := threeRunners(t)
		hs := hellos(t, rs, 1)
		hellos(t, rs[:1], 1)
		_, err := rs[0].DKGDeal(context.Background(), hs)
		wantRefused(t, err, backend.StatusBadRequest, "own hello is missing")
	})
	t.Run("out of order", func(t *testing.T) {
		rs := threeRunners(t)
		hs := hellos(t, rs, 1)
		_, err := rs[0].DKGFinish(context.Background(), hs)
		wantRefused(t, err, backend.StatusBadRequest, "out of order")
		wantNoSession(t, rs[0])
	})
	t.Run("abort", func(t *testing.T) {
		rs := threeRunners(t)
		hs := hellos(t, rs, 1)
		_ = rs[0].DKGAbort(context.Background())
		_, err := rs[0].DKGDeal(context.Background(), hs)
		wantRefused(t, err, backend.StatusNotReady, "no session")
	})
	t.Run("commit without finish", func(t *testing.T) {
		rs := threeRunners(t)
		_, err := rs[0].DKGCommit(context.Background(), &dkgmsg.CommitRequest{Confirms: []*dkgmsg.Confirm{{}}})
		wantRefused(t, err, backend.StatusNotReady, "no finished session")
	})
}

// Share IDs follow the policy order whatever order the runners answer in:
// the runner at position i holds f(i+1).
func TestDKGFiveRunnersThresholdThree(t *testing.T) {
	rs := newRunners(t, 5, 3, "")
	out, err := relay.Run(context.Background(), asRelay(rs), 2, relay.Options{})
	if err != nil {
		t.Fatal(err)
	}
	for v, gk := range out.Result.GroupKeys {
		ids := []uint64{2, 4, 5}
		var shares [][32]byte
		for _, id := range ids {
			shares = append(shares, rs[id-1].secrets[gk])
		}
		if pk, _ := core.PubkeyOf(lagrange0(ids, shares)); pk != gk {
			t.Fatalf("validator %d: shares 2, 4, 5 do not give the key", v)
		}
		got, err := core.RecoverPubkey([]uint64{1, 2, 3}, out.Result.PublicShares[v][:3])
		if err != nil || got != gk {
			t.Fatal("public shares 1..3 do not recover the key")
		}
	}
	assertNoSecrets(t, rs)
}

func TestParsePolicy(t *testing.T) {
	keys := [][32]byte{{1}, {2}, {3}}
	ok := policyFor(keys, 2, "")
	k3 := hex.EncodeToString(keys[2][:])
	last := `"operator_key":"` + k3 + `","attestation":{"verifier":"dev"}}]`
	withLast := func(att string) string {
		return strings.Replace(ok, last, `"operator_key":"`+k3+`","attestation":`+att+`}]`, 1)
	}
	pcr := strings.Repeat("ab", 48)
	setup := func(s string) string { return strings.TrimSuffix(ok, "}") + `,"setup":` + s + "}" }
	goodSetup := `{"path":"charon","withdrawal_address":"0x8943545177806ed17b9f23f0a21ee5948ecaa776","deposit_amounts_gwei":[32000000000],"charon_enrs":["enr:a","enr:b","enr:c"]}`
	if _, _, err := ParsePolicy([]byte(setup(goodSetup)), "dev"); err != nil {
		t.Fatalf("policy with setup: %v", err)
	}
	if _, _, err := ParsePolicy([]byte(ok), "dev"); err != nil {
		t.Fatal(err)
	}
	_, h1, _ := ParsePolicy([]byte(ok), "dev")
	_, h2, _ := ParsePolicy([]byte(ok+"\n"), "dev")
	if h1 == h2 {
		t.Fatal("hash ignores the file bytes")
	}
	bad := []struct{ name, policy, platform, want string }{
		{"dev verifier on a cloud", ok, "azure", "verifier dev accepts unsigned documents"},
		{"threshold half", strings.Replace(ok, `"threshold":2`, `"threshold":1`, 1), "dev", "threshold 1 of 3"},
		{"threshold over n", strings.Replace(ok, `"threshold":2`, `"threshold":4`, 1), "dev", "threshold 4 of 3"},
		{"version", strings.Replace(ok, `"version":1`, `"version":2`, 1), "dev", "version 2"},
		{"unknown field", strings.Replace(ok, `"version":1`, `"version":1,"x":1`, 1), "dev", "unknown field"},
		{"repeated name", strings.Replace(ok, `"op2"`, `"op1"`, 1), "dev", "repeated name"},
		{"one participant", policyFor(keys[:1], 1, ""), "dev", "1 participants"},
		{"no verifier", withLast(`{}`), "dev", "attestation.verifier: not set"},
		{"jwks file", withLast(`{"verifier":"gcp-cs","gcp_jwks_file":"/x"}`), "dev", "gcp_jwks_file is not allowed"},
		{"maa without hash", withLast(`{"verifier":"azure-maa","maa_host":"a.b"}`), "dev", "participant 3"},
		{"trailing", ok + "{}", "dev", "trailing data"},
		{"no operator key", strings.Replace(ok, `"operator_key":"`+k3+`",`, ``, 1), "dev", "operator_key: want 64 hex digits"},
		{"repeated operator key", policyFor([][32]byte{{1}, {2}, {1}}, 2, ""), "dev", "operator_key repeats"},
		{"gcp without project", withLast(`{"verifier":"gcp-cs","gcp_image_digest":"sha256:` + strings.Repeat("ab", 32) +
			`","gcp_audience":"a","gcp_hwmodels":["GCP_INTEL_TDX"],"gcp_service_account":"s@p.iam.gserviceaccount.com"}`), "dev", "needs gcp_project_id and gcp_service_account"},
		{"gcp without service account", withLast(`{"verifier":"gcp-cs","gcp_image_digest":"sha256:` + strings.Repeat("ab", 32) +
			`","gcp_audience":"a","gcp_hwmodels":["GCP_INTEL_TDX"],"gcp_project_id":"signer-project"}`), "dev", "needs gcp_project_id and gcp_service_account"},
		{"nitro without PCR3", withLast(`{"verifier":"aws-nitro","nitro_pcrs":{"0":"` + pcr + `","1":"` + pcr + `","2":"` + pcr + `"}}`), "dev", "needs PCR3"},
		{"setup path", setup(`{"path":"vouch","withdrawal_address":"0x8943545177806ed17b9f23f0a21ee5948ecaa776","deposit_amounts_gwei":[32000000000]}`), "dev", "path \"vouch\""},
		{"setup zero address", setup(`{"path":"dirk","withdrawal_address":"0x0000000000000000000000000000000000000000","deposit_amounts_gwei":[32000000000]}`), "dev", "withdrawal_address is zero"},
		{"setup no amounts", setup(`{"path":"dirk","withdrawal_address":"0x8943545177806ed17b9f23f0a21ee5948ecaa776","deposit_amounts_gwei":[]}`), "dev", "deposit_amounts_gwei is empty"},
		{"charon setup without ENRs", setup(`{"path":"charon","withdrawal_address":"0x8943545177806ed17b9f23f0a21ee5948ecaa776","deposit_amounts_gwei":[32000000000]}`), "dev", "charon_enrs lists 0 nodes for 3 participants"},
		{"dirk setup with ENRs", setup(`{"path":"dirk","withdrawal_address":"0x8943545177806ed17b9f23f0a21ee5948ecaa776","deposit_amounts_gwei":[32000000000],"charon_enrs":["enr:a","enr:b","enr:c"]}`), "dev", "charon_enrs is for the charon path"},
		{"setup 64 ETH without compounding", setup(`{"path":"dirk","withdrawal_address":"0x8943545177806ed17b9f23f0a21ee5948ecaa776","compounding":false,"deposit_amounts_gwei":[64000000000]}`), "dev", "want 1 ETH to 32 ETH"},
	}
	for _, c := range bad {
		if _, _, err := ParsePolicy([]byte(c.policy), c.platform); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: got %v, want %q", c.name, err, c.want)
		}
	}
}

// The hello attestation binds the policy hash: the nonce it is attested
// with is the hello's AttestNonce.
func TestHelloAttestationBindsFields(t *testing.T) {
	rs := threeRunners(t)
	hs := hellos(t, rs, 1)
	h, err := dkgmsg.DecodeHello(hs[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := remote.DevVerifier(context.Background(), h.AttestNonce(), h.Identity); err != nil {
		t.Fatal(err)
	}
	if h.PolicyHash != rs[0].m.PolicyHash() || binary.BigEndian.Uint16(hs[0][1+32+1+32:]) != 1 {
		t.Fatal("hello fields")
	}
	h.PolicyHash[0] ^= 1
	if err := remote.DevVerifier(context.Background(), h.AttestNonce(), h.Identity); err == nil {
		t.Fatal("changed policy hash still verifies")
	}
}
