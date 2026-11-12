package backend

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	blst "github.com/supranational/blst/bindings/go"

	proto "github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/web3signer-api/signing"
)

// testKey is a validator key split t of n: the secret, its public key, and
// share i (index i+1) of each signer.
type testKey struct {
	sk     blst.SecretKey
	pk     phase0.BLSPubKey
	shares []blst.SecretKey
}

// randScalar is a random nonzero scalar mod r.
func randScalar(t *testing.T) *big.Int {
	t.Helper()
	for {
		k, err := rand.Int(rand.Reader, groupR)
		if err != nil {
			t.Fatal(err)
		}
		if k.Sign() != 0 {
			return k
		}
	}
}

// randKey is a random secret key.
func randKey(t *testing.T) blst.SecretKey {
	t.Helper()

	return *blstKey(randScalar(t))
}

func splitKey(t *testing.T, threshold, n int) *testKey {
	t.Helper()
	poly := make([]*big.Int, threshold)
	for i := range poly {
		poly[i] = randScalar(t)
	}
	k := &testKey{sk: *blstKey(poly[0])}
	k.pk = pubOf(&k.sk)
	for x := 1; x <= n; x++ {
		y := new(big.Int)
		for i := threshold - 1; i >= 0; i-- { // Horner
			y.Mul(y, big.NewInt(int64(x))).Add(y, poly[i]).Mod(y, groupR)
		}
		k.shares = append(k.shares, *blstKey(y))
	}

	return k
}

func pubOf(s *blst.SecretKey) phase0.BLSPubKey {
	return blstPub(s)
}

func signRoot(s *blst.SecretKey, root phase0.Root) proto.Signature {
	return proto.Signature(blstSign(s, root, popDST))
}

// fakeRunner is a signer that holds shares and signs the root the test
// gives it, or fails as the test says.
type fakeRunner struct {
	mu        sync.Mutex
	keys      []proto.ValidatorKey
	secret    map[proto.Pubkey]*blst.SecretKey
	root      phase0.Root
	err       error           // every call fails with it
	signer    *blst.SecretKey // signs with this key instead of the share (a bad partial)
	hang      chan struct{}   // Sign waits until it closes or ctx ends
	signs     int
	mode      string // the signing_mode HEALTH reports
	healthErr error  // HEALTH fails with it
	health    int    // HEALTH calls
	protocol  int    // the protocol level HEALTH reports
}

func (f *fakeRunner) Health(context.Context) (*proto.Health, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.health++
	if f.healthErr != nil {
		return nil, f.healthErr
	}

	return &proto.Health{Ready: true, SigningMode: f.mode, Protocol: f.protocol}, nil
}

func (f *fakeRunner) PublicKeys(context.Context) ([]proto.ValidatorKey, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}

	return append([]proto.ValidatorKey(nil), f.keys...), nil
}

func (f *fakeRunner) Sign(ctx context.Context, req proto.SignRequest) (proto.Signature, error) {
	f.mu.Lock()
	f.signs++
	err, hang, root, sk := f.err, f.hang, f.root, f.secret[req.Pubkey]
	if f.signer != nil {
		sk = f.signer
	}
	f.mu.Unlock()
	if hang != nil {
		select {
		case <-hang:
		case <-ctx.Done():
			return proto.Signature{}, ctx.Err()
		}
	}
	if err != nil {
		return proto.Signature{}, err
	}
	if sk == nil {
		return proto.Signature{}, proto.Refused(proto.StatusUnknownValidator, "no share")
	}

	return signRoot(sk, root), nil
}

func (f *fakeRunner) Close() error { return nil }

func (f *fakeRunner) set(fn func(f *fakeRunner)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn(f)
}

// cluster is n fake signers that hold share i of each key. A single
// signer's setup says signing_mode = single, the others' threshold.
func cluster(keys []*testKey, n int) []*fakeRunner {
	fakes := make([]*fakeRunner, n)
	mode := "threshold"
	if n == 1 {
		mode = "single"
	}
	for i := range fakes {
		f := &fakeRunner{secret: map[proto.Pubkey]*blst.SecretKey{}, mode: mode}
		for _, k := range keys {
			f.keys = append(f.keys, proto.ValidatorKey{Pubkey: proto.Pubkey(k.pk), SharePubkey: proto.Pubkey(pubOf(&k.shares[i])),
				Index: proto.IndexUnknown})
			f.secret[proto.Pubkey(k.pk)] = &k.shares[i]
		}
		fakes[i] = f
	}

	return fakes
}

func newTestSigners(t *testing.T, fakes []*fakeRunner) *Signers {
	t.Helper()
	runners := make([]runner, len(fakes))
	names := make([]string, len(fakes))
	for i, f := range fakes {
		runners[i], names[i] = f, fmt.Sprintf("signer-%d", i+1)
	}
	s := newSigners(names, runners, 0, 2*time.Second, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if _, err := s.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}

	return s
}

var testRoot = phase0.Root{0xaa, 0xbb}

func attestationJob() *signing.Job {
	return &signing.Job{Type: "ATTESTATION", Method: signing.MethodAttestation, SigningRoot: testRoot,
		Attestation: &phase0.AttestationData{Slot: 64, Source: &phase0.Checkpoint{Epoch: 1}, Target: &phase0.Checkpoint{Epoch: 2}}}
}

func setRoot(fakes []*fakeRunner) {
	for _, f := range fakes {
		f.set(func(f *fakeRunner) { f.root = testRoot })
	}
}

func signWith(t *testing.T, s *Signers, pk phase0.BLSPubKey) (phase0.BLSSignature, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	return s.Sign(ctx, pk, attestationJob())
}

// The combined signature of 2 of 3 partials is the signature of the whole
// key: BLS signatures are unique, so it equals the one the secret makes.
func TestCombineTwoOfThree(t *testing.T) {
	k := splitKey(t, 2, 3)
	fakes := cluster([]*testKey{k}, 3)
	setRoot(fakes)
	s := newTestSigners(t, fakes)
	if keys := s.PublicKeys(context.Background()); len(keys) != 1 || keys[0] != k.pk {
		t.Fatalf("public keys %x", keys)
	}
	sig, err := signWith(t, s, k.pk)
	if err != nil {
		t.Fatal(err)
	}
	if want := signRoot(&k.sk, testRoot); sig != phase0.BLSSignature(want) {
		t.Fatal("combined signature is not the signature of the validator key")
	}
	if err := VerifyBLS(k.pk, testRoot, sig); err != nil {
		t.Fatal(err)
	}
}

func TestCombineOneSignerDown(t *testing.T) {
	for down := range 3 {
		k := splitKey(t, 2, 3)
		fakes := cluster([]*testKey{k}, 3)
		setRoot(fakes)
		s := newTestSigners(t, fakes)
		fakes[down].set(func(f *fakeRunner) { f.err = fmt.Errorf("dial: %w", io.EOF) })
		sig, err := signWith(t, s, k.pk)
		if err != nil {
			t.Fatalf("signer %d down: %v", down+1, err)
		}
		if err := VerifyBLS(k.pk, testRoot, sig); err != nil {
			t.Fatalf("signer %d down: %v", down+1, err)
		}
	}
}

// A signer that does not answer does not hold the others up.
func TestCombineDoesNotWaitForASlowSigner(t *testing.T) {
	k := splitKey(t, 2, 3)
	fakes := cluster([]*testKey{k}, 3)
	setRoot(fakes)
	s := newTestSigners(t, fakes)
	hang := make(chan struct{})
	defer close(hang)
	fakes[0].set(func(f *fakeRunner) { f.hang = hang })
	start := time.Now()
	if _, err := signWith(t, s, k.pk); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("waited %v for the slow signer", d)
	}
}

// A partial signature that does not verify under its share key never
// reaches the combination: the other two sign.
func TestCombineSkipsABadPartial(t *testing.T) {
	k := splitKey(t, 2, 3)
	other := splitKey(t, 1, 1)
	fakes := cluster([]*testKey{k}, 3)
	setRoot(fakes)
	s := newTestSigners(t, fakes)
	fakes[1].set(func(f *fakeRunner) { f.signer = &other.sk })
	// Let the bad partial come first.
	hang := make(chan struct{})
	fakes[0].set(func(f *fakeRunner) { f.hang = hang })
	fakes[2].set(func(f *fakeRunner) { f.hang = hang })
	go func() { time.Sleep(100 * time.Millisecond); close(hang) }()
	sig, err := signWith(t, s, k.pk)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyBLS(k.pk, testRoot, sig); err != nil {
		t.Fatal(err)
	}

	// Two bad partials: no signature, and no denial (HTTP 500).
	fakes[2].set(func(f *fakeRunner) { f.signer = &other.sk })
	_, err = signWith(t, s, k.pk)
	var denied *DeniedError
	if err == nil || errors.As(err, &denied) || !strings.Contains(err.Error(), "does not verify under the share key") {
		t.Fatalf("two bad partials: %v", err)
	}
}

func TestCombineAllDown(t *testing.T) {
	k := splitKey(t, 2, 3)
	fakes := cluster([]*testKey{k}, 3)
	setRoot(fakes)
	s := newTestSigners(t, fakes)
	for _, f := range fakes {
		f.set(func(f *fakeRunner) { f.err = errors.New("connection refused") })
	}
	// Two failures leave the threshold out of reach: no wait for the third.
	_, err := signWith(t, s, k.pk)
	var denied *DeniedError
	if err == nil || errors.As(err, &denied) || !strings.Contains(err.Error(), "0 signed, 0 denied, 2 failed of 3 signers") {
		t.Fatalf("all down: %v", err)
	}
	// The key stays known: the list keeps the last answers.
	if !s.HasKey(context.Background(), k.pk) {
		t.Fatal("key lost while the signers are down")
	}
}

// Two signers refuse on slashing protection or its floor: a denial (HTTP
// 412), as soon as the threshold is out of reach.
func TestCombineDenied(t *testing.T) {
	for _, code := range []proto.Status{proto.StatusSlashTarget, proto.StatusFloor, proto.StatusFloorUnproven} {
		t.Run(code.String(), func(t *testing.T) {
			k := splitKey(t, 2, 3)
			fakes := cluster([]*testKey{k}, 3)
			setRoot(fakes)
			s := newTestSigners(t, fakes)
			hang := make(chan struct{})
			defer close(hang)
			fakes[0].set(func(f *fakeRunner) { f.err = proto.Refused(code, "refused") })
			fakes[1].set(func(f *fakeRunner) { f.err = proto.Refused(code, "refused") })
			fakes[2].set(func(f *fakeRunner) { f.hang = hang })
			_, err := signWith(t, s, k.pk)
			var denied *DeniedError
			if !errors.As(err, &denied) || !strings.Contains(err.Error(), code.String()) {
				t.Fatalf("want a denial, got %v", err)
			}
		})
	}
}

func TestUnknownKey(t *testing.T) {
	k := splitKey(t, 2, 3)
	s := newTestSigners(t, cluster([]*testKey{k}, 3))
	if _, err := signWith(t, s, phase0.BLSPubKey{1}); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("got %v", err)
	}
}

// The share indices come from the public keys: signers listed in another
// order than their indices still combine, and a key whose shares do not
// interpolate to it is not served.
func TestShareIndicesFromPublicKeys(t *testing.T) {
	k := splitKey(t, 2, 3)
	fakes := cluster([]*testKey{k}, 3)
	fakes[0], fakes[2] = fakes[2], fakes[0]
	setRoot(fakes)
	s := newTestSigners(t, fakes)
	g, ok := s.keys.lookup(k.pk)
	if !ok || g.threshold != 2 || g.shares[0].index != 3 || g.shares[1].index != 2 || g.shares[2].index != 1 {
		t.Fatalf("group %+v", g)
	}
	for down := range 3 {
		fakes[down].set(func(f *fakeRunner) { f.err = io.EOF })
		if _, err := signWith(t, s, k.pk); err != nil {
			t.Fatalf("signer %d down: %v", down+1, err)
		}
		fakes[down].set(func(f *fakeRunner) { f.err = nil })
	}

	// A third share from another split.
	bad := splitKey(t, 2, 3)
	fakes = cluster([]*testKey{k}, 3)
	fakes[2].keys[0].SharePubkey = proto.Pubkey(pubOf(&bad.shares[2]))
	s = newTestSigners(t, append(fakes, cluster([]*testKey{splitKey(t, 1, 1)}, 1)...))
	if s.HasKey(context.Background(), k.pk) {
		t.Fatal("a key with a foreign share is served")
	}

	// 3 of 3, a whole key on one signer, and a whole key on two signers.
	k3 := splitKey(t, 3, 3)
	g3, err := deriveGroup(k3.pk, []share{{node: 0, pub: pubOf(&k3.shares[0])}, {node: 1, pub: pubOf(&k3.shares[1])},
		{node: 2, pub: pubOf(&k3.shares[2])}}, 3)
	if err != nil || g3.threshold != 3 {
		t.Fatalf("3 of 3: %+v %v", g3, err)
	}
	g1, err := deriveGroup(k3.pk, []share{{node: 0, pub: k3.pk}}, 1)
	if err != nil || g1.threshold != 1 {
		t.Fatalf("whole key on one signer: %+v %v", g1, err)
	}
	if g, err := deriveGroup(k3.pk, []share{{node: 0, pub: k3.pk}, {node: 1, pub: k3.pk}}, 2); err == nil {
		t.Fatalf("whole key on two signers: %+v", g)
	}
	// 2 of 4 with every share: two signers on each side of a pair.
	k4 := splitKey(t, 2, 4)
	var sh4 []share
	for i := range k4.shares {
		sh4 = append(sh4, share{node: i, pub: pubOf(&k4.shares[i])})
	}
	if g, err := deriveGroup(k4.pk, sh4, 4); err == nil {
		t.Fatalf("2 of 4: %+v", g)
	}
}

// A whole key on two signers is not served: each could sign one side of a
// conflicting pair. The log names the key. The same key on one signer is
// served.
func TestWholeKeyOnTwoSignersRefused(t *testing.T) {
	k := splitKey(t, 2, 3)
	w := splitKey(t, 1, 1)
	fakes := cluster([]*testKey{k}, 3)
	for _, f := range fakes[:2] {
		f.keys = append(f.keys, proto.ValidatorKey{Pubkey: proto.Pubkey(w.pk), SharePubkey: proto.Pubkey(w.pk), Index: proto.IndexUnknown})
		f.secret[proto.Pubkey(w.pk)] = &w.sk
	}
	runners, names := make([]runner, len(fakes)), make([]string, len(fakes))
	for i, f := range fakes {
		runners[i], names[i] = f, fmt.Sprintf("signer-%d", i+1)
	}
	var logs strings.Builder
	s := newSigners(names, runners, 0, 2*time.Second, slog.New(slog.NewTextHandler(&logs, nil)))
	if _, err := s.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if s.HasKey(context.Background(), w.pk) {
		t.Fatal("a whole key on two signers is served")
	}
	if !s.HasKey(context.Background(), k.pk) {
		t.Fatal("the 2 of 3 key is not served")
	}
	if l := logs.String(); !strings.Contains(l, "key refused") || !strings.Contains(l, fmt.Sprintf("%#x", w.pk)) {
		t.Fatalf("no refusal naming the key in the log: %s", l)
	}

	fakes = append(cluster([]*testKey{k}, 3), cluster([]*testKey{w}, 1)...)
	setRoot(fakes)
	s = newTestSigners(t, fakes)
	sig, err := signWith(t, s, w.pk)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyBLS(w.pk, testRoot, sig); err != nil {
		t.Fatal(err)
	}
}

// A whole key is served only from a signer whose setup says signing_mode
// = single. A share key equal to the validator key is not enough: a
// signer of a threshold cluster, or one that reports no mode, that lists a
// whole key is refused for that key. The other keys stay served, and
// threshold signers get no HEALTH call.
func TestWholeKeyNeedsSingleMode(t *testing.T) {
	k := splitKey(t, 2, 3)
	w := splitKey(t, 1, 1)
	for _, c := range []struct {
		mode   string
		served bool
	}{{"single", true}, {"threshold", false}, {"", false}} {
		single := cluster([]*testKey{w}, 1)[0]
		single.mode = c.mode
		fakes := append(cluster([]*testKey{k}, 3), single)
		runners, names := make([]runner, len(fakes)), make([]string, len(fakes))
		for i, f := range fakes {
			runners[i], names[i] = f, fmt.Sprintf("signer-%d", i+1)
		}
		var logs strings.Builder
		s := newSigners(names, runners, 0, 2*time.Second, slog.New(slog.NewTextHandler(&logs, nil)))
		if _, err := s.Refresh(context.Background()); err != nil {
			t.Fatal(err)
		}
		if got := s.HasKey(context.Background(), w.pk); got != c.served {
			t.Errorf("signing_mode %q: whole key served %v, want %v", c.mode, got, c.served)
		}
		if !s.HasKey(context.Background(), k.pk) {
			t.Errorf("signing_mode %q: the 2 of 3 key is not served", c.mode)
		}
		if !c.served && !strings.Contains(logs.String(), "signing_mode") {
			t.Errorf("signing_mode %q: the refusal does not name signing_mode: %s", c.mode, logs.String())
		}
		// The threshold signers are asked for HEALTH too (their protocol
		// level), but their signing_mode never decides a whole key.
		for i, f := range fakes[:3] {
			f.set(func(f *fakeRunner) {
				if f.health == 0 {
					t.Errorf("threshold signer %d got no HEALTH call", i+1)
				}
			})
		}
	}
}

// A signer whose HEALTH reports a protocol level above the gateway's gets
// one warning, however many refreshes see it; a signer at the gateway's
// level or without a level gets none.
func TestNewerProtocolLevelWarnsOnce(t *testing.T) {
	newer, same, none := splitKey(t, 1, 1), splitKey(t, 1, 1), splitKey(t, 1, 1)
	fakes := []*fakeRunner{cluster([]*testKey{newer}, 1)[0], cluster([]*testKey{same}, 1)[0], cluster([]*testKey{none}, 1)[0]}
	fakes[0].protocol, fakes[1].protocol = proto.ProtocolLevel+1, proto.ProtocolLevel
	runners, names := make([]runner, len(fakes)), make([]string, len(fakes))
	for i, f := range fakes {
		runners[i], names[i] = f, fmt.Sprintf("signer-%d", i+1)
	}
	var logs strings.Builder
	s := newSigners(names, runners, 0, 2*time.Second, slog.New(slog.NewTextHandler(&logs, nil)))
	for range 3 {
		if _, err := s.Refresh(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	const msg = "newer protocol level"
	if n := strings.Count(logs.String(), msg); n != 1 || !strings.Contains(logs.String(), "signer=signer-1") {
		t.Fatalf("%d warnings, want 1 for signer-1:\n%s", n, logs.String())
	}
	if !s.HasKey(context.Background(), newer.pk) {
		t.Fatal("a signer with a newer level is not served")
	}
}

// In a threshold cluster no signer lists a whole key; a signer with a newer
// protocol level still gets one warning, and the key is still served
// (rv-93s.1).
func TestNewerProtocolLevelWarnsInAThresholdCluster(t *testing.T) {
	k := splitKey(t, 2, 3)
	fakes := cluster([]*testKey{k}, 3)
	fakes[1].protocol = proto.ProtocolLevel + 1
	runners, names := make([]runner, len(fakes)), make([]string, len(fakes))
	for i, f := range fakes {
		runners[i], names[i] = f, fmt.Sprintf("signer-%d", i+1)
	}
	var logs strings.Builder
	s := newSigners(names, runners, 0, 2*time.Second, slog.New(slog.NewTextHandler(&logs, nil)))
	for range 3 {
		if _, err := s.Refresh(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	const msg = "newer protocol level"
	if n := strings.Count(logs.String(), msg); n != 1 || !strings.Contains(logs.String(), "signer=signer-2") {
		t.Fatalf("%d warnings, want 1 for signer-2:\n%s", n, logs.String())
	}
	if !s.HasKey(context.Background(), k.pk) {
		t.Fatal("the 2 of 3 key is not served")
	}
}

// A signer whose HEALTH fails at the first load has its whole key refused;
// once served, the key stays served through a later HEALTH failure (for
// at most modeMaxAge, TestWholeKeyModeAgesOut), and goes when the signer
// reports another mode.
func TestWholeKeyAcrossHealthFailures(t *testing.T) {
	k := splitKey(t, 2, 3)
	w := splitKey(t, 1, 1)
	single := cluster([]*testKey{w}, 1)[0]
	single.healthErr = errors.New("health down")
	s := newTestSigners(t, append(cluster([]*testKey{k}, 3), single))
	if s.HasKey(context.Background(), w.pk) {
		t.Fatal("a whole key is served before its signer reported a mode")
	}
	single.set(func(f *fakeRunner) { f.healthErr = nil })
	if _, err := s.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !s.HasKey(context.Background(), w.pk) {
		t.Fatal("the whole key of a single-mode signer is not served")
	}
	single.set(func(f *fakeRunner) { f.healthErr = errors.New("health down") })
	if _, err := s.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !s.HasKey(context.Background(), w.pk) {
		t.Fatal("a HEALTH failure dropped a whole key served before")
	}
	single.set(func(f *fakeRunner) { f.healthErr, f.mode = nil, "threshold" })
	if _, err := s.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if s.HasKey(context.Background(), w.pk) {
		t.Fatal("the whole key stays served after its signer reported threshold")
	}
}

// Shares 1 and 3 of a 2-of-3 key on two signers, with the indices tried
// up to max_share_index.
func TestShareIndicesWithAGap(t *testing.T) {
	k := splitKey(t, 2, 3)
	g, err := deriveGroup(k.pk, []share{{node: 0, pub: pubOf(&k.shares[0])}, {node: 1, pub: pubOf(&k.shares[2])}}, 3)
	if err != nil || g.threshold != 2 || g.shares[0].index != 1 || g.shares[1].index != 3 {
		t.Fatalf("%+v %v", g, err)
	}
	if _, err := deriveGroup(k.pk, []share{{node: 0, pub: pubOf(&k.shares[0])}, {node: 1, pub: pubOf(&k.shares[2])}}, 2); err == nil {
		t.Fatal("index 3 found with max 2")
	}
}

// A whole key on one signer next to a real split of the same key on
// others is refused, whatever max_share_index: the whole-key signer signs
// alone, so it and the split signers form disjoint signing sets.
func TestWholeKeyNextToSharesRefused(t *testing.T) {
	for _, c := range []struct{ t, n int }{{2, 2}, {2, 3}} {
		k := splitKey(t, c.t, c.n)
		var sh []share
		for i := range k.shares {
			sh = append(sh, share{node: i, pub: pubOf(&k.shares[i])})
		}
		sh = append(sh, share{node: len(sh), pub: k.pk})
		g, err := deriveGroup(k.pk, sh, maxShareIndex)
		if err == nil {
			t.Errorf("%d of %d plus the whole key: served with threshold %d", c.t, c.n, g.threshold)
		} else if !strings.Contains(err.Error(), "whole key") {
			t.Errorf("%d of %d plus the whole key: %v", c.t, c.n, err)
		}
	}
}

// A signer that is down at a key load keeps its last answer, so its
// share stays in the group.
func TestKeyListKeepsAnswersOfASignerThatIsDown(t *testing.T) {
	k := splitKey(t, 2, 3)
	fakes := cluster([]*testKey{k}, 3)
	s := newTestSigners(t, fakes)
	fakes[0].set(func(f *fakeRunner) { f.err = io.EOF })
	if _, err := s.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if g, ok := s.keys.lookup(k.pk); !ok || len(g.shares) != 3 {
		t.Fatalf("group %+v", g)
	}
}

// A signer that was down at the first load joins once a request finds the
// list older than keysMaxAge, even a request for a key the list has.
func TestKeyListReloadsWhenStaleOnAHit(t *testing.T) {
	k := splitKey(t, 2, 3)
	fakes := cluster([]*testKey{k}, 3)
	fakes[0].set(func(f *fakeRunner) { f.err = io.EOF })
	s := newTestSigners(t, fakes)
	if g, ok := s.keys.lookup(k.pk); !ok || len(g.shares) != 2 {
		t.Fatalf("first load: group %+v", g)
	}
	fakes[0].set(func(f *fakeRunner) { f.err = nil })
	var skew atomic.Int64
	s.keys.now = func() time.Time { return time.Now().Add(time.Duration(skew.Load())) }
	skew.Store(int64(keysMaxAge + time.Second))
	if !s.HasKey(context.Background(), k.pk) {
		t.Fatal("key lost")
	}
	for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if g, _ := s.keys.lookup(k.pk); len(g.shares) == 3 {
			return
		}
	}
	t.Fatal("the signer that was down did not join")
}

// The gateway tries share indices up to 8 at most, whatever it is given.
func TestMaxShareIndexCapped(t *testing.T) {
	if s := newSigners(nil, nil, 64, time.Second, slog.New(slog.NewTextHandler(io.Discard, nil))); s.maxIndex != 8 {
		t.Fatalf("max index %d, want 8", s.maxIndex)
	}
}

// skewClock moves the gateway's clock d ahead of the wall clock.
func skewClock(s *Signers, d time.Duration) {
	s.keys.now = func() time.Time { return time.Now().Add(d) }
}

// A whole key is served while its signer's signing_mode is younger than
// three key refreshes. Once HEALTH fails for longer, the next load refuses
// the whole key and says why; the threshold key stays served. A HEALTH
// answer of single brings the whole key back at the next load.
func TestWholeKeyModeAgesOut(t *testing.T) {
	k := splitKey(t, 2, 3)
	w := splitKey(t, 1, 1)
	single := cluster([]*testKey{w}, 1)[0]
	fakes := append(cluster([]*testKey{k}, 3), single)
	runners, names := make([]runner, len(fakes)), make([]string, len(fakes))
	for i, f := range fakes {
		runners[i], names[i] = f, fmt.Sprintf("signer-%d", i+1)
	}
	var logs syncBuilder
	s := newSigners(names, runners, 0, 2*time.Second, slog.New(slog.NewTextHandler(&logs, nil)))
	if _, err := s.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	single.set(func(f *fakeRunner) { f.healthErr = errors.New("health down") })
	skewClock(s, 2*keysMaxAge)
	if _, err := s.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.keys.lookup(w.pk); !ok {
		t.Fatal("a whole key whose mode is two refreshes old is not served")
	}
	skewClock(s, 3*keysMaxAge+time.Second)
	if _, err := s.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.keys.lookup(w.pk); ok {
		t.Fatal("the whole key is still served after its signing_mode aged out")
	}
	if !strings.Contains(logs.String(), "key refused") || !strings.Contains(logs.String(), "older than") {
		t.Fatalf("the refusal does not say the mode is too old:\n%s", logs.String())
	}
	if _, ok := s.keys.lookup(k.pk); !ok {
		t.Fatal("the 2 of 3 key is not served")
	}
	single.set(func(f *fakeRunner) { f.healthErr = nil })
	if _, err := s.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.keys.lookup(w.pk); !ok {
		t.Fatal("the whole key did not come back after HEALTH said single again")
	}
}

// When every key is whole, a load that fails still drops a whole key whose
// signing_mode aged out: the old list is not kept as it was.
func TestWholeKeyModeAgesOutWhenTheLoadFails(t *testing.T) {
	w := splitKey(t, 1, 1)
	single := cluster([]*testKey{w}, 1)[0]
	s := newTestSigners(t, []*fakeRunner{single})
	if _, ok := s.keys.lookup(w.pk); !ok {
		t.Fatal("the whole key of a single-mode signer is not served")
	}
	single.set(func(f *fakeRunner) { f.err = io.EOF })
	skewClock(s, 3*keysMaxAge+time.Second)
	if _, err := s.Refresh(context.Background()); err == nil {
		t.Fatal("a load with no key to serve passed")
	}
	if _, ok := s.keys.lookup(w.pk); ok {
		t.Fatal("a failed load kept a whole key whose signing_mode aged out")
	}
	single.set(func(f *fakeRunner) { f.err = nil })
	if _, err := s.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.keys.lookup(w.pk); !ok {
		t.Fatal("the whole key did not come back after HEALTH said single again")
	}
}

// A sign request for a whole key whose signing_mode aged out since the
// last load waits for a new load instead of signing with the old list: it
// signs when HEALTH says single again, and is refused, without a signer
// call, when HEALTH still fails.
func TestWholeKeySignChecksTheModeAge(t *testing.T) {
	w := splitKey(t, 1, 1)
	single := cluster([]*testKey{w}, 1)[0]
	single.root = testRoot
	s := newTestSigners(t, []*fakeRunner{single})
	skewClock(s, 3*keysMaxAge+time.Second)
	if _, err := signWith(t, s, w.pk); err != nil {
		t.Fatalf("a fresh HEALTH answer did not let the whole key sign: %v", err)
	}
	single.set(func(f *fakeRunner) { f.healthErr, f.signs = errors.New("health down"), 0 })
	skewClock(s, 2*(3*keysMaxAge+time.Second))
	_, err := signWith(t, s, w.pk)
	if !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("whole key with an aged-out signing_mode: %v, want ErrUnknownKey", err)
	}
	single.set(func(f *fakeRunner) {
		if f.signs != 0 {
			t.Errorf("%d sign calls for a whole key whose signing_mode aged out", f.signs)
		}
	})
}

// Threshold keys do not depend on HEALTH: a key of a 2-of-3 cluster stays
// served and signs when no signer answered HEALTH for longer than the
// whole-key limit.
func TestThresholdKeyIgnoresModeAge(t *testing.T) {
	k := splitKey(t, 2, 3)
	fakes := cluster([]*testKey{k}, 3)
	setRoot(fakes)
	s := newTestSigners(t, fakes)
	for _, f := range fakes {
		f.set(func(f *fakeRunner) { f.healthErr = errors.New("health down") })
	}
	skewClock(s, 10*keysMaxAge)
	if _, err := s.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := signWith(t, s, k.pk); err != nil {
		t.Fatal(err)
	}
}

// syncBuilder is a strings.Builder safe for the log writes of background
// loads.
type syncBuilder struct {
	mu sync.Mutex
	b  strings.Builder
}

func (b *syncBuilder) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.b.Write(p)
}

func (b *syncBuilder) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.b.String()
}
