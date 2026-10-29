package backend

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/herumi/bls-eth-go-binary/bls"

	proto "github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/web3signer-api/signing"
)

// testKey is a validator key split t of n: the secret, its public key, and
// share i (index i+1) of each signer.
type testKey struct {
	sk     bls.SecretKey
	pk     phase0.BLSPubKey
	shares []bls.SecretKey
}

func splitKey(t *testing.T, threshold, n int) *testKey {
	t.Helper()
	if err := initBLS(); err != nil {
		t.Fatal(err)
	}
	poly := make([]bls.SecretKey, threshold)
	for i := range poly {
		poly[i].SetByCSPRNG()
	}
	k := &testKey{sk: poly[0]}
	copy(k.pk[:], poly[0].GetPublicKey().Serialize())
	for i := 1; i <= n; i++ {
		id, err := shareID(uint64(i))
		if err != nil {
			t.Fatal(err)
		}
		var s bls.SecretKey
		if err := s.Set(poly, &id); err != nil {
			t.Fatal(err)
		}
		k.shares = append(k.shares, s)
	}

	return k
}

func pubOf(s *bls.SecretKey) phase0.BLSPubKey {
	var pk phase0.BLSPubKey
	copy(pk[:], s.GetPublicKey().Serialize())

	return pk
}

func signRoot(s *bls.SecretKey, root phase0.Root) proto.Signature {
	var sig proto.Signature
	copy(sig[:], s.SignByte(root[:]).Serialize())

	return sig
}

// fakeRunner is a signer that holds shares and signs the root the test
// gives it, or fails as the test says.
type fakeRunner struct {
	mu     sync.Mutex
	keys   []proto.ValidatorKey
	secret map[proto.Pubkey]*bls.SecretKey
	root   phase0.Root
	err    error          // every call fails with it
	signer *bls.SecretKey // signs with this key instead of the share (a bad partial)
	hang   chan struct{}  // Sign waits until it closes or ctx ends
	signs  int
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

// cluster is n fake signers that hold share i of each key.
func cluster(keys []*testKey, n int) []*fakeRunner {
	fakes := make([]*fakeRunner, n)
	for i := range fakes {
		f := &fakeRunner{secret: map[proto.Pubkey]*bls.SecretKey{}}
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

// Two signers refuse on slashing protection: a denial (HTTP 412), as soon
// as the threshold is out of reach.
func TestCombineDenied(t *testing.T) {
	k := splitKey(t, 2, 3)
	fakes := cluster([]*testKey{k}, 3)
	setRoot(fakes)
	s := newTestSigners(t, fakes)
	hang := make(chan struct{})
	defer close(hang)
	fakes[0].set(func(f *fakeRunner) { f.err = proto.Refused(proto.StatusSlashTarget, "double vote") })
	fakes[1].set(func(f *fakeRunner) { f.err = proto.Refused(proto.StatusSlashTarget, "double vote") })
	fakes[2].set(func(f *fakeRunner) { f.hang = hang })
	_, err := signWith(t, s, k.pk)
	var denied *DeniedError
	if !errors.As(err, &denied) || !strings.Contains(err.Error(), "SC_ERR_SLASH_TARGET") {
		t.Fatalf("want a denial, got %v", err)
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

	// 3 of 3, and a whole key on every signer.
	k3 := splitKey(t, 3, 3)
	g3, err := deriveGroup(k3.pk, []share{{node: 0, pub: pubOf(&k3.shares[0])}, {node: 1, pub: pubOf(&k3.shares[1])},
		{node: 2, pub: pubOf(&k3.shares[2])}}, 3)
	if err != nil || g3.threshold != 3 {
		t.Fatalf("3 of 3: %+v %v", g3, err)
	}
	g1, err := deriveGroup(k3.pk, []share{{node: 0, pub: k3.pk}, {node: 1, pub: k3.pk}}, 2)
	if err != nil || g1.threshold != 1 {
		t.Fatalf("whole key: %+v %v", g1, err)
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
