package server

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/wire"
	"github.com/lidofinance/tee-signer/tee-signer/attls"
)

// countingAttester is fakeAttester that counts its calls and can fail.
type countingAttester struct {
	calls atomic.Int32
	fail  atomic.Bool
}

func (c *countingAttester) Attest(ctx context.Context, nonce, userData []byte) (*backend.Attestation, error) {
	c.calls.Add(1)
	if c.fail.Load() {
		return nil, errors.New("platform down")
	}
	return fakeAttester{}.Attest(ctx, nonce, userData)
}

// limitServer is a role server with a counting attester and a clock the
// test moves.
func limitServer(t *testing.T) (*Server, *countingAttester, *time.Time) {
	t.Helper()
	s := roleServer(t)
	att := &countingAttester{}
	s.Platform.Attester = att
	now := time.Unix(1_800_000_000, 0)
	s.limitNow = func() time.Time { return now }
	return s, att, &now
}

func attestFrame(t wire.MsgType, nonce byte) wire.Frame {
	p, _ := wire.EncodeAttest(bytes.Repeat([]byte{nonce}, 32))
	return wire.Frame{Type: t, Payload: p}
}

// An attest-only certificate gets AttestOnlyPerMinute fresh attestations
// in any minute, ATTEST and IDENTITY together; a repeat of a request gets
// its answer again without a platform call while the state stands; the
// minute slides; other certificates and full clients have their own or
// no limit.
func TestAttestOnlyLimit(t *testing.T) {
	s, att, now := limitServer(t)
	ctx := context.Background()
	prover := &client{role: attls.RoleAttestOnly, cert: [32]byte{1}}
	answers := map[byte][]byte{}
	for n := byte(1); n <= backend.AttestOnlyPerMinute; n++ {
		body, err := s.dispatchFor(ctx, attestFrame(wire.TypeAttest, n), prover)
		if err != nil {
			t.Fatalf("fresh attestation %d: %v", n, err)
		}
		answers[n] = body
		*now = now.Add(time.Second)
	}
	if att.calls.Load() != backend.AttestOnlyPerMinute {
		t.Fatalf("%d platform calls", att.calls.Load())
	}
	_, err := s.dispatchFor(ctx, attestFrame(wire.TypeAttest, 9), prover)
	if refusedWith(err) != backend.StatusRateLimited || !strings.Contains(err.Error(), "possible in 56 s") {
		t.Fatalf("fifth fresh attestation: %v", err)
	}
	if _, err := s.dispatchFor(ctx, attestFrame(wire.TypeIdentity, 9), prover); refusedWith(err) != backend.StatusRateLimited {
		t.Fatalf("IDENTITY over the limit: %v", err)
	}
	body, err := s.dispatchFor(ctx, attestFrame(wire.TypeAttest, 2), prover)
	if err != nil || !bytes.Equal(body, answers[2]) || att.calls.Load() != backend.AttestOnlyPerMinute {
		t.Fatalf("repeat of nonce 2: %v, same answer %v, %d platform calls", err, bytes.Equal(body, answers[2]), att.calls.Load())
	}
	if _, err := s.dispatchFor(ctx, attestFrame(wire.TypeIdentity, 2), prover); refusedWith(err) != backend.StatusRateLimited {
		t.Fatalf("IDENTITY with an ATTEST nonce is a fresh attestation: %v", err)
	}
	other := &client{role: attls.RoleAttestOnly, cert: [32]byte{2}}
	if _, err := s.dispatchFor(ctx, attestFrame(wire.TypeAttest, 9), other); err != nil {
		t.Fatalf("another certificate: %v", err)
	}
	for n := byte(1); n <= backend.AttestOnlyPerMinute+2; n++ {
		if _, err := s.dispatchFor(ctx, attestFrame(wire.TypeAttest, 100+n), localAdmin); err != nil {
			t.Fatalf("full client, attestation %d: %v", n, err)
		}
	}

	// A minute after the first one, one more is fresh.
	*now = time.Unix(1_800_000_060, 0)
	if _, err := s.dispatchFor(ctx, attestFrame(wire.TypeAttest, 9), prover); err != nil {
		t.Fatalf("after the first one aged out: %v", err)
	}
	if _, err := s.dispatchFor(ctx, attestFrame(wire.TypeAttest, 10), prover); refusedWith(err) != backend.StatusRateLimited {
		t.Fatalf("full again: %v", err)
	}
	// Another state: the repeat of nonce 3 would bind other bytes, so it is
	// fresh, and the minute is full.
	s.State = constState(backend.SetupState{SetupHash: backend.Root{0xa}, Locked: backend.ConfigGroup{Version: 1}})
	if _, err := s.dispatchFor(ctx, attestFrame(wire.TypeAttest, 3), prover); refusedWith(err) != backend.StatusRateLimited {
		t.Fatalf("repeat after a state change: %v, want a fresh attestation and RATE_LIMITED", err)
	}
}

// A failed attestation counts (it called the platform) and leaves no
// answer to repeat.
func TestAttestOnlyLimitCountsFailures(t *testing.T) {
	s, att, _ := limitServer(t)
	ctx := context.Background()
	prover := &client{role: attls.RoleAttestOnly, cert: [32]byte{3}}
	att.fail.Store(true)
	for i := 0; i < backend.AttestOnlyPerMinute; i++ {
		if _, err := s.dispatchFor(ctx, attestFrame(wire.TypeAttest, 1), prover); refusedWith(err) != backend.StatusPlatform {
			t.Fatalf("try %d: %v", i+1, err)
		}
	}
	att.fail.Store(false)
	if _, err := s.dispatchFor(ctx, attestFrame(wire.TypeAttest, 1), prover); refusedWith(err) != backend.StatusRateLimited {
		t.Fatalf("after %d failures: %v", backend.AttestOnlyPerMinute, err)
	}
}

// AttestOnlyFreshPerMinute bounds the fresh attestations of every
// attest-only certificate together: the next attest-only certificate waits
// until entries age out. The total is the role's own: a signing
// certificate's IDENTITY still passes while attest-only certificates hold
// their whole total, so an attest-only flood (32 certificates, or the
// attest CA minting more) cannot lock the signing clients out. Admin
// clients are not counted.
func TestAttestOnlyFloodLeavesSigningAlone(t *testing.T) {
	s, _, now := limitServer(t)
	ctx := context.Background()
	for i := 0; i < AttestOnlyFreshPerMinute; i++ {
		cl := &client{role: attls.RoleAttestOnly, cert: [32]byte{0x80, byte(i / backend.AttestOnlyPerMinute)}}
		if _, err := s.dispatchFor(ctx, attestFrame(wire.TypeIdentity, byte(1+i%backend.AttestOnlyPerMinute)), cl); err != nil {
			t.Fatalf("attest-only attestation %d: %v", i+1, err)
		}
	}
	extra := &client{role: attls.RoleAttestOnly, cert: [32]byte{0x82}}
	_, err := s.dispatchFor(ctx, attestFrame(wire.TypeIdentity, 1), extra)
	if refusedWith(err) != backend.StatusRateLimited || !strings.Contains(err.Error(), "attest-only client certificates had 128") {
		t.Fatalf("attest-only certificate %d: %v", AttestOnlyFreshPerMinute/backend.AttestOnlyPerMinute+1, err)
	}
	signing := &client{role: attls.RoleSigning, cert: [32]byte{0x81}}
	for n := 1; n <= 16; n++ {
		if _, err := s.dispatchFor(ctx, attestFrame(wire.TypeIdentity, byte(n)), signing); err != nil {
			t.Fatalf("signing IDENTITY %d while the attest-only total is full: %v", n, err)
		}
	}
	if _, err := s.dispatchFor(ctx, attestFrame(wire.TypeIdentity, 2), localAdmin); err != nil {
		t.Fatalf("admin over the limit: %v", err)
	}
	*now = now.Add(attestWindow)
	if _, err := s.dispatchFor(ctx, attestFrame(wire.TypeIdentity, 1), extra); err != nil {
		t.Fatalf("after a minute: %v", err)
	}
}

// SigningFreshPerMinute bounds the fresh IDENTITY answers of every signing
// certificate together: a dozen at their own limit fill it, the next
// signing certificate waits, and an attest-only certificate still has its
// own total.
func TestSigningLimitOverAllCertificates(t *testing.T) {
	s, _, now := limitServer(t)
	ctx := context.Background()
	for i := 0; i < SigningFreshPerMinute; i++ {
		cl := &client{role: attls.RoleSigning, cert: [32]byte{0x90, byte(i / SigningIdentityPerMinute)}}
		if _, err := s.dispatchFor(ctx, attestFrame(wire.TypeIdentity, byte(1+i%SigningIdentityPerMinute)), cl); err != nil {
			t.Fatalf("signing IDENTITY %d: %v", i+1, err)
		}
	}
	extra := &client{role: attls.RoleSigning, cert: [32]byte{0x91}}
	_, err := s.dispatchFor(ctx, attestFrame(wire.TypeIdentity, 1), extra)
	if refusedWith(err) != backend.StatusRateLimited || !strings.Contains(err.Error(), "signing client certificates had 768") {
		t.Fatalf("signing certificate %d: %v", SigningFreshPerMinute/SigningIdentityPerMinute+1, err)
	}
	if _, err := s.dispatchFor(ctx, attestFrame(wire.TypeAttest, 1), &client{role: attls.RoleAttestOnly, cert: [32]byte{0x92}}); err != nil {
		t.Fatalf("attest-only while the signing total is full: %v", err)
	}
	*now = now.Add(attestWindow)
	if _, err := s.dispatchFor(ctx, attestFrame(wire.TypeIdentity, 1), extra); err != nil {
		t.Fatalf("after a minute: %v", err)
	}
}

// A signing certificate gets SigningIdentityPerMinute fresh IDENTITY
// answers a minute; the next is RATE_LIMITED, a repeated nonce is free,
// and an admin client has no limit.
func TestSigningIdentityLimit(t *testing.T) {
	s, att, now := limitServer(t)
	ctx := context.Background()
	fork := &client{role: attls.RoleSigning, cert: [32]byte{9}}
	for n := 1; n <= SigningIdentityPerMinute; n++ {
		if _, err := s.dispatchFor(ctx, attestFrame(wire.TypeIdentity, byte(n)), fork); err != nil {
			t.Fatalf("IDENTITY %d: %v", n, err)
		}
	}
	calls := att.calls.Load()
	if _, err := s.dispatchFor(ctx, attestFrame(wire.TypeIdentity, 3), fork); err != nil {
		t.Fatalf("repeated nonce: %v", err)
	}
	if att.calls.Load() != calls {
		t.Fatal("a repeated nonce called the platform")
	}
	_, err := s.dispatchFor(ctx, attestFrame(wire.TypeIdentity, 200), fork)
	if refusedWith(err) != backend.StatusRateLimited || !strings.Contains(err.Error(), "signing") {
		t.Fatalf("IDENTITY %d: %v, want RATE_LIMITED", SigningIdentityPerMinute+1, err)
	}
	if _, err := s.dispatchFor(ctx, attestFrame(wire.TypeAttest, 1), fork); refusedWith(err) != backend.StatusForbidden {
		t.Fatalf("signing ATTEST: %v, want FORBIDDEN", err)
	}
	for n := 0; n < 2*AttestOnlyFreshPerMinute; n++ {
		if _, err := s.dispatchFor(ctx, attestFrame(wire.TypeIdentity, byte(n)), localAdmin); err != nil {
			t.Fatalf("admin IDENTITY %d: %v", n, err)
		}
	}
	*now = now.Add(attestWindow)
	if _, err := s.dispatchFor(ctx, attestFrame(wire.TypeIdentity, 200), fork); err != nil {
		t.Fatalf("after a minute: %v", err)
	}
}

// Pruning releases the expired answers: the entries it drops from the front
// of a certificate's list must not stay reachable through the backing array.
func TestAttestLimitPruneReleasesExpired(t *testing.T) {
	var l attestLimit
	now := time.Unix(1_800_000_000, 0)
	cert := [32]byte{7}
	for n := byte(1); n <= 3; n++ {
		_, e, err := l.begin(cert, "signing", 8, 8, wire.TypeIdentity, []byte{n}, nil, now)
		if err != nil {
			t.Fatal(err)
		}
		l.finish(e, make([]byte, 1024))
		now = now.Add(attestWindow / 4)
	}
	before := l.certs[cert]
	l.pruneLocked(now.Add(attestWindow / 2))
	if got := len(l.certs[cert]); got != 1 {
		t.Fatalf("live entries: %d, want 1", got)
	}
	for i, f := range before[:2] {
		if f != nil {
			t.Fatalf("expired entry %d still held by the backing array", i)
		}
	}
}
