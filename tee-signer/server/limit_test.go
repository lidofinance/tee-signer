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

// NonAdminFreshPerMinute bounds the fresh attestations of every limited
// certificate together: the next one, from any certificate of either role,
// waits until entries age out. Admin clients are not counted.
func TestAttestLimitOverAllCertificates(t *testing.T) {
	s, _, now := limitServer(t)
	ctx := context.Background()
	for i := 0; i < NonAdminFreshPerMinute; i++ {
		cl := &client{role: attls.RoleAttestOnly, cert: [32]byte{0x80, byte(i)}}
		if i%2 == 1 {
			cl.role = attls.RoleSigning
		}
		if _, err := s.dispatchFor(ctx, attestFrame(wire.TypeIdentity, 1), cl); err != nil {
			t.Fatalf("certificate %d: %v", i, err)
		}
	}
	for _, extra := range []*client{{role: attls.RoleSigning, cert: [32]byte{0x81}}, {role: attls.RoleAttestOnly, cert: [32]byte{0x82}}} {
		if _, err := s.dispatchFor(ctx, attestFrame(wire.TypeIdentity, 1), extra); refusedWith(err) != backend.StatusRateLimited {
			t.Fatalf("%v certificate, attestation %d: %v", extra.role, NonAdminFreshPerMinute+1, err)
		}
	}
	if _, err := s.dispatchFor(ctx, attestFrame(wire.TypeIdentity, 2), localAdmin); err != nil {
		t.Fatalf("admin over the limit: %v", err)
	}
	*now = now.Add(attestWindow)
	if _, err := s.dispatchFor(ctx, attestFrame(wire.TypeIdentity, 1), &client{role: attls.RoleSigning, cert: [32]byte{0x81}}); err != nil {
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
	for n := 0; n < 2*NonAdminFreshPerMinute; n++ {
		if _, err := s.dispatchFor(ctx, attestFrame(wire.TypeIdentity, byte(n)), localAdmin); err != nil {
			t.Fatalf("admin IDENTITY %d: %v", n, err)
		}
	}
	*now = now.Add(attestWindow)
	if _, err := s.dispatchFor(ctx, attestFrame(wire.TypeIdentity, 200), fork); err != nil {
		t.Fatalf("after a minute: %v", err)
	}
}
