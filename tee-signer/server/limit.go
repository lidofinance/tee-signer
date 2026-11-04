package server

import (
	"bytes"
	"context"
	"math"
	"sync"
	"time"

	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/wire"
	"github.com/lidofinance/tee-signer/tee-signer/attls"
)

// The fresh attestation limits. A fresh attestation is an ATTEST or
// IDENTITY answer the runner makes anew for a nonce: one that this
// certificate has not had an answer to in the last minute, for the same
// message type and the same state. A repeat of such a request in that
// minute, while the setup state and the keys are unchanged, gets the same
// answer again and does not count. A prover that retries with the same
// beacon block root costs nothing; a new nonce costs one, and so does an
// attestation that failed, since it called the platform.
//
// Per certificate in any minute: backend.AttestOnlyPerMinute for an
// attest-only certificate (ATTEST and IDENTITY together),
// SigningIdentityPerMinute for a signing certificate (IDENTITY only, it
// may not send ATTEST). Over all certificates of one role together:
// AttestOnlyFreshPerMinute and SigningFreshPerMinute, so many certificates
// of a role cannot add up to an attestation flood. The two roles have
// separate totals: an attest-only flood (the attest CA can mint any number
// of certificates) must not use up what the signing clients need to
// reconnect, since a signing client whose IDENTITY is refused cannot dial
// at all. Admin clients have no limit.

const (
	attestWindow = time.Minute
	// SigningIdentityPerMinute is 4 x the signing client's pool of 16
	// connections per runner. Each connection asks for IDENTITY with a new
	// nonce when it is made, so a repeat never helps a signing client: the
	// whole pool dials at the client's start and again after every runner
	// restart or network cut, and a dial that fails and is tried again
	// costs one more. Four full pool dials in one minute cover a start, a
	// runner restart and two rounds of failed dials together; 2 x the pool
	// did not, and a pool refused here cannot reconnect until the minute
	// ends.
	SigningIdentityPerMinute = 64
	// AttestOnlyFreshPerMinute bounds the fresh attestations of all
	// attest-only certificates together in any minute (32 certificates at
	// their own limit), and so the answers the limit keeps for them.
	AttestOnlyFreshPerMinute = 128
	// SigningFreshPerMinute bounds the fresh IDENTITY answers of all signing
	// certificates together: a dozen signing clients (limits.go plans for
	// that many) each at SigningIdentityPerMinute. It bounds the answers
	// the limit keeps when the signing CA issues many certificates; the
	// clients planned for never reach it before their own limit.
	SigningFreshPerMinute = 12 * SigningIdentityPerMinute
)

// attestLimit holds the fresh attestations of each limited certificate of
// one role in the last attestWindow. The zero value is ready.
type attestLimit struct {
	mu    sync.Mutex
	certs map[[32]byte][]*freshAttest // oldest first
	total int                         // entries over all certs
}

// freshAttest is one fresh attestation: when the runner began it, what it
// answered, and the answer, nil until made or when it failed.
type freshAttest struct {
	at       time.Time
	typ      wire.MsgType
	nonce    []byte
	userData []byte
	body     []byte
}

// pruneLocked drops what is older than the window.
func (l *attestLimit) pruneLocked(now time.Time) {
	for cert, list := range l.certs {
		i := 0
		for i < len(list) && now.Sub(list[i].at) >= attestWindow {
			i++
		}
		l.total -= i
		if i == len(list) {
			delete(l.certs, cert)
		} else if i > 0 {
			l.certs[cert] = list[i:]
		}
	}
}

// begin returns the answer the certificate already had for this request,
// or takes one of its fresh attestations (e, to finish), or refuses with
// RATE_LIMITED. perCert is the certificate's limit, total the limit over
// every certificate of the role, and role names it in the refusal.
func (l *attestLimit) begin(cert [32]byte, role string, perCert, total int, t wire.MsgType, nonce, userData []byte, now time.Time) (body []byte, e *freshAttest, err error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.certs == nil {
		l.certs = map[[32]byte][]*freshAttest{}
	}
	l.pruneLocked(now)
	list := l.certs[cert]
	for _, f := range list {
		if f.body != nil && f.typ == t && bytes.Equal(f.nonce, nonce) && bytes.Equal(f.userData, userData) {
			return f.body, nil, nil
		}
	}
	if len(list) >= perCert {
		wait := attestWindow - now.Sub(list[0].at)
		return nil, nil, backend.Refused(backend.StatusRateLimited,
			"%v: this %s client certificate had %d fresh attestations in the last minute, the limit; the next one is possible in %d s (the same nonce again gets the answer it had)",
			t, role, len(list), int(math.Ceil(wait.Seconds())))
	}
	if l.total >= total {
		return nil, nil, backend.Refused(backend.StatusRateLimited,
			"%v: the %s client certificates had %d fresh attestations in the last minute, the limit over all of them; try again later", t, role, l.total)
	}
	e = &freshAttest{at: now, typ: t, nonce: bytes.Clone(nonce), userData: bytes.Clone(userData)}
	l.certs[cert] = append(list, e)
	l.total++
	return nil, e, nil
}

// finish keeps the answer of e for repeats.
func (l *attestLimit) finish(e *freshAttest, body []byte) {
	l.mu.Lock()
	defer l.mu.Unlock()
	e.body = body
}

// attestation is one ATTEST or IDENTITY answer to make: the user data it
// binds, read now, and how to make it with the platform.
type attestation struct {
	userData []byte
	answer   func(ctx context.Context) ([]byte, error)
}

// attestationFor reads the state an ATTEST or IDENTITY answer for nonce
// binds.
func (s *Server) attestationFor(t wire.MsgType, nonce []byte) attestation {
	attest := func(ctx context.Context, ud []byte) (*backend.Attestation, error) {
		a, err := s.Platform.Attester.Attest(ctx, nonce, ud)
		if err != nil {
			return nil, backend.Refused(backend.StatusPlatform, "attest: %v", err)
		}
		return a, nil
	}
	if t == wire.TypeIdentity {
		id := s.identity()
		ud := backend.IdentityUserData(nonce, id)
		return attestation{ud, func(ctx context.Context) ([]byte, error) {
			a, err := attest(ctx, ud)
			if err != nil {
				return nil, err
			}
			id.Attestation = a
			return wire.EncodeIdentity(id)
		}}
	}
	st, keys := s.stateWithKeys()
	ud := backend.AttestUserData(nonce, &st, backend.KeysHash(keys))
	return attestation{ud, func(ctx context.Context) ([]byte, error) {
		a, err := attest(ctx, ud)
		if err != nil {
			return nil, err
		}
		return wire.EncodeAttestResponse(&st, a)
	}}
}

// limitedAttestation serves ATTEST or IDENTITY to an attest-only or a
// signing client, under its certificate's limit and its role's total.
func (s *Server) limitedAttestation(ctx context.Context, f wire.Frame, cl *client) ([]byte, error) {
	nonce, err := decodeNonce(f.Payload)
	if err != nil {
		return nil, err
	}
	a := s.attestationFor(f.Type, nonce)
	now := time.Now
	if s.limitNow != nil {
		now = s.limitNow
	}
	limit, perCert, total := &s.attestOnlyLimit, backend.AttestOnlyPerMinute, AttestOnlyFreshPerMinute
	if cl.role == attls.RoleSigning {
		limit, perCert, total = &s.signingLimit, SigningIdentityPerMinute, SigningFreshPerMinute
	}
	body, e, err := limit.begin(cl.cert, cl.role.String(), perCert, total, f.Type, nonce, a.userData, now())
	if err != nil {
		s.Log.Warn("refused: attestation limit", "type", f.Type.String(), "role", cl.role.String(), "err", err)
		return nil, err
	}
	if e == nil {
		return body, nil // a repeat: the answer it had
	}
	body, err = a.answer(ctx)
	if err != nil {
		return nil, err
	}
	limit.finish(e, body)
	return body, nil
}
