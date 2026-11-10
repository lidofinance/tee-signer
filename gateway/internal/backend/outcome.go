package backend

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/attestantio/go-eth2-client/spec/phase0"

	proto "github.com/lidofinance/tee-signer/signer-protocol"
)

// Results of one signer in a sign request.
const (
	ResultSigned  = "signed"
	ResultDenied  = "denied"
	ResultError   = "error"
	ResultPending = "pending"  // asked, no answer when the request ended
	ResultNoShare = "no_share" // holds no share of the key, not asked
)

// warnEvery is how often the same signer, request type and reason may log
// a "signer did not sign" line.
const warnEvery = 5 * time.Minute

// errBadPartial marks a partial signature that does not verify under the
// share key.
var errBadPartial = errors.New("partial signature does not verify under the share key")

// Outcome is what one configured signer did with a sign request.
type Outcome struct {
	Signer string
	Result string
	// Reason is the signer's status name for a refusal, else timeout,
	// canceled, bad_partial or failed. Empty when it signed or did not
	// answer.
	Reason string
	Detail string
}

// SignError is a failed sign with the outcome at every configured signer,
// in config order. It wraps the error that says why.
type SignError struct {
	Err      error
	Outcomes []Outcome
}

func (e *SignError) Error() string { return e.Err.Error() }

func (e *SignError) Unwrap() error { return e.Err }

// LogAttr is the outcomes as one log group, signers.<name>.result and so on.
func (e *SignError) LogAttr() slog.Attr {
	attrs := make([]any, 0, len(e.Outcomes))
	for _, o := range e.Outcomes {
		a := []any{slog.String("result", o.Result)}
		if o.Reason != "" {
			a = append(a, slog.String("reason", o.Reason))
		}
		if o.Detail != "" {
			a = append(a, slog.String("detail", o.Detail))
		}
		attrs = append(attrs, slog.Group(o.Signer, a...))
	}

	return slog.Group("signers", attrs...)
}

// outcomeOf turns a signer's answer into an Outcome.
func outcomeOf(name string, err error) Outcome {
	o := Outcome{Signer: name, Result: ResultError}
	var r *proto.RefusedError
	switch {
	case err == nil:
		o.Result = ResultSigned

		return o
	case errors.As(err, &r):
		if isDenial(err) {
			o.Result = ResultDenied
		}
		o.Reason, o.Detail = r.Code.String(), r.Detail

		return o
	case errors.Is(err, errBadPartial):
		o.Reason = "bad_partial"
	case errors.Is(err, context.DeadlineExceeded):
		o.Reason = "timeout"
	case errors.Is(err, context.Canceled):
		o.Reason = "canceled"
	default:
		o.Reason = "failed"
	}
	o.Detail = err.Error()

	return o
}

// outcomes lists every configured signer: the answers in parts, pending for
// the other signers of g, no_share for the rest.
func (s *Signers) outcomes(g group, parts []partial) []Outcome {
	out := make([]Outcome, len(s.names))
	for i, n := range s.names {
		out[i] = Outcome{Signer: n, Result: ResultNoShare}
	}
	for _, sh := range g.shares {
		out[sh.node].Result = ResultPending
	}
	for _, p := range parts {
		out[p.share.node] = outcomeOf(s.names[p.share.node], p.err)
	}

	return out
}

// warnSigner logs a signer that did not sign a request that still got its
// signature, at most once per signer, request type and reason per
// warnEvery.
func (s *Signers) warnSigner(duty string, pubkey phase0.BLSPubKey, p partial) {
	o := outcomeOf(s.names[p.share.node], p.err)
	ok, suppressed := s.warns.allow(warnKey{signer: o.Signer, duty: duty, reason: o.Reason})
	if !ok {
		return
	}
	attrs := []any{"signer", o.Signer, "type", duty, "pubkey", fmt.Sprintf("%#x", pubkey[:4]),
		"result", o.Result, "reason", o.Reason}
	if o.Detail != "" {
		attrs = append(attrs, "detail", o.Detail)
	}
	if suppressed > 0 {
		attrs = append(attrs, "suppressed", suppressed)
	}
	s.log.Warn("signer did not sign, threshold met", attrs...)
}

type warnKey struct{ signer, duty, reason string }

type warnState struct {
	last       time.Time
	suppressed int
}

// warnLimit lets one line per key through per interval and counts the
// rest. The keys are signer names, request types and reasons, a small set.
type warnLimit struct {
	every time.Duration
	now   func() time.Time

	mu   sync.Mutex
	seen map[warnKey]*warnState
}

func newWarnLimit(every time.Duration) *warnLimit {
	return &warnLimit{every: every, now: time.Now, seen: map[warnKey]*warnState{}}
}

// allow reports whether to log k now, and how many lines for k it held
// back since the last one it let through.
func (l *warnLimit) allow(k warnKey) (bool, int) {
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	st, ok := l.seen[k]
	if !ok {
		l.seen[k] = &warnState{last: now}

		return true, 0
	}
	if now.Sub(st.last) < l.every {
		st.suppressed++

		return false, 0
	}
	n := st.suppressed
	st.last, st.suppressed = now, 0

	return true, n
}
