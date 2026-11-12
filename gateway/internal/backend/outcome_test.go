package backend

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	proto "github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/wire"
)

// syncBuf is a log sink the test reads while signer calls still write.
type syncBuf struct {
	mu sync.Mutex
	b  strings.Builder
}

func (w *syncBuf) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	return w.b.Write(p)
}

func (w *syncBuf) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()

	return w.b.String()
}

func newLoggedSigners(t *testing.T, fakes []*fakeRunner) (*Signers, *syncBuf) {
	t.Helper()
	runners := make([]runner, len(fakes))
	names := make([]string, len(fakes))
	for i, f := range fakes {
		runners[i], names[i] = f, fmt.Sprintf("signer-%d", i+1)
	}
	logs := &syncBuf{}
	s := newSigners(names, runners, 0, 2*time.Second, slog.New(slog.NewTextHandler(logs, nil)))
	if _, err := s.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}

	return s, logs
}

func warnLines(logs string) []string {
	var out []string
	for _, l := range strings.Split(logs, "\n") {
		if strings.Contains(l, `msg="signer did not sign, threshold met"`) {
			out = append(out, l)
		}
	}

	return out
}

// A 3-of-4 key that fails names every configured signer with what it did:
// a denial with its status, a failure, one that signed, one still pending,
// and a fifth signer without a share of the key.
func TestSignErrorNamesEverySigner(t *testing.T) {
	k := splitKey(t, 3, 4)
	fakes := append(cluster([]*testKey{k}, 4), cluster([]*testKey{splitKey(t, 1, 1)}, 1)...)
	setRoot(fakes)
	s := newTestSigners(t, fakes)
	late, hang := make(chan struct{}), make(chan struct{})
	defer close(hang)
	fakes[0].set(func(f *fakeRunner) { f.err = proto.Refused(proto.StatusSlashTarget, "double vote") })
	fakes[1].set(func(f *fakeRunner) { f.err, f.hang = errors.New("connection refused"), late })
	fakes[2].set(func(f *fakeRunner) { f.hang = hang })
	go func() { time.Sleep(100 * time.Millisecond); close(late) }()

	_, err := signWith(t, s, k.pk)
	var se *SignError
	var denied *DeniedError
	if !errors.As(err, &se) || !errors.As(err, &denied) {
		t.Fatalf("want a SignError around a denial, got %T %v", err, err)
	}
	want := []Outcome{
		{Signer: "signer-1", Result: ResultDenied, Reason: "SC_ERR_SLASH_TARGET", Detail: "double vote"},
		{Signer: "signer-2", Result: ResultError, Reason: "failed", Detail: "connection refused"},
		{Signer: "signer-3", Result: ResultPending},
		{Signer: "signer-4", Result: ResultSigned},
		{Signer: "signer-5", Result: ResultNoShare},
	}
	if fmt.Sprint(se.Outcomes) != fmt.Sprint(want) {
		t.Fatalf("outcomes\n got %v\nwant %v", se.Outcomes, want)
	}

	var logs strings.Builder
	slog.New(slog.NewTextHandler(&logs, nil)).Warn("denied by signers", se.LogAttr())
	for _, w := range []string{
		`signers.signer-1.result=denied signers.signer-1.reason=SC_ERR_SLASH_TARGET signers.signer-1.detail="double vote"`,
		`signers.signer-2.result=error signers.signer-2.reason=failed signers.signer-2.detail="connection refused"`,
		`signers.signer-3.result=pending`, `signers.signer-4.result=signed`, `signers.signer-5.result=no_share`,
	} {
		if !strings.Contains(logs.String(), w) {
			t.Errorf("log lacks %s: %s", w, logs.String())
		}
	}
}

// A signer that does not answer by the deadline is pending, or a timeout
// when its call ended first.
func TestSignErrorOnDeadline(t *testing.T) {
	k := splitKey(t, 2, 2)
	fakes := cluster([]*testKey{k}, 2)
	setRoot(fakes)
	s := newTestSigners(t, fakes)
	hang := make(chan struct{})
	defer close(hang)
	fakes[1].set(func(f *fakeRunner) { f.hang = hang })
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, err := s.Sign(ctx, k.pk, attestationJob())
	var se *SignError
	if !errors.As(err, &se) || !errors.Is(err, context.DeadlineExceeded) && !strings.Contains(err.Error(), "deadline exceeded") {
		t.Fatalf("got %T %v", err, err)
	}
	o := se.Outcomes[1]
	if se.Outcomes[0].Result != ResultSigned || o.Result != ResultPending && (o.Result != ResultError || o.Reason != "timeout") {
		t.Fatalf("outcomes %v", se.Outcomes)
	}
}

// A signer that refuses while the others still reach the threshold logs a
// warning with its name, the request type, the short key and the reason,
// whether it answers before the threshold or after.
func TestWarnWhenThresholdMet(t *testing.T) {
	k := splitKey(t, 2, 3)
	fakes := cluster([]*testKey{k}, 3)
	setRoot(fakes)
	s, logs := newLoggedSigners(t, fakes)
	fakes[0].set(func(f *fakeRunner) { f.err = proto.Refused(proto.StatusSlashTarget, "double vote") })
	if _, err := signWith(t, s, k.pk); err != nil {
		t.Fatal(err)
	}
	short := fmt.Sprintf("%#x", k.pk[:4])
	want := `level=WARN msg="signer did not sign, threshold met" signer=signer-1 type=ATTESTATION pubkey=` + short +
		` result=denied reason=SC_ERR_SLASH_TARGET detail="double vote"`
	waitLog(t, logs, want)

	// The failure comes after the signature.
	late := make(chan struct{})
	fakes[0].set(func(f *fakeRunner) { f.err, f.hang = errors.New("connection reset"), late })
	if _, err := signWith(t, s, k.pk); err != nil {
		t.Fatal(err)
	}
	close(late)
	waitLog(t, logs, "signer=signer-1 type=ATTESTATION pubkey="+short+` result=error reason=failed detail="connection reset"`)
}

// dialRefusal is the error a remote client returns when the peer on the
// signer's address answers IDENTITY with a refusal, before any
// attestation check.
func dialRefusal(r error) error {
	return fmt.Errorf("remote: dial 10.0.0.1:7100: %w", fmt.Errorf("remote: 10.0.0.1:7100: %w", fmt.Errorf("identity: %w", r)))
}

// A refusal inside a failed dial comes from a peer that passed no
// attestation check: it is an error of the dial, not the signer's denial,
// and the detail keeps the stage, also when the refusal's detail is cut.
func TestDialRefusalIsNoDenial(t *testing.T) {
	k := splitKey(t, 2, 3)
	fakes := cluster([]*testKey{k}, 3)
	setRoot(fakes)
	s, logs := newLoggedSigners(t, fakes)
	fakes[0].set(func(f *fakeRunner) { f.err = dialRefusal(proto.Refused(proto.StatusSlashTarget, "double vote")) })
	if _, err := signWith(t, s, k.pk); err != nil {
		t.Fatal(err)
	}
	short := fmt.Sprintf("%#x", k.pk[:4])
	waitLog(t, logs, "signer=signer-1 type=ATTESTATION pubkey="+short+
		` result=error reason=failed detail="remote: dial 10.0.0.1:7100: remote: 10.0.0.1:7100: identity: `)

	long := strings.Repeat("x", 2*wire.MaxDetail)
	for _, f := range fakes[:2] {
		f.set(func(f *fakeRunner) { f.err = dialRefusal(proto.Refused(proto.StatusSlashTarget, "%s", long)) })
	}
	_, err := signWith(t, s, k.pk)
	var se *SignError
	var denied *DeniedError
	if !errors.As(err, &se) || errors.As(err, &denied) {
		t.Fatalf("want a SignError that is no denial, got %T %v", err, err)
	}
	for _, o := range se.Outcomes[:2] {
		if o.Result != ResultError || o.Reason != "failed" || !strings.HasPrefix(o.Detail, "remote: dial 10.0.0.1:7100: ") ||
			!strings.Contains(o.Detail, ": identity: ") || strings.Contains(o.Detail, long[:wire.MaxDetail+1]) {
			t.Errorf("%s: %+v, want an error of the dial with the stage and a cut detail", o.Signer, o)
		}
	}
}

// A call on the wire ends by the connection deadline, an error that wraps
// os.ErrDeadlineExceeded: a timeout, as the pool metric counts it.
func TestWarnConnectionDeadlineIsTimeout(t *testing.T) {
	k := splitKey(t, 2, 3)
	fakes := cluster([]*testKey{k}, 3)
	setRoot(fakes)
	s, logs := newLoggedSigners(t, fakes)
	stalled := fmt.Errorf("remote: SIGN: %w", &net.OpError{Op: "read", Net: "tcp", Err: os.ErrDeadlineExceeded})
	fakes[0].set(func(f *fakeRunner) { f.err = stalled })
	if _, err := signWith(t, s, k.pk); err != nil {
		t.Fatal(err)
	}
	waitLog(t, logs, "signer=signer-1 type=ATTESTATION pubkey="+fmt.Sprintf("%#x", k.pk[:4])+
		` result=error reason=timeout detail="remote: SIGN: read tcp: i/o timeout"`)
}

// All signers sign: no warning.
func TestNoWarnWhenAllSign(t *testing.T) {
	k := splitKey(t, 2, 3)
	fakes := cluster([]*testKey{k}, 3)
	setRoot(fakes)
	s, logs := newLoggedSigners(t, fakes)
	for range 3 {
		if _, err := signWith(t, s, k.pk); err != nil {
			t.Fatal(err)
		}
	}
	time.Sleep(50 * time.Millisecond)
	if l := warnLines(logs.String()); len(l) != 0 {
		t.Fatalf("warnings: %v", l)
	}
}

// The same signer, type and reason logs once per warnEvery; the next line
// after it says how many it held back.
func TestWarnRateLimited(t *testing.T) {
	k := splitKey(t, 2, 3)
	fakes := cluster([]*testKey{k}, 3)
	setRoot(fakes)
	s, logs := newLoggedSigners(t, fakes)
	now := time.Now()
	var mu sync.Mutex
	s.warns.now = func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	fakes[0].set(func(f *fakeRunner) { f.err = errors.New("connection refused") })
	// sign makes signer-1 answer first, so its warning is out when Sign
	// returns.
	sign := func() {
		t.Helper()
		hang := make(chan struct{})
		for _, f := range fakes[1:] {
			f.set(func(f *fakeRunner) { f.hang = hang })
		}
		go func() { time.Sleep(50 * time.Millisecond); close(hang) }()
		if _, err := signWith(t, s, k.pk); err != nil {
			t.Fatal(err)
		}
	}
	for range 3 {
		sign()
	}
	if l := warnLines(logs.String()); len(l) != 1 || strings.Contains(l[0], "suppressed") {
		t.Fatalf("want 1 line without a count, got %v", l)
	}

	mu.Lock()
	now = now.Add(warnEvery)
	mu.Unlock()
	sign()
	l := warnLines(logs.String())
	if len(l) != 2 || !strings.HasSuffix(l[1], "suppressed=2") {
		t.Fatalf("want a second line with suppressed=2, got %v", l)
	}
}

func TestWarnLimitKeys(t *testing.T) {
	l := newWarnLimit(time.Minute)
	now := time.Now()
	l.now = func() time.Time { return now }
	a := warnKey{"signer-1", "ATTESTATION", "timeout"}
	for i, c := range []struct {
		k    warnKey
		ok   bool
		held int
		step time.Duration
	}{
		{a, true, 0, 0},
		{a, false, 0, 0},
		{warnKey{"signer-2", "ATTESTATION", "timeout"}, true, 0, 0},
		{warnKey{"signer-1", "BLOCK_V2", "timeout"}, true, 0, 0},
		{warnKey{"signer-1", "ATTESTATION", "failed"}, true, 0, 0},
		{a, false, 0, 59 * time.Second},
		{a, true, 2, time.Second},
		{a, false, 0, 0},
	} {
		now = now.Add(c.step)
		if ok, held := l.allow(c.k); ok != c.ok || held != c.held {
			t.Fatalf("step %d: got %v %d, want %v %d", i, ok, held, c.ok, c.held)
		}
	}
}

// waitLog waits until s is in the log.
func waitLog(t *testing.T, logs fmt.Stringer, s string) {
	t.Helper()
	waitFor(t, s, 2*time.Second, func() bool { return strings.Contains(logs.String(), s) })
}

// A signer that answers with a new unknown status each time stays under
// one limit.
func TestWarnLimitUnknownStatusOneBucket(t *testing.T) {
	k := splitKey(t, 2, 3)
	s, logs := newLoggedSigners(t, cluster([]*testKey{k}, 3))
	for i := range 20 {
		s.warnSigner("ATTESTATION", k.pk, partial{share: share{node: 0}, err: proto.Refused(proto.Status(60000+i), "odd")})
	}
	l := warnLines(logs.String())
	if len(l) != 1 || !strings.Contains(l[0], "reason=STATUS_60000") {
		t.Fatalf("want 1 line with the real code, got %v", l)
	}
}

// The limiter keeps at most max keys.
func TestWarnLimitCapped(t *testing.T) {
	l := newWarnLimit(time.Minute)
	l.max = 8
	for i := range 100 {
		l.allow(warnKey{signer: fmt.Sprint(i)})
	}
	if n := len(l.seen); n > 8 {
		t.Fatalf("%d keys, cap 8", n)
	}
}

// A refusal detail over wire.MaxDetail is cut before the error text and the
// outcomes have it.
func TestLongDetailCut(t *testing.T) {
	k := splitKey(t, 2, 3)
	fakes := cluster([]*testKey{k}, 3)
	setRoot(fakes)
	s, logs := newLoggedSigners(t, fakes)
	long := strings.Repeat("x", 60000)
	for _, f := range fakes[:2] {
		f.set(func(f *fakeRunner) { f.err = proto.Refused(proto.StatusSlashTarget, "%s", long) })
	}
	_, err := signWith(t, s, k.pk)
	var se *SignError
	if !errors.As(err, &se) {
		t.Fatalf("got %T %v", err, err)
	}
	for _, o := range se.Outcomes[:2] {
		if len(o.Detail) != wire.MaxDetail {
			t.Fatalf("%s: detail of %d bytes", o.Signer, len(o.Detail))
		}
	}
	if n := len(err.Error()); n > 3*wire.MaxDetail {
		t.Fatalf("error text of %d bytes", n)
	}
	// The third signer, refusing after the threshold was out of reach,
	// may still warn; no log line may carry the whole detail.
	if strings.Contains(logs.String(), long[:wire.MaxDetail+1]) {
		t.Fatal("a log line has the whole detail")
	}
}
