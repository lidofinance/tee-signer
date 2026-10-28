package backend

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/herumi/bls-eth-go-binary/bls"

	"github.com/lidofinance/tee-signer/gateway/internal/certreload"
	"github.com/lidofinance/tee-signer/gateway/internal/metrics"
	proto "github.com/lidofinance/tee-signer/signer-protocol"
)

// expectMetric fails the test unless the series has the value want.
func expectMetric(t *testing.T, what string, got, want float64) {
	t.Helper()
	if got != want {
		t.Errorf("%s = %v, want %v", what, got, want)
	}
}

// Each call through a node moves the counter of its result, and the
// connection state follows what the calls show: a call that reaches the
// signer on a client without a connection is a dial, an error on the
// connection takes it down, and a failed dial counts with the check that
// refused it.
func TestMetricsNodeCallsAndConnections(t *testing.T) {
	m := metrics.New()
	k := splitKey(t, 2, 3)
	f := cluster([]*testKey{k}, 3)[0]
	f.set(func(f *fakeRunner) { f.root = testRoot })
	n, err := newPool("tcp:x", poolConfig{size: 2, name: "s1", m: m}, func(*certreload.Pair) (runner, error) { return f, nil })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { n.Close() })
	up := func() float64 { return m.SignerConnectionsUp.Value("s1") }
	req := func(name string) float64 { return m.SignerRequests.Value("s1", name) }
	dials := func(r string) float64 { return m.SignerDials.Value("s1", r) }
	ctx := context.Background()
	sign := proto.SignRequest{Pubkey: proto.Pubkey(k.pk), Message: &proto.AttestationData{Slot: 1}}

	expectMetric(t, "up at start", up(), 0)
	if _, err := n.PublicKeys(ctx); err != nil {
		t.Fatal(err)
	}
	expectMetric(t, "ok", req("ok"), 1)
	expectMetric(t, "dials ok", dials("ok"), 1)
	expectMetric(t, "up", up(), 1)

	// A refusal comes over a connection: the second client dialed.
	f.set(func(f *fakeRunner) { f.err = proto.Refused(proto.StatusSlashTarget, "double vote") })
	if _, err := n.Sign(ctx, sign); err == nil {
		t.Fatal("no refusal")
	}
	expectMetric(t, "refused", req("refused"), 1)
	expectMetric(t, "dials ok after the second client", dials("ok"), 2)
	expectMetric(t, "up", up(), 2)

	// The connection ends under the call: tried once more on the other
	// client, which fails too. One call, one error, both down.
	f.set(func(f *fakeRunner) { f.err = io.EOF })
	if _, err := n.Sign(ctx, sign); err == nil {
		t.Fatal("no error")
	}
	expectMetric(t, "error", req("error"), 1)
	expectMetric(t, "up after the connections ended", up(), 0)

	// Failed dials, one refused by the attestation check.
	f.set(func(f *fakeRunner) { f.err = fmt.Errorf("remote: dial tcp:x: %w", errors.New("connection refused")) })
	_, _ = n.PublicKeys(ctx)
	f.set(func(f *fakeRunner) {
		f.err = errors.New("remote: dial tcp:x: remote: tcp:x: attestation: wrong measurement")
	})
	_, _ = n.PublicKeys(ctx)
	expectMetric(t, "dials failed", dials("failed"), 2)
	expectMetric(t, "verifier failures", m.SignerAttestationFailures.Value("s1", "verifier"), 1)
	expectMetric(t, "tls failures", m.SignerAttestationFailures.Value("s1", "tls"), 0)
	expectMetric(t, "error after the dials", req("error"), 3)

	// A call that runs out of time.
	f.set(func(f *fakeRunner) { f.err, f.hang = nil, make(chan struct{}) })
	tctx, cancel := context.WithTimeout(ctx, 20*time.Millisecond)
	defer cancel()
	if _, err := n.Sign(tctx, sign); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("want a timeout, got %v", err)
	}
	expectMetric(t, "timeout", req("timeout"), 1)
	f.set(func(f *fakeRunner) { close(f.hang); f.hang = nil })
	if _, err := n.Sign(ctx, sign); err != nil {
		t.Fatal(err)
	}
	expectMetric(t, "ok at the end", req("ok"), 2)
	expectMetric(t, "dials ok at the end", dials("ok"), 3)
	expectMetric(t, "up at the end", up(), 1)
}

// dialFailure reads the texts of signer-protocol/remote. The TLS test
// below checks three of them against the real client; these are the rest.
func TestDialFailureTexts(t *testing.T) {
	for _, c := range []struct {
		err    string
		failed bool
		reason string
	}{
		{"remote: dial tcp:a:1: dial tcp 10.0.0.1:1: connect: connection refused", true, ""},
		{"remote: dial tcp:a:1: remote: tcp:a:1: runner sent no certificate", true, "tls"},
		{"remote: dial tcp:a:1: remote: tcp:a:1: identity: EOF", true, "identity"},
		{"remote: dial tcp:a:1: remote: tcp:a:1: runner presented TLS key 01 but its attested identity names 02", true, "identity"},
		{"remote: SIGN: read tcp: i/o timeout", false, ""},
		{"signer-1: remote: SIGN: context deadline exceeded", false, ""},
	} {
		failed, reason := dialFailure(errors.New(c.err))
		if failed != c.failed || reason != c.reason {
			t.Errorf("%q: failed %v reason %q, want %v %q", c.err, failed, reason, c.failed, c.reason)
		}
	}
}

// A connection refused by a check counts under the check that refused it,
// with the texts of the real runner client.
func TestMetricsAttestationFailureReasons(t *testing.T) {
	ca := newTestCA(t)
	k := splitKey(t, 2, 3)
	for _, c := range []struct {
		reason string
		runner func() *tlsRunner
	}{
		// A signer whose certificate says mainnet, settings without it.
		{"tls", func() *tlsRunner { return startTLSRunner(t, ca, k, 0, false, chainMark(t, proto.Version{0, 0, 0, 0})) }},
		{"key_pin", func() *tlsRunner { return startTLSRunner(t, ca, k, 0, false, nil) }},
		// An attestation document with another nonce.
		{"verifier", func() *tlsRunner { return startTLSRunner(t, ca, k, 0, true, nil) }},
	} {
		r := c.runner()
		conn := devConnection(t, ca, r)
		if c.reason == "key_pin" {
			conn.TLSKeyPin = hex.EncodeToString(make([]byte, 32))
		}
		m := metrics.New()
		n, err := newNode(conn, poolConfig{size: 1, name: "s1", m: m})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := n.PublicKeys(ctxShort(t)); err == nil {
			t.Fatalf("%s: no error", c.reason)
		}
		n.Close()
		for _, reason := range metrics.AttestationReasons {
			want := 0.0
			if reason == c.reason {
				want = 1
			}
			expectMetric(t, c.reason+" case, "+reason, m.SignerAttestationFailures.Value("s1", reason), want)
		}
		expectMetric(t, c.reason+" case, dials failed", m.SignerDials.Value("s1", "failed"), 1)
	}
}

// The signing metrics: time to the combined signature, keys, key lists,
// and each reason of a failed combination.
func TestMetricsSigning(t *testing.T) {
	k := splitKey(t, 2, 3)
	fakes := cluster([]*testKey{k}, 3)
	setRoot(fakes)
	s := newTestSigners(t, fakes)
	m := s.m
	expectMetric(t, "keys", m.Keys.Value(), 1)
	for i := range 3 {
		name := fmt.Sprintf("signer-%d", i+1)
		if v := m.SignerKeysRefreshed.Value(name); v < float64(time.Now().Add(-time.Minute).Unix()) {
			t.Errorf("%s keys refreshed at %v", name, v)
		}
	}
	if _, err := signWith(t, s, k.pk); err != nil {
		t.Fatal(err)
	}
	if n := m.SignDuration.Count("ATTESTATION"); n != 1 {
		t.Fatalf("%d signing times", n)
	}

	// One signer sends a partial under another key: bad_partial.
	var other bls.SecretKey
	other.SetByCSPRNG()
	fakes[0].set(func(f *fakeRunner) { f.signer = &other })
	if _, err := signWith(t, s, k.pk); err != nil {
		t.Fatal(err)
	}
	// The bad partial may come after the two good ones.
	waitFor(t, "a bad partial counted", 2*time.Second, func() bool { return m.CombineFailures.Value("bad_partial") == 1 })

	// Two of three fail: below_threshold.
	fakes[1].set(func(f *fakeRunner) { f.err = errors.New("down") })
	if _, err := signWith(t, s, k.pk); err == nil {
		t.Fatal("signed with one good partial")
	}
	expectMetric(t, "below_threshold", m.CombineFailures.Value("below_threshold"), 1)
	if n := m.SignDuration.Count("ATTESTATION"); n != 2 {
		t.Fatalf("%d signing times, want 2: a failed request is not timed", n)
	}

	// Good partials combined with the wrong indices: verify.
	fakes[0].set(func(f *fakeRunner) { f.signer = nil })
	fakes[1].set(func(f *fakeRunner) { f.err = nil })
	g, _ := s.keys.lookup(k.pk)
	g.shares = append([]share(nil), g.shares...)
	g.shares[0].index, g.shares[1].index, g.shares[2].index = 3, 1, 2
	req := proto.SignRequest{Pubkey: proto.Pubkey(k.pk), Message: &proto.AttestationData{Slot: 1}}
	if _, err := s.fanOut(ctxShort(t), k.pk, g, req, testRoot); err == nil {
		t.Fatal("combined with the wrong indices")
	}
	expectMetric(t, "verify", m.CombineFailures.Value("verify"), 1)
}
