package certreload

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log/slog"
	"math/big"
	mrand "math/rand/v2"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// t0 is the test clock's start.
var t0 = time.Date(2026, 10, 28, 12, 0, 0, 0, time.UTC)

// pemPair is one certificate and key as the files hold them.
type pemPair struct{ cert, key []byte }

var (
	caOnce sync.Once
	caCert *x509.Certificate
	caKey  *ecdsa.PrivateKey
)

// makePair makes a client certificate valid from notBefore to notAfter.
func makePair(t *testing.T, serial int64, notBefore, notAfter time.Time) pemPair {
	t.Helper()
	caOnce.Do(func() {
		caKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"},
			NotBefore: t0.Add(-24 * time.Hour), NotAfter: t0.Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true,
			KeyUsage: x509.KeyUsageCertSign}
		der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &caKey.PublicKey, caKey)
		caCert, _ = x509.ParseCertificate(der)
	})
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "gateway"},
		NotBefore: notBefore, NotAfter: notAfter, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)

	return pemPair{pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})}
}

func goodPair(t *testing.T, serial int64) pemPair {
	t.Helper()

	return makePair(t, serial, t0.Add(-time.Hour), t0.Add(48*time.Hour))
}

// logCount counts log records by message.
type logCount struct {
	mu sync.Mutex
	n  map[string]int
}

func (l *logCount) Enabled(context.Context, slog.Level) bool { return true }
func (l *logCount) Handle(_ context.Context, r slog.Record) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.n[r.Message]++

	return nil
}
func (l *logCount) WithAttrs([]slog.Attr) slog.Handler { return l }
func (l *logCount) WithGroup(string) slog.Handler      { return l }
func (l *logCount) get(msg string) int {
	l.mu.Lock()
	defer l.mu.Unlock()

	return l.n[msg]
}

type fixture struct {
	t        *testing.T
	certPath string
	keyPath  string
	now      time.Time
	logs     *logCount
	w        *Watcher
}

func newFixture(t *testing.T, first pemPair) *fixture {
	t.Helper()
	dir := t.TempDir()
	f := &fixture{t: t, certPath: filepath.Join(dir, "client.pem"), keyPath: filepath.Join(dir, "client-key.pem"), now: t0,
		logs: &logCount{n: map[string]int{}}}
	f.write(first)
	w, err := newWatcher(f.certPath, f.keyPath, slog.New(f.logs), func() time.Time { return f.now })
	if err != nil {
		t.Fatal(err)
	}
	f.w = w

	return f
}

func (f *fixture) write(p pemPair) {
	f.t.Helper()
	if err := os.WriteFile(f.certPath, p.cert, 0o600); err != nil {
		f.t.Fatal(err)
	}
	if err := os.WriteFile(f.keyPath, p.key, 0o600); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fixture) current() []byte { return f.w.Current().certPEM }

// The kinds of content a renewal can leave in the files.
const (
	kindGood = iota
	kindMismatch
	kindExpired
	kindNotYetValid
	kindGarbage
	kindHalfWritten
	kindCount
)

// content makes new content of kind k.
func content(t *testing.T, k int, serial int64) pemPair {
	t.Helper()
	switch k {
	case kindGood:
		return goodPair(t, serial)
	case kindMismatch:
		a, b := goodPair(t, serial), goodPair(t, serial)

		return pemPair{a.cert, b.key}
	case kindExpired:
		return makePair(t, serial, t0.Add(-48*time.Hour), t0.Add(-time.Hour))
	case kindNotYetValid:
		return makePair(t, serial, t0.Add(time.Hour), t0.Add(48*time.Hour))
	case kindGarbage:
		return pemPair{[]byte("not a certificate"), []byte("not a key")}
	default:
		p := goodPair(t, serial)

		return pemPair{p.cert[:len(p.cert)/2], p.key}
	}
}

// Any sequence of good and bad writes leaves the last good pair in force,
// swaps once per good change and logs each bad content once, however
// often it is polled.
func TestLastGoodPairStays(t *testing.T) {
	for seed := range uint64(40) {
		rng := mrand.New(mrand.NewPCG(seed, 7))
		first := goodPair(t, 1)
		f := newFixture(t, first)
		in := first
		swaps, bad := 0, 0
		lastBad := ""
		for step := range 12 {
			k := rng.IntN(kindCount + 1)
			var p pemPair
			switch k {
			case kindCount: // the pair in force written again: no change
				p = in
				lastBad = ""
			case kindGood:
				p = content(t, k, int64(step+2))
				in = p
				swaps++
				lastBad = ""
			default:
				// Garbage is the same each time: a repeat is not logged again.
				p = content(t, k, int64(step+2))
				if s := string(p.cert) + string(p.key); s != lastBad {
					bad++
					lastBad = s
				}
			}
			f.write(p)
			for range 1 + rng.IntN(3) {
				f.w.Poll()
			}
			if string(f.current()) != string(in.cert) {
				t.Fatalf("seed %d step %d (kind %d): the pair in force is not the last good one", seed, step, k)
			}
		}
		if got := f.logs.get(msgReloaded); got != swaps {
			t.Fatalf("seed %d: %d reloads, want %d", seed, got, swaps)
		}
		if got := f.logs.get(msgRefused); got != bad {
			t.Fatalf("seed %d: %d refusals logged, want %d (one per bad content)", seed, got, bad)
		}
	}
}

func TestReloadTable(t *testing.T) {
	type step struct {
		write pemPair
		polls int
		swap  bool
	}
	a, b, c := goodPair(t, 1), goodPair(t, 2), goodPair(t, 3)
	mismatch := pemPair{b.cert, c.key}
	cases := []struct {
		name    string
		steps   []step
		want    pemPair
		refused int
	}{
		{"good change", []step{{b, 1, true}}, b, 0},
		{"same content again", []step{{a, 3, false}}, a, 0},
		{"key of another certificate", []step{{mismatch, 5, false}}, a, 1},
		{"certificate first, key a poll later", []step{{pemPair{b.cert, a.key}, 2, false}, {b, 1, true}}, b, 1},
		{"bad, good, the same bad again", []step{{mismatch, 2, false}, {b, 1, true}, {mismatch, 2, false}}, b, 2},
		{"two good changes", []step{{b, 1, true}, {c, 1, true}}, c, 0},
		{"back to the first pair", []step{{b, 1, true}, {a, 1, true}}, a, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, a)
			for i, s := range tc.steps {
				f.write(s.write)
				swapped := false
				for range s.polls {
					swapped = f.w.Poll() || swapped
				}
				if swapped != s.swap {
					t.Fatalf("step %d: swapped %v, want %v", i, swapped, s.swap)
				}
			}
			if string(f.current()) != string(tc.want.cert) {
				t.Fatal("wrong pair in force")
			}
			if got := f.logs.get(msgRefused); got != tc.refused {
				t.Fatalf("%d refusals logged, want %d", got, tc.refused)
			}
		})
	}
}

// A certificate that is not valid yet is refused until it is, and logged
// once.
func TestNotYetValidTakesEffectLater(t *testing.T) {
	f := newFixture(t, goodPair(t, 1))
	next := content(t, kindNotYetValid, 2)
	f.write(next)
	for range 6 {
		if f.w.Poll() {
			t.Fatal("swapped to a certificate that is not valid yet")
		}
		f.now = f.now.Add(10 * time.Second)
	}
	f.now = t0.Add(time.Hour + time.Second)
	if !f.w.Poll() || string(f.current()) != string(next.cert) {
		t.Fatal("no swap once the certificate is valid")
	}
	if got := f.logs.get(msgRefused); got != 1 {
		t.Fatalf("%d refusals logged, want 1", got)
	}
}

// A certificate that expires with no replacement is logged once a minute,
// and Usable names the file.
func TestExpiredWithoutReplacement(t *testing.T) {
	f := newFixture(t, makePair(t, 1, t0.Add(-time.Hour), t0.Add(time.Minute)))
	if err := f.w.Usable(); err != nil {
		t.Fatal(err)
	}
	for range 6 {
		f.w.Poll()
		f.now = f.now.Add(10 * time.Second)
	}
	if got := f.logs.get(msgExpired); got != 0 {
		t.Fatalf("%d expiry logs before the expiry", got)
	}
	f.now = t0.Add(time.Minute + time.Second)
	for range 18 { // three minutes of 10 s polls
		f.w.Poll()
		f.now = f.now.Add(10 * time.Second)
	}
	if got := f.logs.get(msgExpired); got != 3 {
		t.Fatalf("%d expiry logs in three minutes, want 3", got)
	}
	err := f.w.Usable()
	if err == nil || !strings.Contains(err.Error(), f.certPath) || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("Usable: %v", err)
	}
	// A renewal fixes it at the next poll.
	f.write(makePair(t, 2, f.now.Add(-time.Minute), f.now.Add(time.Hour)))
	if !f.w.Poll() || f.w.Usable() != nil {
		t.Fatal("renewal after the expiry")
	}
}

func TestStartRefusesABadPair(t *testing.T) {
	dir := t.TempDir()
	cert, key := filepath.Join(dir, "c.pem"), filepath.Join(dir, "k.pem")
	for _, p := range []pemPair{content(t, kindMismatch, 1), content(t, kindExpired, 1), content(t, kindGarbage, 1)} {
		_ = os.WriteFile(cert, p.cert, 0o600)
		_ = os.WriteFile(key, p.key, 0o600)
		if _, err := newWatcher(cert, key, slog.New(slog.DiscardHandler), func() time.Time { return t0 }); err == nil {
			t.Fatal("start with a bad pair")
		}
	}
	if _, err := newWatcher(filepath.Join(dir, "none"), key, slog.New(slog.DiscardHandler), time.Now); err == nil {
		t.Fatal("start without the files")
	}
}

// Subscribers hear of each swap, and of nothing else.
func TestSubscribe(t *testing.T) {
	f := newFixture(t, goodPair(t, 1))
	ch := f.w.Subscribe()
	f.write(content(t, kindMismatch, 2))
	f.w.Poll()
	select {
	case <-ch:
		t.Fatal("notified of a refused pair")
	default:
	}
	f.write(goodPair(t, 3))
	f.w.Poll()
	select {
	case <-ch:
	default:
		t.Fatal("no notice of the swap")
	}
	if g := f.w.Current().Gen(); g != 2 {
		t.Fatalf("generation %d, want 2", g)
	}
}

// Files hands out paths that read as the pair in force, even after the
// files on disk changed.
func TestFilesReadAsThePairInForce(t *testing.T) {
	first := goodPair(t, 1)
	f := newFixture(t, first)
	f.write(content(t, kindGarbage, 2))
	err := f.w.Current().Files(func(certPath, keyPath string) error {
		c, err := os.ReadFile(certPath)
		if err != nil {
			return err
		}
		k, err := os.ReadFile(keyPath)
		if err != nil {
			return err
		}
		if string(c) != string(first.cert) || string(k) != string(first.key) {
			t.Error("the paths do not read as the pair in force")
		}

		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// f may leave the files unread.
	if err := f.w.Current().Files(func(string, string) error { return nil }); err != nil {
		t.Fatal(err)
	}
}

func TestRun(t *testing.T) {
	dir := t.TempDir()
	cert, key := filepath.Join(dir, "c.pem"), filepath.Join(dir, "k.pem")
	a := makePair(t, 1, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	_ = os.WriteFile(cert, a.cert, 0o600)
	_ = os.WriteFile(key, a.key, 0o600)
	w, err := New(cert, key, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	ch := w.Subscribe()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go w.Run(ctx, 20*time.Millisecond)
	b := makePair(t, 2, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	_ = os.WriteFile(cert, b.cert, 0o600)
	_ = os.WriteFile(key, b.key, 0o600)
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not pick up the new pair")
	}
}
