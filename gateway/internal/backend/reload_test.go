package backend

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/attestantio/go-eth2-client/spec/phase0"

	"github.com/lidofinance/tee-signer/attestation-verify/runnerclient"
	"github.com/lidofinance/tee-signer/gateway/internal/certreload"
	proto "github.com/lidofinance/tee-signer/signer-protocol"
)

// These tests swap the client certificate under a running pool.

var serialSeq atomic.Int64

// writePair writes a client certificate of ca valid until notAfter, and
// its key, to certPath and keyPath. It returns the certificate (DER).
func (ca *testCA) writePair(t *testing.T, certPath, keyPath string, notAfter time.Time) []byte {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(100 + serialSeq.Add(1)), Subject: pkix.Name{CommonName: "gateway"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: notAfter,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	// Write to a temporary name and rename, as a renewal tool does.
	for _, f := range []struct {
		path string
		b    []byte
	}{
		{certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})},
		{keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})},
	} {
		if err := os.WriteFile(f.path+".new", f.b, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(f.path+".new", f.path); err != nil {
			t.Fatal(err)
		}
	}

	return der
}

func quietLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// watched writes a first pair valid until notAfter and watches it.
func watched(t *testing.T, ca *testCA, notAfter time.Time) (w *certreload.Watcher, certPath, keyPath string, der []byte) {
	t.Helper()
	dir := t.TempDir()
	certPath, keyPath = filepath.Join(dir, "gateway.pem"), filepath.Join(dir, "gateway-key.pem")
	der = ca.writePair(t, certPath, keyPath, notAfter)
	w, err := certreload.New(certPath, keyPath, quietLog())
	if err != nil {
		t.Fatal(err)
	}

	return w, certPath, keyPath, der
}

// pairs returns the generation of the pair each slot's client presents.
func (n *node) pairs() []uint64 {
	n.mu.Lock()
	defer n.mu.Unlock()
	var g []uint64
	for _, s := range n.all {
		g = append(g, s.pair.Gen())
	}

	return g
}

func allOn(gens []uint64, g uint64) bool {
	for _, x := range gens {
		if x != g {
			return false
		}
	}

	return true
}

func waitFor(t *testing.T, what string, d time.Duration, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// poolBook watches the fake clients of a pool: how many can take a
// request, how many redial at once, and whether one is closed under a
// request.
type poolBook struct {
	mu         sync.Mutex
	usable     int
	minUsable  int
	warming    int
	maxWarming int
	closedBusy int
	closed     int // clients closed after they were usable
	warmFails  bool
	warmDelay  time.Duration
}

type fakeConn struct {
	book  *poolBook
	pair  *certreload.Pair
	ready bool // counted in usable
	busy  int
	shut  bool
}

func (b *poolBook) mk(p *certreload.Pair) (runner, error) {
	return &fakeConn{book: b, pair: p}, nil
}

// PublicKeys is the check of a redial. The client counts as usable once
// it passes.
func (c *fakeConn) PublicKeys(ctx context.Context) ([]proto.ValidatorKey, error) {
	b := c.book
	b.mu.Lock()
	b.warming++
	b.maxWarming = max(b.maxWarming, b.warming)
	fails, delay := b.warmFails, b.warmDelay
	b.mu.Unlock()
	time.Sleep(delay)
	b.mu.Lock()
	defer b.mu.Unlock()
	b.warming--
	if fails {
		return nil, errors.New("signer down")
	}
	if !c.ready && !c.shut {
		c.ready = true
		b.usable++
	}

	return nil, nil
}

func (c *fakeConn) Sign(context.Context, proto.SignRequest) (proto.Signature, error) {
	return proto.Signature{}, nil
}

func (c *fakeConn) Close() error {
	b := c.book
	b.mu.Lock()
	defer b.mu.Unlock()
	if c.busy > 0 {
		b.closedBusy++
	}
	if c.ready && !c.shut {
		b.usable--
		b.minUsable = min(b.minUsable, b.usable)
		b.closed++
	}
	c.shut = true

	return nil
}

func (b *poolBook) get(f func(b *poolBook) int) int {
	b.mu.Lock()
	defer b.mu.Unlock()

	return f(b)
}

// newFakePool makes a pool of size fake clients, all counted usable.
func newFakePool(t *testing.T, w *certreload.Watcher, size int, b *poolBook) *node {
	t.Helper()
	n, err := newPool("fake", poolConfig{size: size, certs: w, warm: time.Second, retry: 20 * time.Millisecond, log: quietLog()}, b.mk)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { n.Close() })
	b.mu.Lock()
	for _, s := range n.all {
		s.c.(*fakeConn).ready = true
	}
	b.usable, b.minUsable = size, size
	b.mu.Unlock()

	return n
}

// A good new pair moves every connection to it: each new connection
// passes its check before an old one closes, one at a time, the pool never
// has fewer than its size, and a connection under a request is replaced
// only after the request ends.
func TestRotationRedialsBeforeCloseOneAtATime(t *testing.T) {
	ca := newTestCA(t)
	w, certPath, keyPath, _ := watched(t, ca, time.Now().Add(time.Hour))
	b := &poolBook{warmDelay: 10 * time.Millisecond}
	n := newFakePool(t, w, 3, b)

	started, finish, done := make(chan struct{}), make(chan struct{}), make(chan error)
	go func() {
		done <- n.do(context.Background(), func(r runner) error {
			c := r.(*fakeConn)
			b.mu.Lock()
			c.busy++
			b.mu.Unlock()
			close(started)
			<-finish
			b.mu.Lock()
			defer b.mu.Unlock()
			c.busy--
			if c.shut {
				return errors.New("closed under the request")
			}

			return nil
		})
	}()
	<-started

	ca.writePair(t, certPath, keyPath, time.Now().Add(2*time.Hour))
	if !w.Poll() {
		t.Fatal("no swap")
	}
	closed := func() bool { return b.get(func(b *poolBook) int { return b.closed }) == 2 }
	waitFor(t, "the two idle connections to move", 5*time.Second, closed)
	time.Sleep(50 * time.Millisecond)
	if got := b.get(func(b *poolBook) int { return b.closed }); got != 2 {
		t.Fatalf("%d connections closed while one is under a request", got)
	}
	close(finish)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	waitFor(t, "every connection on the new pair", 5*time.Second, func() bool { return allOn(n.pairs(), 2) })
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed != 3 || b.closedBusy != 0 || b.minUsable < 3 || b.maxWarming != 1 {
		t.Fatalf("closed %d, closed under a request %d, fewest usable %d (want 3), most redials at once %d (want 1)",
			b.closed, b.closedBusy, b.minUsable, b.maxWarming)
	}
}

// A redial that fails leaves the old connections in place and is tried
// again.
func TestRotationRetriesAFailedRedial(t *testing.T) {
	ca := newTestCA(t)
	w, certPath, keyPath, _ := watched(t, ca, time.Now().Add(time.Hour))
	b := &poolBook{warmFails: true}
	n := newFakePool(t, w, 2, b)
	ca.writePair(t, certPath, keyPath, time.Now().Add(2*time.Hour))
	w.Poll()
	time.Sleep(100 * time.Millisecond)
	if got := n.pairs(); !allOn(got, 1) || b.get(func(b *poolBook) int { return b.closed }) != 0 {
		t.Fatalf("a failed redial replaced a connection: %v", got)
	}
	b.mu.Lock()
	b.warmFails = false
	b.mu.Unlock()
	waitFor(t, "every connection on the new pair", 5*time.Second, func() bool { return allOn(n.pairs(), 2) })
	if m := b.get(func(b *poolBook) int { return b.minUsable }); m < 2 {
		t.Fatalf("fewest usable %d", m)
	}
}

// A connection whose certificate expired before the pool could move it
// (its signer was down) takes the new certificate at its next request,
// which dials with it.
func TestExpiredConnectionTakesTheNewPairAtItsNextRequest(t *testing.T) {
	ca := newTestCA(t)
	w, certPath, keyPath, _ := watched(t, ca, time.Now().Add(time.Second))
	b := &poolBook{warmFails: true}
	n := newFakePool(t, w, 1, b)
	ca.writePair(t, certPath, keyPath, time.Now().Add(time.Hour))
	w.Poll()
	time.Sleep(1100 * time.Millisecond)
	var used uint64
	if err := n.do(context.Background(), func(r runner) error { used = r.(*fakeConn).pair.Gen(); return nil }); err != nil {
		t.Fatal(err)
	}
	if used != 2 {
		t.Fatalf("request on a client of pair %d, want 2", used)
	}
}

// A certificate that expired with no replacement fails every request with
// an error that names the file.
func TestExpiredCertificateFailsRequests(t *testing.T) {
	ca := newTestCA(t)
	w, certPath, _, _ := watched(t, ca, time.Now().Add(time.Second))
	n := newFakePool(t, w, 1, &poolBook{})
	time.Sleep(1100 * time.Millisecond)
	ran := false
	err := n.do(context.Background(), func(runner) error { ran = true; return nil })
	if err == nil || ran || !errors.Is(err, certreload.ErrExpired) || !strings.Contains(err.Error(), certPath) {
		t.Fatalf("request with an expired certificate: ran %v, %v", ran, err)
	}
	s := newSigners([]string{"signer-1"}, []runner{n}, 0, time.Second, quietLog())
	s.certs = w
	_, err = s.Sign(context.Background(), phase0.BLSPubKey{1}, attestationJob())
	if err == nil || !strings.Contains(err.Error(), certPath) {
		t.Fatalf("Signers.Sign with an expired certificate: %v", err)
	}
}

// signLoop signs on every node until stop, and counts the failures.
func signLoop(nodes []*node, k *testKey, stop <-chan struct{}) (wait func() (ok, failed int, first error)) {
	var wg sync.WaitGroup
	var mu sync.Mutex
	var okN, failN int
	var firstErr error
	req := proto.SignRequest{Pubkey: proto.Pubkey(k.pk), Message: &proto.AttestationData{Slot: 1}}
	for _, n := range nodes {
		for range 3 {
			wg.Go(func() {
				for {
					select {
					case <-stop:
						return
					default:
					}
					ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
					_, err := n.Sign(ctx, req)
					cancel()
					mu.Lock()
					if err != nil {
						failN++
						if firstErr == nil {
							firstErr = err
						}
					} else {
						okN++
					}
					mu.Unlock()
				}
			})
		}
	}

	return func() (int, int, error) {
		wg.Wait()

		return okN, failN, firstErr
	}
}

// reloadingNode is a node of size connections to r that presents the
// watched pair.
func reloadingNode(t *testing.T, ca *testCA, r *tlsRunner, w *certreload.Watcher, certPath, keyPath string, size int) *node {
	t.Helper()
	conn := devConnection(t, ca, r)
	conn.ClientCert, conn.ClientKey = certPath, keyPath
	n, err := newNode(conn, poolConfig{size: size, certs: w, warm: 3 * time.Second, retry: 50 * time.Millisecond, log: quietLog()},
		runnerclient.WithTimeout(3*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { n.Close() })

	return n
}

// Against signers that accept only certificate N, then only N+1 for new
// connections: no request fails across the swap, and a connection made
// after it presents N+1.
func TestSwapAgainstSignerThatAcceptsOneCertificate(t *testing.T) {
	ca := newTestCA(t)
	k := splitKey(t, 2, 3)
	w, certPath, keyPath, certN := watched(t, ca, time.Now().Add(time.Hour))
	var runners []*tlsRunner
	var nodes []*node
	for i := range 3 {
		r := startTLSRunner(t, ca, k, i, false, nil)
		r.allow(certN)
		runners = append(runners, r)
		nodes = append(nodes, reloadingNode(t, ca, r, w, certPath, keyPath, 2))
	}
	stop := make(chan struct{})
	wait := signLoop(nodes, k, stop)
	time.Sleep(200 * time.Millisecond)

	certN1 := ca.writePair(t, certPath, keyPath, time.Now().Add(2*time.Hour))
	for _, r := range runners {
		r.allow(certN1)
	}
	if !w.Poll() {
		t.Fatal("no swap")
	}
	for _, n := range nodes {
		waitFor(t, "every connection on N+1", 10*time.Second, func() bool { return allOn(n.pairs(), 2) })
	}
	time.Sleep(200 * time.Millisecond)
	close(stop)
	ok, failed, first := wait()
	if failed != 0 || ok == 0 {
		t.Fatalf("%d signed, %d failed across the swap: %v", ok, failed, first)
	}
	// New connections after the swap present N+1, which the signer takes.
	// The first call may meet both dropped connections and fail with EOF,
	// as before this change; the next one dials.
	runners[0].dropConns()
	var err error
	for range 2 {
		if _, err = nodes[0].PublicKeys(ctxShort(t)); err == nil {
			break
		}
	}
	if err != nil {
		t.Fatalf("new connection after the swap: %v", err)
	}
	t.Logf("%d requests signed across the swap, none failed", ok)
}

// The old certificate expires shortly after the swap, and dials are slow:
// every connection is on the new certificate before the old one expires,
// and no request fails.
func TestRedialsLandBeforeTheOldCertificateExpires(t *testing.T) {
	ca := newTestCA(t)
	k := splitKey(t, 2, 3)
	oldEnd := time.Now().Add(4 * time.Second)
	w, certPath, keyPath, _ := watched(t, ca, oldEnd)
	var nodes []*node
	for i := range 3 {
		r := startTLSRunner(t, ca, k, i, false, nil)
		r.setHandshakeDelay(100 * time.Millisecond)
		nodes = append(nodes, reloadingNode(t, ca, r, w, certPath, keyPath, 4))
	}
	stop := make(chan struct{})
	wait := signLoop(nodes, k, stop)
	time.Sleep(time.Second)
	ca.writePair(t, certPath, keyPath, time.Now().Add(time.Hour))
	if !w.Poll() {
		t.Fatal("no swap")
	}
	for _, n := range nodes {
		waitFor(t, "every connection on the new pair", 10*time.Second, func() bool { return allOn(n.pairs(), 2) })
	}
	left := time.Until(oldEnd)
	if left <= 0 {
		t.Fatalf("the last redial landed %v after the old certificate expired", -left)
	}
	t.Logf("every redial landed %v before the old certificate expired", left.Round(time.Millisecond))
	time.Sleep(left + 500*time.Millisecond)
	close(stop)
	if ok, failed, first := wait(); failed != 0 || ok == 0 {
		t.Fatalf("%d signed, %d failed: %v", ok, failed, first)
	}
}
