package remote_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/remote"
	"github.com/lidofinance/tee-signer/signer-protocol/wire"
)

// These tests run the real client against a fake runner that speaks the wire
// protocol over TLS 1.3 and can be slow or stall. They cover what happens to
// the connection when a request times out, and what the callers see.
//
// The signing client's callers end their request as soon as a threshold of the
// other signers has answered, usually long before a new dial to a cloud
// signer (TLS handshake, IDENTITY, attestation check) can finish. A client
// that ties the dial to the request's context never gets a new connection:
// every dial is cancelled with its request. That is how one timed out request
// once left a signing client without its Azure signer until it restarted.

// ---- fake runner ----

type fakeRunner struct {
	ln   net.Listener
	cfg  *tls.Config
	spki []byte
	done chan struct{}

	// Set before the first request.
	handshakeDelay time.Duration // before the runner answers the TLS handshake
	identityDelay  time.Duration // before it answers IDENTITY: a slow attestation
	// otherKey makes the IDENTITY answer of connection conn name another TLS
	// key, as a relay would.
	otherKey func(conn int) bool
	// delay is the time before the answer to request seq (1, 2, ...) on
	// connection conn (1, 2, ... in the order the TCP connections arrived).
	// A negative delay is a stall: no answer until the test ends.
	delay func(conn, seq int) time.Duration

	mu       sync.Mutex
	accepted int         // TCP connections
	shaken   int         // TLS handshakes that finished
	identity int         // IDENTITY requests
	received int         // other requests
	perConn  map[int]int // other requests by connection
}

func selfSigned(t *testing.T, name string, usage x509.ExtKeyUsage) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}
}

// startFake starts a runner. The options set its fields before it accepts
// the first connection.
func startFake(t *testing.T, opts ...func(*fakeRunner)) *fakeRunner {
	t.Helper()
	cert := selfSigned(t, "signer-runner", x509.ExtKeyUsageServerAuth)
	h := sha256.Sum256(cert.Leaf.RawSubjectPublicKeyInfo)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeRunner{
		ln: ln, spki: h[:], done: make(chan struct{}), perConn: map[int]int{},
		cfg: &tls.Config{
			MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert},
			ClientAuth: tls.RequireAnyClientCert,
		},
	}
	for _, o := range opts {
		o(f)
	}
	t.Cleanup(func() { close(f.done); ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			f.mu.Lock()
			f.accepted++
			n := f.accepted
			f.mu.Unlock()
			go f.serve(c, n)
		}
	}()
	return f
}

// sleep waits d, or returns false when the test has ended.
func (f *fakeRunner) sleep(d time.Duration) bool {
	if d <= 0 {
		return true
	}
	select {
	case <-time.After(d):
		return true
	case <-f.done:
		return false
	}
}

func (f *fakeRunner) serve(raw net.Conn, n int) {
	defer raw.Close()
	if !f.sleep(f.handshakeDelay) {
		return
	}
	c := tls.Server(raw, f.cfg)
	if err := c.Handshake(); err != nil {
		return
	}
	f.mu.Lock()
	f.shaken++
	f.mu.Unlock()
	for {
		fr, err := wire.ReadFrame(c)
		if err != nil {
			return
		}
		var body []byte
		if fr.Type == wire.TypeIdentity {
			nonce, err := wire.DecodeAttest(fr.Payload)
			if err != nil {
				return
			}
			f.mu.Lock()
			f.identity++
			f.mu.Unlock()
			if !f.sleep(f.identityDelay) {
				return
			}
			body = f.identityBody(n, nonce)
		} else {
			f.mu.Lock()
			f.received++
			f.perConn[n]++
			seq := f.perConn[n]
			f.mu.Unlock()
			var d time.Duration
			if f.delay != nil {
				d = f.delay(n, seq)
			}
			if d < 0 {
				<-f.done
				return
			}
			if !f.sleep(d) {
				return
			}
			body, _ = wire.EncodeHealth(&backend.Health{Platform: "fake"})
		}
		if err := wire.WriteFrame(c, wire.Frame{Type: fr.Type | wire.ResponseFlag, ID: fr.ID, Payload: wire.EncodeOK(body)}); err != nil {
			return
		}
	}
}

func (f *fakeRunner) identityBody(conn int, nonce []byte) []byte {
	key := f.spki
	if f.otherKey != nil && f.otherKey(conn) {
		other := sha256.Sum256([]byte("another runner's TLS key"))
		key = other[:]
	}
	id := &backend.Identity{
		State: backend.SetupState{SetupHash: backend.Root{1, 2, 3}}, ImportKEM: 0x647a, ImportKDF: 1, ImportAEAD: 2,
		ImportKey: []byte("fake hpke public key"), TLSKeyHash: key,
	}
	ud := backend.IdentityUserData(nonce, id)
	doc, _ := json.Marshal(map[string]any{"nonce": nonce, "user_data": ud})
	id.Attestation = &backend.Attestation{Platform: "dev", Format: "dev-json", UserData: ud, Document: doc}
	b, err := wire.EncodeIdentity(id)
	if err != nil {
		panic(err)
	}
	return b
}

// counts is a snapshot of what the runner saw.
type counts struct {
	accepted, shaken, identity, received int
	perConn                              map[int]int
}

func (f *fakeRunner) counts() counts {
	f.mu.Lock()
	defer f.mu.Unlock()
	pc := map[int]int{}
	for k, v := range f.perConn {
		pc[k] = v
	}
	return counts{f.accepted, f.shaken, f.identity, f.received, pc}
}

// ---- client ----

// verifier is the attestation check of the client: the dev verifier, with a
// count of its calls and a check that no nonce is used twice.
type verifier struct {
	mu     sync.Mutex
	calls  int
	nonces map[string]bool
	fail   func(call int) error
}

func newVerifier() *verifier { return &verifier{nonces: map[string]bool{}} }

func (v *verifier) verify(ctx context.Context, nonce []byte, id *backend.Identity) error {
	v.mu.Lock()
	v.calls++
	n, fresh, fail := v.calls, !v.nonces[string(nonce)], v.fail
	v.nonces[string(nonce)] = true
	v.mu.Unlock()
	if !fresh {
		return errors.New("verifier: nonce used twice")
	}
	if fail != nil {
		if err := fail(n); err != nil {
			return err
		}
	}
	return remote.DevVerifier(ctx, nonce, id)
}

func (v *verifier) count() int {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.calls
}

func newClient(t *testing.T, f *fakeRunner, timeout time.Duration, v *verifier) *remote.Client {
	t.Helper()
	cfg := &tls.Config{
		Certificates: []tls.Certificate{selfSigned(t, "client", x509.ExtKeyUsageClientAuth)},
		MinVersion:   tls.VersionTLS13,
	}
	c, err := remote.New("tcp:"+f.ln.Addr().String(), remote.WithTLS(cfg, v.verify), remote.WithTimeout(timeout))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func health(ctx context.Context, c *remote.Client) error {
	_, err := c.Health(ctx)
	return err
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// stallSecond makes the second request on the first connection stall.
func stallSecond(conn, seq int) time.Duration {
	if conn == 1 && seq == 2 {
		return -1
	}
	return 0
}

var bg = context.Background()

// ---- tests ----

// A request that stalls past the client timeout fails with a timeout, and
// its connection is dropped. The next requests go over a new connection that
// was checked like the first one: new TLS handshake, new IDENTITY with a new
// nonce, one more call of the verifier.
func TestStalledRequestDropsTheConnection(t *testing.T) {
	f := startFake(t, func(f *fakeRunner) { f.delay = stallSecond })
	v := newVerifier()
	c := newClient(t, f, 300*time.Millisecond, v)

	if err := health(bg, c); err != nil {
		t.Fatalf("first request: %v", err)
	}
	start := time.Now()
	err := health(bg, c)
	if !isTimeout(err) {
		t.Fatalf("stalled request: error %v, want a timeout", err)
	}
	if took := time.Since(start); took > 3*time.Second {
		t.Fatalf("stalled request took %v, want about the client timeout of 300 ms", took)
	}
	for i := 0; i < 3; i++ {
		if err := health(bg, c); err != nil {
			t.Fatalf("request %d after the stall: %v", i+1, err)
		}
	}
	got := f.counts()
	if got.accepted != 2 || got.shaken != 2 || got.identity != 2 {
		t.Errorf("runner saw %d connections, %d handshakes, %d IDENTITY requests, want 2 of each", got.accepted, got.shaken, got.identity)
	}
	if got.perConn[1] != 2 || got.perConn[2] != 3 {
		t.Errorf("requests by connection %v, want 2 on the first (the last one stalled) and 3 on the second", got.perConn)
	}
	if v.count() != 2 {
		t.Errorf("the verifier ran %d times, want once for each connection", v.count())
	}
}

// The case of the signing client. After the timeout every request comes with a
// context that ends 30 ms after it starts, and a new dial takes about 250 ms.
// The callers give up on their own, so the dial must not belong to a request.
// Once it is done, the next request finds a connection. Exactly one new
// connection is made: the callers share the dial.
func TestRedialSurvivesCancelledRequests(t *testing.T) {
	f := startFake(t, func(f *fakeRunner) {
		f.handshakeDelay = 150 * time.Millisecond
		f.identityDelay = 100 * time.Millisecond
		f.delay = stallSecond
	})
	v := newVerifier()
	c := newClient(t, f, 400*time.Millisecond, v)

	if err := health(bg, c); err != nil {
		t.Fatalf("first request: %v", err)
	}
	if err := health(bg, c); !isTimeout(err) {
		t.Fatalf("stalled request: error %v, want a timeout", err)
	}

	ok, failed := 0, 0
	var firstErr error
	stalledAt := time.Now()
	var firstOK time.Duration
	limit := time.Now().Add(5 * time.Second)
	for ok < 10 && time.Now().Before(limit) {
		ctx, cancel := context.WithCancel(bg)
		stop := time.AfterFunc(30*time.Millisecond, cancel)
		start := time.Now()
		err := health(ctx, c)
		took := time.Since(start)
		stop.Stop()
		cancel()
		if took > time.Second {
			t.Fatalf("a request took %v, its context ended after 30 ms", took)
		}
		if err == nil {
			if ok == 0 {
				firstOK = time.Since(stalledAt)
			}
			ok++
		} else {
			failed++
			if firstErr == nil {
				firstErr = err
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	if ok < 10 {
		t.Fatalf("%d requests ok and %d failed in 5 s after the stall, the client did not get a new connection. First error: %v", ok, failed, firstErr)
	}
	t.Logf("after the stall: %d requests failed, then the first one succeeded after %v", failed, firstOK.Round(time.Millisecond))
	got := f.counts()
	if got.accepted != 2 || got.shaken != 2 || got.identity != 2 || v.count() != 2 {
		t.Errorf("runner saw %d connections, %d handshakes, %d IDENTITY requests and the verifier ran %d times, want 2 of each: the first connection and one new one",
			got.accepted, got.shaken, got.identity, v.count())
	}
}

// Many callers give up while one request is on the wire. Their requests do
// not reach the runner, they do not wait for their turn, and the connection
// stays.
func TestAbandonedRequestsStayOffTheConnection(t *testing.T) {
	f := startFake(t, func(f *fakeRunner) {
		f.delay = func(conn, seq int) time.Duration { return 20 * time.Millisecond }
	})
	v := newVerifier()
	c := newClient(t, f, 5*time.Second, v)
	if err := health(bg, c); err != nil {
		t.Fatalf("first request: %v", err)
	}

	const n = 200
	ctx, cancel := context.WithCancel(bg)
	defer cancel()
	var wg sync.WaitGroup
	start := time.Now()
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = health(ctx, c)
		}()
	}
	time.AfterFunc(10*time.Millisecond, cancel)
	wg.Wait()
	took := time.Since(start)
	if took > time.Second {
		t.Errorf("%d cancelled requests took %v, want them to stop with their context", n, took)
	}
	got := f.counts()
	t.Logf("%d of %d cancelled requests reached the runner, all of them returned after %v", got.received-1, n, took.Round(time.Millisecond))
	if got.received > 1+3 {
		t.Errorf("the runner received %d requests of the %d, want the first one and at most the few that were on the wire", got.received-1, n)
	}
	if err := health(bg, c); err != nil {
		t.Fatalf("request after the cancelled ones: %v", err)
	}
	if got := f.counts(); got.accepted != 1 || got.identity != 1 || v.count() != 1 {
		t.Errorf("runner saw %d connections and %d IDENTITY requests, want the one connection kept", got.accepted, got.identity)
	}
}

// Many requests are in flight on one client when one of them stalls. Only
// that request fails. The others wait for the new connection, which is made
// once, and all of them succeed on it.
func TestManyRequestsInFlightWhenOneStalls(t *testing.T) {
	f := startFake(t, func(f *fakeRunner) {
		f.delay = func(conn, seq int) time.Duration {
			if conn == 1 && seq == 5 {
				return -1
			}
			return 0
		}
	})
	v := newVerifier()
	c := newClient(t, f, 500*time.Millisecond, v)

	const n = 40
	errs := make(chan error, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- health(bg, c)
		}()
	}
	wg.Wait()
	close(errs)
	failed := 0
	for err := range errs {
		if err != nil {
			failed++
			if !isTimeout(err) {
				t.Errorf("error %v, want a timeout", err)
			}
		}
	}
	if failed != 1 {
		t.Errorf("%d of %d requests failed, want only the stalled one", failed, n)
	}
	got := f.counts()
	if got.accepted != 2 || got.identity != 2 || v.count() != 2 {
		t.Errorf("runner saw %d connections and %d IDENTITY requests, verifier ran %d times, want 2 of each", got.accepted, got.identity, v.count())
	}
	if got.perConn[1] != 5 || got.perConn[2] != n-5 {
		t.Errorf("requests by connection %v, want 5 on the first (the fifth stalled) and %d on the second", got.perConn, n-5)
	}
}

// A new connection is checked like the first one, also after a timeout. A
// runner that names another TLS key, and an attestation the verifier refuses,
// both get no request. The failure is not kept: the connection after that is
// checked again and works.
func TestEveryNewConnectionIsChecked(t *testing.T) {
	setup := func(t *testing.T, configure func(*fakeRunner, *verifier)) (*fakeRunner, *verifier, *remote.Client) {
		v := newVerifier()
		f := startFake(t, func(f *fakeRunner) {
			f.delay = stallSecond
			configure(f, v)
		})
		c := newClient(t, f, 300*time.Millisecond, v)
		if err := health(bg, c); err != nil {
			t.Fatalf("first request: %v", err)
		}
		if err := health(bg, c); !isTimeout(err) {
			t.Fatalf("stalled request: error %v, want a timeout", err)
		}
		return f, v, c
	}
	wantRefused := func(t *testing.T, f *fakeRunner, c *remote.Client, sub string) {
		t.Helper()
		err := health(bg, c)
		if err == nil || !strings.Contains(err.Error(), sub) {
			t.Fatalf("request on the new connection: error %v, want one containing %q", err, sub)
		}
		if n := f.counts().perConn[2]; n != 0 {
			t.Fatalf("the client sent %d requests on the connection it refused", n)
		}
	}

	t.Run("identity names another key", func(t *testing.T) {
		f, v, c := setup(t, func(f *fakeRunner, _ *verifier) { f.otherKey = func(conn int) bool { return conn == 2 } })
		wantRefused(t, f, c, "attested identity names")
		if err := health(bg, c); err != nil {
			t.Fatalf("request on the next connection: %v", err)
		}
		if got := f.counts(); got.accepted != 3 || got.identity != 3 {
			t.Errorf("runner saw %d connections and %d IDENTITY requests, want 3 of each", got.accepted, got.identity)
		}
		if v.count() != 2 {
			t.Errorf("the verifier ran %d times, want 2 (the key check refuses before it)", v.count())
		}
	})

	t.Run("verifier refuses", func(t *testing.T) {
		f, v, c := setup(t, func(_ *fakeRunner, v *verifier) {
			v.fail = func(call int) error {
				if call == 2 {
					return errors.New("measurement mismatch")
				}
				return nil
			}
		})
		wantRefused(t, f, c, "attestation: measurement mismatch")
		if err := health(bg, c); err != nil {
			t.Fatalf("request on the next connection: %v", err)
		}
		if v.count() != 3 {
			t.Errorf("the verifier ran %d times, want 3, once for each connection", v.count())
		}
	})
}

// A request that is on the wire when its context ends is not interrupted:
// that would leave the connection out of step and force a new dial. It
// finishes, and the connection serves the next request.
func TestRequestOnTheWireFinishes(t *testing.T) {
	f := startFake(t, func(f *fakeRunner) {
		f.delay = func(conn, seq int) time.Duration { return 100 * time.Millisecond }
	})
	v := newVerifier()
	c := newClient(t, f, 5*time.Second, v)
	if err := health(bg, c); err != nil {
		t.Fatalf("first request: %v", err)
	}

	ctx, cancel := context.WithCancel(bg)
	time.AfterFunc(10*time.Millisecond, cancel)
	if err := health(ctx, c); err != nil {
		t.Fatalf("request cancelled on the wire: %v", err)
	}
	if err := health(bg, c); err != nil {
		t.Fatalf("next request: %v", err)
	}
	if got := f.counts(); got.accepted != 1 || v.count() != 1 {
		t.Errorf("runner saw %d connections, verifier ran %d times, want one connection", got.accepted, v.count())
	}
}

// A request whose context has ended already is not sent and does not dial.
func TestEndedContextDoesNotDial(t *testing.T) {
	f := startFake(t)
	v := newVerifier()
	c := newClient(t, f, 5*time.Second, v)
	ctx, cancel := context.WithCancel(bg)
	cancel()
	err := health(ctx, c)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error %v, want context.Canceled", err)
	}
	if got := f.counts(); got.accepted != 0 {
		t.Errorf("the client opened %d connections for a cancelled request", got.accepted)
	}
}

// Close drops the connection. The client dials again for the next request.
func TestRequestAfterCloseDials(t *testing.T) {
	f := startFake(t)
	v := newVerifier()
	c := newClient(t, f, 5*time.Second, v)
	if err := health(bg, c); err != nil {
		t.Fatal(err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if err := health(bg, c); err != nil {
		t.Fatalf("request after Close: %v", err)
	}
	if got := f.counts(); got.accepted != 2 || v.count() != 2 {
		t.Errorf("runner saw %d connections, verifier ran %d times, want 2 of each", got.accepted, v.count())
	}
}
