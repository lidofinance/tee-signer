package attls

// Tests of the runner's mutual TLS on a vsock listener. A vsock listener
// needs a kernel with vsock loopback, which the WSL2 kernel of the dev
// machine lacks. So most tests open the listener for a vsock address
// through attls.Listen with a TCP loopback listener in its place: the TLS
// layer sees a net.Conn either way. TestRealVsock runs the same flow over
// real vsock (CID 1) and skips where that does not work, which includes a
// build without vsock (only the platform_aws build has it).

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/signer-protocol/transport"
)

// ---- test CAs and certificates ----

type ca struct {
	cert  *x509.Certificate
	key   *ecdsa.PrivateKey
	chain [][]byte // DER of this CA and the intermediates above it, without the root
}

var serial int64

func nextSerial() *big.Int { serial++; return big.NewInt(serial) }

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// newRoot makes a self-signed CA.
func newRoot(t *testing.T, name string, nb, na time.Time) *ca {
	t.Helper()
	key := newKey(t)
	tmpl := &x509.Certificate{
		SerialNumber: nextSerial(), Subject: pkix.Name{CommonName: name},
		NotBefore: nb, NotAfter: na, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &ca{cert: cert, key: key}
}

// sub makes an intermediate CA under c.
func (c *ca) sub(t *testing.T, name string, nb, na time.Time) *ca {
	t.Helper()
	key := newKey(t)
	tmpl := &x509.Certificate{
		SerialNumber: nextSerial(), Subject: pkix.Name{CommonName: name},
		NotBefore: nb, NotAfter: na, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, &key.PublicKey, c.key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &ca{cert: cert, key: key, chain: append([][]byte{der}, c.chain...)}
}

// client issues a client certificate under c. The chain it sends is the
// leaf and the intermediates, the way a client file with the leaf and the
// intermediate in it does.
func (c *ca) client(t *testing.T, name string, nb, na time.Time, eku ...x509.ExtKeyUsage) tls.Certificate {
	t.Helper()
	if len(eku) == 0 {
		eku = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	key := newKey(t)
	tmpl := &x509.Certificate{
		SerialNumber: nextSerial(), Subject: pkix.Name{CommonName: name},
		NotBefore: nb, NotAfter: na, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: eku,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, &key.PublicKey, c.key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: append([][]byte{der}, c.chain...), PrivateKey: key}
}

func certPEM(c *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
}

// ---- a trusted clock the test moves ----

type testClock struct {
	mu  sync.Mutex
	t   time.Time
	err error
}

func (c *testClock) Now() (time.Time, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t, c.err
}

func (c *testClock) set(t time.Time) { c.mu.Lock(); c.t, c.err = t, nil; c.mu.Unlock() }
func (c *testClock) fail(err error)  { c.mu.Lock(); c.err = err; c.mu.Unlock() }

// ---- a server on a (fake) vsock listener ----

var vsockAddr = transport.Addr{Network: "vsock", CID: transport.AnyCID, Port: 7100}

// loopbackOpen stands in for transport.Listen: it checks that the address
// is the vsock one and listens on TCP loopback.
func loopbackOpen(t *testing.T) func(transport.Addr) (net.Listener, error) {
	return func(a transport.Addr) (net.Listener, error) {
		if a != vsockAddr {
			t.Errorf("listener opened for %v, want %v", a, vsockAddr)
		}
		return net.Listen("tcp", "127.0.0.1:0")
	}
}

// serve accepts on l. The handshake of each connection ends in one entry
// of hs (nil: it worked). After a good handshake the server reads one
// byte and answers it.
func serve(t *testing.T, l net.Listener) (hs chan error) {
	t.Helper()
	hs = make(chan error, 16)
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				tc := c.(*tls.Conn) // the listener must be a TLS one
				_ = tc.SetDeadline(time.Now().Add(5 * time.Second))
				err := tc.Handshake()
				hs <- err
				if err != nil {
					return
				}
				var b [1]byte
				if _, err := io.ReadFull(tc, b[:]); err == nil {
					tc.Write(b[:])
				}
			}()
		}
	}()
	return hs
}

func (c *testClock) config(t *testing.T, ca *ca) (*tls.Config, []byte) {
	t.Helper()
	cfg, h, err := ServerConfig(certPEM(ca.cert), c.Now)
	if err != nil {
		t.Fatal(err)
	}
	return cfg, h
}

// start opens the listener the way the runner does for a vsock address.
func start(t *testing.T, cfg *tls.Config) (addr string, hs chan error) {
	t.Helper()
	l, tlsOn, err := Listen(vsockAddr, cfg, loopbackOpen(t))
	if err != nil {
		t.Fatal(err)
	}
	if !tlsOn {
		t.Fatal("Listen did not turn TLS on for a vsock address")
	}
	return l.Addr().String(), serve(t, l)
}

// try connects with cfg, sends one byte and reads the answer. It returns
// the connection state after the handshake and the first error.
func try(t *testing.T, addr string, cfg *tls.Config) (tls.ConnectionState, error) {
	t.Helper()
	cfg = cfg.Clone()
	cfg.InsecureSkipVerify = true // the runner's certificate is self-signed and pinned through the attestation
	if cfg.MinVersion == 0 {
		cfg.MinVersion = tls.VersionTLS13
	}
	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	tc := tls.Client(conn, cfg)
	if err := tc.Handshake(); err != nil {
		return tls.ConnectionState{}, err
	}
	st := tc.ConnectionState()
	// In TLS 1.3 the client finishes first; a refusal of its certificate
	// arrives as an alert on the first read.
	if _, err := tc.Write([]byte{'x'}); err != nil {
		return st, err
	}
	var b [1]byte
	if _, err := io.ReadFull(tc, b[:]); err != nil {
		return st, err
	}
	return st, nil
}

// handshakeResult waits for the server's side of one handshake.
func handshakeResult(t *testing.T, hs chan error) error {
	t.Helper()
	select {
	case err := <-hs:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("the server saw no handshake")
		return nil
	}
}

func wantContains(t *testing.T, what string, err error, sub string) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: no error, want one containing %q", what, sub)
	}
	if !strings.Contains(err.Error(), sub) {
		t.Fatalf("%s: error %q does not contain %q", what, err, sub)
	}
}

// ---- tests ----

var now0 = time.Now()

func day(n int) time.Duration { return time.Duration(n) * 24 * time.Hour }

func TestVsockListenerMutualTLS(t *testing.T) {
	root := newRoot(t, "root", now0.Add(-day(365)), now0.Add(day(365)))
	clk := &testClock{t: now0}
	cfg, keyHash := clk.config(t, root)
	addr, hs := start(t, cfg)

	st, err := try(t, addr, &tls.Config{Certificates: []tls.Certificate{root.client(t, "dirk", now0.Add(-time.Hour), now0.Add(time.Hour))}})
	if err != nil {
		t.Fatalf("client with a certificate from the pinned CA: %v", err)
	}
	if err := handshakeResult(t, hs); err != nil {
		t.Fatalf("server side: %v", err)
	}
	if st.Version != tls.VersionTLS13 {
		t.Fatalf("TLS version %x, want 1.3", st.Version)
	}
	// The key the client sees is the key the runner puts into its identity.
	got := sha256.Sum256(st.PeerCertificates[0].RawSubjectPublicKeyInfo)
	if string(got[:]) != string(keyHash) {
		t.Fatalf("handshake key %x is not the returned key hash %x", got, keyHash)
	}
}

func TestVsockListenerRefusals(t *testing.T) {
	root := newRoot(t, "root", now0.Add(-day(365)), now0.Add(day(365)))
	other := newRoot(t, "other root", now0.Add(-day(365)), now0.Add(day(365)))
	clk := &testClock{t: now0}
	cfg, _ := clk.config(t, root)
	addr, hs := start(t, cfg)

	good := func(c *ca, nb, na time.Time, eku ...x509.ExtKeyUsage) []tls.Certificate {
		return []tls.Certificate{c.client(t, "dirk", nb, na, eku...)}
	}
	forced := func(c tls.Certificate) *tls.Config {
		// Go's client withholds a certificate the server's CA list does not
		// name, so make it present this one.
		return &tls.Config{GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return &c, nil }}
	}
	cases := []struct {
		name       string
		cfg        *tls.Config
		wantClient string // in the client's error
		wantServer string // in the server's handshake error
	}{
		{"no client certificate", &tls.Config{}, "certificate required", "didn't provide a certificate"},
		{"client certificate from another CA",
			forced(good(other, now0.Add(-time.Hour), now0.Add(time.Hour))[0]), "unknown certificate authority", "unknown authority"},
		{"expired client certificate",
			&tls.Config{Certificates: good(root, now0.Add(-day(3)), now0.Add(-day(2)))}, "expired certificate", "expired"},
		{"client certificate not yet valid",
			&tls.Config{Certificates: good(root, now0.Add(day(2)), now0.Add(day(3)))}, "expired certificate", "expired or is not yet valid"},
		{"client certificate for server auth only",
			&tls.Config{Certificates: good(root, now0.Add(-time.Hour), now0.Add(time.Hour), x509.ExtKeyUsageServerAuth)}, "bad certificate", "incompatible key usage"},
		{"TLS 1.2 with a good client certificate",
			&tls.Config{MaxVersion: tls.VersionTLS12, MinVersion: tls.VersionTLS12,
				Certificates: good(root, now0.Add(-time.Hour), now0.Add(time.Hour))}, "protocol version not supported", "client offered only unsupported versions"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := try(t, addr, tc.cfg)
			srv := handshakeResult(t, hs)
			wantContains(t, "client", err, tc.wantClient)
			wantContains(t, "server", srv, tc.wantServer)
		})
	}

	t.Run("plain connection, no TLS", func(t *testing.T) {
		// The wire protocol's HEALTH request, sent in the clear.
		conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		if _, err := conn.Write([]byte{0, 0, 0, 6, 1, 1, 0, 0, 0, 1}); err != nil {
			t.Fatal(err)
		}
		wantContains(t, "server", handshakeResult(t, hs), "does not look like a TLS handshake")
		// The server closes without answering the request.
		buf := make([]byte, 64)
		n, err := conn.Read(buf)
		if n > 0 && buf[0] != 0x15 { // a TLS alert record is fine, a wire response is not
			t.Fatalf("the server answered a plain request: %x", buf[:n])
		}
		if err == nil {
			t.Fatal("the connection stayed open")
		}
	})

	// The listener still works after all of that.
	if _, err := try(t, addr, &tls.Config{Certificates: good(root, now0.Add(-time.Hour), now0.Add(time.Hour))}); err != nil {
		t.Fatalf("good client after the refusals: %v", err)
	}
	if err := handshakeResult(t, hs); err != nil {
		t.Fatal(err)
	}
}

// The validity dates of the client certificate are checked against the
// trusted clock passed to ServerConfig, not against the system clock.
func TestClientCertificateValidityUsesTheTrustedClock(t *testing.T) {
	root := newRoot(t, "root", now0.Add(-day(365)), now0.Add(day(365)))
	clk := &testClock{t: now0}
	cfg, _ := clk.config(t, root)
	addr, hs := start(t, cfg)

	valid := &tls.Config{Certificates: []tls.Certificate{root.client(t, "dirk", now0.Add(-time.Hour), now0.Add(time.Hour))}}
	expiredBySystem := &tls.Config{Certificates: []tls.Certificate{root.client(t, "old", now0.Add(-day(3)), now0.Add(-day(2)))}}

	check := func(name string, c *tls.Config, want string) {
		t.Helper()
		_, err := try(t, addr, c)
		srv := handshakeResult(t, hs)
		if want == "" {
			if err != nil || srv != nil {
				t.Fatalf("%s: refused: client %v, server %v", name, err, srv)
			}
			return
		}
		wantContains(t, name+": client", err, "expired certificate")
		wantContains(t, name+": server", srv, want)
	}

	check("system clock and trusted clock agree", valid, "")
	clk.set(now0.Add(day(30)))
	check("trusted clock 30 days ahead: certificate valid by the system clock is expired", valid, "expired")
	clk.set(now0.Add(-day(10)))
	check("trusted clock 10 days behind: not yet valid", valid, "expired or is not yet valid")
	clk.set(now0.Add(-day(2) - 12*time.Hour))
	check("certificate that the system clock calls expired, valid by the trusted clock", expiredBySystem, "")
	clk.set(now0)
	check("trusted clock back to the system time", valid, "")

	// The chain is checked at the trusted time too: the CA itself.
	clk.set(now0.Add(day(400)))
	check("trusted clock past the CA's own expiry", valid, "expired")
}

// Without a reading a client connects but its connection has no verified
// chain, so it gets no role (the server answers it HEALTH only). After a
// new reading the handshake verifies the chain with its dates again.
func TestNoTrustedTimeGivesNoVerifiedChain(t *testing.T) {
	root := newRoot(t, "root", now0.Add(-day(365)), now0.Add(day(365)))
	clk := &testClock{t: now0}
	cfg, _ := clk.config(t, root)
	cert := root.client(t, "dirk", now0.Add(-time.Hour), now0.Add(time.Hour))

	clk.fail(errors.New("clock: last reading is 1m30s old"))
	if cs := handshake(t, cfg, cert); len(cs.VerifiedChains) != 0 || RoleOf(&cs) != RoleNone {
		t.Fatalf("without a reading: %d verified chains, role %v; want 0, none", len(cs.VerifiedChains), RoleOf(&cs))
	}
	clk.set(now0)
	if cs := handshake(t, cfg, cert); len(cs.VerifiedChains) == 0 || RoleOf(&cs) != RoleSigning {
		t.Fatalf("after a new reading: %d verified chains, role %v; want the chain, signing", len(cs.VerifiedChains), RoleOf(&cs))
	}
}

// The image pins one CA certificate. With a root and an intermediate, the
// root is the pinned one, the intermediate issues the short-lived client
// certificates, and a new intermediate needs no new image.
func TestPinnedRootWithIntermediate(t *testing.T) {
	root := newRoot(t, "root", now0.Add(-day(365)), now0.Add(day(3650)))
	clk := &testClock{t: now0}
	cfg, _ := clk.config(t, root) // the image holds the root only
	addr, hs := start(t, cfg)
	expect := func(name string, c tls.Certificate, ok bool) {
		t.Helper()
		_, err := try(t, addr, &tls.Config{Certificates: []tls.Certificate{c}})
		srv := handshakeResult(t, hs)
		if ok && (err != nil || srv != nil) {
			t.Fatalf("%s: refused: client %v, server %v", name, err, srv)
		}
		if !ok && (err == nil || srv == nil) {
			t.Fatalf("%s: accepted", name)
		}
	}
	short := func(c *ca) tls.Certificate {
		return c.client(t, "dirk", now0.Add(-5*time.Minute), now0.Add(24*time.Hour))
	}

	int1 := root.sub(t, "intermediate 1", now0.Add(-day(1)), now0.Add(day(90)))
	expect("leaf and intermediate 1", short(int1), true)

	// A client file that holds the leaf only: the server cannot build the
	// chain, and Go's client does not even offer the certificate.
	leafOnly := short(int1)
	leafOnly.Certificate = leafOnly.Certificate[:1]
	expect("leaf without the intermediate", leafOnly, false)

	// Intermediate 1 retires; intermediate 2 comes from the same root. The
	// server configuration is the same one: no new image.
	int2 := root.sub(t, "intermediate 2", now0.Add(-time.Hour), now0.Add(day(90)))
	expect("leaf and intermediate 2, same server", short(int2), true)
	expect("intermediate 1 still works until it expires", short(int1), true)

	// An expired intermediate is refused even with a fresh leaf.
	oldInt := root.sub(t, "expired intermediate", now0.Add(-day(100)), now0.Add(-day(10)))
	expect("expired intermediate", oldInt.client(t, "dirk", now0.Add(-time.Hour), now0.Add(time.Hour)), false)

	// The same intermediate name under another root.
	otherRoot := newRoot(t, "root", now0.Add(-day(365)), now0.Add(day(3650)))
	otherInt := otherRoot.sub(t, "intermediate 1", now0.Add(-day(1)), now0.Add(day(90)))
	expect("intermediate of another root", short(otherInt), false)
}

func TestClientCAFile(t *testing.T) {
	root := newRoot(t, "root", now0.Add(-day(1)), now0.Add(day(1)))
	good := certPEM(root.cert)
	keyDER, err := x509.MarshalPKCS8PrivateKey(root.key)
	if err != nil {
		t.Fatal(err)
	}
	ecDER, err := x509.MarshalECPrivateKey(root.key)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8 := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	ec := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: ecDER})
	enc := pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: keyDER})

	if _, _, err := ServerConfig(good, nil); err != nil {
		t.Fatalf("one CA certificate: %v", err)
	}
	two := append(append([]byte{}, good...), certPEM(newRoot(t, "second", now0, now0.Add(time.Hour)).cert)...)
	if _, _, err := ServerConfig(two, nil); err != nil {
		t.Fatalf("two CA certificates: %v", err)
	}
	for name, file := range map[string][]byte{
		"PKCS#8 key alone":             pkcs8,
		"certificate then a key":       append(append([]byte{}, good...), pkcs8...),
		"key then a certificate":       append(append([]byte{}, pkcs8...), good...),
		"EC private key with the cert": append(append([]byte{}, good...), ec...),
		"encrypted key with the cert":  append(append([]byte{}, good...), enc...),
	} {
		_, _, err := ServerConfig(file, nil)
		wantContains(t, name, err, "private key")
	}
	for name, file := range map[string][]byte{
		"empty file":      nil,
		"text":            []byte("not a certificate\n"),
		"bad certificate": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("junk")}),
	} {
		if _, _, err := ServerConfig(file, nil); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
}

// Every connection does the full handshake, so the full certificate check.
func TestNoSessionResumption(t *testing.T) {
	root := newRoot(t, "root", now0.Add(-day(365)), now0.Add(day(365)))
	clk := &testClock{t: now0}
	cfg, _ := clk.config(t, root)
	addr, hs := start(t, cfg)
	c := &tls.Config{
		Certificates:       []tls.Certificate{root.client(t, "dirk", now0.Add(-time.Hour), now0.Add(time.Hour))},
		ClientSessionCache: tls.NewLRUClientSessionCache(4),
	}
	for i := 0; i < 3; i++ {
		st, err := try(t, addr, c)
		if err != nil {
			t.Fatal(err)
		}
		handshakeResult(t, hs)
		if st.DidResume {
			t.Fatalf("connection %d resumed a session", i+1)
		}
	}
}

func TestTLSKeyIsFreshPerConfig(t *testing.T) {
	root := newRoot(t, "root", now0.Add(-day(1)), now0.Add(day(1)))
	_, h1, err := ServerConfig(certPEM(root.cert), nil)
	if err != nil {
		t.Fatal(err)
	}
	_, h2, err := ServerConfig(certPEM(root.cert), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(h1) != 32 || string(h1) == string(h2) {
		t.Fatalf("key hashes %x and %x", h1, h2)
	}
}

// Only network addresses get TLS. A unix socket stays as it is, and so
// does any listener when there is no TLS configuration.
func TestListenWrapsNetworkAddressesOnly(t *testing.T) {
	root := newRoot(t, "root", now0.Add(-day(1)), now0.Add(day(1)))
	cfg, _, err := ServerConfig(certPEM(root.cert), nil)
	if err != nil {
		t.Fatal(err)
	}
	open := func(transport.Addr) (net.Listener, error) { return net.Listen("tcp", "127.0.0.1:0") }
	for _, tc := range []struct {
		addr string
		cfg  *tls.Config
		tls  bool
	}{
		{"tcp:127.0.0.1:7100", cfg, true},
		{"vsock:any:7100", cfg, true},
		{"vsock:16:7100", cfg, true},
		{"unix:/run/signer/runner.sock", cfg, false},
		{"vsock:any:7100", nil, false},
		{"tcp:127.0.0.1:7100", nil, false},
	} {
		a, err := transport.Parse(tc.addr)
		if err != nil {
			t.Fatal(err)
		}
		l, on, err := Listen(a, tc.cfg, open)
		if err != nil {
			t.Fatal(err)
		}
		l.Close()
		if on != tc.tls {
			t.Fatalf("%s with cfg=%v: TLS %v, want %v", tc.addr, tc.cfg != nil, on, tc.tls)
		}
	}
	if _, _, err := Listen(vsockAddr, cfg, func(transport.Addr) (net.Listener, error) { return nil, errors.New("no vsock") }); err == nil {
		t.Fatal("an open error was swallowed")
	}
}

// The same flow over real vsock, through the transport package the runner
// uses. It needs vsock loopback (CID 1, kernel CONFIG_VSOCKETS_LOOPBACK).
func TestRealVsock(t *testing.T) {
	const port = 7193
	root := newRoot(t, "root", now0.Add(-day(365)), now0.Add(day(365)))
	clk := &testClock{t: now0}
	cfg, keyHash := clk.config(t, root)
	a := transport.Addr{Network: "vsock", CID: 1, Port: port}
	l, tlsOn, err := Listen(a, cfg, transport.Listen)
	if err != nil {
		t.Skipf("vsock listen on CID 1 (loopback) failed: %v", err)
	}
	if !tlsOn {
		t.Fatal("no TLS on a vsock listener")
	}
	hs := serve(t, l)
	raw, err := transport.Dial(context.Background(), a)
	if err != nil {
		t.Skipf("vsock dial to CID 1 failed: %v", err)
	}
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(5 * time.Second))
	cc := tls.Client(raw, &tls.Config{
		MinVersion: tls.VersionTLS13, InsecureSkipVerify: true,
		Certificates: []tls.Certificate{root.client(t, "dirk", now0.Add(-time.Hour), now0.Add(time.Hour))},
	})
	if _, err := cc.Write([]byte{'x'}); err != nil {
		t.Fatal(err)
	}
	var b [1]byte
	if _, err := io.ReadFull(cc, b[:]); err != nil {
		t.Fatal(err)
	}
	if err := handshakeResult(t, hs); err != nil {
		t.Fatal(err)
	}
	got := sha256.Sum256(cc.ConnectionState().PeerCertificates[0].RawSubjectPublicKeyInfo)
	if string(got[:]) != string(keyHash) {
		t.Fatalf("key hash over vsock: %x, want %x", got, keyHash)
	}
	t.Log("mutual TLS 1.3 over vsock loopback, key hash matches")
}
