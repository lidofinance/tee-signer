//go:build !verifierselect

package runnerclient

// End to end: the AWS debug runner (build/<arch>/bin/runner-aws-debugimport) on the
// nitro platform, and this package's client with the aws-nitro verifier.
//
// The runner is the real binary with the real nitro start-up path: the
// platform is named nitro, it refuses to start without -tls-client-ca, it
// serves mutual TLS 1.3, and its IDENTITY carries the hash of its fresh TLS
// key and an attestation of platform nitro, format aws-nitro-cose-sign1,
// whose user data covers that identity. What the test replaces is the
// hardware: the debug build's test_nsm_url option sends the NSM request
// (nonce and user data) to a fake NSM, which answers with a COSE_Sign1
// document from attest/internal/testgen, signed by a local P-384 test CA
// that the client is told to trust in place of the AWS root. Release
// builds have no such option. In place of a vsock listener the runner
// listens on TCP, which is the same TLS layer behind the same
// attls.Listen; the vsock listener itself and the forwarder are tested in
// runner/attls, runner/forward and runner/e2e (TestE2EVsockTLS skips
// without vsock loopback).
//
// Not covered, because it needs AWS: a real NSM, real PCRs, the real AWS
// root and KMS. The test shows that the channel binding passes against a
// runner on the nitro code path, and that the refusals hold against the
// real binary.
//
//	RUNNER_AWS_DEBUG_BIN=build/x86_64/bin/runner-aws-debugimport go test -run TestE2ENitroRunner ./runnerclient

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/attestation-verify"
	"github.com/lidofinance/tee-signer/attestation-verify/internal/testgen"
	"github.com/lidofinance/tee-signer/signer-protocol"
)

// nsmRequest is what the debug runner sends to the fake NSM.
type nsmRequest struct {
	Nonce    []byte `json:"nonce"`
	UserData []byte `json:"user_data"`
}

// fakeNSM is the NSM of the test: it answers each request with a document
// as the spec says. Zero spec: a good document.
type fakeNSM struct {
	t   *testing.T
	env *nitroEnv
	srv *httptest.Server

	mu   sync.Mutex
	spec nitroSpec
	reqs []nsmRequest
}

func newFakeNSM(t *testing.T, env *nitroEnv) *fakeNSM {
	f := &fakeNSM{t: t, env: env}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeNSM) setSpec(s nitroSpec) { f.mu.Lock(); f.spec = s; f.mu.Unlock() }

func (f *fakeNSM) requests() []nsmRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]nsmRequest(nil), f.reqs...)
}

func (f *fakeNSM) serve(w http.ResponseWriter, r *http.Request) {
	var req nsmRequest
	if r.Method != http.MethodPost || json.NewDecoder(r.Body).Decode(&req) != nil || len(req.Nonce) == 0 || len(req.UserData) == 0 {
		http.Error(w, "want a POST with a nonce and user data", http.StatusBadRequest)
		return
	}
	f.mu.Lock()
	s := f.spec
	f.reqs = append(f.reqs, req)
	f.mu.Unlock()
	ca := f.env.ca
	if s.ca != nil {
		ca = s.ca
	}
	nonce, ud := req.Nonce, req.UserData
	if s.nonce != nil {
		nonce = s.nonce
	}
	if s.userData != nil {
		ud = s.userData
	}
	doc := ca.NitroDoc(f.t, testgen.NitroSpec{TS: time.Now().Add(s.skew), PCRs: s.pcrs, Nonce: nonce, UserData: ud})
	if s.flipSig {
		doc[len(doc)-1] ^= 1
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Write(doc)
}

type nitroRunner struct {
	addr    string
	logPath string
	cmd     *exec.Cmd
	done    chan struct{}
	err     *error
}

// launchNitroRunner starts the runner on the nitro platform with the fake
// NSM and returns without waiting for it to listen. args are added to the
// default flags.
func launchNitroRunner(t *testing.T, bin string, fake *fakeNSM, args ...string) nitroRunner {
	t.Helper()
	dir := t.TempDir()
	listen := freeAddr(t)
	logPath := filepath.Join(dir, "runner.log")
	logFile, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { logFile.Close() })
	base := []string{"-platform", "nitro", "-platform-opt", "test_nsm_url=" + fake.srv.URL,
		"-config", "../../governance/chains/chain.testnet.json", "-state-dir", filepath.Join(dir, "state"),
		"-listen", listen, "-mark-store", "none"}
	cmd := exec.Command(bin, append(base, args...)...)
	cmd.Stdout, cmd.Stderr = logFile, logFile
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	r := nitroRunner{addr: listen, logPath: logPath, cmd: cmd, done: make(chan struct{}), err: new(error)}
	go func() {
		*r.err = cmd.Wait()
		close(r.done)
	}()
	t.Cleanup(func() {
		cmd.Process.Kill()
		select {
		case <-r.done:
		case <-time.After(5 * time.Second):
		}
	})
	return r
}

func startNitroRunner(t *testing.T, bin string, ca *testCA, fake *fakeNSM, args ...string) nitroRunner {
	t.Helper()
	caFile := filepath.Join(t.TempDir(), "client-ca.pem")
	writePEM(t, caFile, "CERTIFICATE", ca.cert.Raw, 0o644)
	r := launchNitroRunner(t, bin, fake, append([]string{"-tls-client-ca", caFile}, args...)...)
	deadline := time.Now().Add(30 * time.Second)
	for {
		c, err := net.DialTimeout("tcp", r.addr[len("tcp:"):], time.Second)
		if err == nil {
			c.Close()
			return r
		}
		select {
		case <-r.done:
			log, _ := os.ReadFile(r.logPath)
			t.Fatalf("the runner exited (%v) before it listened:\n%s", *r.err, log)
		default:
		}
		if time.Now().After(deadline) {
			log, _ := os.ReadFile(r.logPath)
			t.Fatalf("the runner did not listen on %s:\n%s", r.addr, log)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func (r nitroRunner) log(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(r.logPath)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// tlsKeyHash reads the TLS key hash the runner logs at start.
func (r nitroRunner) tlsKeyHash(t *testing.T) string {
	t.Helper()
	m := regexp.MustCompile(`tls_key_sha256=([0-9a-f]{64})`).FindStringSubmatch(r.log(t))
	if m == nil {
		t.Fatalf("no tls_key_sha256 in the runner log:\n%s", r.log(t))
	}
	return m[1]
}

func TestE2ENitroRunner(t *testing.T) {
	bin := os.Getenv("RUNNER_AWS_DEBUG_BIN")
	if bin == "" {
		t.Skip("set RUNNER_AWS_DEBUG_BIN to the AWS debug runner (build/<arch>/bin/runner-aws-debugimport)")
	}
	ca := newTestCA(t)
	env := newNitroEnv(t)
	fake := newFakeNSM(t, env)
	r := startNitroRunner(t, bin, ca, fake)
	opts := []Option{withNitroRoots(env.ca.Root)}

	conn := func(r nitroRunner) Connection {
		cert, key := ca.issue(t, t.TempDir(), "client", time.Time{})
		return Connection{Address: r.addr, ClientCert: cert, ClientKey: key, Attestation: nitroGood()}
	}

	t.Run("channel binding passes end to end", func(t *testing.T) {
		c := conn(r)
		cl, err := c.New(append(opts, WithTimeout(10*time.Second))...)
		if err != nil {
			t.Fatal(err)
		}
		defer cl.Close()
		h, err := cl.Health(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if h.Platform != "nitro" {
			t.Fatalf("platform %q", h.Platform)
		}
		// The identity names the TLS key, the verifier accepted the document
		// that covers it, and the key is the one the runner made at start.
		nonce := []byte("a fresh nonce of 32 bytes.......")
		id, err := cl.Identity(ctx, nonce)
		if err != nil {
			t.Fatal(err)
		}
		if got := fmt.Sprintf("%x", id.TLSKeyHash); got != r.tlsKeyHash(t) {
			t.Fatalf("identity names TLS key %s, the runner logged %s", got, r.tlsKeyHash(t))
		}
		if err := cl.Verify(ctx, nonce, id); err != nil {
			t.Fatalf("the aws-nitro verifier refused the identity over the same channel: %v", err)
		}
		reqs := fake.requests()
		if len(reqs) < 2 {
			t.Fatalf("the fake NSM saw %d requests, want at least 2 (connect and identity)", len(reqs))
		}
		last := reqs[len(reqs)-1]
		if string(last.UserData) != string(backend.IdentityUserData(nonce, id)) {
			t.Fatal("the user data the runner sent to the NSM is not the hash of the identity with its TLS key")
		}
		t.Logf("aws-nitro verified an NSM-format document from the runner on the nitro platform; TLS key %s... bound in its user data", r.tlsKeyHash(t)[:12])
	})

	t.Run("pin from the runner log", func(t *testing.T) {
		c := conn(r)
		c.TLSKeyPin = r.tlsKeyHash(t)
		if err := health(t, c, opts...); err != nil {
			t.Fatalf("right pin: %v", err)
		}
		c.TLSKeyPin = strings.Repeat("00", 32)
		wantErr(t, health(t, c, opts...), "is not the pinned key")
	})

	t.Run("client certificate from another CA", func(t *testing.T) {
		c := conn(r)
		c.ClientCert, c.ClientKey = newTestCA(t).issue(t, t.TempDir(), "rogue", time.Time{})
		err := health(t, c, opts...)
		if err == nil || !regexp.MustCompile(`certificate required|unknown certificate authority|bad certificate`).MatchString(err.Error()) {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("plain connection gets no answer", func(t *testing.T) {
		c, err := net.DialTimeout("tcp", r.addr[len("tcp:"):], 3*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(5 * time.Second))
		c.Write([]byte{0, 0, 0, 6, 1, 1, 0, 0, 0, 1}) // HEALTH in the clear
		buf := make([]byte, 64)
		n, err := c.Read(buf)
		if err == nil || (n > 0 && buf[0] != 0x15) { // a TLS alert is fine
			t.Fatalf("plain HEALTH: %d bytes %x, %v", n, buf[:n], err)
		}
	})

	t.Run("pinned PCRs of another image", func(t *testing.T) {
		c := conn(r)
		c.Attestation.NitroPCRs["0"] = hexOf(testgen.PCRValue(0xee))
		if err := health(t, c, opts...); !errors.Is(err, attest.ErrMeasurement) {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("the AWS root is not the test root", func(t *testing.T) {
		// Without the test override the client trusts the AWS root only.
		err := health(t, conn(r))
		if !errors.Is(err, attest.ErrChain) {
			t.Fatalf("got %v", err)
		}
		wantErr(t, err, "not a pinned root")
	})

	// The NSM (and so the runner's hardware) hands out a document the
	// verifier must refuse.
	debug := testgen.DefaultPCRs()
	for _, i := range []uint64{0, 1, 2} {
		debug[i] = make([]byte, 48)
	}
	for _, tc := range []struct {
		name string
		spec nitroSpec
		want error
	}{
		{"debug-mode enclave, zero PCRs", nitroSpec{pcrs: debug}, attest.ErrDebug},
		{"bad signature", nitroSpec{flipSig: true}, attest.ErrSignature},
		{"signed under a CA the client does not trust", nitroSpec{ca: testgen.NewCA(t, time.Now())}, attest.ErrChain},
		{"document for another nonce", nitroSpec{nonce: []byte("another request's nonce")}, attest.ErrNonce},
		{"document for other user data (another TLS key)", nitroSpec{userData: []byte("another identity")}, attest.ErrUserData},
		{"timestamp in the future", nitroSpec{skew: time.Hour}, attest.ErrStale},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake.setSpec(tc.spec)
			defer fake.setSpec(nitroSpec{})
			if err := health(t, conn(r), opts...); !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
	// And back to good.
	if err := health(t, conn(r), opts...); err != nil {
		t.Fatalf("after the refusals: %v", err)
	}
}

func hexOf(b []byte) string { return fmt.Sprintf("%x", b) }

// subCA makes an intermediate CA under ca.
func (ca *testCA) subCA(t *testing.T, name string) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca.n++
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(ca.n + 1000), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-3 * time.Hour), NotAfter: time.Now().Add(12 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &testCA{cert: cert, key: key, pool: pool, n: 1}
}

// The image pins a root. The client certificates come from an intermediate
// under it, so the client file holds the leaf and then the intermediate.
// The runner accepts that file, refuses the leaf alone, and a second
// intermediate under the same root works against the same runner, which
// is the rotation without a new image.
func TestE2ENitroRunnerPinnedRootWithIntermediate(t *testing.T) {
	bin := os.Getenv("RUNNER_AWS_DEBUG_BIN")
	if bin == "" {
		t.Skip("set RUNNER_AWS_DEBUG_BIN to the AWS debug runner (build/<arch>/bin/runner-aws-debugimport)")
	}
	root := newTestCA(t)
	env := newNitroEnv(t)
	r := startNitroRunner(t, bin, root, newFakeNSM(t, env)) // the runner holds the root only
	opts := []Option{withNitroRoots(env.ca.Root)}
	chainFile := func(sub *testCA, withIntermediate bool) Connection {
		cert, key := sub.issue(t, t.TempDir(), "client", time.Time{})
		if withIntermediate {
			leaf, err := os.ReadFile(cert)
			if err != nil {
				t.Fatal(err)
			}
			inter := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: sub.cert.Raw})
			if err := os.WriteFile(cert, append(leaf, inter...), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		return Connection{Address: r.addr, ClientCert: cert, ClientKey: key, Attestation: nitroGood()}
	}
	int1 := root.subCA(t, "intermediate 1")
	if err := health(t, chainFile(int1, true), opts...); err != nil {
		t.Fatalf("leaf and intermediate 1: %v", err)
	}
	if err := health(t, chainFile(int1, false), opts...); err == nil {
		t.Fatal("a client file with the leaf alone was accepted")
	} else {
		t.Logf("leaf without the intermediate: refused: %v", err)
	}
	int2 := root.subCA(t, "intermediate 2")
	if err := health(t, chainFile(int2, true), opts...); err != nil {
		t.Fatalf("leaf and intermediate 2 against the same runner: %v", err)
	}
	if err := health(t, chainFile(newTestCA(t).subCA(t, "intermediate of another root"), true), opts...); err == nil {
		t.Fatal("an intermediate of another root was accepted")
	}
}

// The runner checks the validity dates of the client certificate against
// its own clock. The dev options of the debug build move that clock 2 h
// ahead, which plays a host that moves the system clock; a certificate that
// is valid for one hour is then expired. The same certificate works against
// a runner with the normal clock.
func TestE2ENitroRunnerClientCertificateClock(t *testing.T) {
	bin := os.Getenv("RUNNER_AWS_DEBUG_BIN")
	if bin == "" {
		t.Skip("set RUNNER_AWS_DEBUG_BIN to the AWS debug runner (build/<arch>/bin/runner-aws-debugimport)")
	}
	ca := newTestCA(t)
	env := newNitroEnv(t)
	fake := newFakeNSM(t, env)
	normal := startNitroRunner(t, bin, ca, fake)
	ahead := startNitroRunner(t, bin, ca, fake, "-platform-opt", "clock_offset=2h")
	cert, key := ca.issue(t, t.TempDir(), "short", time.Now().Add(time.Hour))
	conn := func(r nitroRunner) Connection {
		return Connection{Address: r.addr, ClientCert: cert, ClientKey: key, Attestation: nitroGood()}
	}
	opts := []Option{withNitroRoots(env.ca.Root)}
	if err := health(t, conn(normal), opts...); err != nil {
		t.Fatalf("runner with the normal clock: %v", err)
	}
	err := health(t, conn(ahead), opts...)
	wantErr(t, err, "expired certificate")
	t.Logf("client certificate valid for 1 h: accepted by a runner with the normal clock, refused by one whose clock is 2 h ahead: %v", err)
}

// The nitro platform does not start without a client CA, in the debug build
// as in the release build (TestE2ECloudFlagChecks in runner/e2e checks the
// release build).
func TestE2ENitroRunnerNeedsAClientCA(t *testing.T) {
	bin := os.Getenv("RUNNER_AWS_DEBUG_BIN")
	if bin == "" {
		t.Skip("set RUNNER_AWS_DEBUG_BIN to the AWS debug runner (build/<arch>/bin/runner-aws-debugimport)")
	}
	fake := newFakeNSM(t, newNitroEnv(t))
	r := launchNitroRunner(t, bin, fake)
	select {
	case <-r.done:
		var ee *exec.ExitError
		if !errors.As(*r.err, &ee) {
			t.Fatalf("the runner ended with %v, want an exit status", *r.err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("the runner did not stop")
	}
	if !strings.Contains(r.log(t), "-tls-client-ca") {
		t.Fatalf("the log does not name the missing flag:\n%s", r.log(t))
	}
	if c, err := net.DialTimeout("tcp", r.addr[len("tcp:"):], time.Second); err == nil {
		c.Close()
		t.Fatal("the runner listens without a client CA")
	}
}
