//go:build !verifierselect

package runnerclient

// End to end: the Azure debug runner (build/<arch>/bin/runner-azure-debugimport) with
// the azure platform, and this package's client with the azure-maa
// verifier. The runner does the attestation and the key release itself, so
// the test stands up what it talks to: a fake SEV-SNP report (the debug
// build's test_snp_hostdata option), a fake security context directory
// (UVM_SECURITY_CONTEXT_DIR, as hcsshim makes it), a fake metadata service
// for the managed identity token (test_imds_url), a fake MAA that checks
// the request it gets and mints synthetic tokens, and a fake Key Vault that
// checks the release request and wraps a real RSA key to the key in the MAA
// token. The runner trusts the two TLS fakes through SSL_CERT_FILE.
//
// It shows that what the runner binds into its IDENTITY (runtime data, user
// data, TLS key) is what the verifier recomputes, that the refusals hold
// against the real binary, that a refused key release stops the runner, and
// that the runner listens on its one port and nothing else (there is no
// sidecar in the group any more).
//
// Not covered, because it needs Azure: real SNP reports, a real MAA
// provider, real Key Vault answers and a real CCE policy hash. The debug
// build is used because the release build has no fake hardware option.
//
//	RUNNER_AZURE_DEBUG_BIN=build/x86_64/bin/runner-azure-debugimport go test -run TestE2EAzureRunner ./runnerclient

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
	"syscall"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/attestation-verify"
	"github.com/lidofinance/tee-signer/attestation-verify/internal/testgen"
	remoteadmin "github.com/lidofinance/tee-signer/signer-admin/remote/admin"
	"github.com/lidofinance/tee-signer/signer-protocol"
)

const (
	// debugFakeTCBM is the TCB version of the debug runner's fake report
	// (runner/platform/azure/hooks_debug.go, debugFakeTCB).
	debugFakeTCBM = "1c01000000000004"
	fakeVCEK      = "-----BEGIN CERTIFICATE-----\nVkNFSw==\n-----END CERTIFICATE-----\n"
	fakeCertChain = "-----BEGIN CERTIFICATE-----\nQVNL\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nQVJL\n-----END CERTIFICATE-----\n"
	fakeUVMInfo   = "cose-sign1 uvm reference info"
	fakeAADToken  = "aad-token-of-the-group-identity"
)

func b64u(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// azureFakes is everything the azure runner talks to.
type azureFakes struct {
	t        *testing.T
	env      *maaEnv
	spec     tokenSpec
	tlsKey   *rsa.PrivateKey
	tlsCert  *x509.Certificate
	certFile string // PEM of tlsCert, for SSL_CERT_FILE
	ctxDir   string // security context directory
	imds     *httptest.Server
	kv       *httptest.Server
	maa      *httptest.Server
	dek      *rsa.PrivateKey // the key Key Vault releases
	denyKV   bool            // Key Vault answers 403, as for an attestation outside the release policy
	// selfIssuer: the fake MAA is a provider of its own, as the real one
	// is: its tokens' issuer is its own address, and it serves its OpenID
	// configuration and key set (the main key set). The handover test uses
	// it, because a runner checks another runner's token against the key
	// set of its own maa_endpoint.
	selfIssuer bool

	mu       sync.Mutex
	released int
	attested int
}

func newAzureFakes(t *testing.T, env *maaEnv, spec tokenSpec) *azureFakes {
	t.Helper()
	f := &azureFakes{t: t, env: env, spec: spec, tlsKey: testgen.RSAKey(2)}
	dek, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f.dek = dek

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "azure fakes"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:        true, BasicConstraintsValid: true, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &f.tlsKey.PublicKey, f.tlsKey)
	if err != nil {
		t.Fatal(err)
	}
	if f.tlsCert, err = x509.ParseCertificate(der); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	f.certFile = filepath.Join(dir, "fakes.pem")
	writePEM(t, f.certFile, "CERTIFICATE", der, 0o644)

	// What hcsshim puts into the container: the security context directory.
	f.ctxDir = filepath.Join(dir, "security-context-e2e")
	if err := os.MkdirAll(f.ctxDir, 0o755); err != nil {
		t.Fatal(err)
	}
	thim, _ := json.Marshal(map[string]string{"vcekCert": fakeVCEK, "tcbm": debugFakeTCBM, "certificateChain": fakeCertChain, "cacheControl": "{}"})
	for name, content := range map[string]string{
		"reference-info-base64":  base64.StdEncoding.EncodeToString([]byte(fakeUVMInfo)),
		"host-amd-cert-base64":   base64.StdEncoding.EncodeToString(thim),
		"security-policy-base64": base64.StdEncoding.EncodeToString([]byte("package policy")),
	} {
		if err := os.WriteFile(filepath.Join(f.ctxDir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	f.imds = httptest.NewServer(http.HandlerFunc(f.serveIMDS))
	f.kv = f.startTLS(f.serveKeyVault)
	f.maa = f.startTLS(f.serveMAA)
	t.Cleanup(f.imds.Close)
	return f
}

func (f *azureFakes) startTLS(h http.HandlerFunc) *httptest.Server {
	srv := httptest.NewUnstartedServer(h)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{f.tlsCert.Raw}, PrivateKey: f.tlsKey}}}
	srv.StartTLS()
	f.t.Cleanup(srv.Close)
	return srv
}

func hostPort(srv *httptest.Server) string {
	return strings.TrimPrefix(strings.TrimPrefix(srv.URL, "https://"), "http://")
}

func (f *azureFakes) count() (released, attested int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.released, f.attested
}

// serveIMDS is the instance metadata service: a token for Key Vault.
func (f *azureFakes) serveIMDS(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if r.Method != http.MethodGet || r.Header.Get("Metadata") != "true" || q.Get("api-version") != "2018-02-01" ||
		q.Get("resource") != "https://vault.azure.net" {
		http.Error(w, "bad identity request "+r.URL.String(), http.StatusBadRequest)
		return
	}
	fmt.Fprintf(w, `{"access_token":%q,"expires_in":"28799","resource":"https://vault.azure.net/","token_type":"Bearer"}`, fakeAADToken)
}

// serveMAA is the attestation provider's SEV-SNP endpoint. It decodes the
// request as MAA does and mints the token the test's spec asks for, except
// that HOST_DATA comes from the report the runner sent, like the claim does.
func (f *azureFakes) serveMAA(w http.ResponseWriter, r *http.Request) {
	fail := func(format string, a ...any) { http.Error(w, fmt.Sprintf(format, a...), http.StatusBadRequest) }
	if f.selfIssuer && r.Method == http.MethodGet {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			fmt.Fprintf(w, `{"issuer":"https://%s","jwks_uri":"https://%s/certs"}`, r.Host, r.Host)
		case "/certs":
			w.Write(mainKeySet(f.t))
		default:
			http.NotFound(w, r)
		}
		return
	}
	if r.Method != http.MethodPost || r.URL.Path != "/attest/SevSnpVM" || r.URL.RawQuery != "api-version=2020-10-01" {
		fail("bad route %s %s", r.Method, r.URL)
		return
	}
	var req struct {
		Report      string
		RuntimeData struct{ Data, DataType string }
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.RuntimeData.DataType != "JSON" {
		fail("bad body: %v", err)
		return
	}
	dec := base64.URLEncoding.DecodeString
	runtime, err := dec(req.RuntimeData.Data)
	var obj map[string]any
	if err != nil || json.Unmarshal(runtime, &obj) != nil || obj == nil {
		fail("runtime data is not base64url of a JSON object")
		return
	}
	repJSON, err := dec(req.Report)
	if err != nil {
		fail("report: %v", err)
		return
	}
	var rep struct{ SnpReport, VcekCertChain, Endorsements string }
	if err := json.Unmarshal(repJSON, &rep); err != nil {
		fail("report: %v", err)
		return
	}
	report, e1 := dec(rep.SnpReport)
	chain, e2 := dec(rep.VcekCertChain)
	endJSON, e3 := dec(rep.Endorsements)
	var end struct{ Uvm []string }
	if e1 != nil || e2 != nil || e3 != nil || len(report) != 1184 || json.Unmarshal(endJSON, &end) != nil || len(end.Uvm) != 1 {
		fail("report parts do not decode")
		return
	}
	uvm, _ := dec(end.Uvm[0])
	sum := sha256.Sum256(runtime)
	if !bytes.Equal(report[80:112], sum[:]) || !bytes.Equal(report[112:144], make([]byte, 32)) {
		fail("report data is not SHA-256(runtime data) and zeros")
		return
	}
	if string(chain) != fakeVCEK+fakeCertChain || string(uvm) != fakeUVMInfo {
		fail("collateral is not the host's")
		return
	}
	if tcb := binary.LittleEndian.Uint64(report[384:]); fmt.Sprintf("%016x", tcb) != debugFakeTCBM {
		fail("TCB %x", tcb)
		return
	}
	s := f.env.defaults(f.spec)
	s.hostData = hex.EncodeToString(report[192:224])
	if f.selfIssuer {
		s.issuer = "https://" + r.Host
	}
	f.mu.Lock()
	f.attested++
	f.mu.Unlock()
	json.NewEncoder(w).Encode(map[string]string{"token": f.env.token(s, runtime)})
}

// serveKeyVault is Key Vault's release operation for the key signer-kek-1.
func (f *azureFakes) serveKeyVault(w http.ResponseWriter, r *http.Request) {
	reply := func(code int, msg string) {
		w.WriteHeader(code)
		fmt.Fprintf(w, `{"error":{"code":"Forbidden","message":%q}}`, msg)
	}
	if r.Method != http.MethodPost || r.URL.Path != "/keys/signer-kek-1/release" || r.URL.RawQuery != "api-version=7.4" {
		reply(404, "bad route "+r.Method+" "+r.URL.String())
		return
	}
	if r.Header.Get("Authorization") != "Bearer "+fakeAADToken {
		reply(401, "bad bearer token")
		return
	}
	if f.denyKV {
		reply(403, "the attestation does not satisfy the release policy of the key")
		return
	}
	var req struct{ Target string }
	body, _ := io.ReadAll(r.Body)
	if json.Unmarshal(body, &req) != nil {
		reply(400, "no target")
		return
	}
	parts := strings.Split(req.Target, ".")
	if len(parts) != 3 {
		reply(400, "target is not a JWT")
		return
	}
	raw, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var claims struct {
		Runtime struct {
			Keys []struct {
				Kty    string   `json:"kty"`
				N      string   `json:"n"`
				E      string   `json:"e"`
				Kid    string   `json:"kid"`
				KeyOps []string `json:"key_ops"`
			} `json:"keys"`
		} `json:"x-ms-runtime"`
	}
	if json.Unmarshal(raw, &claims) != nil || len(claims.Runtime.Keys) != 1 {
		reply(400, "x-ms-runtime.keys has no key")
		return
	}
	k := claims.Runtime.Keys[0]
	if k.Kty != "RSA" || len(k.KeyOps) != 1 || k.KeyOps[0] != "encrypt" || k.Kid == "" {
		reply(400, "x-ms-runtime.keys[0] is not an RSA encryption key with a kid")
		return
	}
	nb, _ := base64.RawURLEncoding.DecodeString(k.N)
	eb, _ := base64.RawURLEncoding.DecodeString(k.E)
	wrapTo := &rsa.PublicKey{N: new(big.Int).SetBytes(nb), E: int(new(big.Int).SetBytes(eb).Int64())}

	plain, _ := x509.MarshalPKCS8PrivateKey(f.dek)
	kek := make([]byte, 32)
	rand.Read(kek)
	rsaPart, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, wrapTo, kek, nil) // CKM_RSA_AES_KEY_WRAP
	if err != nil {
		reply(500, err.Error())
		return
	}
	block, _ := aes.NewCipher(kek)
	ct := append(rsaPart, kwpWrap(block, plain)...)
	hsm, _ := json.Marshal(map[string]any{"schema_version": "1.0", "header": map[string]any{"alg": "dir"}, "ciphertext": b64u(ct)})
	payload, _ := json.Marshal(map[string]any{
		"request": map[string]any{"api-version": "7.4", "enc": "CKM_RSA_AES_KEY_WRAP", "kid": "https://" + r.Host + "/keys/signer-kek-1/0123456789abcdef0123456789abcdef"},
		"response": map[string]any{"key": map[string]any{
			"key": map[string]any{"kty": "RSA-HSM", "key_ops": []string{"wrapKey", "unwrapKey"}, "key_hsm": b64u(hsm)},
		}},
	})
	hdr, _ := json.Marshal(map[string]any{"alg": "PS256", "x5c": []string{base64.StdEncoding.EncodeToString(f.tlsCert.Raw)}})
	signed := b64u(hdr) + "." + b64u(payload)
	digest := sha256.Sum256([]byte(signed))
	sig, err := rsa.SignPSS(rand.Reader, f.tlsKey, crypto.SHA256, digest[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
	if err != nil {
		reply(500, err.Error())
		return
	}
	f.mu.Lock()
	f.released++
	f.mu.Unlock()
	json.NewEncoder(w).Encode(map[string]string{"value": signed + "." + b64u(sig)})
}

// kwpWrap is AES key wrap with padding (RFC 5649), what Key Vault applies to
// the key before it goes to the target.
func kwpWrap(block interface {
	Encrypt(dst, src []byte)
}, p []byte) []byte {
	padded := append([]byte(nil), p...)
	for len(padded)%8 != 0 {
		padded = append(padded, 0)
	}
	a := []byte{0xA6, 0x59, 0x59, 0xA6, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(a[4:], uint32(len(p)))
	n := len(padded) / 8
	var buf [16]byte
	if n == 1 {
		copy(buf[:8], a)
		copy(buf[8:], padded)
		block.Encrypt(buf[:], buf[:])
		return buf[:]
	}
	for j := 0; j <= 5; j++ {
		for i := 1; i <= n; i++ {
			copy(buf[:8], a)
			copy(buf[8:], padded[(i-1)*8:i*8])
			block.Encrypt(buf[:], buf[:])
			binary.BigEndian.PutUint64(a, binary.BigEndian.Uint64(buf[:8])^uint64(n*j+i))
			copy(padded[(i-1)*8:i*8], buf[8:])
		}
	}
	return append(append([]byte(nil), a...), padded...)
}

type azureRunner struct {
	addr    string
	logPath string
	fakes   *azureFakes
	cmd     *exec.Cmd
	done    chan struct{} // closed when the process has ended
	err     *error        // its exit status, set before done is closed
}

// tlsKeyHash reads the TLS key hash the runner logs at start.
func (r azureRunner) tlsKeyHash(t *testing.T) string {
	t.Helper()
	log, err := os.ReadFile(r.logPath)
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`tls_key_sha256=([0-9a-f]{64})`).FindSubmatch(log)
	if m == nil {
		t.Fatalf("no tls_key_sha256 in the runner log:\n%s", log)
	}
	return string(m[1])
}

func freeAddr(t *testing.T) (listen string) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	return fmt.Sprintf("tcp:127.0.0.1:%d", port)
}

// launchAzureRunner starts the runner and returns without waiting for it to
// listen. extra flags come last and so win over the defaults.
func launchAzureRunner(t *testing.T, bin string, ca *testCA, fakes *azureFakes, extra ...string) azureRunner {
	t.Helper()
	dir := t.TempDir()
	caFile := filepath.Join(dir, "client-ca.pem")
	writePEM(t, caFile, "CERTIFICATE", ca.cert.Raw, 0o644)
	listen := freeAddr(t)
	hostData := fakes.spec.hostData
	if hostData == "" {
		hostData = goodHostData
	}
	logPath := filepath.Join(dir, "runner.log")
	logFile, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { logFile.Close() })
	args := []string{"-platform", "azure",
		"-platform-opt", "maa_endpoint=" + hostPort(fakes.maa), "-platform-opt", "akv_endpoint=" + hostPort(fakes.kv),
		"-platform-opt", "kid=signer-kek-1",
		"-platform-opt", "test_snp_hostdata=" + hostData, "-platform-opt", "test_imds_url=" + fakes.imds.URL + "/token",
		"-config", "../../governance/chains/chain.testnet.json", "-state-dir", filepath.Join(dir, "state"),
		"-listen", listen, "-tls-client-ca", caFile, "-record", "none"}
	cmd := exec.Command(bin, append(args, extra...)...)
	cmd.Env = append(os.Environ(), "UVM_SECURITY_CONTEXT_DIR="+fakes.ctxDir, "SSL_CERT_FILE="+fakes.certFile)
	cmd.Stdout, cmd.Stderr = logFile, logFile
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	r := azureRunner{addr: listen, logPath: logPath, fakes: fakes, cmd: cmd, done: make(chan struct{}), err: new(error)}
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

func startAzureRunner(t *testing.T, bin string, ca *testCA, env *maaEnv, spec tokenSpec) azureRunner {
	t.Helper()
	return waitListening(t, launchAzureRunner(t, bin, ca, newAzureFakes(t, env, spec)))
}

// waitListening waits until r accepts connections.
func waitListening(t *testing.T, r azureRunner) azureRunner {
	t.Helper()
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

// listeningPorts returns the TCP ports that the process with this pid
// listens on, from /proc.
func listeningPorts(t *testing.T, pid int) map[int]bool {
	t.Helper()
	fds, err := os.ReadDir(fmt.Sprintf("/proc/%d/fd", pid))
	if err != nil {
		t.Skipf("no /proc: %v", err)
	}
	inodes := map[string]bool{}
	for _, fd := range fds {
		if l, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/%s", pid, fd.Name())); err == nil && strings.HasPrefix(l, "socket:[") {
			inodes[strings.TrimSuffix(strings.TrimPrefix(l, "socket:["), "]")] = true
		}
	}
	ports := map[int]bool{}
	for _, f := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(b), "\n")[1:] {
			c := strings.Fields(line)
			if len(c) < 10 || c[3] != "0A" || !inodes[c[9]] { // 0A is LISTEN
				continue
			}
			_, p, _ := strings.Cut(c[1], ":")
			var port int
			fmt.Sscanf(p, "%X", &port)
			ports[port] = true
		}
	}
	return ports
}

func TestE2EAzureRunner(t *testing.T) {
	bin := os.Getenv("RUNNER_AZURE_DEBUG_BIN")
	if bin == "" {
		t.Skip("set RUNNER_AZURE_DEBUG_BIN to the Azure debug runner (build/<arch>/bin/runner-azure-debugimport)")
	}
	ca := newTestCA(t)
	env := newMAAEnv(t, mainKeySet(t))
	good := startAzureRunner(t, bin, ca, env, tokenSpec{})

	conn := func(r azureRunner) Connection {
		cert, key := ca.issue(t, t.TempDir(), "client", time.Time{})
		return Connection{Address: r.addr, ClientCert: cert, ClientKey: key,
			Attestation: Attestation{Verifier: VerifierAzureMAA, MAAHost: env.host, CCEPolicySHA256: goodHostData}}
	}
	opts := []Option{WithHTTPClient(env.srv.Client())}

	t.Run("runner and verifier agree", func(t *testing.T) {
		c := conn(good)
		cl, err := c.New(append(opts, WithTimeout(10*time.Second))...)
		if err != nil {
			t.Fatal(err)
		}
		defer cl.Close()
		h, err := cl.Health(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if h.Platform != "azure" {
			t.Fatalf("platform %q", h.Platform)
		}
		keys, err := cl.PublicKeys(ctx)
		if err != nil || len(keys) != 0 {
			t.Fatalf("public keys %v, %v", keys, err)
		}
		released, attested := good.fakes.count()
		if released != 1 || attested < 2 {
			t.Fatalf("Key Vault released %d times, MAA attested %d times (want 1 and at least 2: the key release and this identity)", released, attested)
		}
		t.Logf("identity verified (platform azure, report to MAA, key from Key Vault, all in the runner), health ok, %d keys", len(keys))
	})

	t.Run("nothing but the runner port listens", func(t *testing.T) {
		got := listeningPorts(t, good.cmd.Process.Pid)
		var want int
		fmt.Sscanf(good.addr[strings.LastIndex(good.addr, ":")+1:], "%d", &want)
		if len(got) != 1 || !got[want] {
			t.Fatalf("the runner listens on %v, want only %d", got, want)
		}
	})

	t.Run("pin from the runner log", func(t *testing.T) {
		c := conn(good)
		c.TLSKeyPin = good.tlsKeyHash(t)
		if err := health(t, c, opts...); err != nil {
			t.Fatalf("right pin: %v", err)
		}
		c.TLSKeyPin = strings.Repeat("00", 32)
		wantErr(t, health(t, c, opts...), "is not the pinned key")
	})

	t.Run("expected hash of another runner", func(t *testing.T) {
		c := conn(good)
		c.Attestation.CCEPolicySHA256 = strings.Repeat("ab", 32)
		if err := health(t, c, opts...); !errors.Is(err, attest.ErrMeasurement) {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("another provider host", func(t *testing.T) {
		// Same keys, other host: the token's issuer is not the one configured.
		other := newMAAEnv(t, mainKeySet(t))
		c := conn(good)
		c.Attestation.MAAHost = other.host
		if err := health(t, c, WithHTTPClient(other.srv.Client())); !errors.Is(err, attest.ErrIssuer) {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("compliance status of a confidential VM", func(t *testing.T) {
		c := conn(good)
		c.Attestation.ComplianceStatus = attest.ComplianceCVM
		if err := health(t, c, opts...); !errors.Is(err, attest.ErrClaim) {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("dev verifier does not accept an Azure runner", func(t *testing.T) {
		c := conn(good)
		c.Attestation = Attestation{Verifier: VerifierDev}
		wantErr(t, health(t, c), "is not the dev platform")
	})

	t.Run("client certificate from another CA", func(t *testing.T) {
		c := conn(good)
		c.ClientCert, c.ClientKey = newTestCA(t).issue(t, t.TempDir(), "rogue", time.Time{})
		err := health(t, c, opts...)
		if err == nil || !regexp.MustCompile(`certificate required|unknown certificate authority|bad certificate`).MatchString(err.Error()) {
			t.Fatalf("got %v", err)
		}
	})

	// The runner's MAA (and so its hardware) hands out a token the verifier
	// must refuse. A runner on hardware with another HOST_DATA gets a token
	// for another CCE policy; the other cases change the token itself.
	for _, tc := range []struct {
		name string
		spec tokenSpec
		want error
	}{
		{"token for another CCE policy", tokenSpec{hostData: strings.Repeat("22", 32)}, attest.ErrMeasurement},
		{"debuggable TEE", tokenSpec{debuggable: true}, attest.ErrDebug},
		{"bad signature", tokenSpec{flipSig: true}, attest.ErrSignature},
		{"signed by a key that is not the provider's", tokenSpec{key: testgen.RSAKey(1)}, attest.ErrSignature},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := startAzureRunner(t, bin, ca, env, tc.spec)
			if err := health(t, conn(r), opts...); !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}

// A refused key release stops the runner before it listens: Key Vault says
// no to an attestation outside the release policy, and the runner has no
// key to seal with.
func TestE2EAzureRunnerKeyReleaseRefused(t *testing.T) {
	bin := os.Getenv("RUNNER_AZURE_DEBUG_BIN")
	if bin == "" {
		t.Skip("set RUNNER_AZURE_DEBUG_BIN to the Azure debug runner (build/<arch>/bin/runner-azure-debugimport)")
	}
	fakes := newAzureFakes(t, newMAAEnv(t, mainKeySet(t)), tokenSpec{})
	fakes.denyKV = true
	r := launchAzureRunner(t, bin, newTestCA(t), fakes)
	select {
	case <-r.done:
		var ee *exec.ExitError
		if !errors.As(*r.err, &ee) {
			t.Fatalf("the runner ended with %v, want an exit status", *r.err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("the runner did not stop")
	}
	log, _ := os.ReadFile(r.logPath)
	if !strings.Contains(string(log), "release policy") {
		t.Fatalf("the log does not name the refusal:\n%s", log)
	}
	if c, err := net.DialTimeout("tcp", r.addr[len("tcp:"):], time.Second); err == nil {
		c.Close()
		t.Fatal("the runner listens although the key release failed")
	}
}

// fastChain writes a chain config with 2-second epochs (1-second slots, 2
// per epoch) whose genesis was 1000 epochs ago, so a test sees several
// epochs. It returns the file and the genesis time.
func fastChain(t *testing.T) (string, uint64) {
	t.Helper()
	genesis := uint64(time.Now().Unix()) - 2000
	cfg := fmt.Sprintf(`{"genesis_validators_root":"0x%s","genesis_fork_version":"0x00000001","voluntary_exit_fork_version":"0x03000001",
"genesis_time":%d,"seconds_per_slot":1,"slots_per_epoch":2,"max_epochs_ahead":1,"exit_allowlist":[7],
"fee_recipients":["0x1111111111111111111111111111111111111111"],"gas_limit_min":30000000,"gas_limit_max":60000000,
"registration_max_future_seconds":3600,"commit_ahead":{"block_slots":32,"source_epochs":1,"target_epochs":1}}`,
		strings.Repeat("ab", 32), genesis)
	p := filepath.Join(t.TempDir(), "chain.json")
	if err := os.WriteFile(p, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	return p, genesis
}

// fastChainAttester is the attester domain of fastChain, which has one fork
// version: what a client sends with each vote.
func fastChainAttester() backend.Root {
	var gvr backend.Root
	for i := range gvr {
		gvr[i] = 0xab
	}
	return backend.ComputeDomain(backend.DomainBeaconAttester, backend.Version{0, 0, 0, 1}, gvr)
}

// A BLS key for the lost-state test (made with backend/core, which this
// module does not link): secret and public key.
const (
	lostStateSecret = "70a0039da91e3c6d9993cfa2f2f446ee1747b47ebd247b03f36afabecb23beef"
	lostStatePubkey = "8660b06e9d12df741dc0f6be8ebe8bf97ce92cdba1ac9ac9d2f08e97dea469860ada4ea0af104f015b74e4e6b3c9b364"
)

// A restart with lost local state on the Azure path: the runner releases
// the Key Vault key again, derives the same key wrapping key from it and
// reads its mark log (a file log here; the WORM fakes of the three stores
// run in runner/e2e and runner/markstore). Its share is gone with the
// state; after a sealed import it continues from the newest mark: a vote
// with a source below the log's is refused. The import carries no history,
// so it sets the share's own source floor at the import: the first honest
// vote is refused below it, and each one at or above it signs. A group
// whose Key Vault key is another one (a new key version) does not open the
// records' keys and does not start.
func TestE2EAzureRunnerMarkLogLostState(t *testing.T) {
	bin := os.Getenv("RUNNER_AZURE_DEBUG_BIN")
	if bin == "" {
		t.Skip("set RUNNER_AZURE_DEBUG_BIN to the Azure debug runner (build/<arch>/bin/runner-azure-debugimport)")
	}
	ca := newTestCA(t)
	env := newMAAEnv(t, mainKeySet(t))
	fakes := newAzureFakes(t, env, tokenSpec{})
	chain, genesis := fastChain(t)
	logDir := t.TempDir()
	state := filepath.Join(t.TempDir(), "state")
	flags := []string{"-config", chain, "-state-dir", state, "-mark-store", "file:" + logDir, "-mark-signer", "signer-1"}

	var sk [32]byte
	var pk backend.Pubkey
	hex.Decode(sk[:], []byte(lostStateSecret))
	hex.Decode(pk[:], []byte(lostStatePubkey))
	epochNow := func() uint64 { return (uint64(time.Now().Unix()) - genesis) / 2 }
	waitEpoch := func(e uint64) {
		for {
			now := time.Now()
			if epochNow() >= e && now.Nanosecond() > 300e6 && now.Nanosecond() < 800e6 {
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
	stableEpoch := func() uint64 {
		for {
			now := time.Now()
			if (uint64(now.Unix())-genesis)%2 == 0 && now.Nanosecond() > 200e6 && now.Nanosecond() < 700e6 {
				return epochNow()
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
	vote := func(source, target uint64, tag byte) *backend.AttestationData {
		return &backend.AttestationData{Slot: target * 2, BeaconBlockRoot: backend.Root{tag},
			Source: backend.Checkpoint{Epoch: source, Root: backend.Root{0x51}},
			Target: backend.Checkpoint{Epoch: target, Root: backend.Root{0x52}}}
	}
	// dial with admin set uses an admin certificate, for the import
	// (docs/protocol.md, "Client roles").
	dial := func(r azureRunner, admin bool) *Client {
		cert, key := ca.issue(t, t.TempDir(), "client", time.Time{})
		if admin {
			cert, key = ca.issueAdmin(t, t.TempDir(), "admin")
		}
		c := Connection{Address: r.addr, ClientCert: cert, ClientKey: key,
			Attestation: Attestation{Verifier: VerifierAzureMAA, MAAHost: env.host, CCEPolicySHA256: goodHostData}}
		cl, err := c.New(WithHTTPClient(env.srv.Client()), WithTimeout(10*time.Second))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { cl.Close() })
		return cl
	}
	connect := func(r azureRunner) *Client { return dial(r, false) }
	load := func(r azureRunner, cl *Client) {
		if _, err := remoteadmin.Wrap(dial(r, true).Client).ImportShareSealed(ctx, backend.ImportShareRequest{Pubkey: pk, Secret: sk, Index: 7}, pk, cl.Verify); err != nil {
			t.Fatal(err)
		}
	}
	sign := func(cl *Client, m backend.Message) error {
		_, err := cl.Sign(ctx, backend.SignRequest{Pubkey: pk, Message: m, Domain: fastChainAttester()})
		return err
	}
	stop := func(r azureRunner) {
		r.cmd.Process.Signal(syscall.SIGTERM)
		select {
		case <-r.done:
		case <-time.After(10 * time.Second):
			t.Fatal("the runner did not stop")
		}
	}

	r := waitListening(t, launchAzureRunner(t, bin, ca, fakes, flags...))
	cl := connect(r)
	load(r, cl)
	e0 := stableEpoch() + 3
	s0 := e0 - 1
	var last uint64
	for e := e0; e < e0+3; e++ {
		waitEpoch(e)
		if err := sign(cl, vote(s0, e, 0x10)); err != nil {
			t.Fatalf("before the restart, target %d: %v", e, err)
		}
		last = e
	}
	stop(r)
	if err := os.RemoveAll(state); err != nil {
		t.Fatal(err)
	}

	r = waitListening(t, launchAzureRunner(t, bin, ca, fakes, flags...))
	cl = connect(r)
	h, err := cl.Health(ctx)
	if err != nil || h.Validators != 0 {
		t.Fatalf("after the state was wiped: %+v %v", h, err)
	}
	// The newest record holds the last target signed, or the next epoch if
	// the raise at three quarters of the epoch ran before the stop.
	log, _ := os.ReadFile(r.logPath)
	m := regexp.MustCompile(`mark log: newest record.* target=(\d+)`).FindSubmatch(log)
	var nt uint64
	if m != nil {
		fmt.Sscanf(string(m[1]), "%d", &nt)
	}
	if nt != last && nt != last+1 {
		t.Fatalf("the restarted runner read target %d, want the newest record (target %d or %d):\n%s", nt, last, last+1, log)
	}
	released, _ := fakes.count()
	t.Logf("state wiped: Key Vault released the key %d times in all, the log was read, health %q", released, h.Record)
	load(r, cl)
	start := stableEpoch()
	lower, signed, belowFloor := 0, 0, 0
	var floor uint64
	for e := start; e < start+6; e++ {
		waitEpoch(e)
		errL := sign(cl, vote(s0-2, e, 0x30))
		// An honest node's source: s0, or the epoch before the target.
		ns := max(s0, e-1)
		errN := sign(cl, vote(ns, e, 0x20))
		t.Logf("after the restart, target %d: source %d (below the log's): %v | source %d: %v", e, s0-2, errL, ns, errN)
		if errL == nil {
			lower++
		}
		f, isFloor := sourceFloorRefusal(errN)
		switch {
		case isFloor && ns >= f:
			t.Fatalf("target %d: source %d refused below the source floor %d", e, ns, f)
		case isFloor:
			floor = f
			belowFloor++
		case e == start:
			t.Fatalf("target %d, right after the import without history: source %d: %v, want a refusal below the source floor", e, ns, errN)
		case errN != nil:
			t.Fatalf("target %d: source %d at or above the source floor %d: %v", e, ns, floor, errN)
		default:
			signed++
		}
	}
	if lower != 0 || signed == 0 {
		t.Fatalf("after the restart: %d votes with a lower source signed, %d with an honest source", lower, signed)
	}
	t.Logf("after the restart: %d votes refused below the source floor %d, %d signed", belowFloor, floor, signed)
	stop(r)

	// Another Key Vault key (newAzureFakes makes a new one): another
	// wrapping key, the records' keys do not open, the runner stops.
	other := launchAzureRunner(t, bin, ca, newAzureFakes(t, env, tokenSpec{}),
		append(flags[:len(flags):len(flags)], "-state-dir", filepath.Join(t.TempDir(), "state"))...)
	select {
	case <-other.done:
	case <-time.After(30 * time.Second):
		t.Fatal("the runner with another Key Vault key did not stop")
	}
	olog, _ := os.ReadFile(other.logPath)
	if !strings.Contains(string(olog), "none is a valid record") {
		t.Fatalf("the runner with another Key Vault key:\n%s", olog)
	}
	t.Logf("another Key Vault key: refused to start")
}

var floorRE = regexp.MustCompile(`below the source floor epoch (\d+)`)

// sourceFloorRefusal returns the floor epoch if err refuses a vote whose
// source is below a validator's source floor.
func sourceFloorRefusal(err error) (uint64, bool) {
	var r *backend.RefusedError
	if !errors.As(err, &r) || r.Code != backend.StatusSlashSource {
		return 0, false
	}
	m := floorRE.FindStringSubmatch(r.Detail)
	if m == nil {
		return 0, false
	}
	var f uint64
	fmt.Sscanf(m[1], "%d", &f)
	return f, true
}
