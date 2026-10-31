//go:build platform_aws && nts

package e2e

// The NTS clock of the Nitro runner, as the enclave image runs it
// (-nts-clock), on the AWS debug build: the nitro platform with its fake
// NSM (test_nsm_url), NTS-KE through the proxy routes and NTP through the
// UDP relay (cmd/udprelay), against four NTS test servers (runner/nts/
// ntstest) and three HTTPS-date servers. The proxy routes and the relay
// use TCP on loopback where the enclave uses vsock; the code paths in the
// runner are the enclave's (platform/nitro NetDial). Needs -tags
// platform_aws,nts and a runner-aws-debugimport built with the tag nts
// (scripts/build-runner.sh).

import (
	"context"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/lidofinance/tee-signer/trusted-time/nts/ntstest"
)

// rawNow is CLOCK_MONOTONIC_RAW, the runner's NTS local clock. The test
// servers run at its rate: the host's wall clock is slewed (timesyncd in
// WSL, about -44,000 ppm), and the runner's drift check would see that.
func rawNow() int64 {
	const clockMonotonicRaw = 4 // linux/time.h
	var ts syscall.Timespec
	if _, _, e := syscall.RawSyscall(syscall.SYS_CLOCK_GETTIME, clockMonotonicRaw, uintptr(unsafe.Pointer(&ts)), 0); e != 0 {
		panic(e)
	}
	return ts.Nano()
}

func udprelayBinary(t *testing.T) string {
	t.Helper()
	if p := os.Getenv("UDPRELAY_BIN"); p != "" {
		return p
	}
	p := filepath.Join(binDir, "udprelay")
	binMu.Lock()
	defer binMu.Unlock()
	if _, err := os.Stat(p); err != nil {
		if err := goBuild(p, "../../platform-aws/cmd/udprelay", "platform_aws"); err != nil {
			t.Fatalf("build udprelay: %v (or set UDPRELAY_BIN)", err)
		}
	}
	return p
}

func TestE2ENTSClockThroughRelay(t *testing.T) {
	bin := runnerBinary(t, "aws-debug")
	if out, err := runnerCmd(bin, "-nts-selftest").CombinedOutput(); err != nil {
		t.Fatalf("%s has no NTS library (build it with the tag nts): %v %s", bin, err, out)
	}
	dir := t.TempDir()
	raw0, start := rawNow(), time.Now()
	serverClock := func() time.Time { return start.Add(time.Duration(rawNow() - raw0)) }

	// Four operators. c's KE names its NTP server by name (the relay
	// resolves localhost), the others by address. d's NTP port is not on the
	// relay's allowlist, so d's queries are refused and the quorum is a, b, c.
	type op struct {
		name, host, ntpHost string
		ntp                 *ntstest.NTPServer
		ke                  *ntstest.KEServer
	}
	ops := []*op{{name: "a", ntpHost: "127.0.0.1"}, {name: "b", ntpHost: "127.0.0.1"}, {name: "c", ntpHost: "localhost"}, {name: "d", ntpHost: "127.0.0.1"}}
	var roots []byte
	var servers, routes, allowPorts []string
	for _, o := range ops {
		o.host = "nts-" + o.name + ".test"
		store := ntstest.NewStore()
		var err error
		if o.ntp, err = ntstest.StartNTP(store, ntstest.NTPOptions{Clock: serverClock}); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(o.ntp.Close)
		cert, ca, err := ntstest.CertificatePEM(o.host, start.Add(-time.Hour), start.Add(24*time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		if o.ke, err = ntstest.StartKE(cert, store, ntstest.KEOptions{NTPServer: o.ntpHost, NTPPort: o.ntp.Port}); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(o.ke.Close)
		roots = append(roots, ca...)
		servers = append(servers, o.name+"="+o.host)
		routes = append(routes, o.host+":4460=tcp:"+o.ke.Addr)
		if o.name != "d" {
			allowPorts = append(allowPorts, strconv.Itoa(int(o.ntp.Port)))
		}
	}
	rootsFile := filepath.Join(dir, "nts-roots.pem")
	if err := os.WriteFile(rootsFile, roots, 0o600); err != nil {
		t.Fatal(err)
	}

	// The coarse check: three HTTPS servers with a Date header, reached
	// through proxy routes as on Nitro.
	coarse, croutes, caFile := coarseServers(t, dir)
	routes = append(routes, croutes...)

	// The relay, the binary that runs on the parent.
	relayPort := freePort(t)
	relayLog := filepath.Join(dir, "udprelay.log")
	lf, err := os.Create(relayLog)
	if err != nil {
		t.Fatal(err)
	}
	relay := exec.Command(udprelayBinary(t), "-listen", fmt.Sprintf("tcp:127.0.0.1:%d", relayPort),
		"-allow-names", "localhost", "-allow-nets", "127.0.0.1/32", "-allow-ports", strings.Join(allowPorts, ","), "-debug")
	relay.Stdout, relay.Stderr = lf, lf
	if err := relay.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = relay.Process.Kill()
		_ = relay.Wait()
		lf.Close()
		if t.Failed() {
			b, _ := os.ReadFile(relayLog)
			t.Logf("---- udprelay log ----\n%s", b)
		}
	})
	for i := 0; ; i++ {
		c, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", relayPort))
		if err == nil {
			c.Close()
			break
		}
		if i > 100 {
			t.Fatalf("relay not listening: %v", err)
		}
		time.Sleep(50 * time.Millisecond)
	}

	t.Setenv("SSL_CERT_FILE", caFile)
	t.Setenv("RUNNER_NTS_TEST_SERVERS", strings.Join(servers, ","))
	t.Setenv("RUNNER_NTS_TEST_ROOTS", rootsFile)
	t.Setenv("RUNNER_NTS_STATUS_EVERY", "1s")
	t.Setenv("RUNNER_NTS_CLOCK", "")
	c := newChain(t)
	sock := filepath.Join(dir, "r.sock")
	args := []string{"-platform", "nitro", "-record", "none",
		"-platform-opt", "test_nsm_url=http://127.0.0.1:1/",
		"-platform-opt", "proxy=" + strings.Join(routes, ","),
		"-platform-opt", fmt.Sprintf("ntp_relay=tcp:127.0.0.1:%d", relayPort),
		"-nts-clock", "-nts-coarse-urls", strings.Join(coarse, ","), "-nts-wait", "30s"}

	r := newRunnerOn(t, bin, "runner-nts-nitro", c, "unix:"+sock, args...)
	r.start()
	cl := client(t, "unix:"+sock)
	h := waitReady(t, cl)
	if h.ClockSource != "nts(a,b,c,d)" || !h.ClockTrusted {
		t.Fatalf("clock %s trusted=%v", h.ClockSource, h.ClockTrusted)
	}
	if off := int64(h.ClockUnix) - serverClock().Unix(); off < -2 || off > 2 {
		t.Fatalf("runner clock %d s off the servers' clock", off)
	}
	// The status line: a, b, c in the quorum, the bound well under 100 ms.
	deadline := time.Now().Add(20 * time.Second)
	for !strings.Contains(r.logText(), "members=a,b,c ") {
		if time.Now().After(deadline) {
			t.Fatal("no status line with the quorum a, b, c")
		}
		time.Sleep(200 * time.Millisecond)
	}
	for _, o := range ops {
		if o.ke.Sessions.Load() < 1 {
			t.Errorf("%s: no NTS-KE through its proxy route", o.name)
		}
		got := o.ntp.Requests.Load()
		switch {
		case o.name == "d" && got != 0:
			t.Errorf("d: %d NTP requests passed the relay, whose allowlist lacks its port", got)
		case o.name != "d" && got < 1:
			t.Errorf("%s: no NTP request through the relay", o.name)
		}
	}
	h2, err := cl.Health(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// HEALTH carries the NTS state and the time in milliseconds.
	if n := h2.NTS; n == nil || !n.Quorum || strings.Join(n.Members, ",") != "a,b,c" || n.BoundNowMS <= 0 || n.BoundNowMS > 100 ||
		n.MaxBoundMS != 100 || n.CoarseDiffMS < -1000 || n.CoarseDiffMS > 2000 {
		t.Fatalf("health nts %+v", h2.NTS)
	}
	if h2.ClockUnixMS/1000 != h2.ClockUnix {
		t.Fatalf("clock_unix_ms %d and clock_unix %d differ", h2.ClockUnixMS, h2.ClockUnix)
	}
	rl, _ := os.ReadFile(relayLog)
	if !strings.Contains(string(rl), "destination refused") || !strings.Contains(string(rl), "dest=localhost:"+strconv.Itoa(int(ops[2].ntp.Port))) {
		t.Fatalf("relay log lacks the refusal of d or the session of c:\n%s", rl)
	}
	var status string
	for _, l := range strings.Split(r.logText(), "\n") {
		if strings.Contains(l, "nts: status") {
			status = l
		}
	}
	t.Logf("health: clock %s trusted=%v unix=%d; NTP requests a=%d b=%d c=%d d=%d", h2.ClockSource, h2.ClockTrusted, h2.ClockUnix,
		ops[0].ntp.Requests.Load(), ops[1].ntp.Requests.Load(), ops[2].ntp.Requests.Load(), ops[3].ntp.Requests.Load())
	t.Logf("last status line: %s", status)
}

// coarseServers starts three HTTPS-date servers on loopback and returns
// their URLs, their proxy routes and a roots file for SSL_CERT_FILE.
func coarseServers(t *testing.T, dir string) (urls, routes []string, caFile string) {
	t.Helper()
	var certPEM []byte
	for range 3 {
		s := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
		t.Cleanup(s.Close)
		urls = append(urls, s.URL+"/")
		hostport := strings.TrimPrefix(s.URL, "https://")
		routes = append(routes, hostport+"=tcp:"+hostport)
		certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.Certificate().Raw})
	}
	caFile = filepath.Join(dir, "https-roots.pem")
	if err := os.WriteFile(caFile, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	return urls, routes, caFile
}

// TestE2ENTSRelayInterop is the same path against the four public NTS
// operators: NTS-KE over TCP (where the enclave has vsock-proxy) and NTP
// through udprelay with its default allowlist. Network: TCP 4460 and UDP
// 123 and 4123 to those four only (the coarse check uses loopback servers).
// Runs only with NTS_INTEROP=1, for NTS_INTEROP_FOR (default 150s).
func TestE2ENTSRelayInterop(t *testing.T) {
	if os.Getenv("NTS_INTEROP") != "1" {
		t.Skip("set NTS_INTEROP=1 to run (network: the four public NTS operators)")
	}
	run := 150 * time.Second
	if s := os.Getenv("NTS_INTEROP_FOR"); s != "" {
		var err error
		if run, err = time.ParseDuration(s); err != nil {
			t.Fatal(err)
		}
	}
	bin := runnerBinary(t, "aws-debug")
	dir := t.TempDir()
	coarse, routes, caFile := coarseServers(t, dir)
	for _, h := range []string{"time.cloudflare.com", "nts.netnod.se", "ptbtime1.ptb.de", "ntppool1.time.nl"} {
		routes = append(routes, h+":4460=tcp:"+h+":4460")
	}
	relayPort := freePort(t)
	relayLog := filepath.Join(dir, "udprelay.log")
	lf, err := os.Create(relayLog)
	if err != nil {
		t.Fatal(err)
	}
	// The relay with its defaults: the four names, Netnod's block, 123 and 4123.
	relay := exec.Command(udprelayBinary(t), "-listen", fmt.Sprintf("tcp:127.0.0.1:%d", relayPort), "-debug", "-stats-every", "30s")
	relay.Stdout, relay.Stderr = lf, lf
	if err := relay.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = relay.Process.Signal(os.Interrupt)
		_ = relay.Wait()
		lf.Close()
		b, _ := os.ReadFile(relayLog)
		t.Logf("---- udprelay log ----\n%s", b)
	})
	time.Sleep(200 * time.Millisecond)
	t.Setenv("SSL_CERT_FILE", caFile)
	t.Setenv("RUNNER_NTS_STATUS_EVERY", "30s")
	t.Setenv("RUNNER_NTS_TEST_SERVERS", "")
	c := newChain(t)
	sock := filepath.Join(dir, "r.sock")
	r := newRunnerOn(t, bin, "runner-nts-interop", c, "unix:"+sock, "-platform", "nitro", "-record", "none",
		"-platform-opt", "test_nsm_url=http://127.0.0.1:1/",
		"-platform-opt", "proxy="+strings.Join(routes, ","),
		"-platform-opt", fmt.Sprintf("ntp_relay=tcp:127.0.0.1:%d", relayPort),
		"-nts-clock", "-nts-coarse-urls", strings.Join(coarse, ","))
	r.start()
	cl := client(t, "unix:"+sock)
	h := waitReady(t, cl)
	t.Logf("ready: clock %s trusted=%v", h.ClockSource, h.ClockTrusted)
	end := time.Now().Add(run)
	for time.Now().Before(end) {
		time.Sleep(10 * time.Second)
		h, err := cl.Health(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if !h.Ready || !h.ClockTrusted {
			t.Errorf("health: ready=%v trusted=%v", h.Ready, h.ClockTrusted)
		}
	}
	var lines []string
	for _, l := range strings.Split(r.logText(), "\n") {
		if strings.Contains(l, "nts: status") || strings.Contains(l, "nts: key exchange") || strings.Contains(l, "level=WARN") ||
			strings.Contains(l, "level=ERROR") {
			lines = append(lines, l)
		}
	}
	t.Logf("runner log, NTS lines:\n%s", strings.Join(lines, "\n"))
	last := ""
	for _, l := range lines {
		if strings.Contains(l, "nts: status") {
			last = l
		}
	}
	if !strings.Contains(last, "members=cloudflare,netnod,ptb,time.nl ") {
		t.Fatalf("the last status line lacks the quorum of all four: %s", last)
	}
}
