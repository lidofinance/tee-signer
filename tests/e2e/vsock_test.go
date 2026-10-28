//go:build platform_aws

package e2e

// The vsock tests. Only the AWS build has vsock (backend/transport/vsock.go),
// so they need -tags platform_aws, and they run on the AWS debug build with
// the dev platform too (RUNNER_AWS_DEBUG_BIN, tags platform_aws,platform_dev,
// debugimport): the dev build has no vsock. The runner code under test, the
// listener and the mutual TLS on it, is the same as in the Nitro enclave.

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mdlayher/vsock"

	"github.com/lidofinance/tee-signer/signer-core/core"
	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/remote"
)

// TestE2EVsock tries vsock loopback (CID 1). WSL2 kernels ship without
// CONFIG_VSOCKETS_LOOPBACK, so this usually skips there.
func TestE2EVsock(t *testing.T) {
	const port = 7199
	l, err := vsock.ListenContextID(1, port, nil)
	if err != nil {
		t.Skipf("vsock listen on CID 1 (loopback) failed: %v", err)
	}
	go func() {
		c, err := l.Accept()
		if err == nil {
			c.Close()
		}
	}()
	conn, err := vsock.Dial(1, port, nil)
	l.Close()
	if err != nil {
		t.Skipf("vsock dial to CID 1 failed: %v", err)
	}
	conn.Close()

	c := newChain(t)
	addr := "vsock:1:7198"
	r := newRunnerOn(t, runnerBinary(t, "aws-debug"), "runner-vsock", c, addr, "-allow-import")
	r.start()
	cl := client(t, addr)
	waitReady(t, cl)
	sk, _ := core.NewSecret()
	pk, _ := core.PubkeyOf(sk)
	if _, err := adminOf(cl).ImportShare(ctx, backend.ImportShareRequest{Pubkey: pk, Secret: sk, Index: 7}); err != nil {
		t.Fatal(err)
	}
	e := c.stableEpoch(t)
	c.waitEpoch(t, e+3)
	data := att(e+2, e+3, 1)
	sig, err := cl.Sign(ctx, c.req(pk, data))
	if err != nil {
		t.Fatal(err)
	}
	root, _ := c.cfg.SigningRoot(data)
	if !core.Verify(pk, root, sig) {
		t.Fatal("vsock signature")
	}
	t.Log("signed and verified over vsock loopback")
}

// TestE2EVsockTLS: a runner on vsock loopback serves mutual TLS
// only, directly and through the forwarder (TCP on the parent side), which
// holds no key. Skips without vsock loopback (the WSL2 kernel has none).
func TestE2EVsockTLS(t *testing.T) {
	const port = 7197
	probe, err := vsock.ListenContextID(1, port+1, nil)
	if err != nil {
		t.Skipf("vsock listen on CID 1 (loopback) failed: %v", err)
	}
	go func() {
		if c, err := probe.Accept(); err == nil {
			c.Close()
		}
	}()
	pc, err := vsock.Dial(1, port+1, nil)
	probe.Close()
	if err != nil {
		t.Skipf("vsock dial to CID 1 failed: %v", err)
	}
	pc.Close()

	c := newChain(t)
	dir := t.TempDir()
	caFile, goodCfg := testPKI(t, dir, "vsock")
	_, rogueCfg := testPKI(t, dir, "vsockrogue")
	vaddr := fmt.Sprintf("vsock:1:%d", port)
	r := newRunnerOn(t, runnerBinary(t, "aws-debug"), "runner-vsock-tls", c, vaddr, "-tls-client-ca", caFile)
	r.start()

	good, err := newTLSClient(vaddr, goodCfg, remote.DevVerifier, remote.WithTimeout(5*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer good.Close()
	waitReady(t, good)
	id := devIdentity(t, good)
	if len(id.TLSKeyHash) != 32 {
		t.Fatalf("identity over vsock names no TLS key: %x", id.TLSKeyHash)
	}

	refused := func(name string, opts ...remote.Option) {
		t.Helper()
		cl, err := remote.New(vaddr, append(opts, remote.WithTimeout(3*time.Second))...)
		if err != nil {
			t.Fatal(err)
		}
		defer cl.Close()
		if _, err := cl.Health(ctx); err == nil {
			t.Fatalf("%s: connected", name)
		} else {
			t.Logf("%s: refused: %v", name, err)
		}
	}
	refused("plain vsock, no TLS")
	refused("TLS without a client certificate", remote.WithTLS(&tls.Config{}, remote.DevVerifier))
	rogue := rogueCfg.Certificates[0]
	refused("client certificate from another CA", remote.WithTLS(&tls.Config{
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return &rogue, nil }}, remote.DevVerifier))

	// The parent's side: the forwarder from TCP into the enclave.
	taddr := fmt.Sprintf("tcp:127.0.0.1:%d", freePort(t))
	forwarderBin := filepath.Join(binDir, "forwarder")
	if err := goBuild(forwarderBin, "../../platform-aws/cmd/forwarder", "platform_aws"); err != nil {
		t.Fatal(err)
	}
	fwd := exec.Command(forwarderBin, "-listen", taddr, "-to", vaddr)
	if err := fwd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { fwd.Process.Kill(); fwd.Wait() })
	viaFwd, err := newTLSClient(taddr, goodCfg, remote.DevVerifier, remote.WithTimeout(5*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer viaFwd.Close()
	waitReady(t, viaFwd)
	if id2 := devIdentity(t, viaFwd); !bytes.Equal(id2.TLSKeyHash, id.TLSKeyHash) {
		t.Fatalf("the key behind the forwarder is %x, the runner's is %x", id2.TLSKeyHash, id.TLSKeyHash)
	}
	t.Logf("mutual TLS 1.3 over vsock loopback, direct and through the forwarder; key %x... in the identity", id.TLSKeyHash[:6])
}

// TestE2EVsockListenerIsTLS: the runner binds a vsock address
// (vsock:any, which works without loopback) and serves mutual TLS on it,
// with the TLS key in its log and so in its identity. No byte crosses
// vsock here, so this shows the listener setup only; TestE2EVsockTLS needs
// loopback for the rest.
func TestE2EVsockListenerIsTLS(t *testing.T) {
	c := newChain(t)
	caFile, _ := testPKI(t, t.TempDir(), "vsocklisten")
	r := newRunnerOn(t, runnerBinary(t, "aws-debug"), "runner-vsock-listen", c, "vsock:any:7186", "-tls-client-ca", caFile)
	r.start()
	deadline := time.Now().Add(20 * time.Second)
	for {
		log := r.logText()
		if strings.Contains(log, `addr=vsock:any:7186 tls="mutual, TLS 1.3"`) && strings.Contains(log, "tls_key_sha256=") {
			t.Log("runner listens on vsock:any:7186 with mutual TLS 1.3 and names its TLS key in the identity")
			return
		}
		if strings.Contains(log, "listen vsock") {
			t.Skipf("no vsock bind here: %s", strings.TrimSpace(log))
		}
		if time.Now().After(deadline) {
			t.Fatalf("no vsock listener with TLS in the runner log:\n%s", log)
		}
		time.Sleep(100 * time.Millisecond)
	}
}
