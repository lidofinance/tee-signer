package e2e

// End-to-end tests for the cloud task round: sealed share import, mutual
// TLS bound to the attested identity, the clone guard with two runner
// processes from one sealed state, and the start-up refusals of cloud
// images.

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/signer-core/core"
	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/remote"
	"github.com/lidofinance/tee-signer/signer-protocol/sealedimport"
)

func devIdentity(t *testing.T, c *remote.Client) *backend.Identity {
	t.Helper()
	nonce := make([]byte, 32)
	rand.Read(nonce)
	id, err := c.Identity(ctx, nonce)
	if err != nil {
		t.Fatal(err)
	}
	if err := remote.DevVerifier(ctx, nonce, id); err != nil {
		t.Fatal(err)
	}
	return id
}

// TestE2ESealedImport: a release runner (as in the cloud images) answers
// plaintext IMPORT_SHARE as an unknown message type and takes shares
// sealed to its attested per-boot key. A share sealed for another runner,
// or with a changed header, is refused. The dealer tool reads the share
// from a file.
func TestE2ESealedImport(t *testing.T) {
	c := newChain(t)
	addrA := fmt.Sprintf("tcp:127.0.0.1:%d", freePort(t))
	addrB := fmt.Sprintf("tcp:127.0.0.1:%d", freePort(t))
	a := newRunnerArgs(t, "runner-a", c, addrA)
	b := newRunnerArgs(t, "runner-b", c, addrB)
	a.start()
	b.start()
	ca, cb := client(t, addrA), client(t, addrB)
	waitReady(t, ca)
	waitReady(t, cb)

	sk, _ := core.NewSecret()
	pk, _ := core.PubkeyOf(sk)
	shares, _ := core.Split(sk, 3, 5)
	share := shares[0].Secret
	sharePk, _ := core.PubkeyOf(share)

	_, err := adminOf(ca).ImportShare(ctx, backend.ImportShareRequest{Pubkey: pk, Secret: share, Index: 9})
	wantRefused(t, err, backend.StatusUnsupported)
	if !strings.Contains(err.Error(), "message type IMPORT_SHARE") {
		t.Fatalf("release runner should answer IMPORT_SHARE as an unknown type: %v", err)
	}
	t.Logf("plaintext IMPORT_SHARE refused by the release build: %v", err)

	idA, idB := devIdentity(t, ca), devIdentity(t, cb)
	t.Logf("runner-a identity: HPKE suite kem=%#04x kdf=%#04x aead=%#04x, import key %d bytes, attestation %s/%s",
		idA.ImportKEM, idA.ImportKDF, idA.ImportAEAD, len(idA.ImportKey), idA.Attestation.Platform, idA.Attestation.Format)
	if bytes.Equal(idA.ImportKey, idB.ImportKey) {
		t.Fatal("two runners have the same import key")
	}

	// Sealed for runner-b, sent to runner-a (a replay to another instance).
	req := &backend.SealedImportRequest{Pubkey: pk, SharePubkey: sharePk, Index: 9}
	if req.Sealed, err = sealedimport.Seal(idB, req, &share); err != nil {
		t.Fatal(err)
	}
	_, err = adminOf(ca).ImportSealed(ctx, req)
	wantRefused(t, err, backend.StatusBadKey)
	t.Logf("share sealed for runner-b, sent to runner-a: refused: %v", err)

	// Sealed for runner-a, index changed in transit.
	if req.Sealed, err = sealedimport.Seal(idA, req, &share); err != nil {
		t.Fatal(err)
	}
	moved := *req
	moved.Index = 10
	_, err = adminOf(ca).ImportSealed(ctx, &moved)
	wantRefused(t, err, backend.StatusBadKey)
	t.Logf("validator index changed in transit: refused: %v", err)

	// Right key, wrong share_pubkey claim.
	wrong := &backend.SealedImportRequest{Pubkey: pk, SharePubkey: pk, Index: 9}
	if wrong.Sealed, err = sealedimport.Seal(idA, wrong, &share); err != nil {
		t.Fatal(err)
	}
	_, err = adminOf(ca).ImportSealed(ctx, wrong)
	wantRefused(t, err, backend.StatusBadKey)

	// The dealer tool, share in a 0600 file.
	shareFile := filepath.Join(t.TempDir(), "share.hex")
	if err := os.WriteFile(shareFile, []byte(hex.EncodeToString(share[:])), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(shareImportBin, "-addr", addrA, "-pubkey", pk.String(), "-index", "9",
		"-share-file", shareFile, "-verifier", "dev")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("share-import: %v\n%s", err, out)
	}
	t.Logf("share-import: %s", strings.TrimSpace(string(out)))
	if strings.Contains(strings.Join(cmd.Args, " "), hex.EncodeToString(share[:])) {
		t.Fatal("share on the command line")
	}

	e := c.stableEpoch(t)
	c.waitEpoch(t, e+3)
	data := att(e+2, e+3, 0x5e)
	sig, err := ca.Sign(ctx, c.req(pk, data))
	if err != nil {
		t.Fatal(err)
	}
	root, _ := c.cfg.SigningRoot(data)
	if !core.Verify(sharePk, root, sig) {
		t.Fatal("signature of the sealed-imported share does not verify")
	}
	t.Logf("epoch %d: runner-a signed with the sealed-imported share; partial verifies under the share key", e+3)

	// After a restart the share loads from the platform-sealed store, and
	// the import key is new.
	a.stop()
	ca.Close()
	a.start()
	if h := waitReady(t, ca); h.Validators != 1 {
		t.Fatalf("after restart: %d validators", h.Validators)
	}
	if idA2 := devIdentity(t, ca); bytes.Equal(idA2.ImportKey, idA.ImportKey) {
		t.Fatal("import key survived a restart")
	}
	for _, needle := range []string{hex.EncodeToString(share[:]), strings.ToUpper(hex.EncodeToString(share[:]))} {
		if strings.Contains(a.logText(), needle) {
			t.Fatal("share in the runner log")
		}
	}
	t.Logf("restart: share reloaded from sealed storage, new import key; share hex not in the runner log")
}

// testPKI makes a CA and a client certificate in dir and returns the CA
// file and a tls.Config carrying the client certificate.
func testPKI(t *testing.T, dir, name string) (string, *tls.Config) {
	return testPKIValid(t, dir, name, 24*time.Hour, 24*time.Hour)
}

// testPKIValid is testPKI with the time the CA and the client certificate
// stay valid from now. The configuration is the signing leaf of rolePKI;
// its admin twin serves the admin calls (roles_test.go).
func testPKIValid(t *testing.T, dir, name string, caFor, clientFor time.Duration) (string, *tls.Config) {
	t.Helper()
	r := rolePKI(t, dir, name, caFor, clientFor)
	return r.caFile, r.signing
}

// mitmProxy terminates TLS with its own certificate and opens its own
// mutual-TLS session to the runner with a valid client certificate,
// relaying bytes both ways: what a host that holds a client certificate
// could try.
func mitmProxy(t *testing.T, upstream string, cliCfg *tls.Config) string {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "mitm"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	l, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			in, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer in.Close()
				cfg := cliCfg.Clone()
				cfg.InsecureSkipVerify = true
				out, err := tls.Dial("tcp", strings.TrimPrefix(upstream, "tcp:"), cfg)
				if err != nil {
					return
				}
				defer out.Close()
				go io.Copy(out, in)
				io.Copy(in, out)
			}()
		}
	}()
	return "tcp:" + l.Addr().String()
}

// TestE2EMutualTLS: a runner with -tls-client-ca accepts only clients with
// a certificate from that CA, and clients accept only a runner whose TLS
// key is the one its attested identity names.
func TestE2EMutualTLS(t *testing.T) {
	c := newChain(t)
	dir := t.TempDir()
	caFile, goodCfg := testPKI(t, dir, "good")
	_, rogueCfg := testPKI(t, dir, "rogue")
	addr := fmt.Sprintf("tcp:127.0.0.1:%d", freePort(t))
	r := newRunnerArgs(t, "runner-tls", c, addr, "-tls-client-ca", caFile)
	r.start()

	good, err := newTLSClient(addr, goodCfg, remote.DevVerifier, remote.WithTimeout(5*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer good.Close()
	h := waitReady(t, good)
	t.Logf("TLS 1.3 with a client certificate from the pinned CA, runner key bound to the attested identity: health ok (%s)", h.Platform)

	try := func(name string, opts ...remote.Option) error {
		cl, err := remote.New(addr, append(opts, remote.WithTimeout(3*time.Second))...)
		if err != nil {
			return err
		}
		defer cl.Close()
		_, err = cl.Health(ctx)
		if err == nil {
			t.Fatalf("%s: connected", name)
		}
		t.Logf("%s: refused: %v", name, err)
		return err
	}
	try("plain TCP, no TLS")
	try("TLS without a client certificate", remote.WithTLS(&tls.Config{}, remote.DevVerifier))
	// remote.WithTLS always asks for TLS 1.3, so try TLS 1.2 by hand, with a
	// good client certificate.
	tls12 := goodCfg.Clone()
	tls12.InsecureSkipVerify, tls12.MinVersion, tls12.MaxVersion = true, tls.VersionTLS12, tls.VersionTLS12
	if c, err := tls.Dial("tcp", strings.TrimPrefix(addr, "tcp:"), tls12); err == nil {
		c.Close()
		t.Fatal("TLS 1.2 accepted")
	} else {
		t.Logf("TLS 1.2 with a good client certificate: refused: %v", err)
	}
	// Go's client withholds a certificate the runner's CA list does not
	// name, so force it to present the rogue one.
	rogue := rogueCfg.Certificates[0]
	forced := &tls.Config{GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return &rogue, nil }}
	if err := try("client certificate from another CA", remote.WithTLS(forced, remote.DevVerifier)); !strings.Contains(err.Error(), "unknown certificate authority") {
		t.Fatalf("want the runner to reject the CA, got %v", err)
	}
	if err := try("pinned to another key", remote.WithTLS(goodCfg, nil), remote.WithTLSKeyPin(make([]byte, 32))); !strings.Contains(err.Error(), "pinned") {
		t.Fatalf("want a pin mismatch, got %v", err)
	}
	mitm := mitmProxy(t, addr, goodCfg)
	cl, _ := newTLSClient(mitm, goodCfg, remote.DevVerifier, remote.WithTimeout(3*time.Second))
	_, err = cl.Health(ctx)
	cl.Close()
	if err == nil || !strings.Contains(err.Error(), "attested identity names") {
		t.Fatalf("relay with its own certificate: want an identity mismatch, got %v", err)
	}
	t.Logf("relay that terminates TLS with its own key (and holds a valid client certificate): refused: %v", err)

	// The right pin works without a verifier; then sign over the channel.
	id := devIdentity(t, good)
	pinned, _ := newTLSClient(addr, goodCfg, nil, remote.WithTLSKeyPin(id.TLSKeyHash))
	defer pinned.Close()
	sk, _ := core.NewSecret()
	pk, _ := core.PubkeyOf(sk)
	if _, err := adminOf(pinned).ImportShareSealed(ctx, backend.ImportShareRequest{Pubkey: pk, Secret: sk, Index: 7}, pk, remote.DevVerifier); err != nil {
		t.Fatal(err)
	}
	e := c.stableEpoch(t)
	c.waitEpoch(t, e+3)
	data := att(e+2, e+3, 0x71)
	sig, err := good.Sign(ctx, c.req(pk, data))
	if err != nil {
		t.Fatal(err)
	}
	root, _ := c.cfg.SigningRoot(data)
	if !core.Verify(pk, root, sig) {
		t.Fatal("signature over TLS")
	}
	t.Logf("sealed import and signing over mutual TLS (key pin %x...): signature verifies", id.TLSKeyHash[:6])
}

// TestE2EClientCertificateUsesTheRunnerClock: the runner checks the validity
// dates of the client certificate against its own clock. The dev platform
// plays a host that moves the clock (clock_offset); the platform clock is
// the one the runner trusts for this. A certificate that is valid for the
// test is expired for a runner whose clock runs 2 h ahead, and the same
// certificate works against a runner with the normal clock.
func TestE2EClientCertificateUsesTheRunnerClock(t *testing.T) {
	c := newChain(t)
	caFile, cfg := testPKIValid(t, t.TempDir(), "clock", 10*365*24*time.Hour, time.Hour)
	start := func(name string, extra ...string) *remote.Client {
		addr := fmt.Sprintf("tcp:127.0.0.1:%d", freePort(t))
		r := newRunnerArgs(t, name, c, addr, append([]string{"-tls-client-ca", caFile}, extra...)...)
		r.start()
		cl, err := newTLSClient(addr, cfg, remote.DevVerifier, remote.WithTimeout(3*time.Second))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { cl.Close() })
		return cl
	}
	waitReady(t, start("runner-clock-normal"))

	ahead := start("runner-clock-ahead", "-platform-opt", "clock_offset=2h")
	deadline := time.Now().Add(20 * time.Second)
	for {
		_, err := ahead.Health(ctx)
		if err != nil && strings.Contains(err.Error(), "expired certificate") {
			t.Logf("client certificate valid for 1 h: accepted by a runner with the normal clock, refused by one 2 h ahead: %v", err)
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("runner clock 2 h ahead: want the client certificate refused as expired, got %v", err)
		}
		time.Sleep(100 * time.Millisecond) // the runner may not listen yet
	}
}

// TestE2ECloneSharedRecord: two runner processes from one binary and one
// sealed state (a copy of the first runner's state directory, as a host
// would feed both enclaves the same sealed blob) share one record. The host
// asks each for a different vote in every epoch. Without the record both
// sign; with it at most one signs per target, and the first runner refuses
// once the second has claimed the record.
func TestE2ECloneSharedRecord(t *testing.T) {
	c := newChain(t)
	sk, _ := core.NewSecret()
	pk, _ := core.PubkeyOf(sk)

	type result struct{ aSigned, bSigned, doubles int }
	run := func(name string, guard []string) (result, *runner) {
		addrA := fmt.Sprintf("tcp:127.0.0.1:%d", freePort(t))
		addrB := fmt.Sprintf("tcp:127.0.0.1:%d", freePort(t))
		a := newRunner(t, name+"-a", c, addrA, guard...)
		a.start()
		ca := client(t, addrA)
		waitReady(t, ca)
		if _, err := adminOf(ca).ImportShare(ctx, backend.ImportShareRequest{Pubkey: pk, Secret: sk, Index: 7}); err != nil {
			t.Fatal(err)
		}
		e0 := c.stableEpoch(t)
		c.waitEpoch(t, e0+3)
		if _, err := ca.Sign(ctx, c.req(pk, att(e0+2, e0+3, 0xa0))); err != nil {
			t.Fatal(err)
		}
		// The clone: same binary, same flags, a copy of a's sealed state.
		b := newRunner(t, name+"-b", c, addrB, guard...)
		if out, err := exec.Command("cp", "-a", a.stateDir, b.stateDir).CombinedOutput(); err != nil {
			t.Fatalf("copy state: %v %s", err, out)
		}
		b.start()
		cb := client(t, addrB)
		if h := waitReady(t, cb); h.Validators != 1 {
			t.Fatalf("clone loaded %d validators", h.Validators)
		}
		var res result
		start := c.stableEpoch(t)
		for e := start; e < start+6; e++ {
			c.waitEpoch(t, e)
			first, second := ca, cb
			if e%2 == 1 {
				first, second = cb, ca
			}
			_, e1 := first.Sign(ctx, c.req(pk, att(e-1, e, byte(0xa0+e%2))))
			_, e2 := second.Sign(ctx, c.req(pk, att(e-1, e, byte(0xb0+e%2))))
			errA, errB := e1, e2
			if first == cb {
				errA, errB = e2, e1
			}
			if errA == nil {
				res.aSigned++
			}
			if errB == nil {
				res.bSigned++
			}
			if errA == nil && errB == nil {
				res.doubles++
			}
			t.Logf("%s target %d: a: %v | b: %v", name, e, short(errA), short(errB))
		}
		return res, a
	}

	ctl, _ := run("no-record", nil)
	t.Logf("without the record: a signed %d, b signed %d, targets signed twice with different votes: %d", ctl.aSigned, ctl.bSigned, ctl.doubles)
	if ctl.doubles == 0 {
		t.Fatal("control: expected double votes without the record")
	}

	recDir := t.TempDir()
	res, a := run("record", []string{"-record", "file:" + recDir, "-record-key", "node-1"})
	t.Logf("with the shared record: a signed %d, b signed %d, targets signed twice: %d", res.aSigned, res.bSigned, res.doubles)
	if res.doubles != 0 || res.bSigned == 0 {
		t.Fatalf("with the record: %+v", res)
	}
	if !strings.Contains(a.logText(), "record taken over by another instance") {
		t.Fatal("runner a does not report losing the record")
	}
	b, _ := os.ReadFile(filepath.Join(recDir, "node-1.rec"))
	t.Logf("record file after the run: %d bytes, %s", len(b), strings.SplitN(string(b), ",", 2)[0])
}

func short(err error) string {
	if err == nil {
		return "signed"
	}
	var r *backend.RefusedError
	if errors.As(err, &r) {
		d := r.Detail
		if len(d) > 90 {
			d = d[:90] + "..."
		}
		return r.Code.String() + " " + d
	}
	return err.Error()
}

// TestE2ECloudFlagChecks: the runner refuses flag sets that would weaken a
// cloud image, before it touches the platform. The release builds have no
// -allow-import flag at all; the debug builds refuse it off dev. Each case
// runs on the binary of its platform (build is a key of runnerBuilds).
func TestE2ECloudFlagChecks(t *testing.T) {
	c := newChain(t)
	port := freePort(t)
	devTCP := fmt.Sprintf("tcp:127.0.0.1:%d", port)
	caFile, _ := testPKI(t, t.TempDir(), "flags")
	keyInCA := filepath.Join(t.TempDir(), "ca-with-key.pem")
	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		t.Fatal(err)
	}
	withKey := append(append([]byte{}, caPEM...), []byte("-----BEGIN PRIVATE KEY-----\nQUJD\n-----END PRIVATE KEY-----\n")...)
	if err := os.WriteFile(keyInCA, withKey, 0o600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name  string
		build string
		args  []string
		want  string
	}{
		{"nitro on vsock without mutual TLS", "aws", []string{"-platform", "nitro", "-listen", "vsock:any:7100", "-record", "none"}, "-tls-client-ca"},
		{"nitro on TCP without mutual TLS", "aws", []string{"-platform", "nitro", "-listen", "tcp:0.0.0.0:7100", "-record", "none"}, "-tls-client-ca"},
		{"nitro on vsock without mutual TLS (debug build)", "aws-debug", []string{"-platform", "nitro", "-listen", "vsock:any:7100", "-record", "none"}, "-tls-client-ca"},
		{"plain vsock in the release build", "dev", []string{"-platform", "dev", "-listen", "vsock:any:7100"}, "mutual TLS only"},
		{"plain vsock next to a TCP listener in the release build", "dev", []string{"-platform", "dev", "-listen", devTCP + ",vsock:any:7100"}, "mutual TLS only"},
		{"client CA file with a private key", "dev", []string{"-platform", "dev", "-listen", devTCP, "-tls-client-ca", keyInCA}, "private key"},
		{"gcp on TCP without mutual TLS", "gcp", []string{"-platform", "gcp", "-listen", fmt.Sprintf("tcp:0.0.0.0:%d", port), "-record", "none"}, "-tls-client-ca"},
		{"azure on TCP without mutual TLS", "azure", []string{"-platform", "azure", "-listen", fmt.Sprintf("tcp:0.0.0.0:%d", port), "-record", "none"}, "-tls-client-ca"},
		{"plaintext import flag in the release build", "dev", []string{"-platform", "dev", "-listen", devTCP, "-allow-import"}, "flag provided but not defined: -allow-import"},
		{"plaintext import flag in the Nitro release build", "aws", []string{"-platform", "nitro", "-listen", "vsock:any:7100", "-allow-import", "-record", "none"}, "flag provided but not defined: -allow-import"},
		{"plaintext import flag in the Azure release build", "azure", []string{"-platform", "azure", "-listen", fmt.Sprintf("tcp:0.0.0.0:%d", port), "-allow-import", "-record", "none"}, "flag provided but not defined: -allow-import"},
		{"plaintext import flag in the GCP release build", "gcp", []string{"-platform", "gcp", "-listen", fmt.Sprintf("tcp:0.0.0.0:%d", port), "-allow-import", "-record", "none"}, "flag provided but not defined: -allow-import"},
		{"plaintext import on a cloud platform (debug build)", "aws-debug", []string{"-platform", "nitro", "-listen", "vsock:any:7100", "-allow-import", "-record", "none"}, "dev platform only"},
		{"plaintext import on Azure (debug build)", "azure-debug", []string{"-platform", "azure", "-listen", fmt.Sprintf("tcp:0.0.0.0:%d", port), "-allow-import", "-record", "none"}, "dev platform only"},
		{"cloud platform without a clone guard choice", "aws", []string{"-platform", "nitro", "-listen", "vsock:any:7100", "-tls-client-ca", caFile}, "set -mark-store"},
		{"mark log and clone guard record together", "aws", []string{"-platform", "nitro", "-listen", "vsock:any:7100", "-tls-client-ca", caFile, "-mark-store", "s3:bucket=b,region=r", "-record", "dynamodb:table=t,region=r"}, "-mark-store replaces -record"},
		{"network state flag in the release build", "dev", []string{"-platform", "dev", "-listen", devTCP, "-net-state-dir", "/tmp/ts"}, "flag provided but not defined: -net-state-dir"},
		{"floor margin max_epochs_ahead", "dev", []string{"-platform", "dev", "-listen", devTCP, "-floor-margin", "1"}, "max_epochs_ahead + 1"},
	}
	for _, tc := range cases {
		args := append([]string{"-config", c.path, "-state-dir", filepath.Join(t.TempDir(), "s")}, tc.args...)
		out, err := runnerCmd(runnerBinary(t, tc.build), args...).CombinedOutput()
		var ee *exec.ExitError
		if !errors.As(err, &ee) || !strings.Contains(string(out), tc.want) {
			t.Fatalf("%s: err %v, output %q", tc.name, err, out)
		}
		t.Logf("%s: refused at start: %s", tc.name, strings.TrimSpace(string(out)))
	}
}
