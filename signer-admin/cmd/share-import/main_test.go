package main

// The built share-import against fake runners: a plain TCP fake, which is
// what anyone on the network path can run, and fakerunner over TLS. The
// binary is built once per run from this directory, or taken from
// SHARE_IMPORT_BIN.

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/signer-admin/fakerunner"
	cloud "github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/sealedimport"
	"github.com/lidofinance/tee-signer/signer-protocol/wire"
	wireadmin "github.com/lidofinance/tee-signer/signer-protocol/wire/admin"
)

var bin string

func TestMain(m *testing.M) {
	bin = os.Getenv("SHARE_IMPORT_BIN")
	var dir string
	if bin == "" {
		var err error
		if dir, err = os.MkdirTemp("", "share-import-test"); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		bin = filepath.Join(dir, "share-import")
		goBin, err := exec.LookPath("go")
		if err != nil {
			goBin = filepath.Join(runtime.GOROOT(), "bin", "go")
		}
		if out, err := exec.Command(goBin, "build", "-o", bin, ".").CombinedOutput(); err != nil {
			fmt.Fprintf(os.Stderr, "go build: %v\n%s", err, out)
			os.RemoveAll(dir)
			os.Exit(1)
		}
	}
	code := m.Run()
	if dir != "" {
		os.RemoveAll(dir)
	}
	os.Exit(code)
}

func tool(t *testing.T, args ...string) (string, error) {
	t.Helper()
	out, err := exec.Command(bin, args...).CombinedOutput()
	t.Logf("share-import %s\n%s", strings.Join(args, " "), out)
	return string(out), err
}

func shareFile(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "share.hex")
	if err := os.WriteFile(p, []byte("0x10"+strings.Repeat("22", 31)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

var testPubkey = "0x" + "a0" + strings.Repeat("11", 47)

// flagPathState is the state of a runner without a setup: setup_hash only.
// The dev verifier accepts it without -setup-sha256.
func flagPathState() cloud.SetupState {
	return cloud.SetupState{SetupHash: sha256.Sum256([]byte("config file"))}
}

// plainFake answers on plain TCP, no TLS: IDENTITY with the dev document
// and IMPORT_SHARE_SEALED opened with a real HPKE key.
type plainFake struct {
	ln       net.Listener
	importer *sealedimport.Key
	mu       sync.Mutex
	held     int
	seen     map[wire.MsgType]int
}

func startPlainFake(t *testing.T, state cloud.SetupState) *plainFake {
	t.Helper()
	f := &plainFake{seen: map[wire.MsgType]int{}}
	var err error
	if f.importer, err = sealedimport.Generate(); err != nil {
		t.Fatal(err)
	}
	if f.ln, err = net.Listen("tcp", "127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.ln.Close() })
	go func() {
		for {
			c, err := f.ln.Accept()
			if err != nil {
				return
			}
			go f.serve(c, state)
		}
	}()
	return f
}

func (f *plainFake) addr() string { return "tcp:" + f.ln.Addr().String() }

func (f *plainFake) serve(c net.Conn, state cloud.SetupState) {
	defer c.Close()
	for {
		fr, err := wire.ReadFrame(c)
		if err != nil {
			return
		}
		f.mu.Lock()
		f.seen[fr.Type]++
		f.mu.Unlock()
		var answer []byte
		switch fr.Type {
		case wire.TypeIdentity:
			nonce, err := wire.DecodeAttest(fr.Payload)
			if err != nil {
				return
			}
			fakeTLS := sha256.Sum256([]byte("no tls at all"))
			id := &cloud.Identity{State: state, TLSKeyHash: fakeTLS[:]}
			f.importer.Fill(id)
			ud := cloud.IdentityUserData(nonce, id)
			doc, _ := json.Marshal(map[string]any{"nonce": nonce, "user_data": ud})
			id.Attestation = &cloud.Attestation{Platform: "dev", Format: "dev-json", UserData: ud, Document: doc}
			body, err := wire.EncodeIdentity(id)
			if err != nil {
				return
			}
			answer = wire.EncodeOK(body)
		case wireadmin.TypeImportSealed:
			req, err := wireadmin.DecodeImportSealed(fr.Payload)
			if err != nil {
				answer = wire.EncodeError(cloud.Refused(cloud.StatusDecode, "%v", err))
				break
			}
			if _, err := f.importer.Open(&req); err != nil {
				answer = wire.EncodeError(cloud.Refused(cloud.StatusBadKey, "%v", err))
				break
			}
			// The fake holds the plaintext share now.
			f.mu.Lock()
			f.held++
			f.mu.Unlock()
			answer = wire.EncodeOK(wire.AppendKey(nil, cloud.ValidatorKey{Pubkey: req.Pubkey, SharePubkey: req.SharePubkey, Index: req.Index}))
		default:
			answer = wire.EncodeError(cloud.Refused(cloud.StatusForbidden, "not served"))
		}
		if err := wire.WriteFrame(c, wire.Frame{Type: fr.Type | wire.ResponseFlag, ID: fr.ID, Payload: answer}); err != nil {
			return
		}
	}
}

func (f *plainFake) count(t wire.MsgType) (held, seen int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.held, f.seen[t]
}

// The dev verifier takes the unsigned document from whoever answers, so a
// fake on the network path with a real HPKE key would be sealed the
// share. share-import refuses the dev verifier for an address that is not
// this machine, on both transports, before it dials and before it reads
// the share. 192.0.2.10 is TEST-NET-1: a dial to it would hang.
func TestDevVerifierRefusedOffMachine(t *testing.T) {
	const remote = "tcp:192.0.2.10:7100"
	const want = "is not local"
	check := func(name, out string, err error, took time.Duration) {
		t.Helper()
		switch {
		case err == nil:
			t.Fatalf("%s: the tool went on", name)
		case !strings.Contains(out, want):
			t.Fatalf("%s: error does not say %q:\n%s", name, want, out)
		case strings.Contains(out, "no such file"):
			t.Fatalf("%s: the share file was read before the refusal:\n%s", name, out)
		case took > 5*time.Second:
			t.Fatalf("%s: took %s, so the tool dialed before the refusal", name, took)
		}
	}
	start := time.Now()
	out, err := tool(t, "-addr", remote, "-pubkey", testPubkey, "-share-file", "/nonexistent/share", "-verifier", "dev")
	check("plain tcp", out, err, time.Since(start))

	r := fakerunner.Start(t, flagPathState())
	cert, key := r.ClientFiles(t, t.TempDir())
	start = time.Now()
	out, err = tool(t, "-addr", remote, "-pubkey", testPubkey, "-share-file", "/nonexistent/share",
		"-tls-cert", cert, "-tls-key", key, "-verifier", "dev")
	check("tls", out, err, time.Since(start))
}

// On this machine the dev verifier works on both transports: a runner
// without TLS (a local runner without -tls-client-ca), and a TLS runner
// whose certificate carries no chain mark.
func TestDevVerifierOnLoopback(t *testing.T) {
	f := startPlainFake(t, flagPathState())
	out, err := tool(t, "-addr", f.addr(), "-pubkey", testPubkey, "-index", "7", "-share-file", shareFile(t), "-verifier", "dev")
	if err != nil {
		t.Fatalf("plain tcp on loopback: %v\n%s", err, out)
	}
	if held, _ := f.count(wire.TypeIdentity); held != 1 || !strings.Contains(out, "identity checked with the dev verifier") {
		t.Fatalf("plain fake holds %d shares, want 1:\n%s", held, out)
	}

	r := fakerunner.Start(t, flagPathState())
	cert, key := r.ClientFiles(t, t.TempDir())
	out, err = tool(t, "-addr", r.Addr(), "-pubkey", testPubkey, "-share-file", shareFile(t),
		"-tls-cert", cert, "-tls-key", key, "-verifier", "dev")
	if err != nil {
		t.Fatalf("tls on loopback: %v\n%s", err, out)
	}
	if n := len(r.Keys()); n != 1 {
		t.Fatalf("fake runner holds %d keys, want 1", n)
	}
}
