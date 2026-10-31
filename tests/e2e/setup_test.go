package e2e

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/governance/setupwire"
	"github.com/lidofinance/tee-signer/platform/setup"
	"github.com/lidofinance/tee-signer/signer-core/core"
	"github.com/lidofinance/tee-signer/signer-core/software"
	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/remote"
	"github.com/lidofinance/tee-signer/signer-protocol/sealedimport"
)

// setupForTest is the dev sample setup of backend/setupwire with its
// stores in dir and the CA of caFile as its client CA.
func setupForTest(t *testing.T, dir, caFile string) []byte {
	t.Helper()
	sample, err := os.ReadFile(filepath.Join("..", "..", "governance", "setupwire", "testdata", "setup-dev.bin"))
	if err != nil {
		t.Fatal(err)
	}
	s, err := setupwire.DecodeSetup(sample)
	if err != nil {
		t.Fatal(err)
	}
	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		t.Fatal(err)
	}
	blk, _ := pem.Decode(caPEM)
	s.Platform.AllowedClientCA = [][]byte{blk.Bytes}
	s.Platform.SlashingLogStore.Dir = filepath.Join(dir, "marks")
	s.Platform.EncryptedStateStore = &setupwire.Store{Dir: filepath.Join(dir, "state-copy")}
	raw, err := s.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// startSetupRunner starts the dev release runner with args and env and
// stops it at the end of the test.
func startSetupRunner(t *testing.T, logPath string, env []string, args ...string) *exec.Cmd {
	t.Helper()
	f, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	cmd := runnerCmd(runnerBinary(t, "dev"), args...)
	cmd.Stdout, cmd.Stderr, cmd.Env = f, f, append(os.Environ(), env...)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cmd.Process.Kill()
		cmd.Wait()
		f.Close()
		if t.Failed() {
			b, _ := os.ReadFile(logPath)
			t.Logf("---- %s ----\n%s", filepath.Base(logPath), b)
		}
	})
	return cmd
}

// TestE2ESetup: a dev runner with -setup takes its chain config, client CA,
// mark log and state copy from the setup. Its identity
// carries setup_hash. The setup comes from a file or from SIGNER_SETUP.
func TestE2ESetup(t *testing.T) {
	for _, via := range []string{"file", "env"} {
		t.Run(via, func(t *testing.T) {
			dir := t.TempDir()
			caFile, cliCfg := testPKI(t, dir, "setup")
			raw := setupForTest(t, dir, caFile)
			hash, _ := setupwire.SetupHash(raw)
			addr := fmt.Sprintf("tcp:127.0.0.1:%d", freePort(t))
			args := []string{"-platform", "dev", "-state-dir", filepath.Join(dir, "state"), "-listen", addr}
			var env []string
			if via == "file" {
				path := filepath.Join(dir, "setup.bin")
				if err := os.WriteFile(path, raw, 0o600); err != nil {
					t.Fatal(err)
				}
				args = append(args, "-setup", "file:"+path)
			} else {
				env = []string{setup.EnvVar + "=" + base64.StdEncoding.EncodeToString(raw)}
				args = append(args, "-setup", "platform")
			}
			startSetupRunner(t, filepath.Join(dir, "runner.log"), env, args...)

			// Mutual TLS with the setup's CA: a client certificate of that CA gets in.
			cl, err := newTLSClient(addr, cliCfg, remote.DevVerifier, remote.WithTimeout(5*time.Second))
			if err != nil {
				t.Fatal(err)
			}
			defer cl.Close()
			h := waitReady(t, cl)
			id := devIdentity(t, cl)
			// IDENTITY: setup_hash, version 0 of both groups under the
			// setup's group hashes, nothing pending, the setup's approvers.
			s, err := setupwire.DecodeSetup(raw)
			if err != nil {
				t.Fatal(err)
			}
			lh, _ := s.GroupHash(setupwire.GroupLocked)
			oh, _ := s.GroupHash(setupwire.GroupOpen)
			want := backend.SetupState{SetupHash: hash, Locked: backend.ConfigGroup{Hash: lh}, Open: backend.ConfigGroup{Hash: oh},
				ApproverSetHash: s.Locked.Approvers.Hash()}
			if id.State != want {
				t.Fatalf("identity state %+v, want %+v", id.State, want)
			}
			if h.Setup == nil || *h.Setup != want || h.ConfigHash != hash {
				t.Fatalf("health setup state %+v (config_hash %x), want %+v", h.Setup, h.ConfigHash, want)
			}
			// The mark log is in the setup's directory; the state copy opens
			// there and writes its first commit with the first change.
			if ents, err := os.ReadDir(filepath.Join(dir, "marks")); err != nil || len(ents) == 0 {
				t.Fatalf("the setup's mark store is empty: %v", err)
			}
			log, _ := os.ReadFile(filepath.Join(dir, "runner.log"))
			for _, want := range []string{fmt.Sprintf("setup_sha256=%x", hash), fmt.Sprintf("config_sha256=%x", hash),
				`state_copy="statecopy file:` + filepath.Join(dir, "state-copy") + " signer=signer-dev"} {
				if !strings.Contains(string(log), want) {
					t.Fatalf("the log lacks %s", want)
				}
			}
			t.Logf("setup via %s: setup_hash %x in the identity, mutual TLS with the setup's CA, mark log and state copy in the setup's directories", via, hash[:8])
		})
	}
}

// TestE2ESetupSharesStayWithTheSetup: a share imported into a runner with a
// setup loads again after a restart with that setup. A restart with another
// setup over the same state (here: another cluster_id) finds an empty mark
// log under its own setup_hash while shares are stored, and stops.
func TestE2ESetupSharesStayWithTheSetup(t *testing.T) {
	dir := t.TempDir()
	caFile, cliCfg := testPKI(t, dir, "setup")
	s, err := setupwire.DecodeSetup(setupForTest(t, dir, caFile))
	if err != nil {
		t.Fatal(err)
	}
	// Approvers 1 to 3 (configApprover), k = 2, to sign the import order.
	s.Locked.Approvers = setupwire.ApproverSet{ApprovalsNeeded: 2}
	for id := byte(1); id <= 3; id++ {
		s.Locked.Approvers.Keys = append(s.Locked.Approvers.Keys, [32]byte(configApprover(id).Public().(ed25519.PublicKey)))
	}
	raw, err := s.Encode()
	if err != nil {
		t.Fatal(err)
	}
	hash := mustSetupHash(t, raw)
	firstSetup := *s
	s.ClusterID[31] ^= 1
	other, err := s.Encode()
	if err != nil {
		t.Fatal(err)
	}
	files := map[string]string{"one": filepath.Join(dir, "one.bin"), "other": filepath.Join(dir, "other.bin")}
	for name, b := range map[string][]byte{"one": raw, "other": other} {
		if err := os.WriteFile(files[name], b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	addr := fmt.Sprintf("tcp:127.0.0.1:%d", freePort(t))
	args := func(which string) []string {
		return []string{"-platform", "dev", "-state-dir", filepath.Join(dir, "state"), "-listen", addr, "-setup", "file:" + files[which]}
	}
	connect := func() *remote.Client {
		cl, err := newTLSClient(addr, cliCfg, remote.DevVerifier, remote.WithTimeout(5*time.Second))
		if err != nil {
			t.Fatal(err)
		}
		return cl
	}

	first := startSetupRunner(t, filepath.Join(dir, "first.log"), nil, args("one")...)
	cl := connect()
	waitReady(t, cl)
	sk, _ := software.NewSecret()
	pk, _ := core.PubkeyOf(sk)
	shares, commitments, _ := software.SplitWithCommitments(sk, 2, 3)
	share := shares[0].Secret
	sharePk, _ := core.PubkeyOf(share)
	req := &backend.SealedImportRequest{Pubkey: pk, SharePubkey: sharePk, Index: 3,
		Order: importOrder(t, &firstSetup, hash, pk, 2, 3, 1, commitments), T: 2, N: 3, ShareIndex: 1, Commitments: commitments}
	if req.Sealed, err = sealedimport.Seal(devIdentity(t, cl), req, &share); err != nil {
		t.Fatal(err)
	}
	if _, err := adminOf(cl).ImportSealed(ctx, req); err != nil {
		t.Fatal(err)
	}
	cl.Close()
	first.Process.Signal(syscall.SIGTERM)
	first.Wait()

	second := startSetupRunner(t, filepath.Join(dir, "second.log"), nil, args("one")...)
	cl = connect()
	if h := waitReady(t, cl); h.Validators != 1 {
		t.Fatalf("restart with the same setup: %d validators", h.Validators)
	}
	cl.Close()
	second.Process.Signal(syscall.SIGTERM)
	second.Wait()

	out, err := runnerCmd(runnerBinary(t, "dev"), args("other")...).CombinedOutput()
	if err == nil || !strings.Contains(string(out), "mark log") {
		t.Fatalf("another setup over the same state: err %v, output %s", err, out)
	}
	t.Logf("share loads again under its setup; another setup over the same state stops: %s", finalLine(out))
}

func finalLine(b []byte) string {
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	return lines[len(lines)-1]
}

// TestE2ESetupRefused: a setup that does not pass, or a command that also
// names a value the setup carries, stops the runner before its platform
// exists: the dev platform never creates its state directory.
func TestE2ESetupRefused(t *testing.T) {
	dir := t.TempDir()
	caFile, _ := testPKI(t, dir, "setup")
	good := setupForTest(t, dir, caFile)
	nitro, err := os.ReadFile(filepath.Join("..", "..", "governance", "setupwire", "testdata", "setup-nitro.bin"))
	if err != nil {
		t.Fatal(err)
	}
	write := func(name string, b []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	goodFile := write("good.bin", good)
	cases := []struct {
		name  string
		extra []string
		env   []string
		want  string
	}{
		{"trailing byte", []string{"-setup", "file:" + write("long.bin", append(append([]byte{}, good...), 0))}, nil, "1 trailing bytes"},
		{"nitro setup", []string{"-setup", "file:" + write("nitro.bin", nitro)}, nil, "platform is nitro, this image is dev"},
		{"no SIGNER_SETUP", []string{"-setup", "platform"}, nil, "SIGNER_SETUP is not set"},
		{"SIGNER_SETUP not base64", []string{"-setup", "platform"}, []string{setup.EnvVar + "=@@@"}, "not base64"},
		{"chain.json too", []string{"-setup", "file:" + goodFile, "-config", "/etc/signer/chain.json"}, nil, "-config cannot be used with -setup"},
		{"client CA file too", []string{"-setup", "file:" + goodFile, "-tls-client-ca", caFile}, nil, "-tls-client-ca cannot be used with -setup"},
		{"mark-create", []string{"-setup", "file:" + goodFile, "-mark-create"}, nil, "-mark-create cannot be used with -setup"},
		{"state-create", []string{"-setup", "file:" + goodFile, "-state-create"}, nil, "-state-create cannot be used with -setup"},
		{"another mark store", []string{"-setup", "file:" + goodFile, "-mark-store", "file:/tmp/x"}, nil, "-mark-store cannot be used with -setup"},
	}
	for _, c := range cases {
		state := filepath.Join(dir, "state-"+strings.ReplaceAll(c.name, " ", "-"))
		args := append([]string{"-platform", "dev", "-state-dir", state, "-listen", fmt.Sprintf("tcp:127.0.0.1:%d", freePort(t))}, c.extra...)
		cmd := runnerCmd(runnerBinary(t, "dev"), args...)
		env := os.Environ()
		for i, kv := range env {
			if strings.HasPrefix(kv, setup.EnvVar+"=") {
				env[i] = "UNSET_" + kv
			}
		}
		cmd.Env = append(env, c.env...)
		out, err := cmd.CombinedOutput()
		if err == nil || !strings.Contains(string(out), c.want) {
			t.Fatalf("%s: err %v, output %s", c.name, err, out)
		}
		if _, err := os.Stat(state); err == nil {
			t.Fatalf("%s: the platform was built (state directory made)", c.name)
		}
		t.Logf("%s: refused before the platform: %s", c.name, strings.TrimSpace(string(out)))
	}
}
