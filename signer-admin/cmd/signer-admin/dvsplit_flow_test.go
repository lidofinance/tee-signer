package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/attestation-verify/runnerclient"
)

// The dv_share track with a dev runner: a setup that says
// signing_mode = dv_share, dv-split from a Charon cluster lock (3 of 4,
// the runner holds share 2), import-draft, two approvers, and import from
// the shares file of a single-mode import (each share under its own key).
// The runner lists each share under its own key and signs its partial
// selection proof with it.
//
// SIGNER_ADMIN_RUNNER names a dev runner binary of this repo; without it
// the test is skipped.
func TestDVShareDevRunner(t *testing.T) {
	bin := os.Getenv("SIGNER_ADMIN_RUNNER")
	if bin == "" {
		t.Skip("SIGNER_ADMIN_RUNNER is not set (a dev runner binary of this repo)")
	}
	dir := t.TempDir()
	pki, ca, cert, key := clientPKIWith(t, dir)
	signCert, signKey := filepath.Join(dir, "signing.pem"), filepath.Join(dir, "signing-key.pem")
	pki.issue(t, signCert, signKey, false)
	keys := approvers(t, dir, 3)
	genesis := genesisTime()
	text := strings.Replace(setupText(dir, ca, genesis, lockedText(keys, 2, 0, fee1), "d1"), "signing_mode = single", "signing_mode = dv_share", 1)
	conf := writeFile(t, filepath.Join(dir, "setup.conf"), text)
	hashes := setupHashes(mustTool(t, "setup", "-out", filepath.Join(dir, "setups"), conf))

	addr := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	logPath := writeFile(t, filepath.Join(dir, "d1", "runner.log"), "")
	f, err := os.OpenFile(logPath, os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, "-platform", "dev", "-state-dir", filepath.Join(dir, "d1", "state"), "-listen", "tcp:"+addr,
		"-setup", "file:"+filepath.Join(dir, "setups", "d1.setup"))
	cmd.Stdout, cmd.Stderr = f, f
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cmd.Process.Kill()
		cmd.Wait()
		f.Close()
		if t.Failed() {
			t.Logf("---- %s ----\n%s", logPath, mustRead(t, logPath))
		}
	})
	waitTCP(t, addr)
	for _, c := range []struct{ name, cert, key string }{{"d1", cert, key}, {"d1-lane", signCert, signKey}} {
		writeJSONFile(t, filepath.Join(dir, c.name, "cloud.json"), map[string]any{
			"address": "tcp:" + addr, "client_cert": c.cert, "client_key": c.key,
			"attestation": map[string]any{"verifier": "dev", "setup_sha256": hashes["d1"]},
		})
	}
	cl := writeJSONFile(t, filepath.Join(dir, "cluster.json"), map[string]any{"signers": []map[string]string{
		{"name": "d1", "cloud": "d1/cloud.json", "setup": "setups/d1.setup"}}})

	c := newCharonCluster(t, 2, 3, 4)
	lock := c.lock(t, filepath.Join(dir, "cluster-lock.json"), nil)
	splitPath := filepath.Join(dir, "split.json")
	mustTool(t, "dv-split", "-lock", lock, "-signers", "d1=2", "-out", splitPath)

	// The shares file of the single-mode import: share 2 of each validator
	// under its own key.
	var lines strings.Builder
	for v := range c.groups {
		fmt.Fprintf(&lines, "%s %d 0x%x\n", c.sharePub(t, v, 1), 100+v, c.secrets[v][1])
	}
	sharesPath := filepath.Join(dir, "shares.txt")
	if err := os.WriteFile(sharesPath, []byte(lines.String()), 0o600); err != nil {
		t.Fatal(err)
	}

	body := filepath.Join(dir, "import.bin")
	mustTool(t, "import-draft", "-cluster", cl, "-signer", "d1", "-split", splitPath, "-out", body)
	var sigs []string
	for _, i := range []int{0, 2} {
		mustTool(t, "sign", "-key", keys[i].file, "-expect-sha256", expectOf(t, body), body)
		sigs = append(sigs, fmt.Sprintf("%s.%s.sig", body, keys[i].pub[2:10]))
	}
	signed := filepath.Join(dir, "import.signed")
	mustTool(t, append([]string{"assemble", "-out", signed, body}, sigs...)...)
	out := mustTool(t, "import", "-cluster", cl, "-signer", "d1", "-order", signed, "-shares", sharesPath, "-commitments", splitPath)
	t.Logf("import\n%s", out)
	wantIn(t, out, "2 shares named by their own key", "imported 2 shares")

	conn, err := loadConn(filepath.Join(dir, "d1-lane", "cloud.json"))
	if err != nil {
		t.Fatal(err)
	}
	lane, err := conn.New(runnerclient.WithTimeout(10 * time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer lane.Close()
	ctx := context.Background()
	held, err := lane.PublicKeys(ctx)
	if err != nil || len(held) != 2 {
		t.Fatalf("PUBLIC_KEYS: %v, %v", held, err)
	}
	for v := range c.groups {
		sp := c.sharePub(t, v, 1)
		found := false
		for _, k := range held {
			found = found || k.Pubkey == sp && k.SharePubkey == sp
		}
		if !found {
			t.Fatalf("validator %d: the runner does not list share %s under its own key: %+v", v, sp, held)
		}
	}
}
