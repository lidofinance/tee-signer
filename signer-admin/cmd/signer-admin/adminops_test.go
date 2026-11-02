package main

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/attestation-verify/runnerclient"
	"github.com/lidofinance/tee-signer/governance/exitapproval"
	"github.com/lidofinance/tee-signer/governance/setupwire"
	"github.com/lidofinance/tee-signer/signer-core/core"
	"github.com/lidofinance/tee-signer/signer-core/software"
	"github.com/lidofinance/tee-signer/signer-protocol"
)

// issue-client-cert gives the role asked for and refuses what would not:
// an admin leaf from a root or an unmarked issuer, a signing leaf from a
// marked issuer, an intermediate from an intermediate, a CA key others
// can read.
func TestIssueClientCert(t *testing.T) {
	dir := t.TempDir()
	writePKI(t, dir, newPKI(t))
	pki := func(f string) string { return filepath.Join(dir, "pki", f) }
	out := filepath.Join(dir, "out")
	issueArgs := func(ca, role, name string) []string {
		return []string{"issue-client-cert", "-ca-cert", pki(ca + ".pem"), "-ca-key", pki(ca + "-key.pem"), "-role", role, "-name", name, "-out", out}
	}
	wantIn(t, mustTool(t, issueArgs("admin-ca", "admin", "coord")...), "role admin", "wrote "+filepath.Join(out, "coord.pem"))
	certs := readCerts(t, filepath.Join(out, "coord.pem"))
	if len(certs) != 2 || !hasMark(certs[0], backend.AdminClientOID) || !hasMark(certs[1], backend.AdminClientOID) {
		t.Fatalf("admin leaf: %d certificates", len(certs))
	}
	roots := x509.NewCertPool()
	roots.AddCert(readCerts(t, pki("root-ca.pem"))[0])
	inter := x509.NewCertPool()
	inter.AddCert(certs[1])
	if _, err := certs[0].Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Fatalf("admin leaf does not verify for clientAuth: %v", err)
	}
	if fi, err := os.Stat(filepath.Join(out, "coord-key.pem")); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("key file: %v %v", fi, err)
	}
	wantIn(t, mustTool(t, issueArgs("signing-ca", "signing", "lane-1")...), "role signing")
	wantIn(t, mustTool(t, issueArgs("signing-ca", "attest", "dashboard")...), "role attest")
	if c := readCerts(t, filepath.Join(out, "dashboard.pem")); !hasMark(c[0], backend.AttestOnlyClientOID) {
		t.Fatal("attest leaf without the attest-only mark")
	}
	wantIn(t, failTool(t, issueArgs("root-ca", "admin", "x1")...), "the issuer is a root")
	wantIn(t, failTool(t, issueArgs("signing-ca", "admin", "x2")...), "does not carry the admin mark")
	wantIn(t, failTool(t, issueArgs("admin-ca", "signing", "x3")...), "carries a role mark")
	wantIn(t, failTool(t, issueArgs("admin-ca", "admin", "coord")...), "exists; not overwriting it")
	wantIn(t, failTool(t, "issue-client-cert", "-ca-cert", pki("admin-ca.pem"), "-ca-key", pki("admin-ca-key.pem"), "-make-intermediate", "admin",
		"-name", "x4", "-out", out), "is not a root")
	wantIn(t, failTool(t, "issue-client-cert", "-ca-cert", pki("admin-ca.pem"), "-ca-key", pki("signing-ca-key.pem"), "-role", "admin",
		"-name", "x5", "-out", out), "is not the key of")
	if err := os.Chmod(pki("signing-ca-key.pem"), 0o640); err != nil {
		t.Fatal(err)
	}
	wantIn(t, failTool(t, issueArgs("signing-ca", "signing", "x6")...), "mode 0640")

	// A new admin intermediate from the root, then a leaf from it.
	wantIn(t, mustTool(t, "issue-client-cert", "-ca-cert", pki("root-ca.pem"), "-ca-key", pki("root-ca-key.pem"), "-make-intermediate", "admin",
		"-name", "admin2", "-out", out), "intermediate CA admin2, role admin")
	wantIn(t, mustTool(t, "issue-client-cert", "-ca-cert", filepath.Join(out, "admin2-ca.pem"), "-ca-key", filepath.Join(out, "admin2-ca-key.pem"),
		"-role", "admin", "-name", "coord2", "-out", out), "role admin")
}

// readCerts parses every certificate of a PEM file.
func readCerts(t *testing.T, path string) []*x509.Certificate {
	t.Helper()
	b := mustRead(t, path)
	var out []*x509.Certificate
	for {
		var blk *pem.Block
		if blk, b = pem.Decode(b); blk == nil {
			return out
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, c)
	}
}

// split writes the split file of a t-of-n split of one new validator and
// returns its key, the shares, and the path.
func split(t *testing.T, dir string, tt, n int, names []string) (backend.Pubkey, []software.Share, string) {
	t.Helper()
	sk, err := software.NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	pk, err := core.PubkeyOf(sk)
	if err != nil {
		t.Fatal(err)
	}
	shares, comm, err := software.SplitWithCommitments(sk, tt, n)
	if err != nil {
		t.Fatal(err)
	}
	idx := map[string]int{}
	for i, name := range names {
		idx[name] = i + 1
	}
	return pk, shares, writeJSONFile(t, filepath.Join(dir, "split.json"), map[string]any{
		"t": tt, "n": n, "shares": idx, "validators": []any{map[string]any{"pubkey": pk, "commitments": comm}},
	})
}

// The import order and exit approval tracks without a runner that takes
// them: import-draft, show, sign in both forms, assemble; exit-draft,
// show, sign, assemble; push refuses an import order and a batch of 9.
func TestImportAndExitOffline(t *testing.T) {
	fc := newFakeCluster(t)
	cl := fc.cluster
	mustTool(t, "pin", "-cluster", cl)
	pk, _, splitPath := split(t, fc.dir, 3, 4, []string{"s1", "s2", "s3", "s4"})

	body := fc.path("import.bin")
	out := mustTool(t, "import-draft", "-cluster", cl, "-signer", "s2", "-split", splitPath, "-out", body)
	wantIn(t, out, "import order for s2", "1 validators, 3 of 4, share index 2", "order_sha256 ")
	out = mustTool(t, "show", body)
	wantIn(t, out, "import order", "share_index = 2", "validator = "+pk.String(), "target: s2", "signing message, direct form: signer-import-order-v1",
		"signing message, hashed form (sign -hashed): sha256 of signer-import-order-hash-v1")
	s0 := mustTool(t, "sign", "-key", fc.keys[0].file, body)
	wantIn(t, s0, "direct form")
	s1 := mustTool(t, "sign", "-key", "file:"+fc.keys[1].file, "-hashed", body)
	wantIn(t, s1, "hashed form")
	sigs := []string{fmt.Sprintf("%s.%s.sig", body, fc.keys[0].pub[2:10]), fmt.Sprintf("%s.%s.sig", body, fc.keys[1].pub[2:10])}
	wantIn(t, string(mustRead(t, sigs[1])), "form = hashed", "signer-import-order-hash-v1")
	wantIn(t, failTool(t, "assemble", "-out", fc.path("one.signed"), body, sigs[0]), "approvals_needed is 2")
	signed := fc.path("import.signed")
	wantIn(t, mustTool(t, "assemble", "-out", signed, body, sigs[0], sigs[1]), "2 approvers")
	wantIn(t, mustTool(t, "show", "-active", body+".active", signed), "signatures: complete and valid")
	wantIn(t, failTool(t, "push", "-cluster", cl, signed), "an import order is not pushed")

	exit := fc.path("exit.bin")
	out = mustTool(t, "exit-draft", "-cluster", cl, "-pubkey", pk.String(), "-index", "7", "-epoch", "1000", "-balance", "32000000000", "-out", exit)
	wantIn(t, out, "exit approval for validator 7", "push sends it to all 3 signers")
	if fi, err := os.Stat(exit); err != nil || fi.Size() != exitapproval.Len {
		t.Fatalf("exit.bin: %v %v", fi, err)
	}
	wantIn(t, mustTool(t, "show", exit), "validator_index = 7", "before you sign, check on the beacon chain", "signer-ta-exit-approval-hash-v1")
	var esigs []string
	for _, i := range []int{0, 2} {
		mustTool(t, "sign", "-hashed", "-key", fc.keys[i].file, exit)
		esigs = append(esigs, fmt.Sprintf("%s.%s.sig", exit, fc.keys[i].pub[2:10]))
	}
	esigned := fc.path("exit.signed")
	wantIn(t, mustTool(t, "assemble", "-out", esigned, exit, esigs[0], esigs[1]), "exit_approvals_needed 2")
	wantIn(t, mustTool(t, "show", "-active", exit+".active", esigned), "signatures: complete and valid")
	many := []string{"push", "-cluster", cl}
	for range 9 {
		many = append(many, esigned)
	}
	wantIn(t, failTool(t, many...), "9 exit approvals in one push", "at most 8")
}

// probe, import and exits against a dev runner with a setup: probe tells
// the admin leaf from a signing leaf; import seals a share under an
// import order with the admin leaf and gets FORBIDDEN with a signing leaf;
// an exit is refused until push brought its approval, then the signing
// leaf's VOLUNTARY_EXIT signs.
//
// SIGNER_ADMIN_RUNNER names a dev runner of this repo with the role
// check; without it the test is skipped.
func TestAdminFlowDevRunner(t *testing.T) {
	bin := os.Getenv("SIGNER_ADMIN_RUNNER")
	if bin == "" {
		t.Skip("SIGNER_ADMIN_RUNNER is not set (a dev runner binary of this repo)")
	}
	dir := t.TempDir()
	pki, ca, cert, key := clientPKIWith(t, dir)
	keys := approvers(t, dir, 3)
	genesis := genesisTime()
	conf := writeFile(t, filepath.Join(dir, "setup.conf"), setupText(dir, ca, genesis, lockedText(keys, 2, 0, fee1)+"exit_allowed_validators = 7\n", "g1"))
	hashes := setupHashes(mustTool(t, "setup", "-out", filepath.Join(dir, "setups"), conf))

	addr := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	logPath := writeFile(t, filepath.Join(dir, "g1", "runner.log"), "")
	f, err := os.OpenFile(logPath, os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, "-platform", "dev", "-state-dir", filepath.Join(dir, "g1", "state"), "-listen", "tcp:"+addr,
		"-setup", "file:"+filepath.Join(dir, "setups", "g1.setup"))
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
	connFile := func(name, cert, key string) string {
		return writeJSONFile(t, filepath.Join(dir, name, "cloud.json"), map[string]any{
			"address": "tcp:" + addr, "client_cert": cert, "client_key": key,
			"attestation": map[string]any{"verifier": "dev", "setup_sha256": hashes["g1"]},
		})
	}
	connFile("g1", cert, key)
	cl := writeJSONFile(t, filepath.Join(dir, "cluster.json"), map[string]any{
		"signers": []any{map[string]string{"name": "g1", "cloud": "g1/cloud.json", "setup": "setups/g1.setup"}}})
	// The same runner through a signing leaf of the same root.
	signCert, signKey := filepath.Join(dir, "signing.pem"), filepath.Join(dir, "signing-key.pem")
	pki.issue(t, signCert, signKey, false)
	connFile("lane", signCert, signKey)
	laneCl := writeJSONFile(t, filepath.Join(dir, "lane-cluster.json"), map[string]any{
		"signers": []any{map[string]string{"name": "g1", "cloud": "lane/cloud.json", "setup": "setups/g1.setup"}}})

	wantIn(t, mustTool(t, "probe", "-cluster", cl), "g1 admin: the role check passed (BAD_REQUEST)")
	wantIn(t, failTool(t, "probe", "-cluster", laneCl), "g1 not admin")

	pk, shares, splitPath := split(t, dir, 1, 1, []string{"g1"})
	body := filepath.Join(dir, "import.bin")
	mustTool(t, "import-draft", "-cluster", cl, "-signer", "g1", "-split", splitPath, "-out", body)
	var sigs []string
	for _, i := range []int{0, 1} {
		mustTool(t, "sign", "-key", keys[i].file, body)
		sigs = append(sigs, fmt.Sprintf("%s.%s.sig", body, keys[i].pub[2:10]))
	}
	signed := filepath.Join(dir, "import.signed")
	mustTool(t, "assemble", "-out", signed, body, sigs[0], sigs[1])
	sharesFile := filepath.Join(dir, "shares.txt")
	if err := os.WriteFile(sharesFile, fmt.Appendf(nil, "%s 7 0x%x\n", pk, shares[0].Secret), 0o600); err != nil {
		t.Fatal(err)
	}
	importArgs := func(cluster string) []string {
		return []string{"import", "-cluster", cluster, "-signer", "g1", "-order", signed, "-shares", sharesFile, "-commitments", splitPath}
	}
	wantIn(t, failTool(t, importArgs(laneCl)...), "not admin")
	wantIn(t, mustTool(t, importArgs(cl)...), "g1 imported "+pk.String())
	// Again through the connection file, with the seed's line format: the
	// share is held already and -skip-loaded leaves it out.
	sp, _ := core.PubkeyOf(shares[0].Secret)
	seedShares := filepath.Join(dir, "seed.shares")
	if err := os.WriteFile(seedShares, fmt.Appendf(nil, "0x%x %s 7 %s\n", shares[0].Secret, pk, sp), 0o600); err != nil {
		t.Fatal(err)
	}
	wantIn(t, mustTool(t, "import", "-conn", filepath.Join(dir, "g1", "cloud.json"), "-order", signed, "-commitments", splitPath,
		"-shares", seedShares, "-skip-loaded"), "imported 0 shares, skipped 1 already held")

	// The signing leaf's client, as the signing client's.
	conn, err := loadConn(filepath.Join(dir, "lane", "cloud.json"))
	if err != nil {
		t.Fatal(err)
	}
	lane, err := conn.New(runnerclient.WithTimeout(10 * time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer lane.Close()
	setup, err := setupwire.DecodeSetup(mustRead(t, filepath.Join(dir, "setups", "g1.setup")))
	if err != nil {
		t.Fatal(err)
	}
	epoch := uint64(time.Now().Unix()-genesis) / (secondsPerSlot * slotsPerEpoch)
	exitReq := backend.SignRequest{Pubkey: pk, Message: &backend.VoluntaryExit{Epoch: epoch, ValidatorIndex: 7},
		Domain: backend.ComputeDomain(backend.DomainVoluntaryExit, setup.Chain.VoluntaryExitForkVersion, setup.Chain.GenesisValidatorsRoot)}
	ctx := context.Background()
	if _, err := lane.Sign(ctx, exitReq); err == nil || !strings.Contains(err.Error(), "exit approval") {
		t.Fatalf("exit before its approval: %v", err)
	}
	// A signing leaf cannot push the approval.
	exit := filepath.Join(dir, "exit.bin")
	mustTool(t, "exit-draft", "-cluster", cl, "-pubkey", pk.String(), "-index", "7", "-epoch", fmt.Sprint(epoch), "-balance", "32000000000", "-out", exit)
	var esigs []string
	for _, i := range []int{1, 2} {
		mustTool(t, "sign", "-hashed", "-key", keys[i].file, exit)
		esigs = append(esigs, fmt.Sprintf("%s.%s.sig", exit, keys[i].pub[2:10]))
	}
	esigned := filepath.Join(dir, "exit.signed")
	mustTool(t, "assemble", "-out", esigned, exit, esigs[0], esigs[1])
	wantIn(t, failTool(t, "push", "-cluster", laneCl, esigned), "FORBIDDEN")
	wantIn(t, mustTool(t, "push", "-cluster", cl, esigned), "g1 holds "+esigned)
	if _, err := lane.Sign(ctx, exitReq); err != nil {
		t.Fatalf("exit after its approval: %v", err)
	}
	b, _ := json.Marshal(exitReq.Message)
	t.Logf("signed %s", b)
}

// The shares file: both line formats, and a share pubkey that is not the
// secret's is refused at import; a file others can read is refused.
func TestReadShares(t *testing.T) {
	sk, _ := software.NewSecret()
	pk, _ := core.PubkeyOf(sk)
	p := filepath.Join(t.TempDir(), "s.txt")
	if err := os.WriteFile(p, fmt.Appendf(nil, "# a comment\n%s - 0x%x\n0x%x %s 9 %s\n", pk, sk, sk, pk, pk), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := readShares(p)
	if err != nil || len(got) != 2 || got[0].index != backend.IndexUnknown || got[1].index != 9 || got[1].sharePub != pk || got[0].secret != sk {
		t.Fatalf("%+v %v", got, err)
	}
	if err := os.Chmod(p, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readShares(p); err == nil || !strings.Contains(err.Error(), "mode 0644") {
		t.Fatalf("mode 0644: %v", err)
	}
}
