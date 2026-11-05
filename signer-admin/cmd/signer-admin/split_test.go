package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"golang.org/x/crypto/scrypt"

	adminapprover "github.com/lidofinance/tee-signer/signer-admin/approver"
	"github.com/lidofinance/tee-signer/signer-admin/fakerunner"
	"github.com/lidofinance/tee-signer/signer-core/core"
	"github.com/lidofinance/tee-signer/signer-core/software"
	"github.com/lidofinance/tee-signer/signer-core/threshold"
	cloud "github.com/lidofinance/tee-signer/signer-protocol"
)

const splitTestPassword = "split test password"

// writeKeystore writes an EIP-2335 keystore of a new key, encrypted with
// password under kdf (scrypt or pbkdf2, with low cost), and returns the
// key's pubkey.
func writeKeystore(t *testing.T, dir, name, kdf, password string) cloud.Pubkey {
	t.Helper()
	sk, err := software.NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	pk, err := core.PubkeyOf(sk)
	if err != nil {
		t.Fatal(err)
	}
	salt, iv := make([]byte, 32), make([]byte, 16)
	rand.Read(salt)
	rand.Read(iv)
	var dk []byte
	var params map[string]any
	switch kdf {
	case "scrypt":
		dk, err = scrypt.Key([]byte(password), salt, 16, 8, 1, 32)
		params = map[string]any{"dklen": 32, "n": 16, "r": 8, "p": 1, "salt": hex.EncodeToString(salt)}
	case "pbkdf2":
		dk, err = pbkdf2.Key(sha256.New, password, salt, 4, 32)
		params = map[string]any{"dklen": 32, "c": 4, "prf": "hmac-sha256", "salt": hex.EncodeToString(salt)}
	}
	if err != nil {
		t.Fatal(err)
	}
	blk, err := aes.NewCipher(dk[:16])
	if err != nil {
		t.Fatal(err)
	}
	ct := make([]byte, 32)
	cipher.NewCTR(blk, iv).XORKeyStream(ct, sk[:])
	sum := sha256.Sum256(append(slices.Clone(dk[16:32]), ct...))
	ks := map[string]any{
		"crypto": map[string]any{
			"kdf":      map[string]any{"function": kdf, "params": params, "message": ""},
			"checksum": map[string]any{"function": "sha256", "params": map[string]any{}, "message": hex.EncodeToString(sum[:])},
			"cipher":   map[string]any{"function": "aes-128-ctr", "params": map[string]any{"iv": hex.EncodeToString(iv)}, "message": hex.EncodeToString(ct)},
		},
		"pubkey":  hex.EncodeToString(pk[:]),
		"path":    "m/12381/3600/0/0/0",
		"uuid":    "00000000-0000-4000-8000-000000000000",
		"version": 4,
	}
	writeJSONFile(t, filepath.Join(dir, "keystore-"+name+".json"), ks)
	return pk
}

// splitEnv is a folder of keystores, their password file and an output
// path, with the tmpfs check off.
type splitEnv struct {
	dir, ks, pass, out string
	pks                []cloud.Pubkey
}

func newSplitEnv(t *testing.T, kdfs ...string) *splitEnv {
	t.Helper()
	oldFS, oldSwaps := splitOutFS, splitSwaps
	t.Cleanup(func() { splitOutFS, splitSwaps = oldFS, oldSwaps })
	e := &splitEnv{dir: t.TempDir()}
	splitOutFS = func(string) error { return nil }
	// No swap, whatever the test host has.
	splitSwaps = writeFile(t, filepath.Join(e.dir, "swaps"), "Filename\tType\tSize\tUsed\tPriority\n")
	e.ks = filepath.Join(e.dir, "keys")
	if err := os.Mkdir(e.ks, 0o700); err != nil {
		t.Fatal(err)
	}
	for i, kdf := range kdfs {
		e.pks = append(e.pks, writeKeystore(t, e.ks, string(rune('a'+i)), kdf, splitTestPassword))
	}
	e.pass = writePrivate(t, filepath.Join(e.dir, "password.txt"), splitTestPassword+"\n")
	e.out = filepath.Join(e.dir, "out")
	return e
}

func (e *splitEnv) args(extra ...string) []string {
	return append([]string{"split", "-keystores", e.ks, "-password-file", e.pass, "-out", e.out}, extra...)
}

// writePrivate writes a file with mode 0600, as split wants its password
// file.
func writePrivate(t *testing.T, path, text string) string {
	t.Helper()
	writeFile(t, path, text)
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeExpect(t *testing.T, dir string, pks ...cloud.Pubkey) string {
	t.Helper()
	var b strings.Builder
	for _, pk := range pks {
		b.WriteString(pk.String() + "\n")
	}
	return writeFile(t, filepath.Join(dir, "expect.txt"), b.String())
}

// split writes files that import-draft and import read: every t-subset of
// the shares recovers each key, the share pubkeys are on the commitments,
// the shares file is private and import-draft takes the split.
func TestSplitKeystores(t *testing.T) {
	e := newSplitEnv(t, "scrypt", "pbkdf2", "scrypt")
	// The order of -expect, not of the files.
	want := []cloud.Pubkey{e.pks[2], e.pks[0], e.pks[1]}
	names := []string{"s1", "s2", "s3", "s4"}
	out := mustTool(t, e.args("-t", "3", "-n", "4", "-signers", strings.Join(names, ","), "-expect", writeExpect(t, e.dir, want...))...)
	wantIn(t, out, "key 1: "+want[0].String(), "key 3: "+want[2].String(), "split 3 keys 3 of 4", "wrote "+e.out)

	sf, err := readSplit(filepath.Join(e.out, "split.json"))
	if err != nil {
		t.Fatal(err)
	}
	if sf.T != 3 || sf.N != 4 || len(sf.Validators) != 3 {
		t.Fatalf("split.json: %d of %d, %d validators", sf.T, sf.N, len(sf.Validators))
	}
	for i, name := range names {
		if sf.Shares[name] != uint8(i+1) {
			t.Fatalf("split.json: %s has share index %d", name, sf.Shares[name])
		}
	}
	shares := map[string][]share{}
	for _, name := range names {
		p := filepath.Join(e.out, "shares", name, "shares.txt")
		if err := adminapprover.CheckPrivateFile(p); err != nil {
			t.Fatal(err)
		}
		s, err := readShares(p)
		if err != nil {
			t.Fatal(err)
		}
		shares[name] = s
	}
	for v, pk := range want {
		if sf.Validators[v].Pubkey != pk {
			t.Fatalf("validator %d is %s, want %s", v+1, sf.Validators[v].Pubkey, pk)
		}
		pubs := make([]cloud.Pubkey, len(names))
		for i, name := range names {
			s := shares[name][v]
			if s.pubkey != pk || s.index != cloud.IndexUnknown {
				t.Fatalf("%s line %d: %s index %d", name, v+1, s.pubkey, s.index)
			}
			sp, err := core.PubkeyOf(s.secret)
			if err != nil || sp != s.sharePub {
				t.Fatalf("%s line %d: the share pubkey is not the secret's", name, v+1)
			}
			if f, err := threshold.FeldmanEval(sf.Validators[v].Commitments, uint64(i+1)); err != nil || f != sp {
				t.Fatalf("%s line %d: not on the commitments", name, v+1)
			}
			pubs[i] = sp
		}
		for _, set := range [][]int{{0, 1, 2}, {0, 1, 3}, {0, 2, 3}, {1, 2, 3}} {
			var ids []uint64
			var ps []cloud.Pubkey
			for _, i := range set {
				ids, ps = append(ids, uint64(i+1)), append(ps, pubs[i])
			}
			if got, err := threshold.RecoverPubkey(ids, ps); err != nil || got != pk {
				t.Fatalf("validator %d: shares %v do not recover the key", v+1, ids)
			}
		}
	}

	raw, err := os.ReadFile(filepath.Join(e.out, "split.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m struct {
		SplitSHA   string `json:"split_sha256"`
		Validators []struct {
			Pubkey       cloud.Pubkey            `json:"pubkey"`
			SharePubkeys map[string]cloud.Pubkey `json:"share_pubkeys"`
		} `json:"validators"`
	}
	mraw, err := os.ReadFile(filepath.Join(e.out, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(mraw, &m); err != nil {
		t.Fatal(err)
	}
	if sum := sha256.Sum256(raw); m.SplitSHA != hex.EncodeToString(sum[:]) || len(m.Validators) != 3 ||
		m.Validators[1].SharePubkeys["s3"] != shares["s3"][1].sharePub {
		t.Fatalf("manifest.json does not match:\n%s", mraw)
	}

	fc := newFakeCluster(t)
	mustTool(t, "pin", "-cluster", fc.cluster)
	out = mustTool(t, "import-draft", "-cluster", fc.cluster, "-signer", "s2", "-split", filepath.Join(e.out, "split.json"), "-out", fc.path("import.bin"))
	wantIn(t, out, "3 validators, 3 of 4, share index 2")
}

// A 1 of 1 split for a single-node signer: commitment 0 is the key and
// the only commitment, the share at index 1 is the whole key, and
// import-draft takes the split for a signer with signing_mode = single
// and refuses it for one with signing_mode = threshold. The default chain
// is mainnet, where 1 of 1 passes the threshold rule.
func TestSplitSingle(t *testing.T) {
	e := newSplitEnv(t, "scrypt", "pbkdf2")
	out := mustTool(t, e.args("-t", "1", "-n", "1", "-signers", "x1")...)
	wantIn(t, out, "split 2 keys 1 of 1; share indices x1")

	splitPath := filepath.Join(e.out, "split.json")
	sf, err := readSplit(splitPath)
	if err != nil {
		t.Fatal(err)
	}
	if sf.T != 1 || sf.N != 1 || len(sf.Shares) != 1 || sf.Shares["x1"] != 1 || len(sf.Validators) != 2 {
		t.Fatalf("split.json: %d of %d, shares %v, %d validators", sf.T, sf.N, sf.Shares, len(sf.Validators))
	}
	p := filepath.Join(e.out, "shares", "x1", "shares.txt")
	if err := adminapprover.CheckPrivateFile(p); err != nil {
		t.Fatal(err)
	}
	shares, err := readShares(p)
	if err != nil {
		t.Fatal(err)
	}
	for v, pk := range e.pks {
		if c := sf.Validators[v].Commitments; sf.Validators[v].Pubkey != pk || len(c) != 1 || c[0] != pk {
			t.Fatalf("validator %d: %s with commitments %v, want %s alone", v+1, sf.Validators[v].Pubkey, c, pk)
		}
		s := shares[v]
		sp, err := core.PubkeyOf(s.secret)
		if err != nil || s.pubkey != pk || sp != pk || s.sharePub != pk {
			t.Fatalf("line %d: the share is not the whole key %s", v+1, pk)
		}
		if got, err := threshold.RecoverPubkey([]uint64{1}, []cloud.Pubkey{sp}); err != nil || got != pk {
			t.Fatalf("validator %d: share 1 does not recover the key", v+1)
		}
	}

	// A single-mode signer named x1.
	dir := t.TempDir()
	conf := writeFile(t, filepath.Join(dir, "setup.conf"), setupText(dir, caDER(t), genesisTime(), lockedText(approvers(t, dir, 3), 2, 0, fee1), "x1"))
	mustTool(t, "setup", "-out", filepath.Join(dir, "setups"), conf)
	r := fakerunner.StartSetup(t, mustRead(t, filepath.Join(dir, "setups", "x1.setup")))
	cert, key := r.ClientFiles(t, t.TempDir())
	writeJSONFile(t, filepath.Join(dir, "x1", "cloud.json"), map[string]any{
		"address": r.Addr(), "client_cert": cert, "client_key": key, "attestation": map[string]any{"verifier": "dev"}})
	cl := writeJSONFile(t, filepath.Join(dir, "cluster.json"), map[string]any{
		"signers": []any{map[string]string{"name": "x1", "cloud": "x1/cloud.json", "setup": "setups/x1.setup"}}})
	mustTool(t, "pin", "-cluster", cl)
	out = mustTool(t, "import-draft", "-cluster", cl, "-signer", "x1", "-split", splitPath, "-out", filepath.Join(dir, "import.bin"))
	wantIn(t, out, "signing_mode single", "2 validators, 1 of 1, share index 1")

	// A threshold-mode signer named x1 refuses the same split.
	fc := newFakeCluster(t)
	mustTool(t, "pin", "-cluster", fc.cluster)
	e2 := newSplitEnv(t, "scrypt")
	mustTool(t, e2.args("-t", "1", "-n", "1", "-signers", "s1")...)
	wantIn(t, failTool(t, "import-draft", "-cluster", fc.cluster, "-signer", "s1", "-split", filepath.Join(e2.out, "split.json"), "-out", fc.path("import.bin")),
		"signing_mode = threshold")
}

// Without -expect, split takes every keystore and lists it.
func TestSplitAllKeystores(t *testing.T) {
	e := newSplitEnv(t, "scrypt", "pbkdf2")
	out := mustTool(t, e.args("-chain", "devnet", "-t", "2", "-n", "3", "-signers", "a,b,c")...)
	wantIn(t, out, "key 1: "+e.pks[0].String()+" (keystore-a.json)", "key 2: "+e.pks[1].String()+" (keystore-b.json)", "split 2 keys 2 of 3")
	if _, err := readSplit(filepath.Join(e.out, "split.json")); err != nil {
		t.Fatal(err)
	}
}

// split refuses a wrong password, a changed keystore, a key set that is not
// the one of -expect, an output that exists or is not on tmpfs, and a t or
// n that import-draft would refuse. Nothing is written then.
func TestSplitRefuses(t *testing.T) {
	tn := []string{"-t", "3", "-n", "4", "-signers", "s1,s2,s3,s4"}
	edit := func(t *testing.T, e *splitEnv, f func(map[string]any)) {
		t.Helper()
		p := filepath.Join(e.ks, "keystore-a.json")
		raw, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		var ks map[string]any
		if err := json.Unmarshal(raw, &ks); err != nil {
			t.Fatal(err)
		}
		f(ks)
		writeJSONFile(t, p, ks)
	}
	cases := []struct {
		name string
		args func(t *testing.T, e *splitEnv) []string
		want string
	}{
		{"wrong password", func(t *testing.T, e *splitEnv) []string {
			writePrivate(t, e.pass, "another password\n")
			return e.args(tn...)
		}, "checksum mismatch (wrong password?)"},
		{"checksum", func(t *testing.T, e *splitEnv) []string {
			edit(t, e, func(ks map[string]any) {
				c := ks["crypto"].(map[string]any)["checksum"].(map[string]any)
				c["message"] = strings.Repeat("00", 32)
			})
			return e.args(tn...)
		}, "checksum mismatch"},
		{"pubkey", func(t *testing.T, e *splitEnv) []string {
			edit(t, e, func(ks map[string]any) { ks["pubkey"] = strings.TrimPrefix(e.pks[1].String(), "0x") })
			return e.args(tn...)
		}, "is not the keystore's pubkey"},
		{"kdf", func(t *testing.T, e *splitEnv) []string {
			edit(t, e, func(ks map[string]any) { ks["crypto"].(map[string]any)["kdf"].(map[string]any)["function"] = "argon2" })
			return e.args(tn...)
		}, `kdf "argon2", want scrypt or pbkdf2`},
		{"key not expected", func(t *testing.T, e *splitEnv) []string {
			return e.args(append(tn, "-expect", writeExpect(t, e.dir, e.pks[0]))...)
		}, "refusing to split it"},
		{"expected key missing", func(t *testing.T, e *splitEnv) []string {
			other := e.pks[0]
			other[47] ^= 1
			return e.args(append(tn, "-expect", writeExpect(t, e.dir, e.pks[0], e.pks[1], other))...)
		}, "which no keystore in"},
		{"out exists", func(t *testing.T, e *splitEnv) []string {
			if err := os.Mkdir(e.out, 0o700); err != nil {
				t.Fatal(err)
			}
			return e.args(tn...)
		}, "exists; split writes a new folder"},
		{"not tmpfs", func(t *testing.T, e *splitEnv) []string {
			splitOutFS = func(dir string) error { return checkTmpfs(dir) }
			if checkTmpfs(e.dir) == nil {
				t.Skip("the test folder is on tmpfs")
			}
			return e.args(tn...)
		}, "is not on tmpfs"},
		{"2 of 3 on mainnet", func(t *testing.T, e *splitEnv) []string {
			return e.args("-t", "2", "-n", "3", "-signers", "s1,s2,s3")
		}, "on a prod chain"},
		{"half", func(t *testing.T, e *splitEnv) []string {
			return e.args("-chain", "devnet", "-t", "2", "-n", "4", "-signers", "s1,s2,s3,s4")
		}, "want more than half"},
		{"signer twice", func(t *testing.T, e *splitEnv) []string {
			return e.args("-t", "3", "-n", "4", "-signers", "s1,s2,s3,s1")
		}, "s1 twice"},
		{"signer path", func(t *testing.T, e *splitEnv) []string {
			return e.args("-t", "3", "-n", "4", "-signers", "s1,s2,s3,../s4")
		}, `name "../s4"`},
		{"names and n", func(t *testing.T, e *splitEnv) []string {
			return e.args("-t", "3", "-n", "4", "-signers", "s1,s2,s3")
		}, "-signers has 3 names, -n is 4"},
		{"1 of 1 with two signers", func(t *testing.T, e *splitEnv) []string {
			return e.args("-t", "1", "-n", "1", "-signers", "s1,s2")
		}, "-signers has 2 names, -n is 1"},
		{"1 of 2", func(t *testing.T, e *splitEnv) []string {
			return e.args("-t", "1", "-n", "2", "-signers", "s1,s2")
		}, "threshold 1 of 2: want more than half"},
		{"1 of 3 on devnet", func(t *testing.T, e *splitEnv) []string {
			return e.args("-chain", "devnet", "-t", "1", "-n", "3", "-signers", "s1,s2,s3")
		}, "threshold 1 of 3: want more than half"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newSplitEnv(t, "scrypt", "pbkdf2")
			args := c.args(t, e)
			_, existed := os.Lstat(e.out)
			wantIn(t, failTool(t, args...), c.want)
			if existed != nil {
				if _, err := os.Lstat(e.out); err == nil {
					t.Fatalf("%s was written", e.out)
				}
			}
		})
	}
}

// setKDFParam sets one kdf param of the keystore at path.
func setKDFParam(t *testing.T, path, key string, v any) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var ks map[string]any
	if err := json.Unmarshal(raw, &ks); err != nil {
		t.Fatal(err)
	}
	ks["crypto"].(map[string]any)["kdf"].(map[string]any)["params"].(map[string]any)[key] = v
	writeJSONFile(t, path, ks)
}

// decryptKeystore refuses kdf costs above its bounds before it runs the
// kdf: scrypt work n*r*p above 2^24 (p alone can ask for 128*r*p bytes)
// and pbkdf2 c above 2^24. The EIP-2335 defaults (scrypt n 2^18, r 8, p 1;
// pbkdf2 c 2^18) pass, as TestSplitEIP2335Vectors shows.
func TestSplitKDFBounds(t *testing.T) {
	for _, c := range []struct {
		name, kdf, key string
		v              any
		want           string
	}{
		{"scrypt p", "scrypt", "p", 1 << 18, "scrypt n 16, r 8, p 262144: out of range"},
		{"pbkdf2 c", "pbkdf2", "c", 1<<24 + 1, "want hmac-sha256 and 1 <= c <= 2^24"},
	} {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			writeKeystore(t, dir, "a", c.kdf, splitTestPassword)
			p := filepath.Join(dir, "keystore-a.json")
			setKDFParam(t, p, c.key, c.v)
			var sk [32]byte
			_, err := decryptKeystore(p, []byte(splitTestPassword), &sk)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("got %v, want %q", err, c.want)
			}
		})
	}
}

// split takes at most 16 shares.
func TestSplitShareCap(t *testing.T) {
	e := newSplitEnv(t, "scrypt")
	var names []string
	for i := 1; i <= 17; i++ {
		names = append(names, fmt.Sprintf("s%d", i))
	}
	wantIn(t, failTool(t, e.args("-chain", "devnet", "-t", "17", "-n", "17", "-signers", strings.Join(names, ","))...), "-n 17: at most 16 shares")
	if _, err := os.Lstat(e.out); err == nil {
		t.Fatalf("%s was written", e.out)
	}
}

// split refuses a password file that others can read, or that is not a
// regular file, as the other secret inputs of signer-admin.
func TestSplitPasswordFileMode(t *testing.T) {
	e := newSplitEnv(t, "scrypt")
	if err := os.Chmod(e.pass, 0o640); err != nil {
		t.Fatal(err)
	}
	tn := []string{"-chain", "devnet", "-t", "2", "-n", "3", "-signers", "a,b,c"}
	wantIn(t, failTool(t, e.args(tn...)...), "has mode 0640")
	e.pass = e.ks
	wantIn(t, failTool(t, e.args(tn...)...), "is not a regular file")
}

// checkDealt recovers the key once, from the first t shares; the
// commitments and the Feldman check of each share prove the rest. Every
// t-subset was C(n, t) recoveries.
func TestSplitDealtRecoversOnce(t *testing.T) {
	sk, err := software.NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	pk, err := core.PubkeyOf(sk)
	if err != nil {
		t.Fatal(err)
	}
	shares, comm, err := software.SplitWithCommitments(sk, 3, 5)
	if err != nil {
		t.Fatal(err)
	}
	var calls [][]uint64
	old := splitRecover
	splitRecover = func(ids []uint64, ps []cloud.Pubkey) (cloud.Pubkey, error) {
		calls = append(calls, slices.Clone(ids))
		return old(ids, ps)
	}
	t.Cleanup(func() { splitRecover = old })
	pubs, err := checkDealt(pk, shares, comm, 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(calls) != 1 || !slices.Equal(calls[0], []uint64{1, 2, 3}) {
		t.Fatalf("recoveries %v, want one of shares [1 2 3]", calls)
	}
	for i, s := range shares {
		if sp, err := core.PubkeyOf(s.Secret); err != nil || pubs[i] != sp {
			t.Fatalf("share %d: pubkey %s is not the share's", i+1, pubs[i])
		}
	}
}

// captureStderr runs f and returns what it wrote to os.Stderr.
func captureStderr(t *testing.T, f func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stderr
	os.Stderr = w
	done := make(chan []byte)
	go func() { b, _ := io.ReadAll(r); done <- b }()
	f()
	os.Stderr = old
	w.Close()
	return string(<-done)
}

// A dealt split that does not check out (a wrong commitment, a short
// commitment list, a share that is not on the commitments) fails split
// after it made the output folder, and split removes the folder. Share 3
// is outside the recovery of shares 1 and 2, so only its Feldman check
// catches it.
func TestSplitDealtRefusedRemovesOut(t *testing.T) {
	for _, c := range []struct {
		name   string
		tamper func(shares []software.Share, comm []cloud.Pubkey) []cloud.Pubkey
		want   string
	}{
		{"commitment 0", func(_ []software.Share, comm []cloud.Pubkey) []cloud.Pubkey {
			comm[0] = comm[1]
			return comm
		}, "commitment 0 is not the key"},
		{"short commitments", func(_ []software.Share, comm []cloud.Pubkey) []cloud.Pubkey {
			return comm[:1]
		}, "commitment 0 is not the key"},
		{"commitment 1", func(_ []software.Share, comm []cloud.Pubkey) []cloud.Pubkey {
			comm[1] = comm[0]
			return comm
		}, "share 1 is not on the commitments"},
		{"share 3", func(shares []software.Share, comm []cloud.Pubkey) []cloud.Pubkey {
			shares[2].Secret = shares[0].Secret
			return comm
		}, "share 3 is not on the commitments"},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := newSplitEnv(t, "scrypt", "pbkdf2")
			old := splitDeal
			dealt := 0
			splitDeal = func(secret [32]byte, tt, n int) ([]software.Share, []cloud.Pubkey, error) {
				shares, comm, err := old(secret, tt, n)
				// The second key, so the first one's shares are in memory.
				if dealt++; dealt == 2 && err == nil {
					comm = c.tamper(shares, comm)
				}
				return shares, comm, err
			}
			t.Cleanup(func() { splitDeal = old })
			wantIn(t, failTool(t, e.args("-chain", "devnet", "-t", "2", "-n", "3", "-signers", "a,b,c")...), e.pks[1].String()+": "+c.want)
			if dealt != 2 {
				t.Fatalf("dealt %d keys, want 2", dealt)
			}
			if _, err := os.Lstat(e.out); !os.IsNotExist(err) {
				t.Fatalf("%s is left after the failure: %v", e.out, err)
			}
		})
	}
}
