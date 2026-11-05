package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"

	"golang.org/x/crypto/scrypt"

	"github.com/lidofinance/tee-signer/governance/runnerchain"
	"github.com/lidofinance/tee-signer/governance/setupwire"
	adminapprover "github.com/lidofinance/tee-signer/signer-admin/approver"
	"github.com/lidofinance/tee-signer/signer-core/core"
	"github.com/lidofinance/tee-signer/signer-core/software"
	"github.com/lidofinance/tee-signer/signer-core/threshold"
	cloud "github.com/lidofinance/tee-signer/signer-protocol"
)

// ---- split ----

const splitUsage = "usage: signer-admin split -keystores DIR -password-file FILE -t T -n N -signers NAME,... [-chain mainnet|hoodi|devnet|ci-test] [-expect FILE] -out DIR"

// splitOutFS checks that the output folder's parent is on tmpfs. Tests
// replace it.
var splitOutFS = checkTmpfs

// splitSwaps lists the active swap devices (proc(5)). Tests replace it.
var splitSwaps = "/proc/swaps"

// splitDeal and splitRecover are the dealer's split and the recovery of
// the key from shares. Tests replace them.
var (
	splitDeal    = software.SplitWithCommitments
	splitRecover = threshold.RecoverPubkey
)

// cmdSplit splits EIP-2335 keystores t of n as a trusted dealer: it
// decrypts each whole key, splits it with Feldman commitments, checks each
// share against the commitments and writes
//
//	OUT/split.json             public: the split file of import-draft and import
//	OUT/shares/NAME/shares.txt secret, mode 0600, one line per validator:
//	                           "0x<share secret> 0x<pubkey> - 0x<share pubkey>"
//	                           (readShares; the validator index is "-")
//	OUT/manifest.json          public: t, n, share indices, every share
//	                           pubkey and the sha256 of split.json
//
// OUT must be a new folder on tmpfs; split warns when swap is on. With
// -expect, exactly the listed keys are split, in that order, and every one
// must be found.
func cmdSplit(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("split", flag.ContinueOnError)
	ksDir := fs.String("keystores", "", "folder with the EIP-2335 keystores (keystore-*.json)")
	passFile := fs.String("password-file", "", "file with the one password of every keystore")
	t := fs.Int("t", 0, "threshold: shares needed to sign")
	n := fs.Int("n", 0, "number of shares, one per signer")
	signers := fs.String("signers", "", "signer names of cluster.json, comma separated, in share index order 1..n")
	chain := fs.String("chain", string(runnerchain.Mainnet), "the chain of the signers' setups: mainnet, hoodi, devnet or ci-test; t and n must pass its threshold rule")
	expect := fs.String("expect", "", "file with one 0xPUBKEY per line: exactly these keys are split, in this order")
	outDir := fs.String("out", "", "output folder: new, on tmpfs")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *ksDir == "" || *passFile == "" || *outDir == "" || *signers == "" || *t == 0 || *n == 0 {
		return errors.New(splitUsage)
	}
	names := strings.Split(*signers, ",")
	if len(names) != *n {
		return fmt.Errorf("-signers has %d names, -n is %d", len(names), *n)
	}
	if *n > 16 {
		return fmt.Errorf("-n %d: at most 16 shares", *n)
	}
	idx := map[string]uint8{}
	for i, name := range names {
		if !splitNameOK(name) {
			return fmt.Errorf("-signers: name %q: want letters, digits, '.', '_' or '-', not starting with '.'", name)
		}
		if _, ok := idx[name]; ok {
			return fmt.Errorf("-signers: %s twice", name)
		}
		idx[name] = uint8(i + 1)
	}
	c, err := runnerchain.Parse(*chain)
	if err != nil {
		return fmt.Errorf("-chain: %w", err)
	}
	row, ok := setupwire.ChainRowByName(string(c))
	if !ok {
		return fmt.Errorf("-chain %s: no row in the chain table", c)
	}
	// The chain's genesis validators root; zero for a row without one
	// (devnet, ci-test), which such a row takes.
	var root cloud.Root
	if row.Root != "" {
		if _, err := hex.Decode(root[:], []byte(row.Root)); err != nil {
			return fmt.Errorf("-chain %s: root: %w", c, err)
		}
	}
	// The rules import-draft applies to the split file.
	if err := setupwire.CheckThreshold(row.ForkVersion, root, *t, *n); err != nil {
		return err
	}
	if err := setupwire.CheckShareIndices(*n, idx); err != nil {
		return err
	}
	if _, err := os.Lstat(*outDir); err == nil {
		return fmt.Errorf("%s exists; split writes a new folder", *outDir)
	}
	if err := splitOutFS(filepath.Dir(*outDir)); err != nil {
		return err
	}
	warnSwap(splitSwaps)
	var want []cloud.Pubkey
	if *expect != "" {
		if want, err = readExpect(*expect); err != nil {
			return err
		}
	}

	keys, err := readKeystores(*ksDir, *passFile)
	defer func() {
		for i := range keys {
			clear(keys[i].secret[:])
		}
	}()
	if err != nil {
		return err
	}
	byPub := map[cloud.Pubkey]*dealtKey{}
	for i := range keys {
		k := &keys[i]
		if byPub[k.pub] != nil {
			return fmt.Errorf("%s: pubkey %s also in %s", k.source, k.pub, byPub[k.pub].source)
		}
		if *expect != "" && !slices.Contains(want, k.pub) {
			return fmt.Errorf("%s: pubkey %s is not in %s; refusing to split it", k.source, k.pub, *expect)
		}
		byPub[k.pub] = k
	}
	if *expect == "" {
		for _, k := range keys {
			want = append(want, k.pub)
		}
	} else {
		for _, pk := range want {
			if byPub[pk] == nil {
				return fmt.Errorf("%s lists %s, which no keystore in %s holds", *expect, pk, *ksDir)
			}
		}
	}
	for i, pk := range want {
		fprintf(out, "key %d: %s (%s)\n", i+1, pk, filepath.Base(byPub[pk].source))
	}

	if err := os.Mkdir(*outDir, 0o700); err != nil {
		return err
	}
	if err := writeSplit(*outDir, names, idx, *t, *n, want, byPub, out); err != nil {
		os.RemoveAll(*outDir)
		return err
	}
	return nil
}

// writeSplit splits each key and writes the three outputs into the new
// folder dir, then reads split.json and each shares.txt back with the
// readers of import-draft and import.
func writeSplit(dir string, names []string, idx map[string]uint8, t, n int, want []cloud.Pubkey, byPub map[cloud.Pubkey]*dealtKey, out io.Writer) error {
	if err := os.Mkdir(filepath.Join(dir, "shares"), 0o700); err != nil {
		return err
	}
	for _, name := range names {
		if err := os.Mkdir(filepath.Join(dir, "shares", name), 0o700); err != nil {
			return err
		}
	}
	type manifestValidator struct {
		Pubkey       cloud.Pubkey            `json:"pubkey"`
		SharePubkeys map[string]cloud.Pubkey `json:"share_pubkeys"`
	}
	manifest := struct {
		T          int                 `json:"t"`
		N          int                 `json:"n"`
		ShareIndex map[string]uint8    `json:"share_index"`
		Validators []manifestValidator `json:"validators"`
		SplitSHA   string              `json:"split_sha256"`
	}{T: t, N: n, ShareIndex: idx}
	sf := splitFile{T: uint8(t), N: uint8(n), Shares: idx}
	lines := make([][]byte, n)
	defer func() {
		for i := range lines {
			clear(lines[i])
		}
	}()
	for _, pk := range want {
		shares, comm, err := splitDeal(byPub[pk].secret, t, n)
		if err != nil {
			return fmt.Errorf("%s: %w", pk, err)
		}
		pubs, err := checkDealt(pk, shares, comm, t)
		if err != nil {
			for i := range shares {
				clear(shares[i].Secret[:])
			}
			return err
		}
		sf.Validators = append(sf.Validators, splitValidator{Pubkey: pk, Commitments: comm})
		mv := manifestValidator{Pubkey: pk, SharePubkeys: map[string]cloud.Pubkey{}}
		for i := range shares {
			lines[i] = fmt.Appendf(lines[i], "0x%x %s - %s\n", shares[i].Secret[:], pk, pubs[i])
			clear(shares[i].Secret[:])
			mv.SharePubkeys[names[i]] = pubs[i]
		}
		manifest.Validators = append(manifest.Validators, mv)
	}
	raw, err := json.MarshalIndent(&sf, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	splitPath := filepath.Join(dir, "split.json")
	if err := os.WriteFile(splitPath, raw, 0o644); err != nil {
		return err
	}
	sum := sha256.Sum256(raw)
	manifest.SplitSHA = hex.EncodeToString(sum[:])
	for i, name := range names {
		if err := os.WriteFile(filepath.Join(dir, "shares", name, "shares.txt"), lines[i], 0o600); err != nil {
			return err
		}
	}
	mraw, err := json.MarshalIndent(&manifest, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), append(mraw, '\n'), 0o644); err != nil {
		return err
	}

	// The outputs as import-draft and import read them.
	back, err := readSplit(splitPath)
	if err != nil {
		return fmt.Errorf("split.json does not read back: %w", err)
	}
	if len(back.Validators) != len(want) {
		return fmt.Errorf("split.json reads back with %d validators, want %d", len(back.Validators), len(want))
	}
	for _, name := range names {
		got, err := readShares(filepath.Join(dir, "shares", name, "shares.txt"))
		for i := range got {
			clear(got[i].secret[:])
		}
		if err != nil {
			return fmt.Errorf("shares of %s do not read back: %w", name, err)
		}
		if len(got) != len(want) {
			return fmt.Errorf("shares of %s read back with %d lines, want %d", name, len(got), len(want))
		}
		for i := range got {
			if got[i].pubkey != want[i] || got[i].sharePub != manifest.Validators[i].SharePubkeys[name] {
				return fmt.Errorf("shares of %s, line %d, do not read back", name, i+1)
			}
		}
	}
	fprintf(out, "split %d keys %d of %d; share indices %s; split_sha256 %s; wrote %s\n",
		len(want), t, n, strings.Join(names, ","), manifest.SplitSHA, dir)
	return nil
}

// checkDealt checks a split of the key pk: there are t commitments,
// commitment 0 is the key, the public key of each share is the value of
// the commitments at its index, and the first t shares recover the key.
// It returns the share public keys.
func checkDealt(pk cloud.Pubkey, shares []software.Share, comm []cloud.Pubkey, t int) ([]cloud.Pubkey, error) {
	if len(comm) != t || comm[0] != pk {
		return nil, fmt.Errorf("%s: commitment 0 is not the key", pk)
	}
	pubs := make([]cloud.Pubkey, len(shares))
	for i, s := range shares {
		sp, err := core.PubkeyOf(s.Secret)
		if err != nil {
			return nil, fmt.Errorf("%s: share %d: %w", pk, s.ID, err)
		}
		if f, err := threshold.FeldmanEval(comm, s.ID); err != nil || f != sp {
			return nil, fmt.Errorf("%s: share %d is not on the commitments", pk, s.ID)
		}
		pubs[i] = sp
	}
	// With every share on the t commitments, any t shares recover the key.
	// One recovery checks the share IDs and the recovery itself.
	ids := make([]uint64, t)
	for i := range ids {
		ids[i] = shares[i].ID
	}
	if got, err := splitRecover(ids, pubs[:t]); err != nil || got != pk {
		return nil, fmt.Errorf("%s: shares %v do not recover the key", pk, ids)
	}
	return pubs, nil
}

// splitNameOK reports whether a signer name is safe as a folder name.
func splitNameOK(name string) bool {
	if name == "" || name[0] == '.' {
		return false
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '_', r == '-':
		default:
			return false
		}
	}
	return true
}

// readExpect reads one 0x-hex pubkey per line; blank lines are skipped.
func readExpect(path string) ([]cloud.Pubkey, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []cloud.Pubkey
	sc := bufio.NewScanner(f)
	for ln := 1; sc.Scan(); ln++ {
		s := strings.TrimSpace(sc.Text())
		if s == "" {
			continue
		}
		pk, err := parseKeyHex(s)
		if err != nil {
			return nil, fmt.Errorf("%s:%d: %v", path, ln, err)
		}
		if slices.Contains(out, pk) {
			return nil, fmt.Errorf("%s:%d: %s twice", path, ln, pk)
		}
		out = append(out, pk)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%s: no pubkey", path)
	}
	return out, nil
}

func parseKeyHex(s string) (cloud.Pubkey, error) {
	var pk cloud.Pubkey
	b, err := hex.DecodeString(strings.TrimPrefix(strings.ToLower(s), "0x"))
	if err != nil || len(b) != len(pk) {
		return pk, fmt.Errorf("pubkey %q: want 48 bytes of hex", s)
	}
	copy(pk[:], b)
	return pk, nil
}

// ---- EIP-2335 keystores ----

type dealtKey struct {
	pub    cloud.Pubkey
	secret [32]byte
	source string
}

type keystoreFile struct {
	Crypto struct {
		KDF struct {
			Function string         `json:"function"`
			Params   map[string]any `json:"params"`
		} `json:"kdf"`
		Checksum struct {
			Function string `json:"function"`
			Message  string `json:"message"`
		} `json:"checksum"`
		Cipher struct {
			Function string `json:"function"`
			Params   struct {
				IV string `json:"iv"`
			} `json:"params"`
			Message string `json:"message"`
		} `json:"cipher"`
	} `json:"crypto"`
	Pubkey  string `json:"pubkey"`
	Version int    `json:"version"`
}

// readKeystores decrypts every keystore-*.json of dir with the password in
// passFile. On an error it returns the keys decrypted so far, so the caller
// can wipe them.
func readKeystores(dir, passFile string) ([]dealtKey, error) {
	fs, err := filepath.Glob(filepath.Join(dir, "keystore-*.json"))
	if err != nil {
		return nil, err
	}
	if len(fs) == 0 {
		return nil, fmt.Errorf("%s: no keystore-*.json", dir)
	}
	if err := adminapprover.CheckPrivateFile(passFile); err != nil {
		return nil, err
	}
	pass, err := os.ReadFile(passFile)
	if err != nil {
		return nil, err
	}
	defer clear(pass)
	pw := bytes.TrimRight(pass, "\r\n")
	if len(pw) == 0 {
		return nil, fmt.Errorf("%s: empty password", passFile)
	}
	// EIP-2335 takes the NFKD form of the password without control codes.
	// For printable ASCII that is the password itself.
	for _, b := range pw {
		if b < 0x20 || b > 0x7e {
			return nil, fmt.Errorf("%s: the password has characters outside printable ASCII, which this tool does not normalize", passFile)
		}
	}
	// Preallocated: an append that grows the slice would leave copies of
	// the secrets in the old array, out of reach of the caller's clear.
	keys := make([]dealtKey, 0, len(fs))
	for _, f := range fs {
		secret, pub, err := decryptKeystore(f, pw)
		if err != nil {
			return keys, err
		}
		keys = append(keys, dealtKey{pub: pub, secret: secret, source: f})
		clear(secret[:])
	}
	return keys, nil
}

// decryptKeystore decrypts one EIP-2335 keystore (version 4, kdf scrypt or
// pbkdf2 with hmac-sha256, checksum sha256, cipher aes-128-ctr) and checks
// that the secret's public key is the keystore's pubkey.
func decryptKeystore(path string, password []byte) (secret [32]byte, pub cloud.Pubkey, err error) {
	fail := func(format string, a ...any) ([32]byte, cloud.Pubkey, error) {
		clear(secret[:])
		return [32]byte{}, cloud.Pubkey{}, fmt.Errorf("%s: "+format, append([]any{path}, a...)...)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return secret, pub, err
	}
	var ks keystoreFile
	if err := json.Unmarshal(raw, &ks); err != nil {
		return fail("%v", err)
	}
	if ks.Version != 4 {
		return fail("keystore version %d, want 4", ks.Version)
	}
	c := &ks.Crypto
	p := c.KDF.Params
	salt, err := hex.DecodeString(ksString(p["salt"]))
	if err != nil || len(salt) == 0 {
		return fail("kdf salt: want hex")
	}
	if ksInt(p["dklen"]) != 32 {
		return fail("kdf dklen %v, want 32", p["dklen"])
	}
	var dk []byte
	switch c.KDF.Function {
	case "scrypt":
		n, r, par := ksInt(p["n"]), ksInt(p["r"]), ksInt(p["p"])
		// 128 * n * r bytes of memory, 128 * r * p more, and work n * r * p.
		// The EIP-2335 default is n * r * p = 2^21 (256 MiB); the cap is
		// 2^24.
		if n < 2 || r < 1 || par < 1 || n > 1<<24/r || par > 1<<24/(n*r) {
			return fail("scrypt n %d, r %d, p %d: out of range", n, r, par)
		}
		dk, err = scrypt.Key(password, salt, n, r, par, 32)
	case "pbkdf2":
		iter := ksInt(p["c"])
		// The EIP-2335 default is c = 2^18; the cap is 2^24.
		if ksString(p["prf"]) != "hmac-sha256" || iter < 1 || iter > 1<<24 {
			return fail("pbkdf2 prf %v, c %v: want hmac-sha256 and 1 <= c <= 2^24", p["prf"], p["c"])
		}
		dk, err = pbkdf2.Key(sha256.New, string(password), salt, iter, 32)
	default:
		return fail("kdf %q, want scrypt or pbkdf2", c.KDF.Function)
	}
	if err != nil {
		return fail("kdf: %v", err)
	}
	defer clear(dk)
	ct, err := hex.DecodeString(c.Cipher.Message)
	if err != nil {
		return fail("cipher message: want hex")
	}
	h := sha256.Sum256(append(slices.Clone(dk[16:32]), ct...))
	sum, err := hex.DecodeString(c.Checksum.Message)
	if c.Checksum.Function != "sha256" || err != nil || !slices.Equal(sum, h[:]) {
		return fail("checksum mismatch (wrong password?)")
	}
	if c.Cipher.Function != "aes-128-ctr" || len(ct) != 32 {
		return fail("cipher %s with %d bytes, want aes-128-ctr with 32", c.Cipher.Function, len(ct))
	}
	iv, err := hex.DecodeString(c.Cipher.Params.IV)
	if err != nil || len(iv) != aes.BlockSize {
		return fail("cipher iv: want 16 bytes of hex")
	}
	blk, err := aes.NewCipher(dk[:16])
	if err != nil {
		return fail("%v", err)
	}
	cipher.NewCTR(blk, iv).XORKeyStream(secret[:], ct)
	got, err := core.PubkeyOf(secret)
	if err != nil {
		return fail("secret: %v", err)
	}
	if want, err := parseKeyHex(ks.Pubkey); err != nil || want != got {
		return fail("the public key of the secret is not the keystore's pubkey")
	}
	return secret, got, nil
}

func ksString(v any) string { s, _ := v.(string); return s }

// ksInt is a JSON number that is a whole int, or -1.
func ksInt(v any) int {
	f, ok := v.(float64)
	if !ok || f != float64(int(f)) {
		return -1
	}
	return int(f)
}

// warnSwap prints a warning to stderr when the swaps file (/proc/swaps)
// lists an active swap device or cannot be read. With swap on, tmpfs
// pages and the heap, and the secrets in them, can reach a disk.
func warnSwap(path string) {
	raw, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "signer-admin split: warning: cannot read %s, so swap may be on; run swapoff -a first\n", path)
		return
	}
	// The first line is the header, each further line a swap device.
	var devs []string
	for i, l := range strings.Split(string(raw), "\n") {
		if f := strings.Fields(l); i > 0 && len(f) > 0 {
			devs = append(devs, f[0])
		}
	}
	if len(devs) > 0 {
		fmt.Fprintf(os.Stderr, "signer-admin split: warning: swap is on (%s), so secrets can reach a disk; run swapoff -a first\n", strings.Join(devs, ", "))
	}
}

// tmpfsMagic is the f_type of tmpfs (linux/magic.h).
const tmpfsMagic = 0x01021994

// checkTmpfs refuses a folder that is not on tmpfs, so the shares never
// reach a disk.
func checkTmpfs(dir string) error {
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return err
	}
	if int64(st.Type) != tmpfsMagic {
		return fmt.Errorf("%s is not on tmpfs; split writes the shares only to tmpfs", dir)
	}
	return nil
}
