package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/attestation-verify/runnerclient"
	"github.com/lidofinance/tee-signer/governance/setupwire"
	"github.com/lidofinance/tee-signer/signer-core/core"
	"github.com/lidofinance/tee-signer/signer-core/threshold"
	cloud "github.com/lidofinance/tee-signer/signer-protocol"
)

// The test vectors of EIP-2335 ("Test Cases"). Their password is
// "𝔱𝔢𝔰𝔱𝔭𝔞𝔰𝔰𝔴𝔬𝔯𝔡🔑", which is "testpassword🔑" after NFKD.
const (
	eipSecret   = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
	eipPubkey   = "9612d7a727c9d0a22e185a1c768478dfe919cada9266988cb32359c11f2b7b27f4ae4040902382ae2910c15e2b420d07"
	eipPassword = "𝔱𝔢𝔰𝔱𝔭𝔞𝔰𝔰𝔴𝔬𝔯𝔡🔑"
	eipEncoded  = "testpassword\xf0\x9f\x94\x91"

	eipScrypt = `{
    "crypto": {
        "kdf": {"function": "scrypt", "params": {"dklen": 32, "n": 262144, "p": 1, "r": 8,
            "salt": "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"}, "message": ""},
        "checksum": {"function": "sha256", "params": {}, "message": "d2217fe5f3e9a1e34581ef8a78f7c9928e436d36dacc5e846690a5581e8ea484"},
        "cipher": {"function": "aes-128-ctr", "params": {"iv": "264daa3f303d7259501c93d997d84fe6"},
            "message": "06ae90d55fe0a6e9c5c3bc5b170827b2e5cce3929ed3f116c2811e6366dfe20f"}
    },
    "description": "This is a test keystore that uses scrypt to secure the secret.",
    "pubkey": "9612d7a727c9d0a22e185a1c768478dfe919cada9266988cb32359c11f2b7b27f4ae4040902382ae2910c15e2b420d07",
    "path": "m/12381/60/3141592653/589793238",
    "uuid": "1d85ae20-35c5-4611-98e8-aa14a633906f",
    "version": 4
}`
	eipPBKDF2 = `{
    "crypto": {
        "kdf": {"function": "pbkdf2", "params": {"dklen": 32, "c": 262144, "prf": "hmac-sha256",
            "salt": "d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3"}, "message": ""},
        "checksum": {"function": "sha256", "params": {}, "message": "8a9f5d9912ed7e75ea794bc5a89bca5f193721d30868ade6f73043c6ea6febf1"},
        "cipher": {"function": "aes-128-ctr", "params": {"iv": "264daa3f303d7259501c93d997d84fe6"},
            "message": "cee03fde2af33149775b7223e7845e4fb2c8ae1792e5f99fe9ecf474cc8c16ad"}
    },
    "description": "This is a test keystore that uses PBKDF2 to secure the secret.",
    "pubkey": "9612d7a727c9d0a22e185a1c768478dfe919cada9266988cb32359c11f2b7b27f4ae4040902382ae2910c15e2b420d07",
    "path": "m/12381/60/0/0",
    "uuid": "64625def-3331-4eea-ab6f-782f3ed16a83",
    "version": 4
}`
)

// decryptKeystore opens both EIP-2335 vectors with the encoded password and
// gets the vector's secret and pubkey. split refuses the vector's own
// password, which is not printable ASCII and needs NFKD.
func TestSplitEIP2335Vectors(t *testing.T) {
	dir := t.TempDir()
	for name, ks := range map[string]string{"scrypt": eipScrypt, "pbkdf2": eipPBKDF2} {
		t.Run(name, func(t *testing.T) {
			p := writeFile(t, filepath.Join(dir, name, "keystore-"+name+".json"), ks)
			secret, pub, err := decryptKeystore(p, []byte(eipEncoded))
			if err != nil {
				t.Fatal(err)
			}
			if fmt.Sprintf("%x", secret) != eipSecret || pub.String() != "0x"+eipPubkey {
				t.Fatalf("secret %x, pubkey %s", secret, pub)
			}
			if _, _, err := decryptKeystore(p, []byte("testpassword")); err == nil {
				t.Fatal("another password opened the keystore")
			}
		})
	}
	splitOutFS = func(string) error { return nil }
	t.Cleanup(func() { splitOutFS = checkTmpfs })
	pass := writePrivate(t, filepath.Join(dir, "password.txt"), eipPassword+"\n")
	wantIn(t, failTool(t, "split", "-keystores", filepath.Join(dir, "scrypt"), "-password-file", pass, "-chain", "devnet",
		"-t", "2", "-n", "3", "-signers", "a,b,c", "-out", filepath.Join(dir, "out")), "outside printable ASCII")
}

// The split track against three dev runners of this repo: split two new
// keys 2 of 3, then per signer import-draft, sign, assemble and import of
// its shares file. Each runner lists the share pubkey of the split for
// each key, two runners sign a RANDAO reveal, and the two partial
// signatures combine into a signature that verifies under the validator
// key.
//
// SIGNER_ADMIN_RUNNER names a dev runner binary of this repo (go build
// -tags platform_dev in tee-signer/); without it the test is skipped.
func TestSplitDevRunners(t *testing.T) {
	splitDevRunners(t, names, 2, []string{"s1", "s3"})
}

// The same track for a single-node signer: split the keys 1 of 1 for one
// dev runner whose setup says signing_mode = single. It holds each whole
// key (share pubkey = validator key) and its RANDAO reveal verifies under
// the validator key.
func TestSplitDevRunnerSingle(t *testing.T) {
	splitDevRunners(t, []string{"x1"}, 1, []string{"x1"})
}

// splitDevRunners runs the split track with one dev runner per name of
// signerNames (one name: a single-mode setup, more: threshold), a split
// tt of len(signerNames), and RANDAO reveals by the signers of signing.
func splitDevRunners(t *testing.T, signerNames []string, tt int, signing []string) {
	t.Helper()
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
	conf := writeFile(t, filepath.Join(dir, "setup.conf"), setupText(dir, ca, genesis, lockedText(keys, 2, 0, fee1), signerNames...))
	hashes := setupHashes(mustTool(t, "setup", "-out", filepath.Join(dir, "setups"), conf))

	var signers []map[string]string
	for _, n := range signerNames {
		addr := fmt.Sprintf("127.0.0.1:%d", freePort(t))
		logPath := writeFile(t, filepath.Join(dir, n, "runner.log"), "")
		f, err := os.OpenFile(logPath, os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(bin, "-platform", "dev", "-state-dir", filepath.Join(dir, n, "state"), "-listen", "tcp:"+addr,
			"-setup", "file:"+filepath.Join(dir, "setups", n+".setup"))
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
		for _, c := range []struct{ name, cert, key string }{{n, cert, key}, {n + "-lane", signCert, signKey}} {
			writeJSONFile(t, filepath.Join(dir, c.name, "cloud.json"), map[string]any{
				"address": "tcp:" + addr, "client_cert": c.cert, "client_key": c.key,
				"attestation": map[string]any{"verifier": "dev", "setup_sha256": hashes[n]},
			})
		}
		signers = append(signers, map[string]string{"name": n, "cloud": n + "/cloud.json", "setup": "setups/" + n + ".setup"})
	}
	cl := writeJSONFile(t, filepath.Join(dir, "cluster.json"), map[string]any{"signers": signers})

	e := newSplitEnv(t, "scrypt", "pbkdf2")
	out := mustTool(t, e.args("-chain", "ci-test", "-t", strconv.Itoa(tt), "-n", strconv.Itoa(len(signerNames)),
		"-signers", strings.Join(signerNames, ","))...)
	t.Logf("signer-admin split\n%s", out)
	splitPath := filepath.Join(e.out, "split.json")
	sf, err := readSplit(splitPath)
	if err != nil {
		t.Fatal(err)
	}

	for _, n := range signerNames {
		body := filepath.Join(dir, n, "import.bin")
		mustTool(t, "import-draft", "-cluster", cl, "-signer", n, "-split", splitPath, "-out", body)
		mustTool(t, "show", body)
		var sigs []string
		for _, i := range []int{0, 2} {
			mustTool(t, "sign", "-key", keys[i].file, "-expect-sha256", expectOf(t, body), body)
			sigs = append(sigs, fmt.Sprintf("%s.%s.sig", body, keys[i].pub[2:10]))
		}
		signed := filepath.Join(dir, n, "import.signed")
		mustTool(t, append([]string{"assemble", "-out", signed, body}, sigs...)...)
		out := mustTool(t, "import", "-cluster", cl, "-signer", n, "-order", signed,
			"-shares", filepath.Join(e.out, "shares", n, "shares.txt"), "-commitments", splitPath)
		t.Logf("import %s\n%s", n, out)
		for _, pk := range e.pks {
			wantIn(t, out, n+" imported "+pk.String())
		}
	}

	setup, err := setupwire.DecodeSetup(mustRead(t, filepath.Join(dir, "setups", signerNames[0]+".setup")))
	if err != nil {
		t.Fatal(err)
	}
	cfg := core.Config{GenesisValidatorsRoot: setup.Chain.GenesisValidatorsRoot, GenesisForkVersion: setup.Chain.GenesisForkVersion,
		SlotsPerEpoch: setup.Chain.SlotsPerEpoch}
	for _, f := range setup.Open.ForkSchedule {
		cfg.Forks = append(cfg.Forks, core.Fork{Epoch: f.Epoch, Version: f.Version})
	}
	epoch := uint64(time.Now().Unix()-genesis) / (secondsPerSlot * slotsPerEpoch)
	ctx := context.Background()
	partial := map[string]map[cloud.Pubkey]cloud.Signature{}
	for i, n := range signerNames {
		conn, err := loadConn(filepath.Join(dir, n+"-lane", "cloud.json"))
		if err != nil {
			t.Fatal(err)
		}
		lane, err := conn.New(runnerclient.WithTimeout(10 * time.Second))
		if err != nil {
			t.Fatal(err)
		}
		defer lane.Close()
		held, err := lane.PublicKeys(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if len(held) != len(e.pks) {
			t.Fatalf("%s holds %d keys, want %d", n, len(held), len(e.pks))
		}
		for _, k := range held {
			v := slices.IndexFunc(sf.Validators, func(x splitValidator) bool { return x.Pubkey == k.Pubkey })
			if v < 0 {
				t.Fatalf("%s holds %s, which is not in the split", n, k.Pubkey)
			}
			want, err := threshold.FeldmanEval(sf.Validators[v].Commitments, uint64(i+1))
			if err != nil || k.SharePubkey != want {
				t.Fatalf("%s: share pubkey %s of %s, the split's is %s", n, k.SharePubkey, k.Pubkey, want)
			}
		}
		t.Logf("%s PUBLIC_KEYS: %d keys, share pubkeys match the split", n, len(held))
		if !slices.Contains(signing, n) {
			continue
		}
		partial[n] = map[cloud.Pubkey]cloud.Signature{}
		for _, pk := range e.pks {
			m := &cloud.RootMessage{Type: cloud.RootRandaoReveal, Epoch: epoch, ObjectRoot: cloud.HashTreeRootUint64(epoch),
				Domain: cfg.Domain(cloud.DomainRandao, epoch)}
			sig, err := lane.Sign(ctx, cloud.SignRequest{Pubkey: pk, Message: m, Domain: m.Domain})
			if err != nil {
				t.Fatalf("%s RANDAO for %s: %v", n, pk, err)
			}
			partial[n][pk] = sig
		}
	}
	for _, pk := range e.pks {
		m := &cloud.RootMessage{Type: cloud.RootRandaoReveal, Epoch: epoch, ObjectRoot: cloud.HashTreeRootUint64(epoch),
			Domain: cfg.Domain(cloud.DomainRandao, epoch)}
		root, err := cfg.SigningRoot(m)
		if err != nil {
			t.Fatal(err)
		}
		var ids []uint64
		var sigs []cloud.Signature
		for _, n := range signing {
			ids = append(ids, uint64(slices.Index(signerNames, n)+1))
			sigs = append(sigs, partial[n][pk])
		}
		sig, err := threshold.RecoverSignature(ids, sigs)
		if err != nil {
			t.Fatal(err)
		}
		if !core.Verify(pk, root, sig) {
			t.Fatalf("%s: the combined RANDAO signature of %v does not verify", pk, signing)
		}
		if tt == 1 && !core.Verify(pk, root, sigs[0]) {
			t.Fatalf("%s: the RANDAO signature of %s does not verify under the validator key", pk, signing[0])
		}
		t.Logf("%s: RANDAO epoch %d, signatures of %v combine into a valid signature", pk, epoch, signing)
	}
}
