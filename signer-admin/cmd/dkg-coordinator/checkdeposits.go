package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/lidofinance/tee-signer/signer-core/core"
	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/tee-signer/charonlock"
	"github.com/lidofinance/tee-signer/tee-signer/keygen"
)

// cmdCheckDeposits checks deposits before anyone sends them: those of
// `deposits` (Dirk path) or those inside a Charon lock (Charon path). The
// result file comes from the coordinator, which is not trusted, so the
// check asks the runners too (TKGARTIFACT-01): each runner of -config, over
// a connection attested with the policy's settings for its position, must
// answer the operator key the policy pins there and hold, for every key of
// the result, the share at its position with the public share the result
// names. A result of keys no runner holds is refused. Every deposit must be for a key of the result, one
// per key, with the policy's withdrawal credentials and the given amount,
// and its signature must verify under the validator key with the deposit
// domain of the chain's genesis fork version. The roots are recomputed. A
// lock must also pass Charon's own checks (hashes, shares, registrations,
// signature_aggregate) and carry the result's keys and shares. The checked
// deposits go to -out in the deposit-data.json format, in result order.
func cmdCheckDeposits(args []string) error {
	fs := flag.NewFlagSet("check-deposits", flag.ExitOnError)
	policyPath := fs.String("policy", "", "the key generation policy the runners loaded")
	orderPath := fs.String("order", "", "or: the DKG order of runners with a setup (signed, or its body)")
	lockedPath := fs.String("locked", "", "with -order: the signers' setup, or the locked update in force, for the withdrawal credentials and deposit amounts")
	platform := fs.String("platform", "", `platform the runners run on; "dev" allows the dev verifier in the policy`)
	resultPath := fs.String("result", "dkg-result.json", "the keygen result, or several comma-separated as one (same participants)")
	depositsPath := fs.String("deposits", "", "deposit-data.json from `deposits` (or -lock)")
	lockPath := fs.String("lock", "", "a Charon lock from `charon-lock` (or -deposits)")
	forkHex := fs.String("fork-version", "", "the chain's genesis fork version, 4 bytes hex")
	amount := fs.Uint64("amount", 32_000_000_000, "the deposit amount in gwei; one of the policy's amounts")
	network := fs.String("network-name", "", "network name for the output")
	outPath := fs.String("out", "", "where to write the checked deposits")
	configPath := fs.String("config", "", "coordinator config naming the runners of the result's participants, in share ID order: each must hold its shares of the result's keys")
	timeout := fs.Duration("timeout", 2*time.Minute, "time limit of each runner request")
	_ = fs.Parse(args)
	if (*depositsPath == "") == (*lockPath == "") {
		return errors.New("give -deposits or -lock")
	}
	if (*policyPath == "") == (*orderPath == "") || *outPath == "" {
		return errors.New("-policy or -order, and -out, are required")
	}
	if *orderPath != "" && *lockedPath == "" {
		return errors.New("-order needs -locked")
	}
	if *configPath == "" {
		return errors.New("-config is required: the result file is the coordinator's, and only the runners show that the DKG made its keys")
	}
	fork, err := parseFork(*forkHex)
	if err != nil {
		return err
	}
	var pol *keygen.Policy
	var polHash [32]byte
	if *orderPath != "" {
		pol, polHash, _, err = loadOrder(*orderPath, *lockedPath, *platform)
	} else {
		var raw []byte
		if raw, err = os.ReadFile(*policyPath); err == nil {
			pol, polHash, err = keygen.ParsePolicy(raw, *platform)
		}
	}
	if err != nil {
		return err
	}
	res, err := readResult(*resultPath, polHash)
	if err != nil {
		return err
	}
	var in []DepositData
	if *lockPath != "" {
		in, err = lockDeposits(*lockPath, pol, res, fork)
	} else {
		in, err = readDeposits(*depositsPath)
	}
	if err != nil {
		return err
	}
	out, err := checkDeposits(in, pol, res, fork, *amount)
	if err != nil {
		return err
	}
	cfg, err := readConfig(*configPath)
	if err != nil {
		return err
	}
	if err := checkRunners(context.Background(), cfg, pol, res, *timeout); err != nil {
		return err
	}
	for i := range out {
		out[i].NetworkName = *network
	}
	if err := writeJSON(*outPath, out); err != nil {
		return err
	}
	wc, _ := pol.WithdrawalCredentials()
	fmt.Fprintf(os.Stderr, "%d deposits checked: one per key of the result, every runner holds its shares of them, %d gwei, credentials %x, signatures verify under the validator keys (fork %x), roots recompute; in %s\n",
		len(out), *amount, wc[:], fork[:], *outPath)
	return nil
}

// checkRunners is runnersHold; the command's tests put the runners of
// their fixture in its place.
var checkRunners = runnersHold

// runnersHold asks each runner of cfg, attested with the policy's settings
// for its position, for its operator key and its loaded keys. The key must
// be the one the policy pins at that position, and the runner must hold
// every key of the result with the share at that position (heldBy).
func runnersHold(ctx context.Context, cfg *Config, pol *keygen.Policy, res *Result, timeout time.Duration) error {
	n := len(pol.Participants)
	if len(cfg.Runners) != n || len(res.Participants) != n {
		return fmt.Errorf("-config names %d runners, the policy %d participants and the result %d", len(cfg.Runners), n, len(res.Participants))
	}
	for i := range n {
		pt := pol.Participants[i]
		want, err := hex.DecodeString(pt.OperatorKey)
		if err != nil || len(want) != 32 {
			return fmt.Errorf("policy participant %d: operator key %q", i+1, pt.OperatorKey)
		}
		cl, err := cfg.connect(ctx, i, pt.Attestation, pt.Name, timeout)
		if err != nil {
			return err
		}
		err = func() error {
			defer cl.Close()
			qctx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			key, err := operatorKeyOf(qctx, cl, pt.Attestation)
			if err != nil {
				return err
			}
			if !bytes.Equal(key[:], want) {
				return fmt.Errorf("answers operator key %x, the policy pins %x at this position", key[:8], want[:8])
			}
			keys, err := cl.PublicKeys(qctx)
			if err != nil {
				return err
			}
			return heldBy(res, i, keys)
		}()
		if err != nil {
			return fmt.Errorf("runner %d (%s): %w", i+1, pt.Name, err)
		}
	}
	return nil
}

// heldBy checks that keys, the loaded keys of the runner at position i
// (from 0), hold every validator of the result with the share at x = i+1.
func heldBy(res *Result, i int, keys []backend.ValidatorKey) error {
	gks, shares, err := res.Keys()
	if err != nil {
		return err
	}
	have := map[backend.Pubkey]backend.Pubkey{}
	for _, k := range keys {
		have[k.Pubkey] = k.SharePubkey
	}
	for v, gk := range gks {
		s, ok := have[gk]
		switch {
		case !ok:
			return fmt.Errorf("does not hold validator %d (%x): the result names a key the DKG did not make on this runner", v, gk[:6])
		case i >= len(shares[v]) || s != shares[v][i]:
			return fmt.Errorf("holds another share of validator %d (%x) than the result names at share ID %d", v, gk[:6], i+1)
		}
	}
	return nil
}

func readDeposits(path string) ([]DepositData, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var in []DepositData
	if err := dec.Decode(&in); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return in, nil
}

// lockDeposits reads a Charon lock, runs Charon's checks on it, checks that
// it carries the result's keys and shares and the policy's withdrawal
// address, and returns its deposits.
func lockDeposits(path string, pol *keygen.Policy, res *Result, fork backend.Version) ([]DepositData, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	l, err := charonlock.Parse(raw)
	if err != nil {
		return nil, err
	}
	if err := l.VerifyHashes(); err != nil {
		return nil, err
	}
	if err := l.VerifyBLS(); err != nil {
		return nil, err
	}
	lf, err := l.Definition.Fork()
	if err != nil {
		return nil, err
	}
	if lf != fork {
		return nil, fmt.Errorf("lock: fork version %x, the chain's is %x", lf[:], fork[:])
	}
	addr, compounding := pol.SetupAddress()
	if l.Definition.Compounding != compounding {
		return nil, fmt.Errorf("lock: compounding %v, the policy's %v", l.Definition.Compounding, compounding)
	}
	want := "0x" + hex.EncodeToString(addr[:])
	if len(l.Validators) != len(res.Validators) || len(l.Definition.Validators) != len(res.Validators) {
		return nil, fmt.Errorf("lock: %d validators, the result %d", len(l.Validators), len(res.Validators))
	}
	var out []DepositData
	for v, dv := range l.Validators {
		if !strings.EqualFold(l.Definition.Validators[v].WithdrawalAddress, want) {
			return nil, fmt.Errorf("lock: validator %d withdraws to %s, the policy names %s", v, l.Definition.Validators[v].WithdrawalAddress, want)
		}
		rv := res.Validators[v]
		if "0x"+hex.EncodeToString(dv.PubKey) != strings.ToLower(rv.Pubkey) || len(dv.PubShares) != len(rv.PublicShares) {
			return nil, fmt.Errorf("lock: validator %d is not the result's", v)
		}
		for i, s := range dv.PubShares {
			if "0x"+hex.EncodeToString(s) != strings.ToLower(rv.PublicShares[i]) {
				return nil, fmt.Errorf("lock: validator %d share %d is not the result's", v, i+1)
			}
		}
		for _, d := range dv.PartialDepositData {
			out = append(out, DepositData{Pubkey: hex.EncodeToString(d.PubKey), WithdrawalCredentials: hex.EncodeToString(d.WithdrawalCredentials),
				Amount: d.Amount, Signature: hex.EncodeToString(d.Signature)})
		}
	}
	return out, nil
}

func unhex(s string, n int, what string) ([]byte, error) {
	b, err := hex.DecodeString(strings.TrimPrefix(strings.ToLower(s), "0x"))
	if err != nil || len(b) != n {
		return nil, fmt.Errorf("%s %q: want %d bytes of hex", what, s, n)
	}
	return b, nil
}

// checkDeposits keeps the deposits of the given amount and checks them
// against the policy and the result. It returns one deposit per result
// key, in result order, with the roots and fork version filled in. A
// deposit of another amount is refused unless the policy allows that
// amount too (a lock can carry several).
func checkDeposits(in []DepositData, pol *keygen.Policy, res *Result, fork backend.Version, amount uint64) ([]DepositData, error) {
	wc, ok := pol.WithdrawalCredentials()
	if !ok {
		return nil, errNoSetup
	}
	allowed := map[uint64]bool{}
	for _, a := range pol.DepositAmounts() {
		allowed[a] = true
	}
	if !allowed[amount] {
		return nil, fmt.Errorf("amount %d gwei is not among the policy's %v", amount, pol.DepositAmounts())
	}
	gks, _, err := res.Keys()
	if err != nil {
		return nil, err
	}
	if err := checkResult(res); err != nil {
		return nil, err
	}
	pos := map[backend.Pubkey]int{}
	for v, gk := range gks {
		pos[gk] = v
	}
	out := make([]DepositData, len(gks))
	seen := make([]bool, len(gks))
	for i, d := range in {
		where := fmt.Sprintf("deposit %d", i)
		pkb, err := unhex(d.Pubkey, 48, where+": pubkey")
		if err != nil {
			return nil, err
		}
		var pk backend.Pubkey
		copy(pk[:], pkb)
		v, known := pos[pk]
		if !known {
			return nil, fmt.Errorf("%s: key %x is not in the result", where, pk[:6])
		}
		if !allowed[d.Amount] {
			return nil, fmt.Errorf("%s: amount %d gwei is not among the policy's", where, d.Amount)
		}
		if d.Amount != amount {
			continue
		}
		if seen[v] {
			return nil, fmt.Errorf("%s: a second deposit of %d gwei for key %x", where, amount, pk[:6])
		}
		wcb, err := unhex(d.WithdrawalCredentials, 32, where+": withdrawal_credentials")
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(wcb, wc[:]) {
			return nil, fmt.Errorf("%s: withdrawal credentials %x, the policy's are %x", where, wcb, wc[:])
		}
		sb, err := unhex(d.Signature, 96, where+": signature")
		if err != nil {
			return nil, err
		}
		var sig backend.Signature
		copy(sig[:], sb)
		if !core.Verify(pk, charonlock.DepositSigningRoot(pk, wc, amount, fork), sig) {
			return nil, fmt.Errorf("%s: signature does not verify under key %x with fork version %x", where, pk[:6], fork[:])
		}
		mr := charonlock.DepositMessageRoot(pk, wc, amount)
		dr := charonlock.DepositDataRoot(pk, wc, amount, sig)
		for _, c := range []struct{ name, got, want string }{
			{"deposit_message_root", d.DepositMessageRoot, hex.EncodeToString(mr[:])},
			{"deposit_data_root", d.DepositDataRoot, hex.EncodeToString(dr[:])},
			{"fork_version", d.ForkVersion, hex.EncodeToString(fork[:])},
		} {
			if c.got != "" && strings.TrimPrefix(strings.ToLower(c.got), "0x") != c.want {
				return nil, fmt.Errorf("%s: %s %s, recomputed %s", where, c.name, c.got, c.want)
			}
		}
		seen[v] = true
		out[v] = DepositData{Pubkey: hex.EncodeToString(pk[:]), WithdrawalCredentials: hex.EncodeToString(wc[:]), Amount: amount,
			Signature: hex.EncodeToString(sig[:]), DepositMessageRoot: hex.EncodeToString(mr[:]), DepositDataRoot: hex.EncodeToString(dr[:]),
			ForkVersion: hex.EncodeToString(fork[:]), DepositCLIVersion: "2.7.0"}
	}
	for v, ok := range seen {
		if !ok {
			return nil, fmt.Errorf("no deposit of %d gwei for validator %d (%s)", amount, v, res.Validators[v].Pubkey[:14])
		}
	}
	return out, nil
}
