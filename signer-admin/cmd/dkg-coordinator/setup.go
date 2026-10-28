package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/lidofinance/tee-signer/attestation-verify/runnerclient"
	"github.com/lidofinance/tee-signer/signer-core/core"
	"github.com/lidofinance/tee-signer/signer-core/dkgmath"
	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/dkgmsg"
	"github.com/lidofinance/tee-signer/tee-signer/charonlock"
	"github.com/lidofinance/tee-signer/tee-signer/keygen"
)

// setupEnv is what the setup commands share: the policy, the result and an
// attested client per runner.
type setupEnv struct {
	pol     *keygen.Policy
	res     *Result
	gks     []backend.Pubkey
	shares  [][]backend.Pubkey
	clients []*runnerclient.Client
	// dkg is each client's key generation (in the order's envelope for an
	// order).
	dkg []dkgRunner
}

func openSetup(cf *commonFlags, resultPath string) (*setupEnv, error) {
	cfg, err := readConfig(cf.config)
	if err != nil {
		return nil, err
	}
	pol, hash, err := cfg.loadPolicy(cf.platform)
	if err != nil {
		return nil, err
	}
	if pol.SetupPath() == "" {
		return nil, errNoSetup
	}
	if _, ok := pol.WithdrawalCredentials(); !ok && pol.FromOrder() {
		return nil, errors.New("config: the setup commands of an order need locked, the signers' setup or locked update in force")
	}
	res, err := readResult(resultPath, hash)
	if err != nil {
		return nil, err
	}
	gks, shares, err := res.Keys()
	if err != nil {
		return nil, err
	}
	cls, _, err := cfg.connectAll(context.Background(), pol, cf.timeout)
	if err != nil {
		return nil, err
	}
	e := &setupEnv{pol: pol, res: res, gks: gks, shares: shares, clients: cls}
	for _, cl := range cls {
		e.dkg = append(e.dkg, dkgClient(cl, pol, hash))
	}
	return e, nil
}

func (e *setupEnv) close() {
	for _, c := range e.clients {
		c.Close()
	}
}

// threshold asks every runner for a partial signature over root for
// validator v, keeps those that verify under the runner's public share and
// combines the first threshold of them. The combination must verify under
// the validator key.
func (e *setupEnv) threshold(ctx context.Context, v int, q *dkgmsg.SetupRequest, root backend.Root, what string) (backend.Signature, error) {
	var ids []uint64
	var sigs []backend.Signature
	var errs []error
	for i, c := range e.dkg {
		b, err := c.DKGSetupSign(ctx, q)
		if err != nil {
			errs = append(errs, fmt.Errorf("runner %d: %w", i+1, err))
			continue
		}
		var s backend.Signature
		if len(b) != len(s) {
			errs = append(errs, fmt.Errorf("runner %d: answer of %d bytes", i+1, len(b)))
			continue
		}
		copy(s[:], b)
		if !core.Verify(e.shares[v][i], root, s) {
			errs = append(errs, fmt.Errorf("runner %d: partial signature does not verify under its public share", i+1))
			continue
		}
		ids, sigs = append(ids, uint64(i+1)), append(sigs, s)
		if len(ids) == e.res.Threshold {
			break
		}
	}
	if len(ids) < e.res.Threshold {
		return backend.Signature{}, fmt.Errorf("%s of validator %d: %d of %d partial signatures: %w", what, v, len(ids), e.res.Threshold, errors.Join(errs...))
	}
	full, err := core.RecoverSignature(ids, sigs)
	if err != nil || !core.Verify(e.gks[v], root, full) {
		return backend.Signature{}, fmt.Errorf("%s of validator %d: combined signature does not verify under the validator key", what, v)
	}
	return full, nil
}

func (e *setupEnv) deposit(ctx context.Context, v int, wc backend.Root, amount uint64, fork backend.Version) (backend.Signature, error) {
	q := &dkgmsg.SetupRequest{Kind: dkgmsg.SetupDeposit, Deposit: &dkgmsg.Deposit{Pubkey: e.gks[v], WithdrawalCredentials: wc, Amount: amount}}
	return e.threshold(ctx, v, q, charonlock.DepositSigningRoot(e.gks[v], wc, amount, fork), "deposit")
}

func parseFork(s string) (backend.Version, error) {
	var v backend.Version
	b, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
	if err != nil || len(b) != 4 {
		return v, fmt.Errorf("fork version %q: want 4 bytes of hex", s)
	}
	copy(v[:], b)
	return v, nil
}

// DepositData is one entry of deposit-data.json, the format of the staking
// deposit CLI and of Charon's deposit-data files.
type DepositData struct {
	Pubkey                string `json:"pubkey"`
	WithdrawalCredentials string `json:"withdrawal_credentials"`
	Amount                uint64 `json:"amount"`
	Signature             string `json:"signature"`
	DepositMessageRoot    string `json:"deposit_message_root"`
	DepositDataRoot       string `json:"deposit_data_root"`
	ForkVersion           string `json:"fork_version"`
	NetworkName           string `json:"network_name"`
	DepositCLIVersion     string `json:"deposit_cli_version"`
}

// cmdDeposits makes the deposits of every validator for every amount of
// the policy, each a threshold signature of the runners.
func cmdDeposits(args []string) error {
	fs := flag.NewFlagSet("deposits", flag.ExitOnError)
	var cf commonFlags
	cf.register(fs)
	resultPath := fs.String("result", "dkg-result.json", "the keygen result, or several comma-separated as one (same participants)")
	forkHex := fs.String("fork-version", "", "the chain's genesis fork version, 4 bytes hex (as the runners' chain config)")
	network := fs.String("network-name", "", "network name for deposit-data.json")
	outPath := fs.String("out", "deposit-data.json", "where to write the deposits")
	_ = fs.Parse(args)
	fork, err := parseFork(*forkHex)
	if err != nil {
		return err
	}
	e, err := openSetup(&cf, *resultPath)
	if err != nil {
		return err
	}
	defer e.close()
	wc, _ := e.pol.WithdrawalCredentials()
	ctx := context.Background()
	var out []DepositData
	for v := range e.gks {
		for _, amount := range e.pol.DepositAmounts() {
			sig, err := e.deposit(ctx, v, wc, amount, fork)
			if err != nil {
				return err
			}
			mr := charonlock.DepositMessageRoot(e.gks[v], wc, amount)
			dr := charonlock.DepositDataRoot(e.gks[v], wc, amount, sig)
			out = append(out, DepositData{
				Pubkey: hex.EncodeToString(e.gks[v][:]), WithdrawalCredentials: hex.EncodeToString(wc[:]), Amount: amount,
				Signature: hex.EncodeToString(sig[:]), DepositMessageRoot: hex.EncodeToString(mr[:]),
				DepositDataRoot: hex.EncodeToString(dr[:]), ForkVersion: hex.EncodeToString(fork[:]),
				NetworkName: *network, DepositCLIVersion: "2.7.0",
			})
		}
	}
	if err := writeJSON(*outPath, out); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "%d deposits, credentials %x, each a %d-of-%d signature that verifies under its validator key; in %s\n",
		len(out), wc[:], e.res.Threshold, len(e.clients), *outPath)
	return nil
}

// ClusterFile is the -cluster input of charon-lock: what the operators
// agree on besides the policy.
type ClusterFile struct {
	Name                  string   `json:"name"`
	UUID                  string   `json:"uuid,omitempty"`
	Timestamp             string   `json:"timestamp,omitempty"`
	ForkVersion           string   `json:"fork_version"`
	FeeRecipient          string   `json:"fee_recipient"`
	GasLimit              uint64   `json:"gas_limit"`
	RegistrationTimestamp uint64   `json:"registration_timestamp"`
	DepositAmountsGwei    []uint64 `json:"deposit_amounts_gwei,omitempty"`
}

func newUUID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return strings.ToUpper(fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:]))
}

// cmdCharonLock builds a Charon v1.11.0 lock for the keys: deposits and
// builder registrations as threshold signatures of the runners, then every
// runner's signature over the lock hash it computes itself. The node
// signatures come last, from each Charon node (charon-node-sign).
func cmdCharonLock(args []string) error {
	fs := flag.NewFlagSet("charon-lock", flag.ExitOnError)
	var cf commonFlags
	cf.register(fs)
	resultPath := fs.String("result", "dkg-result.json", "the keygen result, or several comma-separated as one (same participants)")
	clusterPath := fs.String("cluster", "cluster.json", "the cluster settings (ClusterFile)")
	outPath := fs.String("out", "cluster-lock.json", "where to write the lock (without node signatures)")
	_ = fs.Parse(args)
	raw, err := os.ReadFile(*clusterPath)
	if err != nil {
		return err
	}
	var cl ClusterFile
	if err := json.Unmarshal(raw, &cl); err != nil {
		return fmt.Errorf("%s: %w", *clusterPath, err)
	}
	fork, err := parseFork(cl.ForkVersion)
	if err != nil {
		return err
	}
	e, err := openSetup(&cf, *resultPath)
	if err != nil {
		return err
	}
	defer e.close()
	if e.pol.SetupPath() != "charon" {
		return fmt.Errorf("the policy's setup path is %s, not charon", e.pol.SetupPath())
	}
	addr, compounding := e.pol.SetupAddress()
	c := &charonlock.Cluster{
		Name: cl.Name, UUID: cl.UUID, Timestamp: cl.Timestamp, ENRs: e.pol.CharonENRs(), Threshold: e.res.Threshold,
		ForkVersion: fork, FeeRecipient: cl.FeeRecipient, WithdrawalAddress: hex0x(addr[:]), Compounding: compounding,
		DepositAmounts: cl.DepositAmountsGwei, GasLimit: cl.GasLimit, RegistrationTimestamp: cl.RegistrationTimestamp,
	}
	if c.UUID == "" {
		c.UUID = newUUID()
	}
	if c.Timestamp == "" {
		c.Timestamp = time.Now().UTC().Format(time.RFC3339)
	}
	amounts := cl.DepositAmountsGwei
	if len(amounts) == 0 {
		amounts = e.pol.DepositAmounts()
	}
	l, err := charonlock.NewLock(c, e.gks, e.shares)
	if err != nil {
		return err
	}
	wc := charonlock.WithdrawalCredentials(addr, compounding)
	ctx := context.Background()
	for v := range e.gks {
		for _, amount := range amounts {
			sig, err := e.deposit(ctx, v, wc, amount, fork)
			if err != nil {
				return err
			}
			l.AddDeposit(v, wc, amount, sig)
		}
		reg, err := l.RegistrationFor(v, c)
		if err != nil {
			return err
		}
		root, err := charonlock.RegistrationSigningRoot(reg, fork)
		if err != nil {
			return err
		}
		sig, err := e.threshold(ctx, v, &dkgmsg.SetupRequest{Kind: dkgmsg.SetupRegistration, Registration: reg}, root, "builder registration")
		if err != nil {
			return err
		}
		l.SetRegistration(v, reg, sig)
	}
	lh, err := l.SetLockHash()
	if err != nil {
		return err
	}
	lockJSON, err := l.Marshal()
	if err != nil {
		return err
	}
	// Compact on the wire: a lock of 640 validators is about 1.07 MB
	// indented and must stay under dkgmsg.MaxLock.
	var compact bytes.Buffer
	if err := json.Compact(&compact, lockJSON); err != nil {
		return err
	}
	if compact.Len() > dkgmsg.MaxLock {
		return fmt.Errorf("the lock is %d bytes, over the %d a runner takes: make it with fewer validators", compact.Len(), dkgmsg.MaxLock)
	}
	lockJSON = compact.Bytes()
	// Every share signs the lock hash: all runners, no threshold.
	q := &dkgmsg.SetupRequest{Kind: dkgmsg.SetupCharonLock, Lock: lockJSON}
	per := make([][]backend.Signature, len(e.gks))
	for v := range per {
		per[v] = make([]backend.Signature, len(e.clients))
	}
	for i, cli := range e.dkg {
		b, err := cli.DKGSetupSign(ctx, q)
		if err != nil {
			return fmt.Errorf("runner %d: lock: %w", i+1, err)
		}
		ls, err := dkgmsg.DecodeLockSigned(b)
		if err != nil {
			return fmt.Errorf("runner %d: %w", i+1, err)
		}
		if ls.LockHash != lh {
			return fmt.Errorf("runner %d computed lock hash %x, the coordinator %x", i+1, ls.LockHash[:], lh[:])
		}
		if len(ls.Signatures) != len(e.gks) {
			return fmt.Errorf("runner %d signed %d of %d keys", i+1, len(ls.Signatures), len(e.gks))
		}
		for _, s := range ls.Signatures {
			v := -1
			for k, gk := range e.gks {
				if gk == s.Pubkey {
					v = k
				}
			}
			if v < 0 || !core.Verify(e.shares[v][i], lh, s.Signature) {
				return fmt.Errorf("runner %d: lock signature for %x does not verify under its public share", i+1, s.Pubkey[:6])
			}
			per[v][i] = s.Signature
		}
	}
	var all []backend.Signature
	for v := range per {
		all = append(all, per[v]...)
	}
	agg, err := dkgmath.AggregateSignatures(all)
	if err != nil {
		return err
	}
	l.SignatureAggregate = agg[:]
	if err := l.VerifyHashes(); err != nil {
		return err
	}
	if err := l.VerifyBLS(); err != nil {
		return err
	}
	out, err := l.Marshal()
	if err != nil {
		return err
	}
	if err := os.WriteFile(*outPath, out, 0o644); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "lock %x: %d validators, %d nodes, threshold %d; hashes recompute, shares, deposits, registrations and signature_aggregate verify; needs each node's signature (charon-node-sign); in %s\n",
		lh[:], len(e.gks), len(e.clients), e.res.Threshold, *outPath)
	return nil
}
