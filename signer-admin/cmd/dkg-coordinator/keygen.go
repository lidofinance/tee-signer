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

	"github.com/lidofinance/tee-signer/attestation-verify/runnerclient"
	remoteadmin "github.com/lidofinance/tee-signer/signer-admin/remote/admin"
	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/dkgmsg"
	"github.com/lidofinance/tee-signer/signer-protocol/remote"
	"github.com/lidofinance/tee-signer/tee-signer/keygen/relay"
)

// Result is dkg-result.json: the public result, for the commands that build
// each path's configuration.
type Result struct {
	Session    string `json:"session"`
	Transcript string `json:"transcript"`
	// PolicySHA256 is the hash every hello carried: the policy file's, or
	// with Order the DKG order's.
	PolicySHA256 string        `json:"policy_sha256"`
	Order        bool          `json:"order,omitempty"`
	Path         string        `json:"path,omitempty"`
	Threshold    int           `json:"threshold"`
	Participants []Participant `json:"participants"`
	Validators   []Validator   `json:"validators"`
	// Confirmations of every runner, hex, in share ID order. A runner that
	// missed the commit round can be given them again (DKG_COMMIT).
	Confirmations []string `json:"confirmations"`
}

type Participant struct {
	Name        string `json:"name"`
	ShareID     int    `json:"share_id"`
	Address     string `json:"address"`
	OperatorKey string `json:"operator_key"`
}

type Validator struct {
	Pubkey string `json:"pubkey"`
	// PublicShares[i] is the key of the share at x = i+1, held by
	// participant i+1.
	PublicShares []string `json:"public_shares"`
}

func hex48(s string) (backend.Pubkey, error) {
	var pk backend.Pubkey
	b, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
	if err != nil || len(b) != len(pk) {
		return pk, fmt.Errorf("bad key %q", s)
	}
	copy(pk[:], b)
	return pk, nil
}

// Keys returns the result's validator keys and public shares.
func (r *Result) Keys() ([]backend.Pubkey, [][]backend.Pubkey, error) {
	var gks []backend.Pubkey
	var shares [][]backend.Pubkey
	for _, v := range r.Validators {
		gk, err := hex48(v.Pubkey)
		if err != nil {
			return nil, nil, err
		}
		var ps []backend.Pubkey
		for _, s := range v.PublicShares {
			p, err := hex48(s)
			if err != nil {
				return nil, nil, err
			}
			ps = append(ps, p)
		}
		gks, shares = append(gks, gk), append(shares, ps)
	}
	return gks, shares, nil
}

// readResult reads the keygen result at path, made under the policy with
// this hash. path may name several results, comma-separated, of the same
// participants and threshold: their keys are taken in that order as one
// result (a Charon lock or one set of shims over several sessions; a session
// makes at most dkgmsg.MaxValidators keys). Such a result has no session,
// transcript or confirmations of its own.
func readResult(path string, policySHA256 [32]byte) (*Result, error) {
	var out *Result
	seen := map[string]bool{}
	for _, p := range strings.Split(path, ",") {
		r, err := readOneResult(p, policySHA256)
		if err != nil {
			return nil, err
		}
		for _, v := range r.Validators {
			k := strings.ToLower(strings.TrimPrefix(v.Pubkey, "0x"))
			if seen[k] {
				return nil, fmt.Errorf("%s: key %s is in an earlier result too", p, k[:12])
			}
			seen[k] = true
		}
		if out == nil {
			out = r
			continue
		}
		if r.Threshold != out.Threshold || len(r.Participants) != len(out.Participants) {
			return nil, fmt.Errorf("%s: another threshold or participant count than the first result", p)
		}
		for i, pt := range r.Participants {
			if pt != out.Participants[i] {
				return nil, fmt.Errorf("%s: participant %d differs from the first result", p, i+1)
			}
		}
		out.Validators = append(out.Validators, r.Validators...)
		out.Session, out.Transcript, out.Confirmations = "", "", nil
	}
	return out, nil
}

func readOneResult(path string, policySHA256 [32]byte) (*Result, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var r Result
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if r.PolicySHA256 != hex.EncodeToString(policySHA256[:]) {
		return nil, fmt.Errorf("%s was made under another policy", path)
	}
	return &r, nil
}

func cmdKeygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	var cf commonFlags
	cf.register(fs)
	count := fs.Int("count", 1, fmt.Sprintf("validator keys to make (1 to %d)", dkgmsg.MaxValidators))
	outPath := fs.String("out", "dkg-result.json", "where to write the public result")
	_ = fs.Parse(args)
	cfg, err := readConfig(cf.config)
	if err != nil {
		return err
	}
	pol, polHash, err := cfg.loadPolicy(cf.platform)
	if err != nil {
		return err
	}
	ctx := context.Background()
	cls, verifiers, err := cfg.connectAll(ctx, pol, cf.timeout)
	if err != nil {
		return err
	}
	runners := make([]relay.Runner, len(cls))
	out := &Result{PolicySHA256: hex.EncodeToString(polHash[:]), Threshold: pol.Threshold, Order: pol.FromOrder(), Path: pol.SetupPath()}
	for i, cl := range cls {
		defer cl.Close()
		runners[i] = dkgClient(cl, pol, polHash)
		out.Participants = append(out.Participants, Participant{Name: pol.Participants[i].Name, ShareID: i + 1,
			Address: cfg.Runners[i].Address, OperatorKey: pol.Participants[i].OperatorKey})
	}
	res, err := relay.Run(ctx, runners, *count, relay.Options{CheckHello: relay.PolicyCheck(polHash, verifiers)})
	if err != nil {
		return err
	}
	r := res.Result
	out.Session, out.Transcript = hex0x(r.Session[:]), hex0x(r.Transcript[:])
	for v, gk := range r.GroupKeys {
		val := Validator{Pubkey: hex0x(gk[:])}
		for _, s := range r.PublicShares[v] {
			val.PublicShares = append(val.PublicShares, hex0x(s[:]))
		}
		out.Validators = append(out.Validators, val)
	}
	for _, c := range res.Confirms {
		out.Confirmations = append(out.Confirmations, hex0x(c.Encode()))
	}
	// Each runner reports the shares at its position.
	for i, keys := range res.Keys {
		for _, k := range keys {
			for v, gk := range r.GroupKeys {
				if k.Pubkey == gk && k.SharePubkey != r.PublicShares[v][i] {
					return fmt.Errorf("runner %d holds another share of validator %d than the result names", i+1, v)
				}
			}
		}
	}
	if err := writeJSON(*outPath, out); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "made %d keys, %d of %d, transcript %s; every runner committed; result in %s\n",
		len(r.GroupKeys), pol.Threshold, len(pol.Participants), out.Transcript[:14], *outPath)
	return nil
}

// cmdOperatorKeys asks each runner for its attested operator key: what each
// operator puts into the policy at its position.
func cmdOperatorKeys(args []string) error {
	fs := flag.NewFlagSet("operator-keys", flag.ExitOnError)
	var cf commonFlags
	cf.register(fs)
	_ = fs.Parse(args)
	cfg, err := readConfig(cf.config)
	if err != nil {
		return err
	}
	ctx := context.Background()
	type entry struct {
		Address     string `json:"address"`
		OperatorKey string `json:"operator_key"`
	}
	var out []entry
	for i, rc := range cfg.Runners {
		if rc.Attestation == nil {
			return fmt.Errorf("runner %d: operator-keys needs the runner's own attestation settings in the config", i+1)
		}
		if rc.Attestation.Verifier == "dev" && cf.platform != "dev" {
			return fmt.Errorf("runner %d: the dev verifier needs -platform dev", i+1)
		}
		cl, err := cfg.connect(ctx, i, *rc.Attestation, rc.Address, cf.timeout)
		if err != nil {
			return err
		}
		key, err := operatorKeyOf(ctx, cl, *rc.Attestation)
		if err != nil {
			cl.Close()
			return fmt.Errorf("runner %d: %w", i+1, err)
		}
		cl.Close()
		out = append(out, entry{Address: rc.Address, OperatorKey: hex.EncodeToString(key[:])})
	}
	b, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(b))
	return nil
}

// operatorKeyOf asks the runner of cl for its operator key with a fresh
// nonce and checks the answer with the verifier of att.
func operatorKeyOf(ctx context.Context, cl *runnerclient.Client, att runnerclient.Attestation) ([32]byte, error) {
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return [32]byte{}, err
	}
	info, err := remoteadmin.Wrap(cl.Client).DKGOperator(ctx, &dkgmsg.OperatorRequest{Nonce: nonce})
	if err != nil {
		return [32]byte{}, err
	}
	ov, err := att.NewDKGOperatorVerifier()
	if err != nil {
		return [32]byte{}, err
	}
	if err := checkOperatorInfo(ctx, ov, nonce, info); err != nil {
		return [32]byte{}, err
	}
	return info.Key, nil
}

// checkOperatorInfo checks a DKG_OPERATOR answer to nonce: its document
// binds the nonce and the key under the operator context (verify, from
// Attestation.NewDKGOperatorVerifier), not IDENTITY's.
func checkOperatorInfo(ctx context.Context, verify remote.VerifyFunc, nonce []byte, info *dkgmsg.OperatorInfo) error {
	if !bytes.Equal(info.Nonce, nonce) || info.Identity == nil || info.Identity.Attestation == nil {
		return errors.New("the DKG_OPERATOR answer does not bind the nonce")
	}
	if err := verify(ctx, info.AttestNonce(), info.Identity); err != nil {
		return fmt.Errorf("operator key attestation: %w", err)
	}
	return nil
}

var errNoSetup = errors.New("the policy has no setup section")
