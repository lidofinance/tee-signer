package keygen

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/lidofinance/tee-signer/attestation-verify/runnerclient"
	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/dkgmsg"
	"github.com/lidofinance/tee-signer/tee-signer/charonlock"
)

// Policy is the key generation policy of one cluster: the threshold, the
// participants in share ID order, and what the setup signatures may say.
// Participant i (from 0) holds the shares at x = i+1, the position Charon
// gives the operator at index i in the lock and Dirk gives participant i+1.
//
// Every runner of the cluster must load the same file, byte for byte: the
// policy hash is in each hello, and a runner refuses a session whose hellos
// name another policy. That is what stops a host from pointing its own
// runner at peers the other operators did not agree on.
type Policy struct {
	Version      int           `json:"version"`
	Threshold    int           `json:"threshold"`
	Participants []Participant `json:"participants"`
	// Setup, if set, allows DKG_SETUP_SIGN for the keys made under this
	// policy. Without it the runner signs no setup message.
	Setup *Setup `json:"setup,omitempty"`

	setup *setupRules

	// A policy made from a DKG order (PolicyFromOrder) has no Setup: its
	// path and ENRs come from the order, and rulesNow gives the withdrawal
	// credentials and deposit amounts of the locked group in force at each
	// setup signature.
	order    bool
	path     string
	enrs     []string
	rulesNow func() (*setupRules, error)
}

// Participant is one runner of the cluster.
type Participant struct {
	// Name is a label for logs and errors (for example the operator).
	Name string `json:"name"`
	// OperatorKey is the runner's operator key (64 hex digits, Ed25519),
	// read from that runner over an attested connection (dkg-coordinator
	// operator-keys). The runner made it once and keeps it sealed, so only a
	// runner that unseals that operator's storage reports it. It binds the
	// position to the operator, where the attestation binds it to an image.
	OperatorKey string `json:"operator_key"`
	// Attestation is the check a peer's hello must pass, with the settings
	// of attest/runnerclient. Besides the image it must name the account
	// where the platform attests one: gcp_project_id and
	// gcp_service_account for gcp-cs, PCR3 (the parent instance's IAM role,
	// whose ARN holds the AWS account) for aws-nitro. MAA tokens of Azure
	// confidential containers carry no subscription; there the operator key
	// is the binding. A runner with a setup needs setup_sha256 here, the
	// hash of the setup its operator built: the hello check refuses another
	// setup, and a setup that no pin names (attest/runnerclient, setup.go).
	Attestation runnerclient.Attestation `json:"attestation"`

	operatorKey [32]byte
	// setupHash is the setup_hash a DKG order names for the position
	// (pinned); every hello of the position must carry it.
	setupHash [32]byte
	pinned    bool
}

// Setup is what the setup signatures may carry.
type Setup struct {
	// Path is "dirk" (deposits only; the Dirk fork lists the accounts) or
	// "charon" (deposits, builder registration and the lock hash).
	Path string `json:"path"`
	// WithdrawalAddress and Compounding give the only withdrawal
	// credentials a deposit may carry: 0x02 (compounding, the default for
	// new keys, invariant 11) or 0x01, then 11 zero bytes and the address.
	WithdrawalAddress string `json:"withdrawal_address"`
	Compounding       *bool  `json:"compounding,omitempty"`
	// DepositAmountsGwei lists the amounts a deposit may have.
	DepositAmountsGwei []uint64 `json:"deposit_amounts_gwei"`
	// CharonENRs, Charon path only and required there, lists each
	// position's Charon node ENR (`charon create enr` on that node), in
	// participant order. A runner signs only a lock whose operators are
	// these nodes in this order.
	CharonENRs []string `json:"charon_enrs,omitempty"`
}

type setupRules struct {
	path        string
	compounding bool
	address     [20]byte
	credentials backend.Root
	amounts     map[uint64]bool
	amountList  []uint64 // the amounts in their source's order
	enrs        []string
}

const policyPrefix = "signer-dkg-policy-v1"

const gwei = 1_000_000_000

// ParsePolicy reads a policy file and returns it with its hash. It refuses
// a verifier this program is not built with, the dev verifier on any
// platform but dev, and a verifier setting that names no account where the
// platform attests one.
func ParsePolicy(raw []byte, platformName string) (*Policy, [32]byte, error) {
	var hash [32]byte
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var p Policy
	if err := dec.Decode(&p); err != nil {
		return nil, hash, fmt.Errorf("dkg policy: %w", err)
	}
	if dec.More() {
		return nil, hash, errors.New("dkg policy: trailing data")
	}
	if p.Version != 1 {
		return nil, hash, fmt.Errorf("dkg policy: version %d, want 1", p.Version)
	}
	n := len(p.Participants)
	if n < 2 || n > dkgmsg.MaxParticipants {
		return nil, hash, fmt.Errorf("dkg policy: %d participants, want 2 to %d", n, dkgmsg.MaxParticipants)
	}
	// A majority threshold: two disjoint groups of signers cannot both
	// reach it.
	if p.Threshold <= n/2 || p.Threshold > n {
		return nil, hash, fmt.Errorf("dkg policy: threshold %d of %d, want more than half and at most all", p.Threshold, n)
	}
	names := map[string]bool{}
	keys := map[[32]byte]bool{}
	for i := range p.Participants {
		pt := &p.Participants[i]
		where := fmt.Sprintf("dkg policy: participant %d (%s)", i+1, pt.Name)
		if pt.Name == "" || names[pt.Name] {
			return nil, hash, fmt.Errorf("dkg policy: participant %d: empty or repeated name", i+1)
		}
		names[pt.Name] = true
		k, err := hex.DecodeString(strings.TrimPrefix(pt.OperatorKey, "0x"))
		if err != nil || len(k) != 32 {
			return nil, hash, fmt.Errorf("%s: operator_key: want 64 hex digits", where)
		}
		copy(pt.operatorKey[:], k)
		if keys[pt.operatorKey] {
			return nil, hash, fmt.Errorf("%s: operator_key repeats", where)
		}
		keys[pt.operatorKey] = true
		a := &pt.Attestation
		if a.Verifier == "" {
			return nil, hash, fmt.Errorf("%s: attestation.verifier: not set", where)
		}
		if !runnerclient.Available(a.Verifier) {
			return nil, hash, fmt.Errorf("%s: verifier %q is not built into this runner; build it with that peer's tag (scripts/build-runner.sh PEERS=...)", where, a.Verifier)
		}
		if a.Verifier == runnerclient.VerifierDev && platformName != "dev" {
			return nil, hash, fmt.Errorf("%s: verifier dev accepts unsigned documents, refused on platform %s", where, platformName)
		}
		// A key set file is a path on the host, so its content would not be
		// covered by the policy hash.
		if a.GCPJWKSFile != "" {
			return nil, hash, fmt.Errorf("%s: gcp_jwks_file is not allowed here", where)
		}
		switch a.Verifier {
		case runnerclient.VerifierGCPCS:
			if a.GCPProjectID == "" || a.GCPServiceAccount == "" {
				return nil, hash, fmt.Errorf("%s: gcp-cs needs gcp_project_id and gcp_service_account, so the position is bound to the operator's project", where)
			}
		case runnerclient.VerifierAWSNitro:
			if a.NitroPCRs["3"] == "" {
				return nil, hash, fmt.Errorf("%s: aws-nitro needs PCR3 (the parent instance's IAM role, in the operator's account) in nitro_pcrs", where)
			}
		}
		if err := a.Validate(); err != nil {
			return nil, hash, fmt.Errorf("%s: %w", where, err)
		}
	}
	if p.Setup != nil {
		r, err := p.Setup.rules()
		if err != nil {
			return nil, hash, fmt.Errorf("dkg policy: setup: %w", err)
		}
		if r.path == "charon" && len(r.enrs) != n {
			return nil, hash, fmt.Errorf("dkg policy: setup: charon_enrs lists %d nodes for %d participants", len(r.enrs), n)
		}
		p.setup = r
	}
	h := sha256.New()
	h.Write([]byte(policyPrefix))
	h.Write(raw)
	h.Sum(hash[:0])
	return &p, hash, nil
}

func (s *Setup) rules() (*setupRules, error) {
	r := &setupRules{path: s.Path, compounding: true, amounts: map[uint64]bool{}}
	if s.Path != "dirk" && s.Path != "charon" {
		return nil, fmt.Errorf("path %q, want dirk or charon", s.Path)
	}
	if s.Compounding != nil {
		r.compounding = *s.Compounding
	}
	if s.Path == "dirk" && len(s.CharonENRs) > 0 {
		return nil, errors.New("charon_enrs is for the charon path")
	}
	seen := map[string]bool{}
	for _, e := range s.CharonENRs {
		if !strings.HasPrefix(e, "enr:") || seen[e] {
			return nil, fmt.Errorf("charon_enrs: %q is not an ENR or repeats", e)
		}
		seen[e] = true
	}
	r.enrs = s.CharonENRs
	a, err := charonlock.Address(s.WithdrawalAddress)
	if err != nil {
		return nil, fmt.Errorf("withdrawal_address: %w", err)
	}
	if a == [20]byte{} {
		return nil, errors.New("withdrawal_address is zero")
	}
	r.address = a
	r.credentials = charonlock.WithdrawalCredentials(a, r.compounding)
	max := uint64(32 * gwei)
	if r.compounding {
		max = 2048 * gwei
	}
	if len(s.DepositAmountsGwei) == 0 {
		return nil, errors.New("deposit_amounts_gwei is empty")
	}
	for _, v := range s.DepositAmountsGwei {
		if v < gwei || v > max {
			return nil, fmt.Errorf("deposit amount %d gwei: want 1 ETH to %d ETH", v, max/gwei)
		}
		r.amounts[v] = true
	}
	r.amountList = append([]uint64(nil), s.DepositAmountsGwei...)
	return r, nil
}

// rules are the setup rules in force: the policy file's setup section, or
// for an order the locked group in force now. nil: no setup signing.
func (p *Policy) rules() (*setupRules, error) {
	if p.rulesNow != nil {
		return p.rulesNow()
	}
	return p.setup, nil
}

// SetupPath is the setup section's path ("dirk" or "charon"), or "" without
// one. A DKG order always has a path.
func (p *Policy) SetupPath() string {
	if p.order {
		return p.path
	}
	if p.setup == nil {
		return ""
	}
	return p.setup.path
}

// FromOrder reports whether the policy is a DKG order's.
func (p *Policy) FromOrder() bool { return p.order }

// rulesOrNil is rules for the accessors below, which report "none" for an
// error.
func (p *Policy) rulesOrNil() *setupRules {
	r, err := p.rules()
	if err != nil {
		return nil
	}
	return r
}

// WithdrawalCredentials are the only credentials a setup deposit may carry.
func (p *Policy) WithdrawalCredentials() (backend.Root, bool) {
	r := p.rulesOrNil()
	if r == nil {
		return backend.Root{}, false
	}
	return r.credentials, true
}

// SetupAddress returns the withdrawal address and whether deposits compound.
func (p *Policy) SetupAddress() ([20]byte, bool) {
	r := p.rulesOrNil()
	if r == nil {
		return [20]byte{}, false
	}
	return r.address, r.compounding
}

// DepositAmounts lists the deposit amounts in gwei, in file order (an
// order's: ascending, as the locked group lists them).
func (p *Policy) DepositAmounts() []uint64 {
	r := p.rulesOrNil()
	if r == nil {
		return nil
	}
	return append([]uint64(nil), r.amountList...)
}

// CharonENRs lists the Charon node of each position.
func (p *Policy) CharonENRs() []string {
	if p.order {
		return append([]string(nil), p.enrs...)
	}
	if p.setup == nil {
		return nil
	}
	return append([]string(nil), p.setup.enrs...)
}
