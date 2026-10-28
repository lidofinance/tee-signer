// Package charonlock reads, writes and hashes a Charon cluster lock of
// version v1.11.0, so that tools outside Charon can build one and a runner
// can check one and compute its hash itself.
//
// Written from the field lists in threshold-signer-poc research/charon-tee-dkg.md
// (Charon v1.11.0 `cluster/ssz.go` and `cluster/helpers.go`, read on GitHub;
// Charon is BSL 1.1 and none of its code is here). The test that matters is
// that stock `charon run` v1.11.0 accepts a lock built with this package,
// and that this package recomputes the hashes of locks Charon made.
package charonlock

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Version is the only lock version this package handles.
const Version = "v1.11.0"

// Hex is a byte string as Charon writes it in JSON: "0x" and lowercase hex,
// "" when empty. It reads hex with or without "0x".
type Hex []byte

func (h Hex) MarshalJSON() ([]byte, error) {
	if len(h) == 0 {
		return []byte(`""`), nil
	}
	return json.Marshal("0x" + hex.EncodeToString(h))
}

func (h *Hex) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	if s == "" {
		*h = nil
		return nil
	}
	v, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
	if err != nil {
		return fmt.Errorf("charonlock: bad hex %q", s)
	}
	*h = v
	return nil
}

// GweiList is deposit_amounts as Charon writes it: null when empty, else
// an array of decimal strings in gwei.
type GweiList []uint64

func (g GweiList) MarshalJSON() ([]byte, error) {
	if len(g) == 0 {
		return []byte("null"), nil
	}
	s := make([]string, len(g))
	for i, v := range g {
		s[i] = strconv.FormatUint(v, 10)
	}
	return json.Marshal(s)
}

func (g *GweiList) UnmarshalJSON(b []byte) error {
	var s []json.Number
	if err := json.Unmarshal(b, &s); err != nil {
		var strs []string
		if err2 := json.Unmarshal(b, &strs); err2 != nil {
			return fmt.Errorf("charonlock: deposit_amounts: %w", err)
		}
		for _, v := range strs {
			s = append(s, json.Number(v))
		}
	}
	out := make(GweiList, 0, len(s))
	for _, n := range s {
		v, err := strconv.ParseUint(string(n), 10, 64)
		if err != nil {
			return fmt.Errorf("charonlock: deposit amount %q", n)
		}
		out = append(out, v)
	}
	if len(out) == 0 {
		out = nil
	}
	*g = out
	return nil
}

// Lock is cluster-lock.json.
type Lock struct {
	Definition         Definition      `json:"cluster_definition"`
	Validators         []DistValidator `json:"distributed_validators"`
	SignatureAggregate Hex             `json:"signature_aggregate"`
	LockHash           Hex             `json:"lock_hash"`
	NodeSignatures     []Hex           `json:"node_signatures"`
}

// Definition is the cluster definition inside the lock.
type Definition struct {
	Name              string               `json:"name,omitempty"`
	Creator           Creator              `json:"creator"`
	Operators         []Operator           `json:"operators"`
	UUID              string               `json:"uuid"`
	Version           string               `json:"version"`
	Timestamp         string               `json:"timestamp"`
	NumValidators     int                  `json:"num_validators"`
	Threshold         int                  `json:"threshold"`
	Validators        []ValidatorAddresses `json:"validators"`
	DKGAlgorithm      string               `json:"dkg_algorithm"`
	ForkVersion       Hex                  `json:"fork_version"`
	DepositAmounts    GweiList             `json:"deposit_amounts"`
	ConsensusProtocol string               `json:"consensus_protocol"`
	TargetGasLimit    uint64               `json:"target_gas_limit"`
	Compounding       bool                 `json:"compounding"`
	ConfigHash        Hex                  `json:"config_hash"`
	DefinitionHash    Hex                  `json:"definition_hash"`
}

// Creator is left empty in locks built here (no EIP-712 signatures).
type Creator struct {
	Address         string `json:"address"`
	ConfigSignature Hex    `json:"config_signature"`
}

// Operator is one node. Locks built here carry only the ENR.
type Operator struct {
	Address         string `json:"address"`
	ENR             string `json:"enr"`
	ConfigSignature Hex    `json:"config_signature"`
	ENRSignature    Hex    `json:"enr_signature"`
}

// ValidatorAddresses are a validator's fee recipient and withdrawal address.
type ValidatorAddresses struct {
	FeeRecipientAddress string `json:"fee_recipient_address"`
	WithdrawalAddress   string `json:"withdrawal_address"`
}

// DistValidator is one distributed validator.
type DistValidator struct {
	PubKey              Hex           `json:"distributed_public_key"`
	PubShares           []Hex         `json:"public_shares"`
	BuilderRegistration Registration  `json:"builder_registration"`
	PartialDepositData  []DepositData `json:"partial_deposit_data"`
}

// DepositData is one deposit of a validator.
type DepositData struct {
	PubKey                Hex    `json:"pubkey"`
	WithdrawalCredentials Hex    `json:"withdrawal_credentials"`
	Amount                uint64 `json:"amount,string"`
	Signature             Hex    `json:"signature"`
}

// Registration is a signed builder registration.
type Registration struct {
	Message   RegistrationMessage `json:"message"`
	Signature Hex                 `json:"signature"`
}

// RegistrationMessage is a ValidatorRegistrationV1; timestamp in Unix seconds.
type RegistrationMessage struct {
	FeeRecipient Hex    `json:"fee_recipient"`
	GasLimit     uint64 `json:"gas_limit"`
	Timestamp    uint64 `json:"timestamp"`
	PubKey       Hex    `json:"pubkey"`
}

// Parse reads a lock. It refuses unknown fields and versions other than
// v1.11.0.
func Parse(b []byte) (*Lock, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var l Lock
	if err := dec.Decode(&l); err != nil {
		return nil, fmt.Errorf("charonlock: %w", err)
	}
	if dec.More() {
		return nil, errors.New("charonlock: trailing data")
	}
	if l.Definition.Version != Version {
		return nil, fmt.Errorf("charonlock: version %q, want %s", l.Definition.Version, Version)
	}
	return &l, nil
}

// Marshal writes the lock as indented JSON.
func (l *Lock) Marshal() ([]byte, error) {
	b, err := json.MarshalIndent(l, "", " ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// Address parses a "0x" and 40 hex digit address.
func Address(s string) ([20]byte, error) {
	var a [20]byte
	if !strings.HasPrefix(s, "0x") || len(s) != 42 {
		return a, fmt.Errorf("charonlock: address %q is not 0x and 40 hex digits", s)
	}
	b, err := hex.DecodeString(s[2:])
	if err != nil {
		return a, fmt.Errorf("charonlock: address %q is not hex", s)
	}
	copy(a[:], b)
	return a, nil
}

// addressOrZero is Charon's hashing of an address field: empty hashes as 20
// zero bytes.
func addressOrZero(s string) ([20]byte, error) {
	if s == "" {
		return [20]byte{}, nil
	}
	return Address(s)
}
