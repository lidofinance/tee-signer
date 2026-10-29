package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/lidofinance/tee-signer/signer-core/core"
	"github.com/lidofinance/tee-signer/signer-core/threshold"
	"github.com/lidofinance/tee-signer/signer-protocol/wire"
)

// AccountsFile is the accounts file of the Dirk fork's TEE backends
// (threshold-signer-poc dirk-fork/backends/accounts) and of the signer shim: public
// keys only. Each participant gets its own, with its share key.
type AccountsFile struct {
	Accounts []AccountEntry `json:"accounts"`
}

type AccountEntry struct {
	Wallet             string            `json:"wallet"`
	Name               string            `json:"name"`
	PubKey             string            `json:"pubkey"`
	SharePubKey        string            `json:"share_pubkey"`
	SigningThreshold   uint32            `json:"signing_threshold"`
	Participants       map[string]string `json:"participants"`
	ParticipantPubKeys map[string]string `json:"participant_pubkeys"`
}

func readResultFile(path string) (*Result, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var r Result
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &r, nil
}

// accountsFor builds participant i's accounts file (from 0).
func accountsFor(r *Result, i int, wallet, prefix string, endpoints []string) AccountsFile {
	var f AccountsFile
	for v, val := range r.Validators {
		e := AccountEntry{Wallet: wallet, Name: fmt.Sprintf("%s%d", prefix, v), PubKey: val.Pubkey,
			SharePubKey: val.PublicShares[i], SigningThreshold: uint32(r.Threshold),
			Participants: map[string]string{}, ParticipantPubKeys: map[string]string{}}
		for j, s := range val.PublicShares {
			id := strconv.Itoa(j + 1)
			e.Participants[id] = endpoints[j]
			e.ParticipantPubKeys[id] = s
		}
		f.Accounts = append(f.Accounts, e)
	}
	return f
}

// cmdAccounts writes accounts-<id>.json per participant for the Dirk fork:
// Dirk participant id is the share ID, endpoints its Dirk's host:port.
func cmdAccounts(args []string) error {
	fs := flag.NewFlagSet("accounts", flag.ExitOnError)
	resultPath := fs.String("result", "dkg-result.json", "the keygen result, or several comma-separated as one (same participants)")
	wallet := fs.String("wallet", "Generated", "wallet name of the accounts")
	prefix := fs.String("name-prefix", "dkg-", "account names are this and the validator's position")
	endpoints := fs.String("endpoints", "", "comma-separated host:port of each participant's Dirk, in share ID order")
	outDir := fs.String("out-dir", ".", "folder for accounts-<id>.json")
	_ = fs.Parse(args)
	r, err := readResultFile(*resultPath)
	if err != nil {
		return err
	}
	eps := strings.Split(*endpoints, ",")
	if len(eps) != len(r.Participants) || *endpoints == "" {
		return fmt.Errorf("-endpoints needs %d host:port values", len(r.Participants))
	}
	if err := checkResult(r); err != nil {
		return err
	}
	for i := range r.Participants {
		p := filepath.Join(*outDir, fmt.Sprintf("accounts-%d.json", i+1))
		if err := writeJSON(p, accountsFor(r, i, *wallet, *prefix, eps)); err != nil {
			return err
		}
	}
	fmt.Fprintf(os.Stderr, "%d accounts files, %d accounts each, in %s\n", len(r.Participants), len(r.Validators), *outDir)
	return nil
}

// checkResult checks that each validator's public shares recover its key
// from every set of threshold shares that includes share 1.
func checkResult(r *Result) error {
	gks, shares, err := r.Keys()
	if err != nil {
		return err
	}
	for v, gk := range gks {
		if len(shares[v]) != len(r.Participants) {
			return fmt.Errorf("validator %d: %d shares for %d participants", v, len(shares[v]), len(r.Participants))
		}
		for x := r.Threshold; x <= len(shares[v]); x++ {
			ids := []uint64{}
			for k := 1; k < r.Threshold; k++ {
				ids = append(ids, uint64(k))
			}
			ids = append(ids, uint64(x))
			var pks = shares[v][:0:0]
			for _, id := range ids {
				pks = append(pks, shares[v][id-1])
			}
			got, err := threshold.RecoverPubkey(ids, pks)
			if err != nil || got != gk {
				return fmt.Errorf("validator %d: public shares %v do not give the key", v, ids)
			}
		}
	}
	return nil
}

// shimFork is one entry of the signer shim's chain.forks.
type shimFork struct {
	Epoch   uint64 `json:"epoch"`
	Version string `json:"version"`
}

// shimChain is the chain section of the signer shim's shim.yml, with the
// shim's field names (gateway/cmd/signer-shim, shimConfig.Chain).
type shimChain struct {
	Preset                   string     `json:"preset"`
	SlotsPerEpoch            uint64     `json:"slots_per_epoch"`
	GenesisForkVersion       string     `json:"genesis_fork_version"`
	GenesisValidatorsRoot    string     `json:"genesis_validators_root"`
	VoluntaryExitForkVersion string     `json:"voluntary_exit_fork_version"`
	Forks                    []shimFork `json:"forks"`
	// GloasForkEpoch is written whenever the chain config sets it, 0 too:
	// the shim refuses every Gloas duty without it (TKGARTIFACT-03).
	GloasForkEpoch *uint64 `json:"gloas_fork_epoch,omitempty"`
}

// shimChainYAML is the runners' chain config as the shim's chain section:
// one JSON object, which YAML reads as a flow mapping. Each field comes
// from core.Config, so a field the shim reads cannot be left out.
func shimChainYAML(c *core.Config) (string, error) {
	sc := shimChain{Preset: c.PresetName(), SlotsPerEpoch: c.SlotsPerEpoch,
		GenesisForkVersion:       hex0x(c.GenesisForkVersion[:]),
		GenesisValidatorsRoot:    hex0x(c.GenesisValidatorsRoot[:]),
		VoluntaryExitForkVersion: hex0x(c.VoluntaryExitForkVersion[:]),
		Forks:                    []shimFork{}, GloasForkEpoch: c.GloasForkEpoch}
	for _, f := range c.Forks {
		sc.Forks = append(sc.Forks, shimFork{Epoch: f.Epoch, Version: hex0x(f.Version[:])})
	}
	b, err := json.Marshal(sc)
	return string(b), err
}

// shimConnections is the number of connections each signer shim keeps to
// its runner, as in the Dirk forks' cloud.json. With one, the selection
// proofs at each epoch start queue behind each other.
const shimConnections = 8

// cmdCharonShims writes each Charon node's signer shim settings: shim.yml
// (the shim, with the runner chain config), cloud.json (the runner
// connection with the policy's attestation settings for that position and
// shimConnections connections) and accounts.json (the node's share key).
// The node operator adds the client certificate the runner accepts.
func cmdCharonShims(args []string) error {
	fs := flag.NewFlagSet("charon-shims", flag.ExitOnError)
	var cf commonFlags
	cf.register(fs)
	resultPath := fs.String("result", "dkg-result.json", "the keygen result, or several comma-separated as one (same participants)")
	chainPath := fs.String("chain", "", "the runners' chain config (JSON, core.Config)")
	listen := fs.String("listen", "127.0.0.1:29220", "address each shim listens on")
	outDir := fs.String("out-dir", "shims", "folder for node<i>/")
	_ = fs.Parse(args)
	cfg, err := readConfig(cf.config)
	if err != nil {
		return err
	}
	pol, hash, err := cfg.loadPolicy(cf.platform)
	if err != nil {
		return err
	}
	r, err := readResult(*resultPath, hash)
	if err != nil {
		return err
	}
	if *chainPath == "" {
		return errors.New("-chain is required")
	}
	chain, _, err := core.LoadConfig(*chainPath)
	if err != nil {
		return err
	}
	if err := checkResult(r); err != nil {
		return err
	}
	y, err := shimChainYAML(&chain)
	if err != nil {
		return err
	}
	var fees []string
	for _, a := range chain.FeeRecipients {
		fees = append(fees, fmt.Sprintf("\"0x%x\"", a[:]))
	}
	names := make([]string, len(r.Participants))
	for i := range names {
		names[i] = fmt.Sprintf("node%d", i)
	}
	for i := range r.Participants {
		dir := filepath.Join(*outDir, fmt.Sprintf("node%d", i))
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
		shim := fmt.Sprintf("# dkg-coordinator charon-shims: signer shim of Charon node %d, in front of runner %d (%s).\nlisten: %s\nchain: %s\nbackend:\n  type: cloud\n  config: cloud.json\npolicy:\n  fee_recipient_allowlist: [%s]\ntimeout: 10s\n",
			i, i+1, cfg.Runners[i].Address, *listen, y, strings.Join(fees, ", "))
		if err := os.WriteFile(filepath.Join(dir, "shim.yml"), []byte(shim), 0o644); err != nil {
			return err
		}
		cloud := map[string]any{
			"address": cfg.Runners[i].Address, "client_cert": "client.pem", "client_key": "client-key.pem",
			"attestation": pol.Participants[i].Attestation, "accounts": "accounts.json", "slots_per_epoch": chain.SlotsPerEpoch,
			"connections": shimConnections, "identity_version": wire.IdentityVersion,
		}
		if err := writeJSON(filepath.Join(dir, "cloud.json"), cloud); err != nil {
			return err
		}
		if err := writeJSON(filepath.Join(dir, "accounts.json"), accountsFor(r, i, "Charon", "dv-", names)); err != nil {
			return err
		}
	}
	fmt.Fprintf(os.Stderr, "signer shim settings for %d Charon nodes in %s (each needs client.pem and client-key.pem for its runner)\n", len(r.Participants), *outDir)
	return nil
}
