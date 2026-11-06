package main

// exit: a voluntary exit signed by t runners of the cluster. Only the admin
// role may SIGN an exit (docs/protocol.md, "Client roles"), so the signing
// client cannot make one; the operator makes it here. With -partial-out, each
// admin certificate holder writes the partials of their own signers, and
// exit-combine makes the exit from t of them offline.

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/lidofinance/tee-signer/governance/setupwire"
	"github.com/lidofinance/tee-signer/signer-core/core"
	"github.com/lidofinance/tee-signer/signer-core/threshold"
	cloud "github.com/lidofinance/tee-signer/signer-protocol"
)

// exitJSON is the body of the beacon API's POST
// /eth/v1/beacon/pool/voluntary_exits.
type exitJSON struct {
	Message struct {
		Epoch          string `json:"epoch"`
		ValidatorIndex string `json:"validator_index"`
	} `json:"message"`
	Signature string `json:"signature"`
}

// exitPartials is the file of exit -partial-out: partial signatures of one
// exit, each verified under its signer's share key, and the chain values
// that give the signing root. It holds nothing secret.
type exitPartials struct {
	Pubkey                   cloud.Pubkey     `json:"pubkey"`
	ValidatorIndex           uint64           `json:"validator_index"`
	Epoch                    uint64           `json:"epoch"`
	VoluntaryExitForkVersion cloud.Version    `json:"voluntary_exit_fork_version"`
	GenesisValidatorsRoot    cloud.Root       `json:"genesis_validators_root"`
	Partials                 []exitPartialSig `json:"partials"`
}

type exitPartialSig struct {
	Signer     string          `json:"signer"`
	ShareIndex uint64          `json:"share_index"`
	Signature  cloud.Signature `json:"signature"`
}

const exitUsage = "usage: signer-admin exit -cluster cluster.json [-signers NAME,...] [-split FILE] -pubkey 0x... -index N -epoch E -out exit.json|-partial-out FILE"

func cmdExit(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("exit", flag.ContinueOnError)
	cf := addClusterFlags(fs)
	splitPath := fs.String("split", "", "the split file of import-draft, for t and each signer's share index; not needed for a cluster of one single-mode signer")
	pubHex := fs.String("pubkey", "", "the validator key")
	index := fs.String("index", "", "the validator index")
	epoch := fs.String("epoch", "", "the exit epoch")
	outPath := fs.String("out", "", "the file for the signed exit, the beacon API's body")
	partialOut := fs.String("partial-out", "", "write the verified partial signatures of the selected signers to this file for exit-combine, instead of -out; needs -split")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *pubHex == "" || *index == "" || *epoch == "" || (*outPath == "") == (*partialOut == "") {
		return errors.New(exitUsage)
	}
	if *partialOut != "" && *splitPath == "" {
		return errors.New("-partial-out needs -split")
	}
	var pk cloud.Pubkey
	if err := pk.UnmarshalText([]byte(*pubHex)); err != nil {
		return fmt.Errorf("-pubkey: %w", err)
	}
	msg := &cloud.VoluntaryExit{}
	var err error
	if msg.ValidatorIndex, err = strconv.ParseUint(*index, 10, 64); err != nil {
		return fmt.Errorf("-index: %w", err)
	}
	if msg.Epoch, err = strconv.ParseUint(*epoch, 10, 64); err != nil {
		return fmt.Errorf("-epoch: %w", err)
	}
	c, err := cf.load()
	if err != nil {
		return err
	}
	// t and the share index of each signer. A single-mode signer holds the
	// whole key: its signature is the exit.
	t, ids := 1, map[string]uint64{}
	if *splitPath != "" {
		split, err := readSplit(*splitPath)
		if err != nil {
			return err
		}
		t = int(split.T)
		for name, i := range split.Shares {
			ids[name] = uint64(i)
		}
	} else if len(c.members) != 1 || c.members[0].setup.SigningMode != setupwire.SigningModeSingle {
		return errors.New("-split is required, except for a cluster of one single-mode signer")
	}
	ch := c.members[0].setup.Chain
	domain, root, err := exitRoot(msg, ch.VoluntaryExitForkVersion, ch.GenesisValidatorsRoot)
	if err != nil {
		return err
	}
	req := cloud.SignRequest{Pubkey: pk, Message: msg, Domain: domain}

	// Ask the signers in turn until t partial signatures verify, or ask
	// every selected signer for -partial-out. A signer that fails or gives
	// a bad partial is skipped.
	parts := exitPartials{Pubkey: pk, ValidatorIndex: msg.ValidatorIndex, Epoch: msg.Epoch,
		VoluntaryExitForkVersion: ch.VoluntaryExitForkVersion, GenesisValidatorsRoot: ch.GenesisValidatorsRoot}
	failed := false
	for _, m := range c.members {
		if *partialOut == "" && len(parts.Partials) == t {
			break
		}
		id, ok := ids[m.name]
		if *splitPath != "" && !ok {
			fprintf(out, "%s: no share index in %s, skipped\n", m.name, *splitPath)
			failed = true
			continue
		}
		sig, err := exitPartial(m, req, root, *cf.timeout)
		if err != nil {
			fprintf(out, "%s: %v\n", m.name, err)
			failed = true
			continue
		}
		parts.Partials = append(parts.Partials, exitPartialSig{Signer: m.name, ShareIndex: id, Signature: sig})
	}
	names := make([]string, len(parts.Partials))
	for i, p := range parts.Partials {
		names[i] = p.Signer
	}
	if *partialOut != "" {
		if len(parts.Partials) == 0 {
			return errors.New("no partial exit verifies; nothing written")
		}
		raw, err := json.MarshalIndent(parts, "", "  ")
		if err != nil {
			return err
		}
		if err := writeAtomic(*partialOut, append(raw, '\n'), 0o644); err != nil {
			return err
		}
		fprintf(out, "partial exits of %s: validator_index %d, epoch %d, signed by %s (%d needed in all); each verifies under its share key\nwrote %s\n",
			pk, msg.ValidatorIndex, msg.Epoch, strings.Join(names, ","), t, *partialOut)
		if failed {
			return errReported
		}
		return nil
	}
	if len(parts.Partials) < t {
		return fmt.Errorf("%d partial exits verify, %d needed; nothing written", len(parts.Partials), t)
	}
	if err := combineAndWrite(parts, root, *outPath); err != nil {
		return err
	}
	fprintf(out, "exit of %s: validator_index %d, epoch %d, signed by %s (%d needed); the signature verifies\nwrote %s\n",
		pk, msg.ValidatorIndex, msg.Epoch, strings.Join(names, ","), t, *outPath)
	return nil
}

const exitCombineUsage = "usage: signer-admin exit-combine -split FILE [-pubkey 0x...] [-index N] [-epoch E] -out exit.json PARTIALS..."

// cmdExitCombine makes the exit from the files of exit -partial-out. It
// talks to no signer: it checks each partial under the share key that the
// split's commitments give for its share index, combines t of them and
// checks the result under the validator key. The split file is the only
// source of share keys.
func cmdExitCombine(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("exit-combine", flag.ContinueOnError)
	splitPath := fs.String("split", "", "the split file of import-draft")
	pubHex := fs.String("pubkey", "", "if given, the validator key the files must name")
	index := fs.String("index", "", "if given, the validator index the files must name")
	epoch := fs.String("epoch", "", "if given, the exit epoch the files must name")
	outPath := fs.String("out", "", "the file for the signed exit, the beacon API's body")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() == 0 || *splitPath == "" || *outPath == "" {
		return errors.New(exitCombineUsage)
	}
	split, err := readSplit(*splitPath)
	if err != nil {
		return err
	}
	var all exitPartials
	var from []string // the file of each partial in all.Partials
	for i, path := range fs.Args() {
		var f exitPartials
		if err := readStrictJSON(path, &f); err != nil {
			return err
		}
		if i == 0 {
			all = f
			all.Partials = nil
		} else if f.Pubkey != all.Pubkey || f.ValidatorIndex != all.ValidatorIndex || f.Epoch != all.Epoch ||
			f.VoluntaryExitForkVersion != all.VoluntaryExitForkVersion || f.GenesisValidatorsRoot != all.GenesisValidatorsRoot {
			return fmt.Errorf("%s: pubkey, validator_index, epoch or chain differ from %s", path, fs.Arg(0))
		}
		all.Partials = append(all.Partials, f.Partials...)
		for range f.Partials {
			from = append(from, path)
		}
	}
	if *pubHex != "" {
		var pk cloud.Pubkey
		if err := pk.UnmarshalText([]byte(*pubHex)); err != nil {
			return fmt.Errorf("-pubkey: %w", err)
		}
		if pk != all.Pubkey {
			return fmt.Errorf("the partial files are for %s, not -pubkey %s", all.Pubkey, pk)
		}
	}
	for _, c := range []struct {
		flag, val string
		got       uint64
	}{{"-index", *index, all.ValidatorIndex}, {"-epoch", *epoch, all.Epoch}} {
		if c.val == "" {
			continue
		}
		v, err := strconv.ParseUint(c.val, 10, 64)
		if err != nil {
			return fmt.Errorf("%s: %w", c.flag, err)
		}
		if v != c.got {
			return fmt.Errorf("the partial files have %d, not %s %d", c.got, c.flag, v)
		}
	}
	comm, ok := split.commitmentsOf(all.Pubkey)
	if !ok {
		return fmt.Errorf("%s: no validator %s", *splitPath, all.Pubkey)
	}
	_, root, err := exitRoot(&cloud.VoluntaryExit{Epoch: all.Epoch, ValidatorIndex: all.ValidatorIndex},
		all.VoluntaryExitForkVersion, all.GenesisValidatorsRoot)
	if err != nil {
		return err
	}
	// The same partial in two files counts once; two signatures for one
	// share index are refused.
	seen := map[uint64]int{} // share index to its first place in all.Partials
	var uniq []exitPartialSig
	for i, p := range all.Partials {
		if id, ok := split.Shares[p.Signer]; !ok || uint64(id) != p.ShareIndex {
			return fmt.Errorf("%s: %s: share index %d is not the index of %s in %s", from[i], p.Signer, p.ShareIndex, p.Signer, *splitPath)
		}
		if j, ok := seen[p.ShareIndex]; ok {
			if all.Partials[j].Signature != p.Signature {
				return fmt.Errorf("share index %d (%s) has different signatures in %s and %s", p.ShareIndex, p.Signer, from[j], from[i])
			}
			continue
		}
		seen[p.ShareIndex] = i
		share, err := threshold.FeldmanEval(comm, p.ShareIndex)
		if err != nil {
			return fmt.Errorf("commitments of %s: %w", all.Pubkey, err)
		}
		if !core.Verify(share, root, p.Signature) {
			return fmt.Errorf("%s: %s: partial signature does not verify under the share key of index %d in %s", from[i], p.Signer, p.ShareIndex, *splitPath)
		}
		uniq = append(uniq, p)
	}
	if len(uniq) < int(split.T) {
		return fmt.Errorf("%d partial exits verify, %d needed; nothing written", len(uniq), split.T)
	}
	all.Partials = uniq[:split.T]
	if err := combineAndWrite(all, root, *outPath); err != nil {
		return err
	}
	names := make([]string, len(all.Partials))
	for i, p := range all.Partials {
		names[i] = p.Signer
	}
	fprintf(out, "exit of %s: validator_index %d, epoch %d, voluntary_exit_fork_version %s, genesis_validators_root %s, combined from %s (%d needed); the signature verifies\nwrote %s\n",
		all.Pubkey, all.ValidatorIndex, all.Epoch, hexOf(all.VoluntaryExitForkVersion[:]), hexOf(all.GenesisValidatorsRoot[:]),
		strings.Join(names, ","), split.T, *outPath)
	return nil
}

func hexOf(b []byte) string { return "0x" + hex.EncodeToString(b) }

// exitRoot is the domain and the signing root of an exit on the chain of
// these values.
func exitRoot(msg *cloud.VoluntaryExit, fork cloud.Version, gvr cloud.Root) (cloud.Root, cloud.Root, error) {
	domain := cloud.ComputeDomain(cloud.DomainVoluntaryExit, fork, gvr)
	obj, err := cloud.HashTreeRoot(msg)
	if err != nil {
		return domain, cloud.Root{}, err
	}
	return domain, cloud.SigningRoot(obj, domain), nil
}

// combineAndWrite combines the partials (combineExit) and writes the beacon
// API body to path.
func combineAndWrite(p exitPartials, root cloud.Root, path string) error {
	ids := make([]uint64, len(p.Partials))
	sigs := make([]cloud.Signature, len(p.Partials))
	for i, s := range p.Partials {
		ids[i], sigs[i] = s.ShareIndex, s.Signature
	}
	full, err := combineExit(p.Pubkey, root, ids, sigs)
	if err != nil {
		return err
	}
	var body exitJSON
	body.Message.Epoch = strconv.FormatUint(p.Epoch, 10)
	body.Message.ValidatorIndex = strconv.FormatUint(p.ValidatorIndex, 10)
	body.Signature = hexOf(full[:])
	raw, err := json.MarshalIndent(body, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(path, append(raw, '\n'), 0o644)
}

// exitPartial asks m for its signature of the exit and checks it against
// m's share key of the validator.
func exitPartial(m *member, req cloud.SignRequest, root cloud.Root, timeout time.Duration) (cloud.Signature, error) {
	cl, err := connectAdmin(m, timeout)
	if err != nil {
		return cloud.Signature{}, err
	}
	defer cl.Close()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	keys, err := cl.PublicKeys(ctx)
	if err != nil {
		return cloud.Signature{}, fmt.Errorf("public keys: %w", err)
	}
	var share *cloud.Pubkey
	for _, k := range keys {
		if k.Pubkey == req.Pubkey {
			share = &k.SharePubkey
		}
	}
	if share == nil {
		return cloud.Signature{}, errors.New("does not hold the validator")
	}
	sig, err := cl.Sign(ctx, req)
	if err != nil {
		return cloud.Signature{}, err
	}
	if !core.Verify(*share, root, sig) {
		return cloud.Signature{}, errors.New("partial signature does not verify under its share key")
	}
	return sig, nil
}

// combineExit combines t partial signatures with share indices ids (one
// signature of a whole key is the result) and checks it under the
// validator key.
func combineExit(pk cloud.Pubkey, root cloud.Root, ids []uint64, sigs []cloud.Signature) (cloud.Signature, error) {
	full := sigs[0]
	if len(sigs) > 1 {
		var err error
		if full, err = threshold.RecoverSignature(ids, sigs); err != nil {
			return full, err
		}
	}
	if !core.Verify(pk, root, full) {
		return full, errors.New("the combined signature does not verify under the validator key; nothing written")
	}
	return full, nil
}
