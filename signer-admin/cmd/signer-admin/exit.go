package main

// exit: a voluntary exit signed by t runners of the cluster. Only the admin
// role may SIGN an exit (docs/protocol.md, "Client roles"), so the signing
// client cannot make one; the operator makes it here.

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

const exitUsage = "usage: signer-admin exit -cluster cluster.json [-signers NAME,...] [-split FILE] -pubkey 0x... -index N -epoch E -out exit.json"

func cmdExit(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("exit", flag.ContinueOnError)
	cf := addClusterFlags(fs)
	splitPath := fs.String("split", "", "the split file of import-draft, for t and each signer's share index; not needed for a cluster of one single-mode signer")
	pubHex := fs.String("pubkey", "", "the validator key")
	index := fs.String("index", "", "the validator index")
	epoch := fs.String("epoch", "", "the exit epoch")
	outPath := fs.String("out", "", "the file for the signed exit, the beacon API's body")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *pubHex == "" || *index == "" || *epoch == "" || *outPath == "" {
		return errors.New(exitUsage)
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
	domain := cloud.ComputeDomain(cloud.DomainVoluntaryExit, ch.VoluntaryExitForkVersion, ch.GenesisValidatorsRoot)
	obj, err := cloud.HashTreeRoot(msg)
	if err != nil {
		return err
	}
	root := cloud.SigningRoot(obj, domain)
	req := cloud.SignRequest{Pubkey: pk, Message: msg, Domain: domain}

	// Ask the signers in turn until t partial signatures verify. A signer
	// that fails or gives a bad partial is skipped.
	var (
		got   []uint64
		sigs  []cloud.Signature
		names []string
	)
	for _, m := range c.members {
		if len(sigs) == t {
			break
		}
		id, ok := ids[m.name]
		if *splitPath != "" && !ok {
			fprintf(out, "%s: no share index in %s, skipped\n", m.name, *splitPath)
			continue
		}
		sig, err := exitPartial(m, req, root, *cf.timeout)
		if err != nil {
			fprintf(out, "%s: %v\n", m.name, err)
			continue
		}
		got, sigs, names = append(got, id), append(sigs, sig), append(names, m.name)
	}
	if len(sigs) < t {
		return fmt.Errorf("%d partial exits verify, %d needed; nothing written", len(sigs), t)
	}
	full, err := combineExit(pk, root, got, sigs)
	if err != nil {
		return err
	}
	var body exitJSON
	body.Message.Epoch = strconv.FormatUint(msg.Epoch, 10)
	body.Message.ValidatorIndex = strconv.FormatUint(msg.ValidatorIndex, 10)
	body.Signature = "0x" + hex.EncodeToString(full[:])
	raw, err := json.MarshalIndent(body, "", "  ")
	if err != nil {
		return err
	}
	if err := writeAtomic(*outPath, append(raw, '\n'), 0o644); err != nil {
		return err
	}
	fprintf(out, "exit of %s: validator_index %d, epoch %d, signed by %s (%d needed); the signature verifies\nwrote %s\n",
		pk, msg.ValidatorIndex, msg.Epoch, strings.Join(names, ","), t, *outPath)
	return nil
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
