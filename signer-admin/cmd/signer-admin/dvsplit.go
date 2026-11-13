package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/lidofinance/tee-signer/governance/setupwire"
	"github.com/lidofinance/tee-signer/signer-core/core"
	"github.com/lidofinance/tee-signer/signer-core/threshold"
	cloud "github.com/lidofinance/tee-signer/signer-protocol"
)

// ---- dv-split: the split file of a Charon cluster ----
//
// A signer with signing_mode = dv_share holds one share of each distributed
// validator of an Obol Charon cluster. The cluster lock lists, for each
// validator, its group key (distributed_public_key) and the public keys of
// its n shares (public_shares, share index i + 1 at position i), and the
// cluster's threshold t. dv-split turns that into the split file that
// import-draft and import read: the commitments come from the first t
// public shares (threshold.Commitments), and every one of the n public
// shares and the group key must agree with them, or nothing is written.
// The lock's signatures and lock_hash are not checked: the admin vouches
// for the file, and the approvers sign the commitments hash it gives.

// charonLock is the part of a Charon cluster-lock.json that dv-split reads.
type charonLock struct {
	Definition struct {
		Threshold int `json:"threshold"`
	} `json:"cluster_definition"`
	Validators []struct {
		Group  cloud.Pubkey   `json:"distributed_public_key"`
		Shares []cloud.Pubkey `json:"public_shares"`
	} `json:"distributed_validators"`
}

// dvSplit reads a cluster lock into a split file without the signers' share
// indices.
func dvSplit(path string) (*splitFile, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var l charonLock
	if err := json.Unmarshal(raw, &l); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	t := l.Definition.Threshold
	if len(l.Validators) == 0 {
		return nil, fmt.Errorf("%s: no distributed_validators", path)
	}
	n := len(l.Validators[0].Shares)
	if t < 1 || t > n || n > 255 {
		return nil, fmt.Errorf("%s: threshold %d of %d public shares, want 1 <= t <= n <= 255", path, t, n)
	}
	sf := &splitFile{T: uint8(t), N: uint8(n)}
	ids := make([]uint64, t)
	for i := range ids {
		ids[i] = uint64(i + 1)
	}
	seen := map[cloud.Pubkey]bool{}
	for v, dv := range l.Validators {
		if len(dv.Shares) != n {
			return nil, fmt.Errorf("%s: validator %d has %d public shares, validator 1 has %d", path, v+1, len(dv.Shares), n)
		}
		if seen[dv.Group] {
			return nil, fmt.Errorf("%s: validator %s is listed twice", path, dv.Group)
		}
		seen[dv.Group] = true
		comm, err := threshold.Commitments(ids, dv.Shares[:t])
		if err != nil {
			return nil, fmt.Errorf("%s: validator %s: %w", path, dv.Group, err)
		}
		if comm[0] != dv.Group {
			return nil, fmt.Errorf("%s: validator %s: its public shares interpolate to another key, %s", path, dv.Group, comm[0])
		}
		for i, ps := range dv.Shares {
			got, err := threshold.FeldmanEval(comm, uint64(i+1))
			if err != nil || got != ps {
				return nil, fmt.Errorf("%s: validator %s: public share %d is not on the polynomial of shares 1 to %d: the lock is inconsistent", path, dv.Group, i+1, t)
			}
		}
		sf.Validators = append(sf.Validators, splitValidator{Pubkey: dv.Group, Commitments: comm})
	}
	return sf, nil
}

func cmdDVSplit(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("dv-split", flag.ContinueOnError)
	lockPath := fs.String("lock", "", "the Charon cluster-lock.json")
	signersArg := fs.String("signers", "", "NAME=INDEX[,NAME=INDEX...]: each dv_share signer of cluster.json and the Charon share index it holds (operator position in the lock, from 1)")
	outPath := fs.String("out", "split.json", "the split file to write, for import-draft and import")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *lockPath == "" || *signersArg == "" {
		return errors.New("usage: signer-admin dv-split -lock cluster-lock.json -signers NAME=INDEX[,NAME=INDEX...] [-out split.json]")
	}
	sf, err := dvSplit(*lockPath)
	if err != nil {
		return err
	}
	sf.Shares = map[string]uint8{}
	for _, p := range strings.Split(*signersArg, ",") {
		name, idx, ok := strings.Cut(p, "=")
		i, err := strconv.ParseUint(idx, 10, 8)
		if !ok || name == "" || err != nil {
			return fmt.Errorf("-signers: %q, want NAME=INDEX", p)
		}
		if _, dup := sf.Shares[name]; dup {
			return fmt.Errorf("-signers: %s named twice", name)
		}
		sf.Shares[name] = uint8(i)
	}
	if err := setupwire.CheckShareIndices(int(sf.N), sf.Shares); err != nil {
		return fmt.Errorf("-signers: %w", err)
	}
	js, err := json.MarshalIndent(sf, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(*outPath, append(js, '\n'), 0o644); err != nil {
		return err
	}
	fprintf(out, "dv-split %s: %d validators, %d of %d; every public share and group key agree with the commitments\nwrote %s\n",
		*lockPath, len(sf.Validators), sf.T, sf.N, *outPath)
	return nil
}

// fileDVShares files the shares of a dv_share signer under their group key.
// A shares file of a single-mode import names each Charon share by its own
// public key, as a whole key. Under an order for share index idx of the
// split, a line whose key is no validator of the split but is that
// validator's share at idx, and whose secret is that key's, is filed under
// the validator: the import sends it with the group key as the validator
// key and the line's key as share_pubkey. markKey keeps the line's key,
// under which a Charon validator client's slashing protection file lists
// the share. It returns how many lines it filed.
func fileDVShares(shares []share, split *splitFile, idx uint8) (int, error) {
	at := map[cloud.Pubkey]cloud.Pubkey{}
	known := map[cloud.Pubkey]bool{}
	for _, v := range split.Validators {
		known[v.Pubkey] = true
		p, err := threshold.FeldmanEval(v.Commitments, uint64(idx))
		if err != nil {
			return 0, fmt.Errorf("commitments of %s: %w", v.Pubkey, err)
		}
		at[p] = v.Pubkey
	}
	n := 0
	for i := range shares {
		s := &shares[i]
		g, ok := at[s.pubkey]
		if known[s.pubkey] || !ok {
			continue
		}
		if sp, err := core.PubkeyOf(s.secret); err != nil || sp != s.pubkey {
			continue // reported in the import loop
		}
		s.markKey, s.pubkey = s.pubkey, g
		n++
	}
	return n, nil
}
