package main

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/lidofinance/tee-signer/signer-core/core"
	"github.com/lidofinance/tee-signer/signer-core/software"
	cloud "github.com/lidofinance/tee-signer/signer-protocol"
)

// charonCluster is a Charon cluster made here: validators split t of n,
// with their group keys, share secrets (index i + 1 at i) and commitments.
type charonCluster struct {
	t, n        int
	groups      []cloud.Pubkey
	secrets     [][][32]byte
	commitments [][]cloud.Pubkey
}

func newCharonCluster(t *testing.T, vals, tt, n int) *charonCluster {
	t.Helper()
	c := &charonCluster{t: tt, n: n}
	for range vals {
		sk, _ := software.NewSecret()
		pk, _ := core.PubkeyOf(sk)
		shares, comm, err := software.SplitWithCommitments(sk, tt, n)
		if err != nil {
			t.Fatal(err)
		}
		var secs [][32]byte
		for _, s := range shares {
			secs = append(secs, s.Secret)
		}
		c.groups, c.secrets, c.commitments = append(c.groups, pk), append(c.secrets, secs), append(c.commitments, comm)
	}
	return c
}

func (c *charonCluster) sharePub(t *testing.T, v, i int) cloud.Pubkey {
	t.Helper()
	p, err := core.PubkeyOf(c.secrets[v][i])
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// lock writes a cluster-lock.json of c, with the fields Charon writes that
// dv-split does not read; change edits validator v's public shares first.
func (c *charonCluster) lock(t *testing.T, path string, change func(v int, shares []string, group *string)) string {
	t.Helper()
	var dvs []any
	for v := range c.groups {
		var shares []string
		for i := range c.n {
			shares = append(shares, c.sharePub(t, v, i).String())
		}
		group := c.groups[v].String()
		if change != nil {
			change(v, shares, &group)
		}
		dvs = append(dvs, map[string]any{"distributed_public_key": group, "public_shares": shares,
			"builder_registration": map[string]any{}, "partial_deposit_data": []any{}})
	}
	ops := make([]any, c.n)
	for i := range ops {
		ops[i] = map[string]any{"address": fmt.Sprintf("0x%040d", i), "enr": "enr:-test"}
	}
	return writeJSONFile(t, path, map[string]any{
		"cluster_definition":     map[string]any{"name": "test", "version": "v1.8.0", "threshold": c.t, "num_validators": len(c.groups), "operators": ops},
		"distributed_validators": dvs, "lock_hash": "0x00", "signature_aggregate": "0x00"})
}

// dv-split reads a Charon cluster lock into the split file of import-draft:
// t, n, the signers' share indices and each validator's group key with the
// commitments interpolated from its public shares, the split's own.
func TestDVSplitFromLock(t *testing.T) {
	dir := t.TempDir()
	c := newCharonCluster(t, 2, 3, 4)
	lock := c.lock(t, filepath.Join(dir, "cluster-lock.json"), nil)
	sp := filepath.Join(dir, "split.json")
	mustTool(t, "dv-split", "-lock", lock, "-signers", "d1=2", "-out", sp)
	sf, err := readSplit(sp)
	if err != nil {
		t.Fatal(err)
	}
	if sf.T != 3 || sf.N != 4 || sf.Shares["d1"] != 2 || len(sf.Shares) != 1 || len(sf.Validators) != 2 {
		t.Fatalf("split %+v", sf)
	}
	for v, g := range c.groups {
		comm, ok := sf.commitmentsOf(g)
		if !ok || !slices.Equal(comm, c.commitments[v]) {
			t.Fatalf("validator %d: commitments differ from the split's", v)
		}
	}
}

// A lock whose public shares are not on one polynomial, or whose group key
// is not the polynomial's, writes nothing.
func TestDVSplitRefusesInconsistentLock(t *testing.T) {
	dir := t.TempDir()
	c := newCharonCluster(t, 2, 3, 4)
	other := newCharonCluster(t, 1, 3, 4)
	sp := filepath.Join(dir, "split.json")
	for _, x := range []struct {
		name   string
		change func(v int, shares []string, group *string)
		want   string
	}{
		{"last share replaced", func(v int, shares []string, _ *string) {
			if v == 1 {
				shares[3] = other.sharePub(t, 0, 3).String()
			}
		}, "public share 4 is not on the polynomial"},
		{"another group key", func(v int, _ []string, group *string) {
			if v == 0 {
				*group = other.groups[0].String()
			}
		}, "interpolate to another key"},
	} {
		lock := c.lock(t, filepath.Join(dir, "lock-"+x.name+".json"), x.change)
		wantIn(t, failTool(t, "dv-split", "-lock", lock, "-signers", "d1=2", "-out", sp), x.want)
		if _, err := os.Stat(sp); err == nil {
			t.Fatalf("%s: split file written", x.name)
		}
	}
	lock := c.lock(t, filepath.Join(dir, "lock.json"), nil)
	wantIn(t, failTool(t, "dv-split", "-lock", lock, "-signers", "d1=5", "-out", sp), "share index 5, want 1 to 4")
	wantIn(t, failTool(t, "dv-split", "-lock", lock, "-signers", "d1=2,d2=2", "-out", sp), "share index 2 is given to")
}

// The shares file of a single-mode import names each Charon share by its
// own key. Under an order for share index 2, fileDVShares files the line
// of share 2 under its group key and keeps its own key for the slashing
// protection file; a line of another index, or of a key the split does not
// know, stays as it is.
func TestFileDVShares(t *testing.T) {
	c := newCharonCluster(t, 2, 3, 4)
	sf := &splitFile{T: 3, N: 4, Shares: map[string]uint8{"d1": 2}}
	for v, g := range c.groups {
		sf.Validators = append(sf.Validators, splitValidator{Pubkey: g, Commitments: c.commitments[v]})
	}
	stranger, strangerPk := func() ([32]byte, cloud.Pubkey) {
		sk, _ := software.NewSecret()
		pk, _ := core.PubkeyOf(sk)
		return sk, pk
	}()
	shares := []share{
		{line: 1, pubkey: c.sharePub(t, 0, 1), secret: c.secrets[0][1]},
		{line: 2, pubkey: c.sharePub(t, 1, 1), secret: c.secrets[1][1]},
		{line: 3, pubkey: c.sharePub(t, 0, 2), secret: c.secrets[0][2]}, // share 3
		{line: 4, pubkey: strangerPk, secret: stranger},
		{line: 5, pubkey: c.sharePub(t, 1, 1), secret: c.secrets[0][1]}, // secret of another key
	}
	n, err := fileDVShares(shares, sf, 2)
	if err != nil || n != 2 {
		t.Fatalf("filed %d, %v; want 2", n, err)
	}
	for i, want := range []cloud.Pubkey{c.groups[0], c.groups[1], c.sharePub(t, 0, 2), strangerPk, c.sharePub(t, 1, 1)} {
		if shares[i].pubkey != want {
			t.Errorf("line %d filed under %s", i+1, shares[i].pubkey)
		}
	}
	if shares[0].markKey != c.sharePub(t, 0, 1) || shares[2].markKey != (cloud.Pubkey{}) {
		t.Error("markKey")
	}
}
