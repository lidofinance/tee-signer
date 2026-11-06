package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/lidofinance/tee-signer/signer-core/core"
	"github.com/lidofinance/tee-signer/signer-core/software"
	cloud "github.com/lidofinance/tee-signer/signer-protocol"
)

// exitFixture is three fake runners with a 2 of 3 split of one validator,
// index 42, and the split file. Runner i holds share i and signs with
// signers[i].
type exitFixture struct {
	fc      *fakeCluster
	pk      cloud.Pubkey
	cfg     core.Config
	keys    []cloud.ValidatorKey
	signers []*core.Signer
	split   string
}

func newExitFixture(t *testing.T) *exitFixture {
	fc := newFakeCluster(t)
	sk, err := software.NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	pk, _ := core.PubkeyOf(sk)
	shares, comm, err := software.SplitWithCommitments(sk, 2, 3)
	if err != nil {
		t.Fatal(err)
	}
	// The chain of setupText.
	cfg := software.DevConfig(uint64(genesisTime()), secondsPerSlot, slotsPerEpoch)
	cfg.GenesisValidatorsRoot = cloud.Root{0x4b, 0x36}
	cfg.VoluntaryExitForkVersion = cloud.Version{0x04, 0x00, 0x00, 0x10}
	f := &exitFixture{fc: fc, pk: pk, cfg: cfg, keys: make([]cloud.ValidatorKey, len(shares)), signers: make([]*core.Signer, len(shares))}
	for i, sh := range shares {
		s, err := core.NewSigner(cfg, 1, 0, software.NewMemHooks())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(s.Close)
		if f.keys[i], err = s.AddValidator(pk, sh.Secret, 42, nil); err != nil {
			t.Fatal(err)
		}
		f.signers[i] = s
	}
	for i, name := range []string{"s1", "s2", "s3"} {
		fc.runners[name].SetSigner(f.keys[i], f.signers[i].Sign)
	}
	f.split = writeJSONFile(t, fc.path("split.json"), map[string]any{
		"t": 2, "n": 3, "shares": map[string]int{"s1": 1, "s2": 2, "s3": 3},
		"validators": []map[string]any{{"pubkey": pk.String(), "commitments": []string{comm[0].String(), comm[1].String()}}},
	})
	return f
}

// verifyExitFile checks that the beacon API body at path is the exit of
// epoch 7 and verifies under the validator key.
func (f *exitFixture) verifyExitFile(t *testing.T, path string) {
	t.Helper()
	var body exitJSON
	if err := json.Unmarshal(mustRead(t, path), &body); err != nil {
		t.Fatal(err)
	}
	if body.Message.Epoch != "7" || body.Message.ValidatorIndex != "42" {
		t.Fatalf("exit body %+v", body)
	}
	var sig cloud.Signature
	if err := sig.UnmarshalText([]byte(body.Signature)); err != nil {
		t.Fatal(err)
	}
	domain := cloud.ComputeDomain(cloud.DomainVoluntaryExit, f.cfg.VoluntaryExitForkVersion, f.cfg.GenesisValidatorsRoot)
	obj, _ := cloud.HashTreeRoot(&cloud.VoluntaryExit{Epoch: 7, ValidatorIndex: 42})
	if !core.Verify(f.pk, cloud.SigningRoot(obj, domain), sig) {
		t.Fatal("the written exit does not verify under the validator key")
	}
}

// exit against three fake runners with a 2 of 3 split: s1 answers with a
// wrong partial and is skipped, s2 and s3 give the exit, whose combined
// signature verifies under the validator key and lands in the beacon API
// body. With s1 and s2 only, one partial verifies and nothing is written.
func TestExitCommand(t *testing.T) {
	f := newExitFixture(t)
	fc := f.fc
	// s1 holds share 1 but signs with share 3.
	fc.runners["s1"].SetSigner(f.keys[0], f.signers[2].Sign)

	out := filepath.Join(fc.dir, "exit.json")
	res := mustTool(t, "exit", "-cluster", fc.cluster, "-split", f.split, "-pubkey", f.pk.String(), "-index", "42", "-epoch", "7", "-out", out)
	wantIn(t, res, "s1: partial signature does not verify under its share key", "signed by s2,s3 (2 needed)", "wrote "+out)
	f.verifyExitFile(t, out)

	out2 := filepath.Join(fc.dir, "exit2.json")
	res = failTool(t, "exit", "-cluster", fc.cluster, "-signers", "s1,s2", "-split", f.split, "-pubkey", f.pk.String(), "-index", "42", "-epoch", "7", "-out", out2)
	wantIn(t, res, "1 partial exits verify, 2 needed")
	if _, err := os.Stat(out2); err == nil {
		t.Fatal("a failed exit wrote its file")
	}
}

// exit -partial-out run once per signer, as each admin certificate holder
// would, then exit-combine: the exit is the one of the one-run path. Each
// check of exit-combine refuses a file made to reach it, and writes nothing.
func TestExitPartialCombine(t *testing.T) {
	f := newExitFixture(t)
	fc := f.fc
	partial := func(name, epoch string) string {
		p := filepath.Join(fc.dir, name+"-"+epoch+".partial.json")
		res := mustTool(t, "exit", "-cluster", fc.cluster, "-signers", name, "-split", f.split, "-pubkey", f.pk.String(), "-index", "42", "-epoch", epoch, "-partial-out", p)
		wantIn(t, res, "signed by "+name+" (2 needed in all)", "wrote "+p)
		return p
	}
	p1, p2, p3 := partial("s1", "7"), partial("s2", "7"), partial("s3", "7")

	one := filepath.Join(fc.dir, "one.json")
	mustTool(t, "exit", "-cluster", fc.cluster, "-split", f.split, "-pubkey", f.pk.String(), "-index", "42", "-epoch", "7", "-out", one)
	for _, ps := range [][]string{{p1, p2}, {p3, p1}, {p1, p2, p3}} {
		out := filepath.Join(fc.dir, "combined.json")
		res := mustTool(t, append([]string{"exit-combine", "-split", f.split, "-out", out}, ps...)...)
		wantIn(t, res, "(2 needed); the signature verifies", "wrote "+out)
		f.verifyExitFile(t, out)
		if !bytes.Equal(mustRead(t, out), mustRead(t, one)) {
			t.Fatal("the combined exit differs from the one-run exit")
		}
	}

	// The same file twice counts once. The optional flags must match.
	out := filepath.Join(fc.dir, "dup.json")
	res := mustTool(t, "exit-combine", "-split", f.split, "-pubkey", f.pk.String(), "-index", "42", "-epoch", "7", "-out", out, p1, p1, p2)
	wantIn(t, res, "combined from s1,s2 (2 needed)", "voluntary_exit_fork_version 0x04000010", "genesis_validators_root 0x4b36")
	f.verifyExitFile(t, out)

	read := func(p string) exitPartials {
		var e exitPartials
		if err := json.Unmarshal(mustRead(t, p), &e); err != nil {
			t.Fatal(err)
		}
		return e
	}
	// edit writes a copy of the partial file p, changed by fn.
	n := 0
	edit := func(p string, fn func(*exitPartials)) string {
		e := read(p)
		fn(&e)
		n++
		return writeJSONFile(t, fc.path("edit"+strconv.Itoa(n)+".partial.json"), e)
	}
	s2sig, s3sig := read(p2).Partials[0].Signature, read(p3).Partials[0].Signature
	sk, err := software.NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	otherPK, _ := core.PubkeyOf(sk)
	// s1's file with s2's signature, and s2's file with s3's. Each error
	// names the file at fault.
	s1bad := edit(p1, func(e *exitPartials) { e.Partials[0].Signature = s2sig })
	s2bad := edit(p2, func(e *exitPartials) { e.Partials[0].Signature = s3sig })

	for _, c := range []struct {
		files []string
		flags []string
		want  string
	}{
		{[]string{p1, partial("s3", "8")}, nil, "pubkey, validator_index, epoch or chain differ from " + p1},
		{[]string{p1, edit(p2, func(e *exitPartials) { e.GenesisValidatorsRoot[0] ^= 1 })}, nil, "epoch or chain differ"},
		{[]string{p1, edit(p2, func(e *exitPartials) { e.VoluntaryExitForkVersion[3] ^= 1 })}, nil, "epoch or chain differ"},
		{[]string{p1, s1bad}, nil, "share index 1 (s1) has different signatures in " + p1 + " and " + s1bad},
		// The bad file first: it fails its own check before p1 is read.
		{[]string{s1bad, p2, p1}, nil, s1bad + ": s1: partial signature does not verify under the share key of index 1"},
		{[]string{p1, s2bad}, nil, s2bad + ": s2: partial signature does not verify under the share key of index 2"},
		// s1's partial, valid under share key 1, given as share 2.
		{[]string{p3, edit(p1, func(e *exitPartials) { e.Partials[0].Signer, e.Partials[0].ShareIndex = "s2", 2 })}, nil, "s2: partial signature does not verify under the share key of index 2"},
		{[]string{p2, edit(p1, func(e *exitPartials) { e.Partials[0].ShareIndex = 3 })}, nil, "s1: share index 3 is not the index of s1"},
		{[]string{edit(p1, func(e *exitPartials) { e.Pubkey = otherPK })}, nil, "no validator " + otherPK.String()},
		{[]string{p1}, nil, "1 partial exits verify, 2 needed; nothing written"},
		{[]string{p1, p1}, nil, "1 partial exits verify, 2 needed"},
		{[]string{p1, p2}, []string{"-epoch", "8"}, "the partial files have 7, not -epoch 8"},
		{[]string{p1, p2}, []string{"-index", "43"}, "the partial files have 42, not -index 43"},
		{[]string{p1, p2}, []string{"-pubkey", otherPK.String()}, "not -pubkey"},
	} {
		out := filepath.Join(fc.dir, "refused.json")
		args := append([]string{"exit-combine", "-split", f.split, "-out", out}, c.flags...)
		wantIn(t, failTool(t, append(args, c.files...)...), c.want)
		if _, err := os.Stat(out); err == nil {
			t.Fatalf("a refused exit-combine wrote its file (%s)", c.want)
		}
	}
	// A file that brings its own share key is refused: the split gives the
	// share keys.
	withKey := edit(p1, func(*exitPartials) {})
	raw := bytes.Replace(mustRead(t, withKey), []byte(`"share_index"`), []byte(`"share_pubkey": "`+otherPK.String()+`", "share_index"`), 1)
	if err := os.WriteFile(withKey, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	wantIn(t, failTool(t, "exit-combine", "-split", f.split, "-out", fc.path("refused.json"), withKey, p2), "share_pubkey")

	common := []string{"exit", "-cluster", fc.cluster, "-pubkey", f.pk.String(), "-index", "42", "-epoch", "7"}
	wantIn(t, failTool(t, append(common, "-split", f.split, "-out", fc.path("x.json"), "-partial-out", fc.path("y.json"))...), "usage: signer-admin exit")
	wantIn(t, failTool(t, append(common, "-partial-out", fc.path("y.json"))...), "-partial-out needs -split")

	// A selected signer fails: the file holds the others, and exit fails.
	fc.runners["s1"].SetSigner(f.keys[0], f.signers[2].Sign)
	pf := fc.path("s1s2.partial.json")
	res = failTool(t, append(common, "-signers", "s1,s2", "-split", f.split, "-partial-out", pf)...)
	wantIn(t, res, "s1: partial signature does not verify under its share key", "signed by s2 (2 needed in all)", "wrote "+pf, errReported.Error())
	if got := read(pf); len(got.Partials) != 1 || got.Partials[0].Signer != "s2" {
		t.Fatalf("partials %+v", got.Partials)
	}
}
