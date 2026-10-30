package main

// The commands signer-config did not have (research/admin-tool.md,
// section 3): probe, import-draft, import, exit-draft, and the import
// order and exit approval paths of show, sign, assemble and push.

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/lidofinance/tee-signer/attestation-verify/runnerclient"
	"github.com/lidofinance/tee-signer/governance/exitapproval"
	"github.com/lidofinance/tee-signer/governance/handoverorder"
	"github.com/lidofinance/tee-signer/governance/importorder"
	"github.com/lidofinance/tee-signer/governance/setupwire"
	adminapprover "github.com/lidofinance/tee-signer/signer-admin/approver"
	admincluster "github.com/lidofinance/tee-signer/signer-admin/cluster"
	remoteadmin "github.com/lidofinance/tee-signer/signer-admin/remote/admin"
	"github.com/lidofinance/tee-signer/signer-core/core"
	cloud "github.com/lidofinance/tee-signer/signer-protocol"
)

// maxExitsPerPush is the runner's maxPendingExits (runner/server/exits.go):
// a runner holds at most 8 exit approvals at once, so push sends at most 8
// per signer per run.
const maxExitsPerPush = 8

// ---- probe ----

// connectAdmin opens an attested connection to m for admin messages. A
// connection file without setup_sha256 gets the setup built for m as its
// pin, so probe and import work before pin and still check that the
// signer runs that setup.
func connectAdmin(m *member, timeout time.Duration) (*runnerclient.Client, error) {
	conn, err := loadConn(m.cloudPath)
	if err != nil {
		return nil, err
	}
	if conn.Attestation.SetupSHA256 == "" {
		conn.Attestation.SetupSHA256 = fullHex(m.setupHash)
	}
	return conn.New(runnerclient.WithTimeout(timeout))
}

// probeMember runs admin/cluster.Probe against m.
func probeMember(m *member, timeout time.Duration) (admincluster.ProbeResult, error) {
	cl, err := connectAdmin(m, timeout)
	if err != nil {
		return admincluster.ProbeResult{}, err
	}
	defer cl.Close()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return admincluster.Probe(ctx, cl.Client)
}

func cmdProbe(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("probe", flag.ContinueOnError)
	cf := addClusterFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("usage: signer-admin probe -cluster cluster.json [-signers NAME,...]")
	}
	c, err := cf.load()
	if err != nil {
		return err
	}
	failed := false
	for _, m := range c.members {
		r, err := probeMember(m, *cf.timeout)
		switch {
		case err != nil:
			failed = true
			fprintf(out, "%s failed: %v\n", m.name, err)
		case !r.OK():
			failed = true
			fprintf(out, "%s %s\n", m.name, r)
		default:
			fprintf(out, "%s %s\n", m.name, r)
		}
	}
	if failed {
		return errReported
	}
	return nil
}

// ---- the split file ----

// splitFile is the public side of a key split, as import-draft and import
// read it:
//
//	{
//	  "t": 3, "n": 4,
//	  "shares": {"signer-1": 1, "signer-2": 2, "signer-3": 3, "signer-4": 4},
//	  "validators": [
//	    {"pubkey": "0x...", "commitments": ["0x...", "0x...", "0x..."]}
//	  ]
//	}
//
// shares maps each signer name to its share index; each validator has its
// t public commitments (Feldman), commitment 0 first, which is the
// validator key. It holds no secret.
type splitFile struct {
	T          uint8            `json:"t"`
	N          uint8            `json:"n"`
	Shares     map[string]uint8 `json:"shares"`
	Validators []struct {
		Pubkey      cloud.Pubkey   `json:"pubkey"`
		Commitments []cloud.Pubkey `json:"commitments"`
	} `json:"validators"`
}

func readSplit(path string) (*splitFile, error) {
	var s splitFile
	if err := readStrictJSON(path, &s); err != nil {
		return nil, err
	}
	if s.T == 0 || s.N < s.T || len(s.Validators) == 0 {
		return nil, fmt.Errorf("%s: want t, n with 1 <= t <= n and at least one validator", path)
	}
	for i, v := range s.Validators {
		if len(v.Commitments) != int(s.T) {
			return nil, fmt.Errorf("%s: validator %d has %d commitments, t is %d", path, i+1, len(v.Commitments), s.T)
		}
		if v.Commitments[0] != v.Pubkey {
			return nil, fmt.Errorf("%s: validator %d: commitment 0 is not the validator key", path, i+1)
		}
	}
	return &s, nil
}

// commitmentsOf is the validator's commitments in the split.
func (s *splitFile) commitmentsOf(pk cloud.Pubkey) ([]cloud.Pubkey, bool) {
	for _, v := range s.Validators {
		if v.Pubkey == pk {
			return v.Commitments, true
		}
	}
	return nil, false
}

// ---- active files of import orders and exit approvals ----

// lockedInForce reads the attested state of m and its locked group in
// force: the body from the archive of push, or the setup's version 0.
func lockedInForce(c *cluster, m *member, timeout time.Duration) (*setupwire.Locked, []byte, ref, error) {
	conn, err := loadConn(m.cloudPath)
	if err != nil {
		return nil, nil, ref{}, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	st, cl, err := readState(ctx, m, conn, timeout)
	if err != nil {
		return nil, nil, ref{}, fmt.Errorf("%s: %w", m.name, err)
	}
	cl.Close()
	r := activeRef(st.state.Locked)
	arch, err := loadArchive(c.updates)
	if err != nil {
		return nil, nil, ref{}, err
	}
	body, raw, err := values(m.setup, setupwire.GroupLocked, r, arch)
	if err != nil {
		return nil, nil, ref{}, err
	}
	if body != nil {
		return body.Locked, raw, r, nil
	}
	return &m.setup.Locked, nil, r, nil
}

// writeActive writes path.active: the setup and the locked body in force.
func writeActive(path string, setupRaw, lockedRaw []byte) error {
	af := activeFile{Setup: hex.EncodeToString(setupRaw)}
	if lockedRaw != nil {
		af.Locked = hex.EncodeToString(lockedRaw)
	}
	aj, err := json.MarshalIndent(af, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path+".active", append(aj, '\n'), 0o644)
}

// loadSetupActive reads an active file of a setup and its locked group in
// force, as import-draft and exit-draft write it.
func loadSetupActive(path string) (*orderActive, error) {
	var f activeFile
	if err := readStrictJSON(path, &f); err != nil {
		return nil, err
	}
	raw, err := hex.DecodeString(f.Setup)
	if err != nil {
		return nil, fmt.Errorf("%s: setup: not hex", path)
	}
	a := &orderActive{}
	if a.setup, err = setupwire.DecodeSetup(raw); err != nil {
		return nil, fmt.Errorf("%s: setup: %w", path, err)
	}
	a.locked = &a.setup.Locked
	h, _ := a.setup.GroupHash(setupwire.GroupLocked)
	a.ref = ref{0, h}
	if f.Locked != "" {
		lb, err := hex.DecodeString(f.Locked)
		if err != nil {
			return nil, fmt.Errorf("%s: locked: not hex", path)
		}
		u, err := setupwire.DecodeUpdateBody(lb)
		if err != nil {
			return nil, fmt.Errorf("%s: locked: %w", path, err)
		}
		if u.Group != setupwire.GroupLocked || u.Matches(a.setup) != nil {
			return nil, fmt.Errorf("%s: locked: an update of another group or cluster", path)
		}
		uh, err := setupwire.UpdateHash(lb)
		if err != nil {
			return nil, err
		}
		a.locked, a.ref = u.Locked, ref{u.Version, uh}
	}
	return a, nil
}

// ---- import-draft ----

func cmdImportDraft(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("import-draft", flag.ContinueOnError)
	cf := addClusterFlags(fs)
	target := fs.String("signer", "", "the target: the signer of cluster.json that takes the shares")
	splitPath := fs.String("split", "", "the split file: t, n, each signer's share index and each validator's commitments (no secret)")
	notAfter := fs.String("not-after", "12h", "the runner takes no share under the order from then on: RFC 3339 time, or a duration from now")
	outPath := fs.String("out", "import.bin", "the order body to sign; the target's setup and locked values in force go to the same name with .active")
	allowGCPSingle := fs.Bool("allow-gcp-unsafe-single-key", false, "confirm a 1 of 1 order to a GCP signer whose setup accepts it; UNSAFE: "+setupwire.UnsafeSingleKeyWarning)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *target == "" || *splitPath == "" {
		return errors.New("usage: signer-admin import-draft -cluster cluster.json -signer NAME -split FILE [-not-after 12h] [-allow-gcp-unsafe-single-key] [-out import.bin]")
	}
	split, err := readSplit(*splitPath)
	if err != nil {
		return err
	}
	*cf.only = *target
	c, err := cf.load()
	if err != nil {
		return err
	}
	m := c.members[0]
	idx, ok := split.Shares[m.name]
	if !ok || idx == 0 || idx > split.N {
		return fmt.Errorf("%s: no share index 1 to %d for %s", *splitPath, split.N, m.name)
	}
	// The target's own rule, so an order its runner refuses is not drafted
	// (CheckThresholdOn: a 1 of 1 order to a GCP signer needs the setup's
	// acceptance). A 1 of 1 order to a GCP signer is unsafe even with it,
	// so the drafter confirms it with -allow-gcp-unsafe-single-key and
	// sees the warning; show prints the same line to each approver.
	if err := setupwire.CheckThresholdOn(&m.setup.Platform, m.setup.Chain.GenesisForkVersion, int(split.T), int(split.N)); err != nil {
		return err
	}
	if m.setup.Platform.Platform == setupwire.PlatformGCP && split.T == 1 && split.N == 1 {
		if !*allowGCPSingle {
			return fmt.Errorf("%s: a 1 of 1 order to a GCP signer: %s; -allow-gcp-unsafe-single-key confirms it", m.name, setupwire.UnsafeSingleKeyWarning)
		}
		fprintf(out, "WARNING %s: 1 of 1 on GCP: %s\n", m.name, setupwire.UnsafeSingleKeyWarning)
	}
	b := &importorder.Body{ClusterID: m.setup.ClusterID, ChainHash: m.setup.Chain.Hash(), Target: m.setupHash,
		T: split.T, N: split.N, ShareIndex: idx}
	if b.NotAfter, err = parseNotAfter(*notAfter, now()); err != nil {
		return fmt.Errorf("-not-after: %w", err)
	}
	for _, v := range split.Validators {
		b.Validators = append(b.Validators, importorder.Entry{Pubkey: v.Pubkey, CommitmentsHash: importorder.CommitmentsHash(v.Commitments)})
	}
	slices.SortFunc(b.Validators, func(x, y importorder.Entry) int { return bytes.Compare(x.Pubkey[:], y.Pubkey[:]) })
	raw, err := b.Encode()
	if err != nil {
		return err
	}
	locked, lockedRaw, r, err := lockedInForce(c, m, *cf.timeout)
	if err != nil {
		return err
	}
	if err := os.WriteFile(*outPath, raw, 0o644); err != nil {
		return err
	}
	if err := writeActive(*outPath, m.setupRaw, lockedRaw); err != nil {
		return err
	}
	fprintf(out, "import order for %s (setup %s): %d validators, %d of %d, share index %d, not after %s\n", m.name, hex8(m.setupHash),
		len(b.Validators), b.T, b.N, b.ShareIndex, when(b.NotAfter))
	fprintf(out, "  approvers in force: locked version %d, %d of %d sign\n", r.version, locked.Approvers.ApprovalsNeeded, len(locked.Approvers.Keys))
	fprintf(out, "order_sha256 %s\nwrote %s and %s\n", fullHex(importorder.Hash(raw)), *outPath, *outPath+".active")
	return nil
}

// isImportFile reports whether raw starts like an import order body or a
// signed one.
func isImportFile(raw []byte) bool { return len(raw) > 0 && (raw[0] == 'I' || raw[0] == 'J') }

// readImport reads an import order body or a signed one.
func readImport(raw []byte) (*importorder.Body, []byte, *importorder.Order, error) {
	if raw[0] == 'J' {
		o, err := importorder.Decode(raw)
		if err != nil {
			return nil, nil, nil, err
		}
		body, err := o.Body.Encode()
		if err != nil {
			return nil, nil, nil, err
		}
		return &o.Body, body, o, nil
	}
	b, err := importorder.DecodeBody(raw)
	if err != nil {
		return nil, nil, nil, err
	}
	return b, raw, nil, nil
}

func showImport(out io.Writer, path string, raw []byte, activePath string) error {
	b, body, signed, err := readImport(raw)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	fprintf(out, "import order\ncluster_id = 0x%x\nchain_hash = 0x%x\ntarget_setup_sha256 = 0x%x\nnot_after = %s\nt = %d\nn = %d\nshare_index = %d\n",
		b.ClusterID, b.ChainHash, b.Target, when(b.NotAfter), b.T, b.N, b.ShareIndex)
	for _, v := range b.Validators {
		fprintf(out, "validator = %s commitments_sha256 0x%x\n", v.Pubkey, v.CommitmentsHash)
	}
	fprintf(out, "\norder_sha256 %s\n", fullHex(importorder.Hash(body)))
	a, err := optionalSetupActive(path, activePath)
	if err != nil {
		return err
	}
	single := b.T == 1 && b.N == 1
	if a == nil && single {
		fprintf(out, "1 of 1: the target holds the whole key; show with its active values (-active, or %s.active) says whether it is a GCP signer, where that is UNSAFE\n", path)
	}
	if a != nil {
		if h, _ := a.setup.Hash(); h != b.Target || a.setup.ClusterID != b.ClusterID {
			fprintf(out, "target: the active values are not of this order's target\n")
		} else {
			fprintf(out, "target: %s, the setup of the active values; approvers of its locked version %d\n", a.setup.SignerName, a.ref.version)
			// What import-draft printed to the drafter, for each approver
			// before sign.
			if single && a.setup.Platform.Platform == setupwire.PlatformGCP {
				fprintf(out, "WARNING %s: 1 of 1 on GCP: %s\n", a.setup.SignerName, setupwire.UnsafeSingleKeyWarning)
			}
		}
	}
	if signed != nil {
		for _, ap := range signed.Approvals {
			fprintf(out, "approver_signature position %d\n", ap.Position)
		}
		if a != nil {
			if err := signed.Verify(&a.locked.Approvers); err != nil {
				return fmt.Errorf("signatures: %w", err)
			}
			fprintf(out, "signatures: complete and valid against the approver set %s in force\n", hex8(a.locked.Approvers.Hash()))
		}
	}
	return nil
}

// optionalSetupActive loads activePath, or path.active when it exists.
func optionalSetupActive(path, activePath string) (*orderActive, error) {
	p := activePath
	if p == "" {
		p = path + ".active"
		if _, err := os.Stat(p); errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
	}
	return loadSetupActive(p)
}

// ---- import ----

// share is one line of the shares file.
type share struct {
	pubkey cloud.Pubkey
	index  uint64
	secret [32]byte
	// sharePub, if set, is what the secret's public key must be.
	sharePub cloud.Pubkey
}

// readShares reads the shares file: one share per line, either
//
//	0x<validator pubkey> <validator index, or - when unknown> 0x<share secret>
//
// or the line of a seed file,
//
//	0x<share secret> 0x<validator pubkey> <validator index> 0x<share pubkey>
//
// whose share pubkey must be the secret's. The file holds secrets, so it
// must be a regular file of mode 0600 or stricter, like an approver key.
func readShares(path string) ([]share, error) {
	if err := adminapprover.CheckPrivateFile(path); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	defer clear(data)
	var out []share
	sc := bufio.NewScanner(bytes.NewReader(data))
	for n := 1; sc.Scan(); n++ {
		l, _, _ := strings.Cut(sc.Text(), "#")
		f := strings.Fields(l)
		if len(f) == 0 {
			continue
		}
		var pkField, indexField, secField, sharePub string
		switch len(f) {
		case 3:
			pkField, indexField, secField = f[0], f[1], f[2]
		case 4:
			secField, pkField, indexField, sharePub = f[0], f[1], f[2], f[3]
		default:
			return nil, fmt.Errorf("%s:%d: want pubkey, index and secret", path, n)
		}
		s := share{index: cloud.IndexUnknown}
		if err := s.pubkey.UnmarshalText([]byte(pkField)); err != nil {
			return nil, fmt.Errorf("%s:%d: pubkey: %w", path, n, err)
		}
		if indexField != "-" {
			i, err := strconv.ParseUint(indexField, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("%s:%d: index: %w", path, n, err)
			}
			s.index = i
		}
		if sharePub != "" {
			if err := s.sharePub.UnmarshalText([]byte(sharePub)); err != nil {
				return nil, fmt.Errorf("%s:%d: share pubkey: %w", path, n, err)
			}
		}
		sec, err := hex.DecodeString(strings.TrimPrefix(secField, "0x"))
		if err != nil || len(sec) != 32 {
			return nil, fmt.Errorf("%s:%d: secret: want 32 bytes of hex", path, n)
		}
		copy(s.secret[:], sec)
		clear(sec)
		out = append(out, s)
	}
	return out, sc.Err()
}

func cmdImport(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("import", flag.ContinueOnError)
	cf := addClusterFlags(fs)
	target := fs.String("signer", "", "the signer of cluster.json that takes the shares")
	connPath := fs.String("conn", "", "in place of -cluster and -signer: the runner's connection file (cloud.json), for a runner outside a cluster.json")
	orderPath := fs.String("order", "", "the signed import order (import.signed); a runner with a setup takes no share without one")
	sharesPath := fs.String("shares", "", "the shares file: one share per line, mode 0600")
	commPath := fs.String("commitments", "", "with -order: the split file of import-draft, for each validator's commitments")
	skip := fs.Bool("skip-loaded", false, "leave out the shares whose validator the runner holds already")
	icPath := fs.String("interchange", "", "EIP-3076 slashing protection file (format 5): each share goes in with its validator's maxima, so the runner refuses everything at or below them")
	if err := fs.Parse(args); err != nil {
		return err
	}
	byCluster := *cf.path != "" || *target != ""
	if fs.NArg() != 0 || *sharesPath == "" || byCluster == (*connPath != "") || byCluster && (*cf.path == "" || *target == "") ||
		(*orderPath == "") != (*commPath == "") {
		return errors.New("usage: signer-admin import (-cluster cluster.json -signer NAME | -conn cloud.json) [-order import.signed -commitments FILE] -shares FILE [-interchange FILE] [-skip-loaded]")
	}
	var (
		name  string
		setup *[32]byte
		dial  func() (*runnerclient.Client, error)
		clID  [32]byte
	)
	if byCluster {
		*cf.only = *target
		c, err := cf.load()
		if err != nil {
			return err
		}
		m := c.members[0]
		name, setup, clID = m.name, &m.setupHash, m.setup.ClusterID
		dial = func() (*runnerclient.Client, error) { return connectAdmin(m, *cf.timeout) }
	} else {
		conn, err := loadConn(*connPath)
		if err != nil {
			return err
		}
		name = conn.Address
		dial = func() (*runnerclient.Client, error) { return conn.New(runnerclient.WithTimeout(*cf.timeout)) }
	}
	var (
		raw   []byte
		o     *importorder.Order
		split *splitFile
		err   error
	)
	if *orderPath != "" {
		if raw, err = os.ReadFile(*orderPath); err != nil {
			return err
		}
		if o, err = importorder.Decode(raw); err != nil {
			return fmt.Errorf("%s: %w", *orderPath, err)
		}
		if setup != nil && (o.Body.Target != *setup || o.Body.ClusterID != clID) {
			return fmt.Errorf("%s is an import order for setup %s, %s runs setup %s", *orderPath, hex8(o.Body.Target), name, hex8(*setup))
		}
		if split, err = readSplit(*commPath); err != nil {
			return err
		}
		if split.T != o.Body.T || split.N != o.Body.N {
			return fmt.Errorf("%s is a %d of %d split, the order names %d of %d", *commPath, split.T, split.N, o.Body.T, o.Body.N)
		}
	}
	var ic *interchange
	if *icPath != "" {
		if ic, err = loadInterchange(*icPath); err != nil {
			return err
		}
		fprintf(out, "interchange %s: %d validators, genesis_validators_root %s\n", *icPath, len(ic.marks), ic.gvr)
	}
	shares, err := readShares(*sharesPath)
	if err != nil {
		return err
	}
	defer func() {
		for i := range shares {
			clear(shares[i].secret[:])
		}
	}()

	cl, err := dial()
	if err != nil {
		return err
	}
	defer cl.Close()
	// The role first: a connection without the admin role is refused before
	// any share is sealed.
	ctx, cancel := context.WithTimeout(context.Background(), *cf.timeout)
	r, err := admincluster.Probe(ctx, cl.Client)
	cancel()
	if err != nil {
		return fmt.Errorf("%s: probe: %w", name, err)
	}
	if !r.OK() {
		return fmt.Errorf("%s: %s", name, r)
	}
	held := map[cloud.Pubkey]bool{}
	if *skip {
		ctx, cancel := context.WithTimeout(context.Background(), *cf.timeout)
		keys, err := cl.PublicKeys(ctx)
		cancel()
		if err != nil {
			return fmt.Errorf("%s: public keys: %w", name, err)
		}
		for _, k := range keys {
			held[k.Pubkey] = true
		}
	}
	ac := remoteadmin.Wrap(cl.Client)
	failed := false
	start, imported, skipped := time.Now(), 0, 0
	for _, s := range shares {
		if held[s.pubkey] {
			skipped++
			continue
		}
		sp, err := core.PubkeyOf(s.secret)
		if err != nil || s.sharePub != (cloud.Pubkey{}) && sp != s.sharePub {
			failed = true
			fprintf(out, "%s %s: the share is not a valid BLS secret key of its share pubkey\n", name, s.pubkey)
			continue
		}
		extra := &cloud.SealedImportRequest{}
		if o != nil {
			comm, ok := split.commitmentsOf(s.pubkey)
			if !ok {
				failed = true
				fprintf(out, "%s %s: not in the split file, not sent\n", name, s.pubkey)
				continue
			}
			extra = &cloud.SealedImportRequest{Order: raw, T: o.Body.T, N: o.Body.N, ShareIndex: o.Body.ShareIndex, Commitments: comm}
		}
		req := cloud.ImportShareRequest{Pubkey: s.pubkey, Secret: s.secret, Index: s.index}
		if ic != nil {
			if req.Interchange, err = ic.markOf(s.pubkey); err != nil {
				failed = true
				fprintf(out, "%s %s: %v, not sent\n", name, s.pubkey, err)
				continue
			}
			if w := req.Interchange; w == nil {
				fprintf(out, "%s %s: interchange: no signed history for this validator\n", name, s.pubkey)
			} else {
				fprintf(out, "%s %s: interchange maxima block_slot %d (%t) source %d target %d (%t)\n", name, s.pubkey,
					w.BlockSlot, w.HasBlock, w.SourceEpoch, w.TargetEpoch, w.HasAttestation)
			}
		}
		ctx, cancel := context.WithTimeout(context.Background(), *cf.timeout)
		k, err := ac.ImportShareSealedWith(ctx, req, sp, cl.Verify, extra)
		cancel()
		if err != nil {
			failed = true
			fprintf(out, "%s %s refused: %v\n", name, s.pubkey, err)
			continue
		}
		imported++
		if len(shares) <= 16 {
			fprintf(out, "%s imported %s share_pubkey %s index %d (sealed to the attested import key)\n", name, k.Pubkey, k.SharePubkey, k.Index)
		}
	}
	fprintf(out, "%s: imported %d shares, skipped %d already held, in %s\n", name, imported, skipped, time.Since(start).Round(time.Millisecond))
	if failed {
		return errReported
	}
	return nil
}

// ---- exit-draft ----

// isExitFile reports whether raw is an exit approval (152 bytes) or a
// signed one: it starts with the TA's magic.
func isExitFile(raw []byte) bool {
	return len(raw) >= exitapproval.Len && binary.LittleEndian.Uint64(raw) == exitapproval.Magic
}

// readExit reads an exit approval, signed or not.
func readExit(raw []byte) (*exitapproval.Approval, *exitapproval.Signed, error) {
	if len(raw) == exitapproval.Len {
		a, err := decodeApproval(raw)
		return a, nil, err
	}
	s, err := exitapproval.Decode(raw)
	if err != nil {
		return nil, nil, err
	}
	return &s.Approval, s, nil
}

// decodeApproval reads the 152-byte approval alone.
func decodeApproval(raw []byte) (*exitapproval.Approval, error) {
	if len(raw) != exitapproval.Len || binary.LittleEndian.Uint64(raw) != exitapproval.Magic {
		return nil, errors.New("exit approval: not 152 bytes with the TA's magic")
	}
	a := &exitapproval.Approval{}
	copy(a.GenesisValidatorsRoot[:], raw[8:40])
	copy(a.Pubkey[:], raw[40:88])
	a.ValidatorIndex = binary.LittleEndian.Uint64(raw[88:])
	a.ExitEpoch = binary.LittleEndian.Uint64(raw[96:])
	a.EffectiveBalance = binary.LittleEndian.Uint64(raw[104:])
	a.NotAfter = binary.LittleEndian.Uint64(raw[112:])
	copy(a.Nonce[:], raw[120:152])
	if !bytes.Equal(a.Encode(), raw) {
		return nil, errors.New("exit approval: does not encode back")
	}
	return a, nil
}

// exitHash names an exit approval in signature files: SHA-256 over
// CtxTAExitApproval and the approval.
func exitHash(a *exitapproval.Approval) [32]byte { return setupwire.CtxTAExitApproval.Hash(a.Encode()) }

func cmdExitDraft(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("exit-draft", flag.ContinueOnError)
	cf := addClusterFlags(fs)
	pubkey := fs.String("pubkey", "", "the validator key (0x...)")
	index := fs.Int64("index", -1, "the validator index on the chain")
	epoch := fs.Int64("epoch", -1, "the exit epoch of the voluntary exit")
	balance := fs.Uint64("balance", 0, "the validator's effective balance in Gwei, as the chain shows it")
	notAfter := fs.String("not-after", "24h", "the runners drop the approval from then on: RFC 3339 time, or a duration from now (at most 7 days)")
	outPath := fs.String("out", "exit.bin", "the approval to sign; the setup and locked values in force go to the same name with .active")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *pubkey == "" || *index < 0 || *epoch < 0 || *balance == 0 {
		return errors.New("usage: signer-admin exit-draft -cluster cluster.json -pubkey 0x.. -index N -epoch E -balance GWEI [-not-after 24h] [-out exit.bin]")
	}
	a := &exitapproval.Approval{ValidatorIndex: uint64(*index), ExitEpoch: uint64(*epoch), EffectiveBalance: *balance}
	if err := a.Pubkey.UnmarshalText([]byte(*pubkey)); err != nil {
		return fmt.Errorf("-pubkey: %w", err)
	}
	t := now()
	var err error
	if a.NotAfter, err = parseNotAfter(*notAfter, t); err != nil {
		return fmt.Errorf("-not-after: %w", err)
	}
	if n := uint64(max(t.Unix(), 0)); a.NotAfter <= n || a.NotAfter-n > exitapproval.MaxLifetime {
		return fmt.Errorf("-not-after %s: want a time in the next %d days, the runners refuse a longer one", when(a.NotAfter), exitapproval.MaxLifetime/86400)
	}
	if _, err := io.ReadFull(toolRand, a.Nonce[:]); err != nil {
		return err
	}
	c, err := cf.load()
	if err != nil {
		return err
	}
	m := c.members[0]
	a.GenesisValidatorsRoot = m.setup.Chain.GenesisValidatorsRoot
	locked, lockedRaw, r, err := lockedInForce(c, m, *cf.timeout)
	if err != nil {
		return err
	}
	raw := a.Encode()
	if err := os.WriteFile(*outPath, raw, 0o644); err != nil {
		return err
	}
	if err := writeActive(*outPath, m.setupRaw, lockedRaw); err != nil {
		return err
	}
	fprintf(out, "exit approval for validator %d, %s, exit epoch %d, effective balance %d Gwei, not after %s\n", a.ValidatorIndex, a.Pubkey,
		a.ExitEpoch, a.EffectiveBalance, when(a.NotAfter))
	fprintf(out, "  %d approvers of locked version %d (%s) sign it; push sends it to all %d signers\n", locked.ExitApprovalsNeeded, r.version, m.name,
		len(c.members))
	fprintf(out, "approval_sha256 %s\nwrote %s and %s\n", fullHex(exitHash(a)), *outPath, *outPath+".active")
	return nil
}

func showExit(out io.Writer, path string, raw []byte, activePath string) error {
	a, signed, err := readExit(raw)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	fprintf(out, "exit approval\ngenesis_validators_root = 0x%x\npubkey = %s\nvalidator_index = %d\nexit_epoch = %d\neffective_balance = %d Gwei\nnot_after = %s\nnonce = 0x%x\n",
		a.GenesisValidatorsRoot, a.Pubkey, a.ValidatorIndex, a.ExitEpoch, a.EffectiveBalance, when(a.NotAfter), a.Nonce)
	fprintf(out, "\napproval_sha256 %s\n", fullHex(exitHash(a)))
	fprintf(out, "before you sign, check on the beacon chain with genesis_validators_root above: validator %d has pubkey %s, "+
		"its effective balance is %d Gwei, it is active and not exiting, and the exit you want names epoch %d\n",
		a.ValidatorIndex, a.Pubkey, a.EffectiveBalance, a.ExitEpoch)
	act, err := optionalSetupActive(path, activePath)
	if err != nil {
		return err
	}
	if act != nil {
		if act.setup.Chain.GenesisValidatorsRoot != a.GenesisValidatorsRoot {
			fprintf(out, "chain: the active values are of another chain\n")
		}
		fprintf(out, "approvers: %d of the set %s in force (locked version %d, exit_approvals_needed)\n", act.locked.ExitApprovalsNeeded,
			hex8(act.locked.Approvers.Hash()), act.ref.version)
	}
	if signed != nil {
		for _, ap := range signed.Approvals {
			fprintf(out, "approver_signature position %d\n", ap.Position)
		}
		if act != nil {
			if err := signed.Verify(&act.locked.Approvers, act.locked.ExitApprovalsNeeded); err != nil {
				return fmt.Errorf("signatures: %w", err)
			}
			fprintf(out, "signatures: complete and valid against the approver set %s in force\n", hex8(act.locked.Approvers.Hash()))
		}
	}
	return nil
}

// ---- sign and assemble of import orders and exit approvals ----

// signKind signs an import order body or an exit approval.
func signKind(out io.Writer, path string, raw []byte, key adminapprover.Signer, hashed bool, outPath string) error {
	var (
		ctx  setupwire.Context
		hash [32]byte
		what string
	)
	switch {
	case isExitFile(raw):
		a, err := decodeApproval(raw)
		if err != nil {
			return fmt.Errorf("%s: %w (sign the 152-byte approval exit-draft wrote)", path, err)
		}
		ctx, hash = setupwire.CtxTAExitApproval, exitHash(a)
		what = fmt.Sprintf("exit approval of validator %d, epoch %d", a.ValidatorIndex, a.ExitEpoch)
		raw = a.Encode()
	default:
		b, err := importorder.DecodeBody(raw)
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		ctx, hash = setupwire.CtxImportOrder, importorder.Hash(raw)
		what = fmt.Sprintf("import order of %d validators for setup %s", len(b.Validators), hex8(b.Target))
	}
	sig, err := adminapprover.Sign(key, ctx, hashed, raw)
	if err != nil {
		return err
	}
	s := &sigFile{bodyHash: hash, key: adminapprover.Key(key), sig: sig, context: ctx.String(), hashed: hashed}
	if outPath == "" {
		outPath = fmt.Sprintf("%s.%s.sig", path, hex.EncodeToString(s.key[:4]))
	}
	if err := os.WriteFile(outPath, s.format(), 0o644); err != nil {
		return err
	}
	fprintf(out, "signed %s, sha256 %s, %s form, with key %s\nwrote %s\n", what, fullHex(hash), adminapprover.Form(hashed), hex.EncodeToString(s.key[:]), outPath)
	return nil
}

// collect checks signature files against hash and the set, and returns the
// approvals in ascending positions.
func collect(sigs []string, hash [32]byte, set *setupwire.ApproverSet, ctx setupwire.Context, body []byte) ([]setupwire.Approval, error) {
	approvals := map[int][64]byte{}
	for _, p := range sigs {
		s, err := parseSigFile(p)
		if err != nil {
			return nil, err
		}
		if s.bodyHash != hash {
			return nil, fmt.Errorf("%s signs %s, not this one (%s)", p, hex8(s.bodyHash), hex8(hash))
		}
		if !setupwire.VerifyApproval(s.key, ctx, s.sig, body) {
			return nil, fmt.Errorf("%s: the signature does not verify", p)
		}
		pa := position(set.Keys, s.key)
		if pa < 0 {
			return nil, fmt.Errorf("%s: key %s is not an approver in force", p, hex.EncodeToString(s.key[:]))
		}
		approvals[pa] = s.sig
	}
	var out []setupwire.Approval
	for p := range len(set.Keys) {
		if sig, ok := approvals[p]; ok {
			out = append(out, setupwire.Approval{Position: uint8(p), Signature: sig})
		}
	}
	return out, nil
}

func assembleKind(out io.Writer, path string, raw []byte, activePath string, sigs []string, outPath string) error {
	a, err := loadSetupActive(activePath)
	if err != nil {
		return err
	}
	set := &a.locked.Approvers
	if isExitFile(raw) {
		ap, err := decodeApproval(raw)
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		approvals, err := collect(sigs, exitHash(ap), set, setupwire.CtxTAExitApproval, raw)
		if err != nil {
			return err
		}
		need := a.locked.ExitApprovalsNeeded
		if len(approvals) < int(need) {
			return fmt.Errorf("%d of the approvers in force signed, exit_approvals_needed is %d: %d more needed", len(approvals), need, int(need)-len(approvals))
		}
		s := &exitapproval.Signed{Approval: *ap, Approvals: approvals}
		if err := s.Verify(set, need); err != nil {
			return err
		}
		enc, err := s.Encode()
		if err != nil {
			return err
		}
		outPath = cmpOr(outPath, "exit.signed")
		if err := os.WriteFile(outPath, enc, 0o644); err != nil {
			return err
		}
		fprintf(out, "exit approval of validator %d: %d approvers (exit_approvals_needed %d)\nwrote %s\n", ap.ValidatorIndex, len(approvals), need, outPath)
		return nil
	}
	b, err := importorder.DecodeBody(raw)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	if h, _ := a.setup.Hash(); h != b.Target {
		return fmt.Errorf("%s: the active values are not of the order's target", activePath)
	}
	approvals, err := collect(sigs, importorder.Hash(raw), set, setupwire.CtxImportOrder, raw)
	if err != nil {
		return err
	}
	if len(approvals) < int(set.ApprovalsNeeded) {
		return fmt.Errorf("%d of the approvers in force signed, approvals_needed is %d: %d more needed", len(approvals), set.ApprovalsNeeded,
			int(set.ApprovalsNeeded)-len(approvals))
	}
	o := &importorder.Order{Body: *b, Approvals: approvals}
	if err := o.Verify(set); err != nil {
		return err
	}
	enc, err := o.Encode()
	if err != nil {
		return err
	}
	outPath = cmpOr(outPath, "import.signed")
	if err := os.WriteFile(outPath, enc, 0o644); err != nil {
		return err
	}
	fprintf(out, "import order for setup %s: %d approvers (k %d)\nwrote %s\n", hex8(b.Target), len(approvals), set.ApprovalsNeeded, outPath)
	return nil
}

// ---- push of exit approvals ----

// pushExits sends signed exit approvals to every signer of the cluster:
// each signer must hold the approval before it signs its part of the exit.
func pushExits(out io.Writer, c *cluster, paths []string, timeout time.Duration) error {
	if len(paths) > maxExitsPerPush {
		return fmt.Errorf("%d exit approvals in one push: a runner holds at most %d at once (maxPendingExits); push them in batches of %d",
			len(paths), maxExitsPerPush, maxExitsPerPush)
	}
	var raws [][]byte
	for _, p := range paths {
		raw, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		s, err := exitapproval.Decode(raw)
		if err != nil {
			return fmt.Errorf("%s: %w", p, err)
		}
		for _, m := range c.members {
			if s.Approval.GenesisValidatorsRoot != m.setup.Chain.GenesisValidatorsRoot {
				return fmt.Errorf("%s is an exit approval for another chain than %s's", p, m.name)
			}
		}
		raws = append(raws, raw)
	}
	failed := false
	for _, m := range c.members {
		cl, err := connectAdmin(m, timeout)
		if err != nil {
			failed = true
			fprintf(out, "%s failed: %v\n", m.name, err)
			continue
		}
		ac := remoteadmin.Wrap(cl.Client)
		for i, raw := range raws {
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			err := ac.ApproveExit(ctx, raw)
			cancel()
			if err != nil {
				failed = true
				fprintf(out, "%s refused %s: %v\n", m.name, paths[i], err)
				continue
			}
			fprintf(out, "%s holds %s\n", m.name, paths[i])
		}
		cl.Close()
	}
	if failed {
		return errReported
	}
	return nil
}

// ---- the signing messages, for show ----

// printSigning names both messages an approver may sign for raw, so an
// approver can compare them over a second channel: the direct form and
// the hashed form (research/admin-tool.md, section 7).
func printSigning(out io.Writer, raw []byte) {
	ctx, body, ok := signingInput(raw)
	if !ok {
		return
	}
	direct := setupwire.ApprovalMessage(ctx, false, body)
	d := sha256.Sum256(direct)
	hc, _ := setupwire.HashedContext(ctx)
	fprintf(out, "signing message, direct form: %s and the body, %d bytes, sha256 %s\n", ctx, len(direct), fullHex(d))
	fprintf(out, "signing message, hashed form (sign -hashed): sha256 of %s and sha256 %s, the 32 bytes %s\n", hc, fullHex(d),
		fullHex([32]byte(setupwire.ApprovalMessage(ctx, true, body))))
}

// signingInput is the approver context and the signed body of any file
// show reads.
func signingInput(raw []byte) (setupwire.Context, []byte, bool) {
	if len(raw) == 0 {
		return setupwire.Context{}, nil, false
	}
	switch {
	case isExitFile(raw):
		if a, _, err := readExit(raw); err == nil {
			return setupwire.CtxTAExitApproval, a.Encode(), true
		}
	case isImportFile(raw):
		if _, body, _, err := readImport(raw); err == nil {
			return setupwire.CtxImportOrder, body, true
		}
	case handoverorder.IsOrder(raw):
		if o, err := handoverorder.Decode(raw); err == nil {
			if body, err := o.Body.Encode(); err == nil {
				return setupwire.CtxHandoverOrder, body, true
			}
		}
	case handoverorder.IsBody(raw):
		return setupwire.CtxHandoverOrder, raw, true
	case raw[0] == 'U':
		if u, err := setupwire.DecodeUpdate(raw); err == nil {
			if h, err := u.Body.Header(); err == nil {
				return setupwire.CtxConfigUpdate, h, true
			}
		}
	default:
		if b, err := setupwire.DecodeUpdateBody(raw); err == nil {
			if h, err := b.Header(); err == nil {
				return setupwire.CtxConfigUpdate, h, true
			}
		}
	}
	return setupwire.Context{}, nil, false
}
