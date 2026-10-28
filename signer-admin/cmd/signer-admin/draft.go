package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/lidofinance/tee-signer/governance/setupwire"
	cloud "github.com/lidofinance/tee-signer/signer-protocol"
)

// activeFile is the file next to a draft (update.bin.active): the active
// values the draft replaces, so that show prints the diff and assemble
// checks signatures on a machine without access to the signers. setup is
// one signer's setup (cluster_id, chain and version 0 of both groups);
// locked and open are the bodies of the active updates above version 0.
// Every value is hex of the binary form.
type activeFile struct {
	Setup  string `json:"setup"`
	Locked string `json:"locked,omitempty"`
	Open   string `json:"open,omitempty"`
}

// active is the active config that a body replaces.
type active struct {
	setup  *setupwire.Setup
	locked *setupwire.Locked
	open   *setupwire.Open
	refs   map[setupwire.Group]ref
	// bodies are the active update bodies above version 0, by group.
	bodies map[setupwire.Group][]byte
}

// values returns the active values of group g of a cluster at r: the
// setup's at version 0, else the body of the update with hash r.hash from
// the updates push kept.
func values(s *setupwire.Setup, g setupwire.Group, r ref, arch map[[32]byte][]byte) (*setupwire.UpdateBody, []byte, error) {
	if r.version == 0 {
		h, err := s.GroupHash(g)
		if err != nil {
			return nil, nil, err
		}
		if h != r.hash {
			return nil, nil, fmt.Errorf("the signers' %s group at version 0 has hash %s, the setup's is %s", g, hex8(r.hash), hex8(h))
		}
		return nil, nil, nil
	}
	raw, ok := arch[r.hash]
	if !ok {
		return nil, nil, fmt.Errorf("no copy of the active %s update (version %d, %s) in the updates folder; put its signed file there", g, r.version, fullHex(r.hash))
	}
	b, err := setupwire.DecodeUpdateBody(raw)
	if err != nil {
		return nil, nil, err
	}
	if b.Group != g || b.Version != r.version {
		return nil, nil, fmt.Errorf("the update %s in the updates folder is %s version %d, not %s version %d", hex8(r.hash), b.Group, b.Version, g, r.version)
	}
	return b, raw, nil
}

// loadArchive reads the signed updates of dir and returns their bodies by
// hash. Files that are not signed updates are skipped.
func loadArchive(dir string) (map[[32]byte][]byte, error) {
	out := map[[32]byte][]byte{}
	ents, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return out, nil
	}
	if err != nil {
		return nil, err
	}
	for _, e := range ents {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".signed") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}
		u, err := setupwire.DecodeUpdate(raw)
		if err != nil {
			continue
		}
		body, err := u.Body.Encode()
		if err != nil {
			continue
		}
		h, err := u.Body.Hash()
		if err != nil {
			continue
		}
		out[h] = body
	}
	return out, nil
}

// archivePath is where push keeps a signed update.
func archivePath(dir string, b *setupwire.UpdateBody, hash [32]byte) string {
	return filepath.Join(dir, fmt.Sprintf("%s-v%d-%s.signed", b.Group, b.Version, hex8(hash)))
}

// loadActive reads an active file and checks it against body: same
// cluster_id and chain, and prev_hash names the active values of the
// body's group (the setup's group at version 0, else the body in the file).
// The active locked values of an open update come from the file unchecked:
// prev_hash binds the open group only.
func loadActive(path string, body *setupwire.UpdateBody) (*active, error) {
	var f activeFile
	if err := readStrictJSON(path, &f); err != nil {
		return nil, err
	}
	dec := func(what, s string) ([]byte, error) {
		b, err := hex.DecodeString(s)
		if err != nil {
			return nil, fmt.Errorf("%s: %s: not hex", path, what)
		}
		return b, nil
	}
	raw, err := dec("setup", f.Setup)
	if err != nil {
		return nil, err
	}
	a := &active{refs: map[setupwire.Group]ref{}, bodies: map[setupwire.Group][]byte{}}
	if a.setup, err = setupwire.DecodeSetup(raw); err != nil {
		return nil, fmt.Errorf("%s: setup: %w", path, err)
	}
	if err := body.Matches(a.setup); err != nil {
		return nil, fmt.Errorf("%s: the active values are not of this update's cluster: %w", path, err)
	}
	a.locked, a.open = &a.setup.Locked, &a.setup.Open
	for _, g := range groups {
		h, _ := a.setup.GroupHash(g)
		a.refs[g] = ref{0, h}
		s := f.Locked
		if g == setupwire.GroupOpen {
			s = f.Open
		}
		if s == "" {
			continue
		}
		raw, err := dec(g.String(), s)
		if err != nil {
			return nil, err
		}
		b, err := setupwire.DecodeUpdateBody(raw)
		if err != nil {
			return nil, fmt.Errorf("%s: %s: %w", path, g, err)
		}
		if b.Group != g || b.Matches(a.setup) != nil {
			return nil, fmt.Errorf("%s: %s: an update of another group or cluster", path, g)
		}
		uh, err := b.Hash()
		if err != nil {
			return nil, fmt.Errorf("%s: %s: %w", path, g, err)
		}
		a.refs[g] = ref{b.Version, uh}
		a.bodies[g] = raw
		if g == setupwire.GroupLocked {
			a.locked = b.Locked
		} else {
			a.open = b.Open
		}
	}
	if r := a.refs[body.Group]; r.hash != body.PrevHash {
		return nil, fmt.Errorf("prev_hash %s is not the active %s values of %s (version %d, %s): the file belongs to another draft or was changed",
			hex8(body.PrevHash), body.Group, path, r.version, hex8(r.hash))
	}
	if r := a.refs[body.Group]; r.version >= body.Version {
		return nil, fmt.Errorf("version %d is not above the active %s version %d", body.Version, body.Group, r.version)
	}
	return a, nil
}

// lines are the "key = value" lines of a group's human form, without
// comments.
func lines(b []byte) []string {
	var out []string
	for _, l := range strings.Split(string(b), "\n") {
		if l != "" && !strings.HasPrefix(l, "#") {
			out = append(out, l)
		}
	}
	return out
}

func groupLines(g setupwire.Group, l *setupwire.Locked, o *setupwire.Open) ([]string, error) {
	var b []byte
	var err error
	if g == setupwire.GroupLocked {
		b, err = l.Format()
	} else {
		b, err = o.Format()
	}
	return lines(b), err
}

// diffLines is a line diff (longest common subsequence): lines only in a
// get "- ", lines only in b "+ ", in file order.
func diffLines(a, b []string) []string {
	n, m := len(a), len(b)
	lcs := make([][]int, n+1)
	for i := range lcs {
		lcs[i] = make([]int, m+1)
	}
	for i := n - 1; i >= 0; i-- {
		for j := m - 1; j >= 0; j-- {
			if a[i] == b[j] {
				lcs[i][j] = lcs[i+1][j+1] + 1
			} else {
				lcs[i][j] = max(lcs[i+1][j], lcs[i][j+1])
			}
		}
	}
	var out []string
	i, j := 0, 0
	for i < n || j < m {
		switch {
		case i < n && j < m && a[i] == b[j]:
			i, j = i+1, j+1
		case i < n && (j == m || lcs[i+1][j] >= lcs[i][j+1]):
			out = append(out, "- "+a[i])
			i++
		default:
			out = append(out, "+ "+b[j])
			j++
		}
	}
	return out
}

// diffAgainst prints the diff of body's group against the active values.
func diffAgainst(out io.Writer, a *active, body *setupwire.UpdateBody) error {
	old, err := groupLines(body.Group, a.locked, a.open)
	if err != nil {
		return err
	}
	next, err := groupLines(body.Group, body.Locked, body.Open)
	if err != nil {
		return err
	}
	d := diffLines(old, next)
	if len(d) == 0 {
		fprintf(out, "no change against the active %s values (version %d); as a pending update's successor it cancels that update\n", body.Group, a.refs[body.Group].version)
		return nil
	}
	fprintf(out, "changes against the active %s values (version %d):\n", body.Group, a.refs[body.Group].version)
	for _, l := range d {
		fprintf(out, "  %s\n", l)
	}
	return nil
}

// versionAt is the fork version of schedule o at epoch e.
func versionAt(genesis [4]byte, o *setupwire.Open, e uint64) [4]byte {
	v := genesis
	for _, f := range o.ForkSchedule {
		if f.Epoch <= e {
			v = f.Version
		}
	}
	return v
}

func gloasAt(o *setupwire.Open, e uint64) bool {
	return o.GloasForkEpoch != nil && e >= *o.GloasForkEpoch
}

// firstChange is the first epoch whose fork version or Gloas state differs
// between a and b. Both change only at their fork and Gloas epochs, so the
// first difference is at one of those.
func firstChange(genesis [4]byte, a, b *setupwire.Open) (uint64, bool) {
	var cand []uint64
	for _, o := range []*setupwire.Open{a, b} {
		for _, f := range o.ForkSchedule {
			cand = append(cand, f.Epoch)
		}
		if o.GloasForkEpoch != nil {
			cand = append(cand, *o.GloasForkEpoch)
		}
	}
	slices.Sort(cand)
	for _, e := range cand {
		if versionAt(genesis, a, e) != versionAt(genesis, b, e) || gloasAt(a, e) != gloasAt(b, e) {
			return e, true
		}
	}
	return 0, false
}

// epochAt is the epoch of Unix time t under the chain's slot times, the
// largest under each list of slot time changes in lists (those in force and
// those of a pending locked update), 0 before genesis.
func epochAt(c *setupwire.Chain, lists [][]setupwire.SlotTimeChange, t uint64) uint64 {
	var e uint64
	for _, l := range lists {
		e = max(e, setupwire.NewSlotClock(c, l).EpochAt(t))
	}
	return e
}

// pendingOf lists the distinct pending updates of group g across the
// signers' states. A push that reached only some signers leaves them with
// different ones, and each runner checks against its own.
func pendingOf(states []*signerState, g setupwire.Group) []cloud.PendingUpdate {
	var out []cloud.PendingUpdate
	for _, st := range states {
		if p := groupOf(st.state, g).Pending; p.Version != 0 && !slices.Contains(out, p) {
			out = append(out, p)
		}
	}
	return out
}

// pendingBody is the body of the pending update p of group g from the
// updates folder, or nil when the folder has no copy.
func pendingBody(g setupwire.Group, p cloud.PendingUpdate, arch map[[32]byte][]byte) *setupwire.UpdateBody {
	raw, ok := arch[p.Hash]
	if !ok {
		return nil
	}
	b, err := setupwire.DecodeUpdateBody(raw)
	if err != nil || b.Group != g || b.Version != p.Version {
		return nil
	}
	return b
}

// forkClash is the fork rule of section 7 as the runner applies it
// (core.Signer.CheckSchedule): every epoch whose fork version or Gloas state
// changes between old and next must be above limit = epoch(at) +
// max_sign_epochs_ahead_of_clock + 1, epoch(at) the largest under the slot
// time lists in lists. It returns the first such epoch e and limit when e
// is not above it. The runner checks it again; the tool says it before
// anyone signs.
func forkClash(s *setupwire.Setup, lists [][]setupwire.SlotTimeChange, old, next *setupwire.Open, at uint64) (e, limit uint64, clash bool) {
	e, ok := firstChange([4]byte(s.Chain.GenesisForkVersion), old, next)
	if !ok {
		return 0, 0, false
	}
	limit = setupwire.SatAdd(setupwire.SatAdd(epochAt(&s.Chain, lists, at), s.Safety.MaxSignEpochsAheadOfClock), 1)
	return e, limit, e <= limit
}

func cmdDraft(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("draft", flag.ContinueOnError)
	cf := addClusterFlags(fs)
	group := fs.String("group", "", "the group the file holds: locked or open")
	margin := fs.Duration("margin", 10*time.Minute, "time for signing and push, added to the wait: activate_at = now + wait + margin")
	outPath := fs.String("out", "update.bin", "the body to sign; the active values go to the same name with .active")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: signer-admin draft -cluster cluster.json -group locked|open [-margin 10m] [-out update.bin] FILE")
	}
	if *margin < 0 || *margin > setupwire.ActivationHorizon*time.Second {
		return fmt.Errorf("-margin %v: want 0 to %v", *margin, time.Duration(setupwire.ActivationHorizon)*time.Second)
	}
	text, err := os.ReadFile(fs.Arg(0))
	if err != nil {
		return err
	}
	body := &setupwire.UpdateBody{}
	switch *group {
	case "locked":
		body.Group = setupwire.GroupLocked
		body.Locked, err = setupwire.ParseLocked(fs.Arg(0), text)
	case "open":
		body.Group = setupwire.GroupOpen
		body.Open, err = setupwire.ParseOpen(fs.Arg(0), text)
	default:
		return errors.New("-group: want locked or open")
	}
	if err != nil {
		return err
	}
	c, err := cf.load()
	if err != nil {
		return err
	}

	// Every signer's state, attested. Their active versions must agree:
	// prev_hash names one update, and an update with another prev_hash is
	// refused.
	states, errs := readAll(c, *cf.timeout)
	if err := errors.Join(errs...); err != nil {
		for i, m := range c.members {
			if errs[i] != nil {
				fprintf(out, "%s error: %v\n", m.name, errs[i])
			}
		}
		return errors.New("draft needs the state of every signer it drafts for (-signers names a part of the cluster)")
	}
	// The waits are the signers' image constants: a testnet build's run in
	// minutes.
	fl, lim, err := clusterLimits(c, states)
	if err != nil {
		return err
	}
	if *margin > time.Duration(lim.ActivationHorizon)*time.Second {
		return fmt.Errorf("-margin %v: want 0 to %v, the activation horizon of a %s build", *margin, time.Duration(lim.ActivationHorizon)*time.Second, fl)
	}
	if body.Locked != nil {
		if err := lim.CheckTimeLock(body.Locked); err != nil {
			return err
		}
	}
	first := states[0].state
	var pend [3]uint64
	for i, st := range states {
		for _, g := range groups {
			gs := groupOf(st.state, g)
			if activeRef(gs) != activeRef(groupOf(first, g)) {
				for j, m := range c.members {
					fprintf(out, "%s %s\n", m.name, describe(states[j]))
				}
				return fmt.Errorf("signers %s and %s are at different %s versions; draft one update per group of signers with -signers", c.members[0].name, c.members[i].name, g)
			}
			pend[g] = max(pend[g], gs.Pending.Version)
		}
	}
	s := c.members[0].setup
	arch, err := loadArchive(c.updates)
	if err != nil {
		return err
	}
	a := &active{setup: s, locked: &s.Locked, open: &s.Open, refs: map[setupwire.Group]ref{}, bodies: map[setupwire.Group][]byte{}}
	for _, g := range groups {
		r := activeRef(groupOf(first, g))
		a.refs[g] = r
		if g == setupwire.GroupOpen && body.Group == setupwire.GroupLocked {
			continue // a locked draft reads them only to check a pending fork, below
		}
		b, raw, err := values(s, g, r, arch)
		if err != nil {
			return err
		}
		if b == nil {
			continue
		}
		a.bodies[g] = raw
		if g == setupwire.GroupLocked {
			a.locked = b.Locked
		} else {
			a.open = b.Open
		}
	}

	r := a.refs[body.Group]
	body.ClusterID, body.ChainHash = s.ClusterID, s.Chain.Hash()
	body.Version = max(r.version, pend[body.Group]) + 1
	body.PrevHash = r.hash
	wait := lim.Wait(a.locked, body)
	t := uint64(max(now().Unix(), 0))
	body.ActivateAt = setupwire.SatAdd(setupwire.SatAdd(t, wait), uint64(margin.Seconds()))
	// Fresh salts for every leaf of the new group: the approvers sign their
	// root, and a withheld field stays hidden after the update too.
	if err := body.DrawSalts(toolRand); err != nil {
		return err
	}
	raw, err := body.Encode()
	if err != nil {
		return err
	}
	if err := body.Matches(s); err != nil {
		return err
	}
	switch body.Group {
	case setupwire.GroupOpen:
		// The fork rule counts epochs under the slot times in force and those
		// of a pending locked update, as the runners do.
		lists := [][]setupwire.SlotTimeChange{a.locked.SlotTimeChanges}
		for _, p := range pendingOf(states, setupwire.GroupLocked) {
			if pb := pendingBody(setupwire.GroupLocked, p, arch); pb != nil {
				lists = append(lists, pb.Locked.SlotTimeChanges)
			} else {
				fprintf(out, "note: locked version %d is pending and the updates folder has no copy; this check skips its slot times, the runners count them\n", p.Version)
			}
		}
		if e, limit, bad := forkClash(s, lists, a.open, body.Open, body.ActivateAt); bad {
			return fmt.Errorf("the fork rule refuses this update: it changes epoch %d, and a signer may sign up to epoch %d by the effective time %s; change nothing before epoch %d, or use a smaller -margin",
				e, limit, when(body.ActivateAt), setupwire.SatAdd(limit, 1))
		}
	case setupwire.GroupLocked:
		// The slot time rule as the runner applies it (core.Signer.CheckSlotTimes).
		if err := setupwire.CheckSlotTimeRule(&s.Chain, s.Safety.MaxSignEpochsAheadOfClock, a.locked.SlotTimeChanges,
			body.Locked.SlotTimeChanges, body.ActivateAt); err != nil {
			return fmt.Errorf("the slot time rule refuses this update: %w; move the change later, or use a smaller -margin", err)
		}
		// New slot times must keep a pending open update clear of the epochs
		// a signer may reach before its effective time. The runners check it
		// as a return to the open values in force with the new slot times
		// pending; the rule is symmetric, so old and next may be either way.
		if ps := pendingOf(states, setupwire.GroupOpen); len(ps) > 0 && !slices.Equal(body.Locked.SlotTimeChanges, a.locked.SlotTimeChanges) {
			ab, _, err := values(s, setupwire.GroupOpen, a.refs[setupwire.GroupOpen], arch)
			old := &s.Open
			if ab != nil {
				old = ab.Open
			}
			lists := [][]setupwire.SlotTimeChange{a.locked.SlotTimeChanges, body.Locked.SlotTimeChanges}
			for _, p := range ps {
				pb := pendingBody(setupwire.GroupOpen, p, arch)
				if pb == nil || err != nil {
					fprintf(out, "note: open version %d is pending and the updates folder lacks its copy or the open values in force; this check skips it, the runners check that the new slot times keep its forks clear\n", p.Version)
					continue
				}
				at := max(p.EffectiveAt, t)
				if e, limit, bad := forkClash(s, lists, old, pb.Open, at); bad {
					return fmt.Errorf("the fork rule refuses these slot times: the pending open version %d changes epoch %d, and under them a signer may sign up to epoch %d by its effective time %s; move the change later or make its slots longer",
						p.Version, e, limit, when(at))
				}
			}
		}
	}

	fprintf(out, "%s update version %d for %d signers, cluster_id 0x%x\n", body.Group, body.Version, len(c.members), body.ClusterID)
	fprintf(out, "  prev_hash %s (active %s version %d)\n", fullHex(body.PrevHash), body.Group, r.version)
	if p := groupOf(first, body.Group).Pending; p.Version != 0 {
		fprintf(out, "  supersedes the pending %s version %d (%s, effective %s); its wait starts again at arrival\n", body.Group, p.Version, hex8(p.Hash), when(p.EffectiveAt))
	}
	if body.IsRotation(&a.locked.Approvers) {
		fprintf(out, "  rotation: approvals_needed of the active approvers sign, and every one of the %d new keys signs too\n", len(body.Locked.Approvers.Keys))
	}
	fprintf(out, "  wait %v (%s build), activate_at %s (now + wait + margin %v)\n", time.Duration(min(wait, math.MaxInt64/uint64(time.Second)))*time.Second, fl, when(body.ActivateAt), *margin)
	if err := diffAgainst(out, a, body); err != nil {
		return err
	}
	hash, err := body.Hash()
	if err != nil {
		return err
	}
	af := activeFile{Setup: hex.EncodeToString(c.members[0].setupRaw)}
	if b := a.bodies[setupwire.GroupLocked]; b != nil {
		af.Locked = hex.EncodeToString(b)
	}
	if b := a.bodies[setupwire.GroupOpen]; b != nil && body.Group == setupwire.GroupOpen {
		af.Open = hex.EncodeToString(b)
	}
	aj, err := json.MarshalIndent(af, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(*outPath, raw, 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(*outPath+".active", append(aj, '\n'), 0o644); err != nil {
		return err
	}
	fprintf(out, "body_sha256 %s\n", fullHex(hash))
	fprintf(out, "wrote %s and %s\n", *outPath, *outPath+".active")
	return nil
}
