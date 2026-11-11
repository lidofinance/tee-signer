package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/lidofinance/tee-signer/attestation-verify/runnerclient"
	"github.com/lidofinance/tee-signer/governance/setupwire"
	remoteadmin "github.com/lidofinance/tee-signer/signer-admin/remote/admin"
	cloud "github.com/lidofinance/tee-signer/signer-protocol"
	wireadmin "github.com/lidofinance/tee-signer/signer-protocol/wire/admin"
)

func cmdPush(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("push", flag.ContinueOnError)
	cf := addClusterFlags(fs)
	raise := fs.Bool("raise-min", false, "once every signer has the update in force, raise min_<group>_version in each cloud.json to its version")
	drop := fs.String("drop-running-image", "", "signer names, comma-separated: the locked update drops the image these signers run on purpose, after their hosts switched to a listed image")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: signer-admin push -cluster cluster.json [-raise-min] [-signers NAME,...] [-drop-running-image NAME,...] update.signed")
	}
	raw, err := os.ReadFile(fs.Arg(0))
	if err != nil {
		return err
	}
	if isImportFile(raw) {
		return errors.New("an import order is not pushed: signer-admin import sends it with the shares")
	}
	u, err := setupwire.DecodeUpdate(raw)
	if err != nil {
		return fmt.Errorf("%s: %w", fs.Arg(0), err)
	}
	b := &u.Body
	hash, err := b.Hash()
	if err != nil {
		return err
	}
	c, err := cf.load()
	if err != nil {
		return err
	}
	// The image rules, for every signer the update goes to: draft checked
	// the signers it was drafted for, and this is the last step before the
	// runners, which accept a list without their own image.
	if b.Locked != nil {
		if err := checkOwnImages(c.members, b.Locked); err != nil {
			return err
		}
		states, errs := readAll(c, *cf.timeout)
		if err := errors.Join(errs...); err != nil {
			for i, m := range c.members {
				if errs[i] != nil {
					fprintf(out, "%s error: %v\n", m.name, errs[i])
				}
			}
			return errors.New("a locked update needs the state of every signer it is pushed to, for the image each runs (-signers names a part of the cluster)")
		}
		if err := checkRunningImages(c.members, states, b.Locked, splitNames(*drop)); err != nil {
			return err
		}
		if err := checkActivateAt(c, states, b, ref{b.Version, hash}); err != nil {
			return err
		}
	} else if *drop != "" {
		return errors.New("-drop-running-image: an open update changes no image")
	}
	want := ref{b.Version, hash}
	states := make([]*cloud.SetupState, len(c.members))
	failed, took := false, false
	for i, m := range c.members {
		outcome, s, err := pushOne(m, raw, b, want, *cf.timeout)
		if err != nil {
			failed = true
			fprintf(out, "%s refused: %v\n", m.name, err)
			continue
		}
		states[i] = s
		took = true
		fprintf(out, "%s %s: %s\n", m.name, outcome, pushLine(s, b.Group, want))
	}
	// A copy for the next draft: the runner has no message that returns
	// the bodies of its updates. It goes in after the loop: the image
	// check of the members still to push reads this folder.
	if took {
		if err := keep(c.updates, raw, b, hash); err != nil {
			return err
		}
	}
	if *raise {
		if err := raiseMin(out, c, states, b, want); err != nil {
			return err
		}
	}
	if failed {
		return errReported
	}
	return nil
}

// checkActivateAt refuses a locked update whose activate_at is earlier than
// now plus its wait, less setupwire.PushSlack, unless every signer has it
// already. A runner brings an update into force at the later of
// activate_at and its arrival plus the wait, so with this rule every
// pushed update comes into force within PushSlack of its activate_at, and
// the image check of the tools (setupwire.ApprovedImages) can count from
// activate_at + PushSlack.
func checkActivateAt(c *cluster, states []*signerState, b *setupwire.UpdateBody, want ref) error {
	missing := false
	for _, st := range states {
		if activeRef(st.state.Locked) != want && pendingRef(st.state.Locked) != want {
			missing = true
		}
	}
	s := c.members[0].setup
	if !missing || b.Matches(s) != nil {
		return nil // pushOne does not send an update of another cluster
	}
	_, lim, err := clusterLimits(c, states)
	if err != nil {
		return err
	}
	// The group the update replaces: the setup's, or one in the updates
	// folder. A prev_hash the tool does not know is the runners' to refuse.
	active := &s.Locked
	if v0, err := s.GroupHash(setupwire.GroupLocked); err != nil {
		return err
	} else if b.PrevHash != v0 {
		arch, err := loadArchive(c.updates)
		if err != nil {
			return err
		}
		raw, ok := arch[b.PrevHash]
		if !ok {
			return nil
		}
		prev, err := setupwire.DecodeUpdateBody(raw)
		if err != nil {
			return err
		}
		active = prev.Locked
	}
	w := lim.Wait(&s.Chain, active, b)
	t := uint64(max(now().Unix(), 0))
	if earliest := setupwire.SatAdd(t, w); setupwire.SatAdd(b.ActivateAt, setupwire.PushSlack) < earliest {
		return fmt.Errorf("activate_at %s is earlier than now plus the wait of %d s (%s), less %d s: the runners would bring it into force later than activate_at, and the image check counts from activate_at; draft it again with a -margin that covers the time to push",
			when(b.ActivateAt), w, when(earliest), setupwire.PushSlack)
	}
	return nil
}

// pushOne sends the update to one signer and reads its attested state
// back. It does not send an update of another cluster or chain. outcome is
// "accepted", or "known" when the signer had the update already.
func pushOne(m *member, raw []byte, b *setupwire.UpdateBody, want ref, timeout time.Duration) (string, *cloud.SetupState, error) {
	if err := b.Matches(m.setup); err != nil {
		return "", nil, fmt.Errorf("not sent: %v (the signer's setup has cluster_id %s)", err, hex8(m.setup.ClusterID))
	}
	conn, err := memberConn(m)
	if err != nil {
		return "", nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cl, err := conn.New(runnerclient.WithTimeout(timeout))
	if err != nil {
		return "", nil, err
	}
	defer cl.Close()
	o, _, err := remoteadmin.Wrap(cl.Client).ConfigUpdate(ctx, raw)
	if err != nil {
		return "", nil, err
	}
	outcome := "accepted"
	if o == wireadmin.ConfigKnown {
		outcome = "known"
	}
	s, err := cl.SetupState(ctx, cl.Verify)
	if err != nil {
		return "", nil, fmt.Errorf("%s, then the state read failed: %w", outcome, err)
	}
	if s.SetupHash != m.setupHash {
		return "", nil, fmt.Errorf("IDENTITY shows setup %s, cluster.json names the setup %s", hex8(s.SetupHash), hex8(m.setupHash))
	}
	if g := groupOf(s, b.Group); activeRef(g) != want && pendingRef(g) != want {
		return "", nil, fmt.Errorf("%s, but the state shows %s %s pending %s, not %s", outcome, b.Group, activeRef(g), pendingRef(g), want)
	}
	return outcome, s, nil
}

// raiseFloor sets att[key] to v unless the file already holds v or more.
// It reads the floor from the same read that the edit writes back, so a
// command that saved a higher floor after memberConn is not undone.
func raiseFloor(att map[string]json.RawMessage, key string, v uint64) (bool, error) {
	var cur uint64
	if raw, ok := att[key]; ok {
		if err := json.Unmarshal(raw, &cur); err != nil {
			return false, fmt.Errorf("%s: %w", key, err)
		}
	}
	if cur >= v {
		return false, nil
	}
	b, err := json.Marshal(v)
	att[key] = b
	return err == nil, err
}

// pushLine says where the update stands on one signer.
func pushLine(s *cloud.SetupState, g setupwire.Group, want ref) string {
	gs := groupOf(s, g)
	if activeRef(gs) == want {
		return fmt.Sprintf("%s %s in force", g, want)
	}
	return fmt.Sprintf("%s %s pending, effective %s (%s)", g, want, when(gs.Pending.EffectiveAt), left(gs.Pending.EffectiveAt, now()))
}

// keep writes the signed update into the updates folder, once.
func keep(dir string, raw []byte, b *setupwire.UpdateBody, hash [32]byte) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	p := archivePath(dir, b, hash)
	if _, err := os.Stat(p); err == nil {
		return nil
	}
	return writeAtomic(p, raw, 0o644)
}

// raiseMin raises min_<group>_version in each signer's cloud.json once every
// signer has the update in force. From then on
// a runner whose host brought back an older config state gets no
// connection from the signing client, signer-admin import or proof-check.
func raiseMin(out io.Writer, c *cluster, states []*cloud.SetupState, b *setupwire.UpdateBody, want ref) error {
	key := fmt.Sprintf("min_%s_version", b.Group)
	for i, m := range c.members {
		if s := states[i]; s == nil || activeRef(groupOf(s, b.Group)) != want {
			fprintf(out, "%s not raised: %s does not have %s %s in force yet; push again with -raise-min after the effective time\n", key, m.name, b.Group, want)
			return nil
		}
	}
	for _, m := range c.members {
		conn, err := memberConn(m)
		if err != nil {
			return err
		}
		old := conn.Attestation.MinLockedVersion
		if b.Group == setupwire.GroupOpen {
			old = conn.Attestation.MinOpenVersion
		}
		if old >= want.version {
			fprintf(out, "%s %s is %d already\n", m.name, key, old)
			continue
		}
		var raised bool
		err = editCloudJSON(m.cloudPath, func(att map[string]json.RawMessage) error {
			raised, err = raiseFloor(att, key, want.version)
			return err
		})
		if err != nil {
			return err
		}
		if !raised {
			fprintf(out, "%s %s is %d or more already\n", m.name, key, want.version)
			continue
		}
		fprintf(out, "%s %s raised from %d to %d in %s\n", m.name, key, old, want.version, m.cloudPath)
	}
	return nil
}
