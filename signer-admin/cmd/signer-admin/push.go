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
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() == 0 {
		return errors.New("usage: signer-admin push -cluster cluster.json [-raise-min] [-signers NAME,...] update.signed|order.signed|handover.signed|exit.signed...")
	}
	raw, err := os.ReadFile(fs.Arg(0))
	if err != nil {
		return err
	}
	if isExitFile(raw) {
		if *raise {
			return errors.New("-raise-min is for config updates, not exit approvals")
		}
		c, err := cf.load()
		if err != nil {
			return err
		}
		return pushExits(out, c, fs.Args(), *cf.timeout)
	}
	if fs.NArg() != 1 {
		return errors.New("push takes one update or order; only exit approvals go several at a time")
	}
	if isImportFile(raw) {
		return errors.New("an import order is not pushed: signer-admin import sends it with the shares")
	}
	if isHandoverFile(fs.Arg(0)) {
		if *raise {
			return errors.New("-raise-min is for config updates, not handover orders")
		}
		c, err := cf.load()
		if err != nil {
			return err
		}
		return pushHandover(out, c, raw, *cf.timeout)
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
	want := ref{b.Version, hash}
	states := make([]*cloud.SetupState, len(c.members))
	failed, kept := false, false
	for i, m := range c.members {
		outcome, s, err := pushOne(m, raw, b, want, *cf.timeout)
		if err != nil {
			failed = true
			fprintf(out, "%s refused: %v\n", m.name, err)
			continue
		}
		states[i] = s
		fprintf(out, "%s %s: %s\n", m.name, outcome, pushLine(s, b.Group, want))
		if !kept {
			// A copy for the next draft: the runner has no message that
			// returns the bodies of its updates.
			if err := keep(c.updates, raw, b, hash); err != nil {
				return err
			}
			kept = true
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

// pushOne sends the update to one signer and reads its attested state
// back. It does not send an update of another cluster or chain. outcome is
// "accepted", or "known" when the signer had the update already.
func pushOne(m *member, raw []byte, b *setupwire.UpdateBody, want ref, timeout time.Duration) (string, *cloud.SetupState, error) {
	if err := b.Matches(m.setup); err != nil {
		return "", nil, fmt.Errorf("not sent: %v (the signer's setup has cluster_id %s)", err, hex8(m.setup.ClusterID))
	}
	conn, err := loadConn(m.cloudPath)
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
// connection from the signing client, cloud-import or proof-check.
func raiseMin(out io.Writer, c *cluster, states []*cloud.SetupState, b *setupwire.UpdateBody, want ref) error {
	key := fmt.Sprintf("min_%s_version", b.Group)
	for i, m := range c.members {
		if s := states[i]; s == nil || activeRef(groupOf(s, b.Group)) != want {
			fprintf(out, "%s not raised: %s does not have %s %s in force yet; push again with -raise-min after the effective time\n", key, m.name, b.Group, want)
			return nil
		}
	}
	for _, m := range c.members {
		conn, err := loadConn(m.cloudPath)
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
		err = editCloudJSON(m.cloudPath, func(att map[string]json.RawMessage) error {
			att[key], err = json.Marshal(want.version)
			return err
		})
		if err != nil {
			return err
		}
		fprintf(out, "%s %s raised from %d to %d in %s\n", m.name, key, old, want.version, m.cloudPath)
	}
	return nil
}
