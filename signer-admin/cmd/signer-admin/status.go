package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/lidofinance/tee-signer/attestation-verify/runnerclient/verify"
	"github.com/lidofinance/tee-signer/governance/setupwire"
	cloud "github.com/lidofinance/tee-signer/signer-protocol"
)

// cmdPin is the first pin. For each signer it
// connects with the hash of the setup built for it as setup_sha256, so the
// attestation check itself refuses a runner the host started with another
// setup. Only then does setup_sha256 go into the signer's cloud.json. A
// cloud.json that pins another setup already is left alone.
func cmdPin(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("pin", flag.ContinueOnError)
	cf := addClusterFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("usage: signer-admin pin -cluster cluster.json [-signers NAME,...]")
	}
	c, err := cf.load()
	if err != nil {
		return err
	}
	failed := false
	for _, m := range c.members {
		line, err := pinOne(m, *cf.timeout)
		if err != nil {
			failed = true
			fprintf(out, "%s not pinned: %v\n", m.name, err)
			continue
		}
		fprintf(out, "%s %s\n", m.name, line)
	}
	if failed {
		return errReported
	}
	return nil
}

func pinOne(m *member, timeout time.Duration) (string, error) {
	conn, err := loadConn(m.cloudPath)
	if err != nil {
		return "", err
	}
	want := fullHex(m.setupHash)
	already := false
	if p := strings.ToLower(strings.TrimPrefix(conn.Attestation.SetupSHA256, "0x")); p != "" {
		if p != want {
			return "", fmt.Errorf("%s pins setup_sha256 %s already, not the setup built for this signer (%s); remove it to pin a new setup", m.cloudPath, p, want)
		}
		already = true
	}
	conn.Attestation.SetupSHA256 = want
	conn.Attestation.AllowUnpinnedSetup = false
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	st, cl, err := readState(ctx, m, conn, timeout)
	if err != nil {
		return "", err
	}
	cl.Close()
	if err := checkFresh(m.setup, st.state); err != nil {
		return "", err
	}
	if already {
		return fmt.Sprintf("pinned already: setup_sha256 %s, %s", want, describe(st)), nil
	}
	err = editCloudJSON(m.cloudPath, func(att map[string]json.RawMessage) error {
		att["setup_sha256"], _ = json.Marshal(want)
		delete(att, "allow_unpinned_setup")
		return nil
	})
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("pinned: setup_sha256 %s in %s, %s", want, m.cloudPath, describe(st)), nil
}

// checkFresh checks the groups at version 0 against the setup: their hashes
// are the setup's, and so is the approver set while locked is at 0.
func checkFresh(s *setupwire.Setup, st *cloud.SetupState) error {
	for _, g := range groups {
		gs := groupOf(st, g)
		if gs.Version != 0 {
			continue
		}
		h, err := s.GroupHash(g)
		if err != nil {
			return err
		}
		if gs.Hash != h {
			return fmt.Errorf("the runner's %s group at version 0 has hash %s, the setup's is %s", g, hex8(gs.Hash), hex8(h))
		}
	}
	if st.Locked.Version == 0 && st.ApproverSetHash != s.Locked.Approvers.Hash() {
		return fmt.Errorf("the runner's approver set %s is not the setup's %s", hex8(st.ApproverSetHash), hex8(s.Locked.Approvers.Hash()))
	}
	return nil
}

// describe is the state part of a status line.
func describe(st *signerState) string {
	s := st.state
	t := now()
	var b strings.Builder
	fmt.Fprintf(&b, "setup=%s", hex8(s.SetupHash))
	for _, g := range groups {
		gs := groupOf(s, g)
		fmt.Fprintf(&b, " %s=%s", g, activeRef(gs))
	}
	fmt.Fprintf(&b, " approvers=%s", hex8(s.ApproverSetHash))
	for _, g := range groups {
		gs := groupOf(s, g)
		if gs.Pending.Version != 0 {
			fmt.Fprintf(&b, " pending=%s:%s@%s(%s)", g, pendingRef(gs), when(gs.Pending.EffectiveAt), left(gs.Pending.EffectiveAt, t))
		}
	}
	if o := s.Order; o.Kind != 0 {
		fmt.Fprintf(&b, " order=%s:%s@%s(%s)", verify.OrderKind(o.Kind), hex.EncodeToString(o.Hash[:4]), when(o.ActAt), left(o.ActAt, t))
	}
	if h := st.health; h != nil {
		trust := "untrusted"
		if h.ClockTrusted {
			trust = "trusted"
		}
		fmt.Fprintf(&b, " clock=%s(%s)", trust, h.ClockSource)
	}
	fmt.Fprintf(&b, " build=%s", st.flavor)
	return b.String()
}

// facets are the values of a signer that the signers of a cluster share,
// by name; differs compares them.
func facets(st *signerState) map[string]string {
	s := st.state
	f := map[string]string{"approvers": hex8(s.ApproverSetHash), "build": string(st.flavor)}
	for _, g := range groups {
		gs := groupOf(s, g)
		f[g.String()] = activeRef(gs).String()
		p := "none"
		if gs.Pending.Version != 0 {
			p = pendingRef(gs).String()
		}
		f[g.String()+"_pending"] = p
	}
	// A handover order names one source, so the others never hold it and
	// it is no difference; no other order kind exists today.
	o := "none"
	if s.Order.Kind != 0 && verify.OrderKind(s.Order.Kind) != "handover" {
		o = hex8(s.Order.Hash)
	}
	f["order"] = o
	return f
}

var facetOrder = []string{"locked", "open", "approvers", "locked_pending", "open_pending", "order", "build"}

// differs returns, for each signer, the facets in which it differs from
// the value most signers have (the first one seen on a tie). Signers
// without a state have none.
func differs(states []*signerState) [][]string {
	out := make([][]string, len(states))
	for _, k := range facetOrder {
		count := map[string]int{}
		var order []string
		for _, st := range states {
			if st == nil {
				continue
			}
			v := facets(st)[k]
			if count[v] == 0 {
				order = append(order, v)
			}
			count[v]++
		}
		common := ""
		for _, v := range order {
			if common == "" || count[v] > count[common] {
				common = v
			}
		}
		for i, st := range states {
			if st != nil && facets(st)[k] != common {
				out[i] = append(out[i], k)
			}
		}
	}
	return out
}

func cmdStatus(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	cf := addClusterFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("usage: signer-admin status -cluster cluster.json [-signers NAME,...]")
	}
	c, err := cf.load()
	if err != nil {
		return err
	}
	states, errs := readAll(c, *cf.timeout)
	diff := differs(states)
	failed := false
	for i, m := range c.members {
		if errs[i] != nil {
			failed = true
			fprintf(out, "%s error: %v\n", m.name, errs[i])
			continue
		}
		line := describe(states[i])
		if len(diff[i]) > 0 {
			failed = true
			line += " DIFFERS:" + strings.Join(diff[i], ",")
		}
		fprintf(out, "%s %s\n", m.name, line)
	}
	if failed {
		return errReported
	}
	return nil
}
