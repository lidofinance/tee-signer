package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/lidofinance/tee-signer/attestation-verify/runnerclient"
	"github.com/lidofinance/tee-signer/governance/flavor"
	"github.com/lidofinance/tee-signer/governance/handoverorder"
	"github.com/lidofinance/tee-signer/governance/setupwire"
	adminapprover "github.com/lidofinance/tee-signer/signer-admin/approver"
	remoteadmin "github.com/lidofinance/tee-signer/signer-admin/remote/admin"
)

// Handover orders (signer-protocol docs/protocol.md, "Handover"): k
// approvers in force sign one order per source signer, which names the one
// target it may hand its shares to.
// The flow is the config update's:
//
//	signer-admin handover-draft -cluster cluster.json -signer NAME -target-cloud target/cloud.json [-out handover.bin]
//	signer-admin show handover.bin                      each approver, offline
//	signer-admin sign -key approver.key handover.bin    each approver
//	signer-admin assemble handover.bin sig...           k signatures of the approvers in force
//	signer-admin push -cluster cluster.json handover.signed
//
// handover-draft reads the source's attested IDENTITY (its setup pinned)
// and its cloud.json for the source's image and settings, and the target's
// cloud.json for the target's: its setup_sha256 (what signer-admin pin
// wrote, or -target-setup-sha256), image and verifier settings. It does not
// connect to the target. The target must be on the source's cloud
// (handoverorder.Runner.CheckSameCloud): a release runner links only its own
// platform's verifier. The target's image must be on the source's
// allowed-images list in force. The draft, show, sign and assemble steps
// work offline.
// handover.bin.active holds the source's setup and its locked group in
// force, so show and assemble check the approvers and the image offline.
//
// The source acts on the order the images minimum time lock after it
// arrives (7 days, 7 minutes on a testnet build; the time lock in force
// when that is longer; the time lock only on a dev runner), and no
// handover starts under it after not_after (default 12 hours).

// handoverDefaultNotAfter is the plan's 12 hours.
const handoverDefaultNotAfter = "12h"

// isHandoverFile reports whether path holds a handover order body or a
// signed one.
func isHandoverFile(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	var b [1]byte
	if _, err := io.ReadFull(f, b[:]); err != nil {
		return false
	}
	return handoverorder.IsBody(b[:]) || handoverorder.IsOrder(b[:])
}

// readHandover reads a handover order body ('H') or a signed one ('T').
func readHandover(path string) (*handoverorder.Body, []byte, *handoverorder.Order, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, nil, err
	}
	return decodeHandover(path, raw)
}

// decodeHandover is readHandover for the bytes raw read from path.
func decodeHandover(path string, raw []byte) (*handoverorder.Body, []byte, *handoverorder.Order, error) {
	if handoverorder.IsOrder(raw) {
		o, err := handoverorder.Decode(raw)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("%s: %w", path, err)
		}
		body, err := o.Body.Encode()
		if err != nil {
			return nil, nil, nil, err
		}
		return &o.Body, body, o, nil
	}
	b, err := handoverorder.DecodeBody(raw)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("%s: %w", path, err)
	}
	return b, raw, nil, nil
}

// loadHandoverActive reads the active file of a handover order: the
// source's setup and its locked group in force.
func loadHandoverActive(path string, b *handoverorder.Body) (*orderActive, error) {
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
	sh, err := setupwire.SetupHash(raw)
	if err != nil {
		return nil, fmt.Errorf("%s: setup: %w", path, err)
	}
	if err := b.Matches(a.setup, sh); err != nil {
		return nil, fmt.Errorf("%s: the active values are not of this order's source: %w", path, err)
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
			return nil, fmt.Errorf("%s: locked: %w", path, err)
		}
		a.locked, a.ref = u.Locked, ref{u.Version, uh}
	}
	return a, nil
}

// parseSetupHash reads 64 hex digits, with or without 0x.
func parseSetupHash(what, s string) ([32]byte, error) {
	b, err := hex.DecodeString(strings.TrimPrefix(strings.ToLower(strings.TrimSpace(s)), "0x"))
	if err != nil || len(b) != 32 {
		return [32]byte{}, fmt.Errorf("%s: want 64 hex digits", what)
	}
	return [32]byte(b), nil
}

func cmdHandoverDraft(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("handover-draft", flag.ContinueOnError)
	cf := addClusterFlags(fs)
	source := fs.String("signer", "", "the source: the signer of cluster.json that hands its shares over")
	targetCloud := fs.String("target-cloud", "", "the target's cloud.json: its address is not used; its attestation settings and setup_sha256 are")
	targetSetup := fs.String("target-setup-sha256", "", "the target's setup_hash, 64 hex digits (default: the setup_sha256 of the target's cloud.json; both must agree when both are set)")
	targetName := fs.String("target-name", "", "a name for the target (default: the source's name with b appended)")
	notAfter := fs.String("not-after", handoverDefaultNotAfter, "no handover starts under the order from then on: RFC 3339 time, or a duration from now (12h, 1d)")
	outPath := fs.String("out", "handover.bin", "the order body to sign; the source's setup and locked values in force go to the same name with .active")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *source == "" || *targetCloud == "" {
		return errors.New("usage: signer-admin handover-draft -cluster cluster.json -signer NAME -target-cloud target/cloud.json " +
			"[-target-setup-sha256 HEX] [-target-name NAME] [-not-after 12h] [-out handover.bin]")
	}
	*cf.only = *source
	c, err := cf.load()
	if err != nil {
		return err
	}
	m := c.members[0]

	// The target: setup_sha256 and settings from its cloud.json.
	tconn, err := loadConn(*targetCloud)
	if err != nil {
		return err
	}
	var th [32]byte
	switch {
	case *targetSetup != "":
		if th, err = parseSetupHash("-target-setup-sha256", *targetSetup); err != nil {
			return err
		}
		if pinned := tconn.Attestation.SetupSHA256; pinned != "" {
			if ph, err := parseSetupHash(*targetCloud+": setup_sha256", pinned); err != nil || ph != th {
				return fmt.Errorf("-target-setup-sha256 %s is not the setup_sha256 %s of %s", hex8(th), pinned, *targetCloud)
			}
		}
	case tconn.Attestation.SetupSHA256 != "":
		if th, err = parseSetupHash(*targetCloud+": setup_sha256", tconn.Attestation.SetupSHA256); err != nil {
			return err
		}
	default:
		return fmt.Errorf("%s pins no setup_sha256; pin the target first (signer-admin pin of its build) or pass -target-setup-sha256", *targetCloud)
	}
	tname := cmpOr(*targetName, m.name+"b")
	target, err := tconn.Attestation.OrderRunner(tname, th)
	if err != nil {
		return fmt.Errorf("target %s: %w", *targetCloud, err)
	}
	// A release runner checks the target with its own platform's verifier
	// only, so the target must be on the source's cloud. Checked here, before
	// the tool connects to the source.
	if err := target.CheckSameCloud(m.setup.Platform.Platform); err != nil {
		return fmt.Errorf("%w (%s, %s)", err, m.name, *targetCloud)
	}

	// The source: its attested state, and its settings from its cloud.json.
	conn, err := loadConn(m.cloudPath)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), *cf.timeout)
	defer cancel()
	st, cl, err := readState(ctx, m, conn, *cf.timeout)
	if err != nil {
		return fmt.Errorf("%s: %w", m.name, err)
	}
	cl.Close()
	src, err := conn.Attestation.OrderRunner(m.name, m.setupHash)
	if err != nil {
		return fmt.Errorf("%s (%s): %w", m.name, m.cloudPath, err)
	}
	b := &handoverorder.Body{ClusterID: m.setup.ClusterID, ChainHash: m.setup.Chain.Hash(), Source: src, Target: target}
	if b.NotAfter, err = parseNotAfter(*notAfter, now()); err != nil {
		return err
	}
	raw, err := b.Encode()
	if err != nil {
		return err
	}

	// The locked group in force at the source.
	r := activeRef(st.state.Locked)
	arch, err := loadArchive(c.updates)
	if err != nil {
		return err
	}
	lockedBody, lockedRaw, err := values(m.setup, setupwire.GroupLocked, r, arch)
	if err != nil {
		return err
	}
	locked := &m.setup.Locked
	if lockedBody != nil {
		locked = lockedBody.Locked
	}
	dev := m.setup.Platform.Platform == setupwire.PlatformDev
	if err := b.CheckImage(locked.AllowedImageMeasurements, dev); err != nil {
		return fmt.Errorf("%w; add the image with a locked update first", err)
	}
	lim := st.flavor.Limits()
	wait := lim.OrderWait(locked, dev)
	if acts := uint64(now().Unix()) + wait; b.NotAfter <= acts {
		return fmt.Errorf("-not-after %s is before the source would act on the order (%s after it arrives); give it more time", when(b.NotAfter),
			time.Duration(min(wait, 1<<62/uint64(time.Second)))*time.Second)
	}
	hash := handoverorder.Hash(raw)
	fprintf(out, "handover order: %s (setup %s, %s) to %s (setup %s, %s), cluster_id 0x%x\n", m.name, hex8(m.setupHash), b.Source.Verifier,
		tname, hex8(th), b.Target.Verifier, b.ClusterID)
	fprintf(out, "  the source acts on it %v after it arrives (%s, %s build), and starts no handover after %s\n",
		time.Duration(min(wait, 1<<62/uint64(time.Second)))*time.Second,
		map[bool]string{true: "a dev signer: the time lock", false: "the images minimum time lock, or the time lock in force when longer"}[dev],
		st.flavor, when(b.NotAfter))
	fprintf(out, "  the target's image is on the allowed list of the locked group in force (version %d)\n", r.version)
	if st.state.Locked.Pending.Version != 0 || st.state.Open.Pending.Version != 0 {
		fprintf(out, "  note: %s has a config update pending; it refuses the handover until the update is in force or replaced\n", m.name)
	}
	if st.state.Order.Kind != 0 {
		fprintf(out, "  note: %s has an order pending (kind %d, %s); a second handover order waits until it expired\n", m.name,
			st.state.Order.Kind, hex8(st.state.Order.Hash))
	}
	af := activeFile{Setup: hex.EncodeToString(m.setupRaw)}
	if lockedRaw != nil {
		af.Locked = hex.EncodeToString(lockedRaw)
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
	fprintf(out, "order_sha256 %s\n", fullHex(hash))
	fprintf(out, "wrote %s and %s\n", *outPath, *outPath+".active")
	return nil
}

// showHandover is show for a handover order body or a signed one.
func showHandover(out io.Writer, path string, file []byte, activePath string) error {
	b, raw, signed, err := decodeHandover(path, file)
	if err != nil {
		return err
	}
	text, err := b.Format()
	if err != nil {
		return err
	}
	if _, err := out.Write(text); err != nil {
		return err
	}
	fprintf(out, "\norder_sha256 %s\n", fullHex(handoverorder.Hash(raw)))
	p, def := activePath, false
	if p == "" {
		p, def = path+".active", true
	}
	if def {
		if _, err := os.Stat(p); errors.Is(err, os.ErrNotExist) {
			fprintf(out, "no active values (%s): no image or signature check\n", p)
			p = ""
		}
	}
	var a *orderActive
	if p != "" {
		if a, err = loadHandoverActive(p, b); err != nil {
			return err
		}
		dev := a.setup.Platform.Platform == setupwire.PlatformDev
		if err := b.CheckImage(a.locked.AllowedImageMeasurements, dev); err != nil {
			fprintf(out, "image: %v\n", err)
		} else {
			fprintf(out, "image: the target's image is on the allowed list of the source's locked version %d\n", a.ref.version)
		}
		wait := flavor.Default.Limits().OrderWait(a.locked, dev)
		fprintf(out, "wait: %d s after it arrives at the source%s\n", wait, testnetWait(wait, flavor.Testnet.Limits().OrderWait(a.locked, dev)))
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

// signHandover is sign for a handover order body.
func signHandover(out io.Writer, path string, raw []byte, key adminapprover.Signer, hashed bool, outPath string) error {
	b, err := handoverorder.DecodeBody(raw)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	sig, err := adminapprover.Sign(key, setupwire.CtxHandoverOrder, hashed, raw)
	if err != nil {
		return err
	}
	s := &sigFile{bodyHash: handoverorder.Hash(raw), key: adminapprover.Key(key), sig: sig, hashed: hashed,
		context: setupwire.CtxHandoverOrder.String()}
	if outPath == "" {
		outPath = fmt.Sprintf("%s.%s.sig", path, hex.EncodeToString(s.key[:4]))
	}
	if err := os.WriteFile(outPath, s.format(), 0o644); err != nil {
		return err
	}
	fprintf(out, "signed handover order %s to %s (setup %s), order_sha256 %s, with key %s\n", b.Source.Name, b.Target.Name,
		hex8(b.Target.SetupHash), fullHex(s.bodyHash), hex.EncodeToString(s.key[:]))
	if _, err := os.Stat(path + ".active"); err == nil {
		if a, err := loadHandoverActive(path+".active", b); err == nil {
			if p := position(a.locked.Approvers.Keys, s.key); p >= 0 {
				fprintf(out, "the key is approver %d in force\n", p)
			}
		}
	}
	fprintf(out, "wrote %s\n", outPath)
	return nil
}

// assembleHandover is assemble for a handover order body.
func assembleHandover(out io.Writer, path string, raw []byte, activePath string, sigs []string, outPath string) error {
	b, err := handoverorder.DecodeBody(raw)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	a, err := loadHandoverActive(activePath, b)
	if err != nil {
		return err
	}
	set := &a.locked.Approvers
	hash := handoverorder.Hash(raw)
	approvals := map[int][64]byte{}
	for _, p := range sigs {
		s, err := parseSigFile(p)
		if err != nil {
			return err
		}
		if s.bodyHash != hash {
			return fmt.Errorf("%s signs %s, not this order (%s)", p, hex8(s.bodyHash), hex8(hash))
		}
		if !setupwire.VerifyApproval(s.key, setupwire.CtxHandoverOrder, s.sig, raw) {
			return fmt.Errorf("%s: the signature does not verify", p)
		}
		pa := position(set.Keys, s.key)
		if pa < 0 {
			return fmt.Errorf("%s: key %s is not an approver in force", p, hex.EncodeToString(s.key[:]))
		}
		approvals[pa] = s.sig
	}
	o := &handoverorder.Order{Body: *b}
	for p := range len(set.Keys) {
		if sig, ok := approvals[p]; ok {
			o.Approvals = append(o.Approvals, setupwire.Approval{Position: uint8(p), Signature: sig})
		}
	}
	if len(o.Approvals) < int(set.ApprovalsNeeded) {
		return fmt.Errorf("%d of the approvers in force signed, approvals_needed is %d: %d more needed", len(o.Approvals), set.ApprovalsNeeded, int(set.ApprovalsNeeded)-len(o.Approvals))
	}
	signed, err := o.Encode()
	if err != nil {
		return err
	}
	if err := o.Verify(set); err != nil {
		return err
	}
	if err := os.WriteFile(outPath, signed, 0o644); err != nil {
		return err
	}
	var pos []string
	for _, ap := range o.Approvals {
		pos = append(pos, fmt.Sprint(ap.Position))
	}
	fprintf(out, "handover order %s to %s, order_sha256 %s: approvers %s of %d (k %d)\nwrote %s\n", b.Source.Name, b.Target.Name, fullHex(hash),
		strings.Join(pos, ","), len(set.Keys), set.ApprovalsNeeded, outPath)
	return nil
}

// pushHandover is push for a signed handover order: HANDOVER_ORDER to the
// source, and the state it answers. Other signers of the cluster are not
// sent it: the order names one source.
func pushHandover(out io.Writer, c *cluster, raw []byte, timeout time.Duration) error {
	o, err := handoverorder.Decode(raw)
	if err != nil {
		return err
	}
	body, _ := o.Body.Encode()
	hash := handoverorder.Hash(body)
	failed, sent := false, false
	for _, m := range c.members {
		if m.setupHash != o.Body.Source.SetupHash {
			fprintf(out, "%s not sent: the order's source is setup %s\n", m.name, hex8(o.Body.Source.SetupHash))
			continue
		}
		sent = true
		st, err := pushHandoverOne(m, raw, &o.Body, timeout)
		if err != nil {
			failed = true
			fprintf(out, "%s refused: %v\n", m.name, err)
			continue
		}
		if st.Hash != hash {
			failed = true
			fprintf(out, "%s answered for order %s\n", m.name, hex8(st.Hash))
			continue
		}
		outcome := "accepted"
		if st.Outcome == handoverorder.Known {
			outcome = "known"
		}
		line := fmt.Sprintf("%s %s: handover order %s %s, to %s (setup %s), arrived %s, acts %s (%s), not after %s", m.name, outcome,
			hex8(hash), st.Status, o.Body.Target.Name, hex8(o.Body.Target.SetupHash), when(st.Arrived), when(st.ActAt), left(st.ActAt, now()),
			when(st.NotAfter))
		if st.Why != "" {
			line += ": " + st.Why
		}
		fprintf(out, "%s\n", line)
	}
	if !sent {
		return fmt.Errorf("no signer of the cluster has the order's source setup %s", hex8(o.Body.Source.SetupHash))
	}
	if failed {
		return errReported
	}
	return nil
}

func pushHandoverOne(m *member, raw []byte, b *handoverorder.Body, timeout time.Duration) (*handoverorder.State, error) {
	if err := b.Matches(m.setup, m.setupHash); err != nil {
		return nil, fmt.Errorf("not sent: %v", err)
	}
	conn, err := loadConn(m.cloudPath)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cl, err := conn.New(runnerclient.WithTimeout(timeout))
	if err != nil {
		return nil, err
	}
	defer cl.Close()
	return remoteadmin.Wrap(cl.Client).HandoverOrder(ctx, raw)
}
