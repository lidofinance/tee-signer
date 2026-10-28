package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/lidofinance/tee-signer/attestation-verify/runnerclient"
	"github.com/lidofinance/tee-signer/governance/dkgorder"
	"github.com/lidofinance/tee-signer/governance/flavor"
	"github.com/lidofinance/tee-signer/governance/setupwire"
	adminapprover "github.com/lidofinance/tee-signer/signer-admin/approver"
	remoteadmin "github.com/lidofinance/tee-signer/signer-admin/remote/admin"
	"github.com/lidofinance/tee-signer/signer-protocol/dkgmsg"
)

// DKG orders (research/setup-phase.md, section 10, "Key generation"): what
// replaces the -dkg-policy file of a runner with a setup. The flow is the
// config update's:
//
//	signer-admin dkg-draft -cluster cluster.json -path dirk|charon [-enrs FILE] -out order.bin
//	signer-admin show order.bin                      each approver, offline
//	signer-admin sign -key approver.key order.bin    each approver
//	signer-admin assemble order.bin sig...           k signatures of the approvers in force
//	signer-admin push -cluster cluster.json order.signed
//
// dkg-draft reads each signer's attested IDENTITY and operator key
// (DKG_OPERATOR) and its cloud.json, and writes the order with one
// participant per signer of cluster.json, in that order: participant i
// holds the shares at x = i+1. The participant's image and attestation
// settings come from its cloud.json (cloud.json's minimum versions stay
// there), its setup_sha256 from its setup. order.bin.active holds the
// locked group in force (the setup, or the active locked update), so show
// and assemble check the approvers and the allowed images offline.
//
// The runner waits the images minimum time lock (7 days, or the time lock
// in force when that is longer) from an order's arrival before it acts on
// it; a dev runner waits its time lock only.

// orderActive is the locked group an order is checked against.
type orderActive struct {
	setup  *setupwire.Setup
	locked *setupwire.Locked
	ref    ref
}

// loadOrderActive reads an active file for an order body: the setup (and
// the active locked update, if any) of the order's cluster and chain.
func loadOrderActive(path string, b *dkgorder.Body) (*orderActive, error) {
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
	if err := b.Matches(a.setup); err != nil {
		return nil, fmt.Errorf("%s: the active values are not of this order's cluster: %w", path, err)
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
		uh, err := u.Hash()
		if err != nil {
			return nil, fmt.Errorf("%s: locked: %w", path, err)
		}
		a.locked, a.ref = u.Locked, ref{u.Version, uh}
	}
	return a, nil
}

// readOrder reads an order body ('D') or a signed order ('O').
func readOrder(path string) (*dkgorder.Body, []byte, *dkgorder.Order, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, nil, err
	}
	return decodeOrder(path, raw)
}

// decodeOrder is readOrder for the bytes raw read from path.
func decodeOrder(path string, raw []byte) (*dkgorder.Body, []byte, *dkgorder.Order, error) {
	if dkgorder.IsOrder(raw) {
		o, err := dkgorder.Decode(raw)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("%s: %w", path, err)
		}
		body, err := o.Body.Encode()
		if err != nil {
			return nil, nil, nil, err
		}
		return &o.Body, body, o, nil
	}
	b, err := dkgorder.DecodeBody(raw)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("%s: %w", path, err)
	}
	return b, raw, nil, nil
}

// isOrderFile reports whether path holds an order body or a signed order.
func isOrderFile(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	var b [1]byte
	if _, err := io.ReadFull(f, b[:]); err != nil {
		return false
	}
	return dkgorder.IsBody(b[:]) || dkgorder.IsOrder(b[:])
}

// parseNotAfter reads -not-after: an RFC 3339 time, or a duration from now
// with h or d units ("2160h", "90d").
func parseNotAfter(s string, t time.Time) (uint64, error) {
	if at, err := time.Parse(time.RFC3339, s); err == nil {
		return uint64(max(at.Unix(), 0)), nil
	}
	if n, ok := strings.CutSuffix(s, "d"); ok {
		days, err := strconv.ParseUint(n, 10, 16)
		if err != nil {
			return 0, fmt.Errorf("-not-after %q: want an RFC 3339 time or a duration like 90d or 2160h", s)
		}
		return uint64(t.Add(time.Duration(days) * 24 * time.Hour).Unix()), nil
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("-not-after %q: want an RFC 3339 time or a duration like 90d or 2160h", s)
	}
	return uint64(t.Add(d).Unix()), nil
}

// readENRs reads one ENR a line ('#' starts a comment).
func readENRs(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 4096), dkgorder.MaxENR+256)
	for sc.Scan() {
		l, _, _ := strings.Cut(sc.Text(), "#")
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	return out, sc.Err()
}

// operatorKey reads a signer's operator key over its attested connection
// and checks that the answer binds the key and a fresh nonce.
func operatorKey(ctx context.Context, cl *runnerclient.Client, att *runnerclient.Attestation) ([32]byte, error) {
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return [32]byte{}, err
	}
	info, err := remoteadmin.Wrap(cl.Client).DKGOperator(ctx, &dkgmsg.OperatorRequest{Nonce: nonce})
	if err != nil {
		return [32]byte{}, err
	}
	if !bytes.Equal(info.Nonce, nonce) || info.Identity == nil || info.Identity.Attestation == nil {
		return [32]byte{}, errors.New("the DKG_OPERATOR answer does not bind the nonce")
	}
	// The answer's document binds the operator context, not IDENTITY's: an
	// IDENTITY answer for the same nonce does not pass.
	verify, err := att.NewDKGOperatorVerifier()
	if err != nil {
		return [32]byte{}, err
	}
	if err := verify(ctx, info.AttestNonce(), info.Identity); err != nil {
		return [32]byte{}, fmt.Errorf("operator key attestation: %w", err)
	}
	return info.Key, nil
}

func cmdDKGDraft(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("dkg-draft", flag.ContinueOnError)
	cf := addClusterFlags(fs)
	path := fs.String("path", "", "what the keys are for: dirk (deposits) or charon (deposits, registrations, the lock)")
	label := fs.String("label", "", "a name for the order (default: the path)")
	threshold := fs.Int("threshold", 0, "signers needed to sign for a key (default: a majority)")
	notAfter := fs.String("not-after", "90d", "no keys are made from then on: RFC 3339 time, or a duration from now (90d, 2160h)")
	enrsPath := fs.String("enrs", "", "charon: a file with each signer's Charon ENR, one a line, in cluster.json order")
	outPath := fs.String("out", "order.bin", "the order body to sign; the locked values in force go to the same name with .active")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("usage: signer-admin dkg-draft -cluster cluster.json -path dirk|charon [-label NAME] [-threshold K] [-not-after 90d] [-enrs FILE] [-out order.bin]")
	}
	p, err := dkgorder.ParsePath(*path)
	if err != nil {
		return fmt.Errorf("-path: %w", err)
	}
	c, err := cf.load()
	if err != nil {
		return err
	}
	b := &dkgorder.Body{Path: p, Label: cmpOr(*label, *path)}
	b.ClusterID, b.ChainHash = c.members[0].setup.ClusterID, c.members[0].setup.Chain.Hash()
	n := len(c.members)
	b.Threshold = uint8(n/2 + 1)
	if *threshold != 0 {
		b.Threshold = uint8(min(*threshold, 255))
	}
	if b.NotAfter, err = parseNotAfter(*notAfter, now()); err != nil {
		return err
	}
	if p == dkgorder.PathCharon {
		if *enrsPath == "" {
			return errors.New("-enrs is required for the charon path")
		}
		if b.CharonENRs, err = readENRs(*enrsPath); err != nil {
			return err
		}
	} else if *enrsPath != "" {
		return errors.New("-enrs is for the charon path")
	}

	// Each signer: attested state (setup pinned), operator key, settings.
	var states []*signerState
	for _, m := range c.members {
		conn, err := loadConn(m.cloudPath)
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), *cf.timeout)
		st, cl, err := readState(ctx, m, conn, *cf.timeout)
		if err != nil {
			cancel()
			return fmt.Errorf("%s: %w", m.name, err)
		}
		key, err := operatorKey(ctx, cl, &conn.Attestation)
		cl.Close()
		cancel()
		if err != nil {
			return fmt.Errorf("%s: %w", m.name, err)
		}
		part, err := conn.Attestation.OrderParticipant(m.name, m.setupHash, key)
		if err != nil {
			return fmt.Errorf("%s (%s): %w", m.name, m.cloudPath, err)
		}
		b.Participants = append(b.Participants, part)
		states = append(states, st)
	}
	// The locked group in force: every signer at one version, the body from
	// the setup or the updates folder.
	r := activeRef(states[0].state.Locked)
	for i, st := range states {
		if activeRef(st.state.Locked) != r {
			return fmt.Errorf("signers %s and %s are at different locked versions; push the locked update to every signer first", c.members[0].name, c.members[i].name)
		}
	}
	arch, err := loadArchive(c.updates)
	if err != nil {
		return err
	}
	s := c.members[0].setup
	lockedBody, lockedRaw, err := values(s, setupwire.GroupLocked, r, arch)
	if err != nil {
		return err
	}
	locked := &s.Locked
	if lockedBody != nil {
		locked = lockedBody.Locked
	}
	raw, err := b.Encode()
	if err != nil {
		return err
	}
	dev := c.members[0].setup.Platform.Platform == setupwire.PlatformDev
	if err := b.CheckImages(locked.AllowedImageMeasurements, dev); err != nil {
		return fmt.Errorf("%w; add the image with a locked update first", err)
	}
	// The signers' build flavour sets the wait: a testnet build's runs in
	// minutes.
	fl, lim, err := clusterLimits(c, states)
	if err != nil {
		return err
	}
	wait := lim.OrderWait(locked, dev)
	hash := dkgorder.Hash(raw)
	fprintf(out, "dkg order %q, path %s, %d of %d, cluster_id 0x%x\n", b.Label, b.Path, b.Threshold, n, b.ClusterID)
	for i, pt := range b.Participants {
		fprintf(out, "  participant %d %s: setup %s, operator key %s, %s\n", i+1, pt.Name, hex8(pt.SetupHash), hex.EncodeToString(pt.OperatorKey[:4]), pt.Verifier)
	}
	fprintf(out, "  each signer acts on it %v after it arrives (%s, %s build), and makes no keys after %s\n",
		time.Duration(min(wait, 1<<62/uint64(time.Second)))*time.Second,
		map[bool]string{true: "a dev signer: the time lock", false: "the images minimum time lock, or the time lock in force when longer"}[dev], fl, when(b.NotAfter))
	fprintf(out, "  withdrawal credentials and deposit amounts: the locked values in force (version %d): %x, %v gwei\n",
		r.version, locked.WithdrawalCredentials[:], locked.AllowedDepositAmounts)
	// A Nitro signer reaches only the hosts of its setup's keygen_peer_attestation_hosts.
	peers := make([]peerHosts, len(b.Participants))
	for i := range b.Participants {
		peers[i] = orderPeer(&b.Participants[i])
	}
	for i, m := range c.members {
		warnPeerEndpoints(out, m.setup, missingPeerEndpoints(m.setup, peers, i),
			"it will refuse this order; only a new setup, so a new signer, can list more")
	}
	af := activeFile{Setup: hex.EncodeToString(c.members[0].setupRaw)}
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

// showOrder is show for an order body or a signed order.
func showOrder(out io.Writer, path string, file []byte, activePath string) error {
	b, raw, signed, err := decodeOrder(path, file)
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
	fprintf(out, "\norder_sha256 %s\n", fullHex(dkgorder.Hash(raw)))
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
		if a, err = loadOrderActive(p, b); err != nil {
			return err
		}
		dev := a.setup.Platform.Platform == setupwire.PlatformDev
		if err := b.CheckImages(a.locked.AllowedImageMeasurements, dev); err != nil {
			fprintf(out, "images: %v\n", err)
		} else {
			fprintf(out, "images: every participant's image is on the allowed list of locked version %d\n", a.ref.version)
		}
		wait := flavor.Default.Limits().OrderWait(a.locked, dev)
		fprintf(out, "wait: %d s after it arrives at each signer%s\n", wait, testnetWait(wait, flavor.Testnet.Limits().OrderWait(a.locked, dev)))
		fprintf(out, "credentials and deposit amounts in force: %x, %v gwei\n", a.locked.WithdrawalCredentials[:], a.locked.AllowedDepositAmounts)
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

// signOrder is sign for an order body.
func signOrder(out io.Writer, path string, raw []byte, key adminapprover.Signer, hashed bool, outPath string) error {
	b, err := dkgorder.DecodeBody(raw)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	sig, err := adminapprover.Sign(key, setupwire.CtxDKGOrder, hashed, raw)
	if err != nil {
		return err
	}
	s := &sigFile{bodyHash: dkgorder.Hash(raw), key: adminapprover.Key(key), sig: sig, hashed: hashed,
		context: setupwire.CtxDKGOrder.String()}
	if outPath == "" {
		outPath = fmt.Sprintf("%s.%s.sig", path, hex.EncodeToString(s.key[:4]))
	}
	if err := os.WriteFile(outPath, s.format(), 0o644); err != nil {
		return err
	}
	fprintf(out, "signed dkg order %q (%s, %d participants), order_sha256 %s, with key %s\n", b.Label, b.Path, len(b.Participants),
		fullHex(s.bodyHash), hex.EncodeToString(s.key[:]))
	if _, err := os.Stat(path + ".active"); err == nil {
		if a, err := loadOrderActive(path+".active", b); err == nil {
			if p := position(a.locked.Approvers.Keys, s.key); p >= 0 {
				fprintf(out, "the key is approver %d in force\n", p)
			}
		}
	}
	fprintf(out, "wrote %s\n", outPath)
	return nil
}

// assembleOrder is assemble for an order body.
func assembleOrder(out io.Writer, path string, raw []byte, activePath string, sigs []string, outPath string) error {
	b, err := dkgorder.DecodeBody(raw)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	a, err := loadOrderActive(activePath, b)
	if err != nil {
		return err
	}
	set := &a.locked.Approvers
	hash := dkgorder.Hash(raw)
	approvals := map[int][64]byte{}
	for _, p := range sigs {
		s, err := parseSigFile(p)
		if err != nil {
			return err
		}
		if s.bodyHash != hash {
			return fmt.Errorf("%s signs %s, not this order (%s)", p, hex8(s.bodyHash), hex8(hash))
		}
		if !setupwire.VerifyApproval(s.key, setupwire.CtxDKGOrder, s.sig, raw) {
			return fmt.Errorf("%s: the signature does not verify", p)
		}
		pa := position(set.Keys, s.key)
		if pa < 0 {
			return fmt.Errorf("%s: key %s is not an approver in force", p, hex.EncodeToString(s.key[:]))
		}
		approvals[pa] = s.sig
	}
	o := &dkgorder.Order{Body: *b}
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
	fprintf(out, "dkg order %q, order_sha256 %s: approvers %s of %d (k %d)\nwrote %s\n", b.Label, fullHex(hash),
		strings.Join(pos, ","), len(set.Keys), set.ApprovalsNeeded, outPath)
	return nil
}

// pushOrder is push for a signed order: DKG_ORDER to every signer, and the
// state each one answers.
func pushOrder(out io.Writer, c *cluster, raw []byte, timeout time.Duration) error {
	o, err := dkgorder.Decode(raw)
	if err != nil {
		return err
	}
	body, _ := o.Body.Encode()
	hash := dkgorder.Hash(body)
	failed := false
	for _, m := range c.members {
		st, err := pushOrderOne(m, raw, &o.Body, timeout)
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
		if st.Outcome == dkgmsg.OrderKnown {
			outcome = "known"
		}
		line := fmt.Sprintf("%s %s: dkg order %s %s as participant %d, arrived %s, acts %s (%s), not after %s",
			m.name, outcome, hex8(hash), st.Status, st.Position+1, when(st.Arrived), when(st.ActAt), left(st.ActAt, now()), when(st.NotAfter))
		if st.Why != "" {
			line += ": " + st.Why
		}
		fprintf(out, "%s\n", line)
	}
	if failed {
		return errReported
	}
	return nil
}

func pushOrderOne(m *member, raw []byte, b *dkgorder.Body, timeout time.Duration) (*dkgmsg.OrderState, error) {
	if err := b.Matches(m.setup); err != nil {
		return nil, fmt.Errorf("not sent: %v (the signer's setup has cluster_id %s)", err, hex8(m.setup.ClusterID))
	}
	if _, ok := b.Position(m.setupHash); !ok {
		return nil, fmt.Errorf("not sent: the order does not name this signer's setup %s", hex8(m.setupHash))
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
	return remoteadmin.Wrap(cl.Client).DKGOrder(ctx, raw)
}
