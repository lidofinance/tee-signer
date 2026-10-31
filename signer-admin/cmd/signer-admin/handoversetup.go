package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/lidofinance/tee-signer/governance/handoverorder"
	"github.com/lidofinance/tee-signer/governance/setuptext"
	"github.com/lidofinance/tee-signer/governance/setupwire"
)

// handover-setup makes the target setups of a handover (protocol.md,
// "Handover", step 1): one per [signer NAME] section of FILE, where NAME is
// a signer of cluster.json. FILE holds the private part only: platform,
// allowed_client_ca, the stores, sealing_key_release and
// peer_attestation_hosts; the lines before the first section belong to
// every target. The tool takes everything else from the source:
// cluster_id, signer_name, chain, safety, max_keys and
// slashing_log_min_lock_days from its setup, handover_generation one
// higher, and version 0 of both groups from the config in force that the
// source's attested IDENTITY names (the bodies above version 0 come from
// the updates folder, as draft reads them). It draws one set of policy
// salts for all targets, so the targets form one cluster, and one platform
// salt per target. Make the targets of a cluster in one run.
//
// The target may keep a longer mark log lock than the source
// (-slashing-log-min-lock-days), never a shorter one, and may take more or
// fewer keys (-max-keys) as long as the source's shares fit; the source
// checks both again before it hands over (handoverorder.CheckTarget).

func cmdHandoverSetup(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("handover-setup", flag.ContinueOnError)
	cf := addClusterFlags(fs)
	dir := fs.String("out", "", "folder for the target setups, one NAME.setup per section")
	maxKeys := fs.Uint("max-keys", 0, "the targets' max_keys (default: the sources')")
	lockDays := fs.Uint("slashing-log-min-lock-days", 0, "the targets' slashing_log_min_lock_days, no lower than the sources' (default: the sources')")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dir == "" || fs.NArg() != 1 {
		return errors.New("usage: signer-admin handover-setup -cluster cluster.json [-max-keys N] [-slashing-log-min-lock-days N] -out DIR FILE")
	}
	path := fs.Arg(0)
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	lines := strings.Split(string(data), "\n")
	shared, secs, err := splitSetupFile(lines)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	c, err := cf.load()
	if err != nil {
		return err
	}
	byName := map[string]*member{}
	for _, m := range c.members {
		byName[m.name] = m
	}
	arch, err := loadArchive(c.updates)
	if err != nil {
		return err
	}

	type target struct {
		src    *member
		locked *setupwire.Locked
		open   *setupwire.Open
		setup  *setupwire.Setup
	}
	var targets []*target
	seen := map[string]bool{}
	for _, sec := range secs {
		m := byName[sec.name]
		if m == nil {
			return fmt.Errorf("%s:%d: %s is not a signer of %s", path, sec.start+1, sec.name, *cf.path)
		}
		if seen[sec.name] {
			return fmt.Errorf("%s:%d: signer %s has a second section", path, sec.start+1, sec.name)
		}
		seen[sec.name] = true
		// The shared lines and this section, each line where it was.
		text := make([]string, len(lines))
		copy(text, lines[:shared])
		copy(text[sec.start+1:], lines[sec.start+1:sec.end])
		pl, err := setuptext.ParsePlatform(path, []byte(strings.Join(text, "\n")))
		if err != nil {
			return fmt.Errorf("signer %s: %w", sec.name, err)
		}
		// The config in force at the source.
		st, err := readOneState(m, *cf.timeout)
		if err != nil {
			return err
		}
		if st.state.Locked.Pending.Version != 0 || st.state.Open.Pending.Version != 0 {
			return fmt.Errorf("%s has a config update pending; make the target once it is in force or replaced (the source refuses a handover meanwhile)", m.name)
		}
		tg := &target{src: m, locked: &m.setup.Locked, open: &m.setup.Open}
		for _, g := range groups {
			body, _, err := values(m.setup, g, activeRef(groupOf(st.state, g)), arch)
			if err != nil {
				return fmt.Errorf("%s: %w", m.name, err)
			}
			switch {
			case body != nil && g == setupwire.GroupLocked:
				tg.locked = body.Locked
			case body != nil:
				tg.open = body.Open
			}
		}
		if err := st.flavor.Limits().CheckTimeLock(tg.locked); err != nil {
			return fmt.Errorf("%s: %w", m.name, err)
		}
		src := m.setup
		s := &setupwire.Setup{SignerName: src.SignerName, ClusterID: src.ClusterID, HandoverGeneration: src.HandoverGeneration + 1,
			Chain: src.Chain, Safety: src.Safety, MaxKeys: src.MaxKeys, SlashingLogMinLockDays: src.SlashingLogMinLockDays,
			Platform: *pl, Locked: *tg.locked, Open: *tg.open}
		if *maxKeys != 0 {
			s.MaxKeys = uint32(min(*maxKeys, 1<<32-1))
		}
		if *lockDays != 0 {
			if uint64(*lockDays) < uint64(src.SlashingLogMinLockDays) {
				return fmt.Errorf("-slashing-log-min-lock-days %d is below the sources' %d: the target's mark log must stay locked at least as long",
					*lockDays, src.SlashingLogMinLockDays)
			}
			s.SlashingLogMinLockDays = uint32(min(*lockDays, 1<<32-1))
		}
		if err := s.CheckValues(); err != nil {
			return fmt.Errorf("signer %s: %w", sec.name, err)
		}
		tg.setup = s
		targets = append(targets, tg)
	}
	// One cluster: every source has the same public values in force, so
	// the targets share one policy_root.
	for _, tg := range targets[1:] {
		a, b := targets[0], tg
		ap, bp := a.setup.Policy(), b.setup.Policy()
		ae, err1 := ap.Locked.Encode()
		be, err2 := bp.Locked.Encode()
		ao, err3 := ap.Open.Encode()
		bo, err4 := bp.Open.Encode()
		if err := errors.Join(err1, err2, err3, err4); err != nil {
			return err
		}
		if a.src.setup.ClusterID != b.src.setup.ClusterID || !bytes.Equal(ae, be) || !bytes.Equal(ao, bo) ||
			ap.HandoverGeneration != bp.HandoverGeneration || ap.Chain != bp.Chain || ap.Safety != bp.Safety ||
			ap.MaxKeys != bp.MaxKeys || ap.SlashingLogMinLockDays != bp.SlashingLogMinLockDays {
			return fmt.Errorf("%s and %s do not have the same public values in force; make their targets in separate runs only if they are separate clusters",
				a.src.name, b.src.name)
		}
	}
	setups := make([]*setupwire.Setup, len(targets))
	for i, tg := range targets {
		setups[i] = tg.setup
	}
	if err := checkNewSetups(out, setups, len(c.members)); err != nil {
		return err
	}
	salts, err := setupwire.NewPolicySalts(toolRand)
	if err != nil {
		return err
	}
	raws := make([][]byte, len(targets))
	for i, tg := range targets {
		if err := tg.setup.DrawSalts(salts, toolRand); err != nil {
			return fmt.Errorf("signer %s: %w", tg.src.name, err)
		}
		// The rule the source applies before it hands over.
		if err := handoverorder.CheckTarget(tg.src.setup, tg.locked, tg.open, tg.setup.Policy()); err != nil {
			return fmt.Errorf("signer %s: %w", tg.src.name, err)
		}
		if raws[i], err = tg.setup.Encode(); err != nil {
			return fmt.Errorf("signer %s: %w", tg.src.name, err)
		}
	}
	if err := os.MkdirAll(*dir, 0o755); err != nil {
		return err
	}
	for _, tg := range targets {
		if p := filepath.Join(*dir, tg.src.name+".setup"); fileExists(p) {
			return fmt.Errorf("%s exists; remove the old target setups first (each run draws new salts)", p)
		}
	}
	for i, tg := range targets {
		p := filepath.Join(*dir, tg.src.name+".setup")
		if err := writeNew(p, raws[i]); err != nil {
			return err
		}
		h, err := setupwire.SetupHash(raws[i])
		if err != nil {
			return err
		}
		fprintf(out, "%s setup_sha256 %s %s\n", tg.src.name, fullHex(h), p)
		fprintf(out, "%s handover_generation %d, from setup %s\n", tg.src.name, tg.setup.HandoverGeneration, hex8(tg.src.setupHash))
	}
	fprintf(out, "next: start each target with its setup, pin it in the target's cloud.json, then handover-draft -target-setup DIR/NAME.setup\n")
	return nil
}

// readOneState reads one member's attested state.
func readOneState(m *member, timeout time.Duration) (*signerState, error) {
	c := &cluster{members: []*member{m}}
	states, errs := readAll(c, timeout)
	if errs[0] != nil {
		return nil, fmt.Errorf("%s: %w", m.name, errs[0])
	}
	return states[0], nil
}

func fileExists(p string) bool { _, err := os.Stat(p); return err == nil }

// writeNew writes a file that must not exist.
func writeNew(p string, data []byte) error {
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}
