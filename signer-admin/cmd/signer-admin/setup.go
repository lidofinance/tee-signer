package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/lidofinance/tee-signer/governance/runnerchain"
	"github.com/lidofinance/tee-signer/governance/setuptext"
	"github.com/lidofinance/tee-signer/governance/setupwire"
)

// The setup file is the human setup format of setupwire ("key = value",
// setup format 2) with one
// [signer NAME] section per signer. The lines before the first section
// belong to every signer: setup_format_version, handover_generation, the
// chain, the safety settings, max_keys, slashing_log_min_lock_days and both
// config groups, and any platform key that is the same for all
// (allowed_client_ca, for example). A section holds the keys of one signer:
// platform, stores, sealing key release, network entry names. NAME becomes the
// signer's signer_name. signing_mode (threshold or single) is shared: a
// single-mode file has one section. The tool draws cluster_id and the salts: the policy
// salts once for the cluster, so every signer with the same public values
// has the same policy_root, and one platform salt per signer. So the file
// names neither signer_name nor cluster_id nor any salt.

var sectionRE = regexp.MustCompile(`^\s*\[signer\s+([^\]\s]+)\s*\]\s*(#.*)?$`)

type section struct {
	name  string
	start int // line index of the header
	end   int // line index after the last line
}

// keyOf is the key of a "key = value" line, or "".
func keyOf(line string) string {
	text, _, _ := strings.Cut(line, "#")
	k, _, ok := strings.Cut(text, "=")
	if !ok {
		return ""
	}
	return strings.TrimSpace(k)
}

// splitSetupFile finds the sections. Line numbers stay those of the file.
func splitSetupFile(lines []string) (shared int, secs []section, err error) {
	shared = len(lines)
	for i, l := range lines {
		if m := sectionRE.FindStringSubmatch(l); m != nil {
			if len(secs) == 0 {
				shared = i
			} else {
				secs[len(secs)-1].end = i
			}
			secs = append(secs, section{name: m[1], start: i, end: len(lines)})
			continue
		}
		if strings.HasPrefix(strings.TrimSpace(l), "[") {
			return 0, nil, fmt.Errorf("line %d: a section header is [signer NAME]", i+1)
		}
		switch keyOf(l) {
		case "cluster_id":
			return 0, nil, fmt.Errorf("line %d: cluster_id: signer-admin setup draws it; leave it out", i+1)
		case "signer_name":
			return 0, nil, fmt.Errorf("line %d: signer_name: the [signer NAME] header gives it", i+1)
		}
		if k := keyOf(l); strings.HasPrefix(k, "salt.") || k == "platform_salt" {
			return 0, nil, fmt.Errorf("line %d: %s: signer-admin setup draws the salts; leave them out", i+1, k)
		}
	}
	if len(secs) == 0 {
		return 0, nil, errors.New("no [signer NAME] section")
	}
	return shared, secs, nil
}

// buildSetups reads a setup file and returns one setup per section, all
// with clusterID.
func buildSetups(name string, data []byte, clusterID [32]byte) ([]*setupwire.Setup, error) {
	lines := strings.Split(string(data), "\n")
	shared, secs, err := splitSetupFile(lines)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	var out []*setupwire.Setup
	seen := map[string]bool{}
	for _, sec := range secs {
		if seen[sec.name] {
			return nil, fmt.Errorf("%s:%d: signer %s has a second section", name, sec.start+1, sec.name)
		}
		seen[sec.name] = true
		// The text of one signer keeps every line where it was, so the
		// parser's line numbers are the file's: the shared lines, the
		// header as signer_name, this section, blanks for the others, and
		// cluster_id past the end.
		text := make([]string, len(lines)+1)
		copy(text, lines[:shared])
		text[sec.start] = "signer_name = " + sec.name
		copy(text[sec.start+1:], lines[sec.start+1:sec.end])
		text[len(lines)] = fmt.Sprintf("cluster_id = 0x%x", clusterID)
		s, err := setuptext.ParseSetup(name, []byte(strings.Join(text, "\n")))
		if err != nil {
			return nil, fmt.Errorf("signer %s: %w", sec.name, err)
		}
		out = append(out, s)
	}
	for i := 1; i < len(out); i++ {
		a, b := &member{name: out[0].SignerName, setup: out[0]}, &member{name: out[i].SignerName, setup: out[i]}
		if err := sameCluster(a, b); err != nil {
			return nil, fmt.Errorf("%s: %w; set these keys before the first section", name, err)
		}
	}
	return out, nil
}

func cmdSetup(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("setup", flag.ContinueOnError)
	dir := fs.String("out", "", "folder for the binary setups, one NAME.setup per signer")
	build := fs.String("build", string(runnerchain.Mainnet), fmt.Sprintf("the chain of the runners' build: mainnet, hoodi, devnet or ci-test; a runner refuses at start a setup of a chain its build does not run on (a non-prod build runs on its own chain only, the mainnet build on mainnet or, on the dev platform, any non-prod chain) and a non-prod runner (all but mainnet) a time lock above %d s, so this refuses them here",
		runnerchain.Devnet.Limits().MaxTimeLock))
	allowGCPSingle := fs.Bool("allow-gcp-unsafe-single-key", false, "accept, in the setup of a one-signer GCP cluster, that the signer holds keys alone (1 of 1); UNSAFE: "+setupwire.UnsafeSingleKeyWarning)
	if err := fs.Parse(args); err != nil {
		return err
	}
	fl, err := runnerchain.Parse(*build)
	if err != nil {
		return fmt.Errorf("-build: %w", err)
	}
	if *dir == "" || fs.NArg() != 1 {
		return errors.New("usage: signer-admin setup [-build mainnet|hoodi|devnet|ci-test] [-allow-gcp-unsafe-single-key] -out DIR FILE")
	}
	data, err := os.ReadFile(fs.Arg(0))
	if err != nil {
		return err
	}
	var clusterID [32]byte
	if _, err := io.ReadFull(toolRand, clusterID[:]); err != nil {
		return err
	}
	setups, err := buildSetups(fs.Arg(0), data, clusterID)
	if err != nil {
		return err
	}
	// A runner of the build refuses a setup of a chain it does not run on
	// before anything else, so the chain comes first: genesis values of two
	// chains, or a build whose runners never start on the file's chain, are
	// refused before the time lock, whose floor follows the chain and whose
	// cap follows the build. The parser checks the mainnet build's cap (30
	// days) and, on a prod chain, its floor (the 2-day default); a non-prod
	// build's are 30 and 2 minutes.
	for _, s := range setups {
		if err := fl.CheckSetupChain(&s.Chain); err != nil {
			return fmt.Errorf("signer %s: a %s runner refuses the setup at start: %w", s.SignerName, fl, err)
		}
		if err := fl.Limits().CheckTimeLock(&s.Chain, &s.Locked); err != nil {
			return fmt.Errorf("signer %s: %w", s.SignerName, err)
		}
	}
	// -allow-gcp-unsafe-single-key is for a single-mode GCP file, which
	// has one signer: it writes the acceptance into that signer's setup,
	// as the key sealing_key_release.unsafe_single_key_accepted in its
	// section would. A threshold file, or a signer that is not on GCP,
	// refuses the flag.
	// signing_mode is a public value, the same for every signer (buildSetups
	// compares them). A single-mode cluster is one signer that holds whole
	// keys; a threshold-mode cluster of one signer could hold no key.
	if err := setupwire.CheckMembers(setups[0].SigningMode, len(setups)); err != nil {
		return fmt.Errorf("%s: %w", fs.Arg(0), err)
	}
	if *allowGCPSingle {
		if s := setups[0]; s.SigningMode != setupwire.SigningModeSingle {
			return fmt.Errorf("-allow-gcp-unsafe-single-key: the file says signing_mode = %s; the acceptance is for a single-mode setup (signing_mode = single)", s.SigningMode)
		}
		if s := setups[0]; s.Platform.Platform != setupwire.PlatformGCP {
			return fmt.Errorf("-allow-gcp-unsafe-single-key: signer %s is on %s, not on GCP; only a GCP signer needs the acceptance to hold keys alone", s.SignerName, s.Platform.Platform)
		}
		setups[0].Platform.SealingKeyRelease.UnsafeSingleKeyAccepted = true
	}
	// Every split of the cluster's keys has at most as many shares as the
	// file has signers. t = n is the split the threshold rule refuses
	// last, so a cluster that fails it can hold no key at all: one GCP
	// signer without the acceptance, or a threshold file with one signer
	// (CheckMembers above refuses that one first). The runners refuse such an order;
	// this refuses the setup, with the reason and the way to accept. On
	// mainnet a GCP runner starts only with the other acceptance,
	// sealing_key_release.no_lock_accepted (platform.Options.CheckNoLock),
	// so a mainnet setup that accepts a key held alone without it would
	// make a runner that never starts: refused here, and the flag never
	// sets no_lock_accepted, as each acceptance is its own decision. A
	// GCP setup with an acceptance gets its WARNING line on every run, so
	// the operator sees it when the setup is made, not only in the file.
	for _, s := range setups {
		k := &s.Platform.SealingKeyRelease
		// A dv_share cluster holds some shares of a Charon split whose other
		// shares sit in signers outside this file, so its size bounds no split.
		if err := setupwire.CheckThresholdOn(s, len(setups), len(setups)); err != nil && s.SigningMode != setupwire.SigningModeDVShare {
			return fmt.Errorf("signer %s: a cluster of %d signer(s) can hold no key: %w", s.SignerName, len(setups), err)
		}
		if err := setupwire.CheckSingleKeyProd(&s.Platform, &s.Chain); err != nil {
			return fmt.Errorf("signer %s: %w in the signer's section (-allow-gcp-unsafe-single-key does not set it)", s.SignerName, err)
		}
		if err := s.CheckOwnImageListed(); err != nil {
			return fmt.Errorf("signer %s: %w", s.SignerName, err)
		}
		if k.NoLockAccepted {
			fprintf(out, "WARNING signer %s: the setup accepts a key rule without a lock (sealing_key_release.no_lock_accepted): Cloud KMS has no lock on the rule that releases the sealing key, and a mainnet runner starts anyway\n", s.SignerName)
		}
		if k.UnsafeSingleKeyAccepted {
			fprintf(out, "WARNING signer %s: the setup accepts a key held alone on GCP (sealing_key_release.unsafe_single_key_accepted): %s\n", s.SignerName, setupwire.UnsafeSingleKeyWarning)
		}
	}
	// One set of policy salts for the cluster, one platform salt per signer.
	salts, err := setupwire.NewPolicySalts(toolRand)
	if err != nil {
		return err
	}
	for _, s := range setups {
		if err := s.DrawSalts(salts, toolRand); err != nil {
			return fmt.Errorf("signer %s: %w", s.SignerName, err)
		}
	}
	raws := make([][]byte, len(setups))
	for i, s := range setups {
		if raws[i], err = s.Encode(); err != nil {
			return fmt.Errorf("signer %s: %w", s.SignerName, err)
		}
	}
	if err := os.MkdirAll(*dir, 0o755); err != nil {
		return err
	}
	// A setup that exists already belongs to another cluster_id: the
	// operator removes it on purpose, never by a second run.
	for _, s := range setups {
		p := filepath.Join(*dir, s.SignerName+".setup")
		if _, err := os.Stat(p); err == nil {
			return fmt.Errorf("%s exists; remove the old setups first (each run draws a new cluster_id)", p)
		}
	}
	fprintf(out, "cluster_id 0x%x\nsigning_mode %s\n", clusterID, setups[0].SigningMode)
	for i, s := range setups {
		p := filepath.Join(*dir, s.SignerName+".setup")
		f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
		if err != nil {
			return err
		}
		if _, err := f.Write(raws[i]); err != nil {
			f.Close()
			return err
		}
		if err := f.Close(); err != nil {
			return err
		}
		h, err := setupwire.SetupHash(raws[i])
		if err != nil {
			return err
		}
		pr, _ := s.PolicyRoot()
		fprintf(out, "%s setup_sha256 %s %s\n", s.SignerName, fullHex(h), p)
		fprintf(out, "%s policy_root %s\n", s.SignerName, fullHex(pr))
	}
	return nil
}
