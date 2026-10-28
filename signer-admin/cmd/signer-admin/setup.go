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

	"github.com/lidofinance/tee-signer/governance/flavor"
	"github.com/lidofinance/tee-signer/governance/setupwire"
)

// The setup file is the human setup format of setupwire ("key = value",
// setup format 1, the field names of attestation-prover.md) with one
// [signer NAME] section per signer. The lines before the first section
// belong to every signer: setup_format_version, handover_generation, the
// chain, the safety settings, max_keys, slashing_log_min_lock_days and both
// config groups, and any platform key that is the same for all
// (allowed_client_ca, for example). A section holds the keys of one signer:
// platform, stores, sealing key release, network entry names. NAME becomes the
// signer's signer_name. The tool draws cluster_id and the salts: the policy
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
		s, err := setupwire.ParseSetup(name, []byte(strings.Join(text, "\n")))
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
	build := fs.String("build", string(flavor.Default), fmt.Sprintf("the runners' build flavour, default or testnet; a testnet runner refuses a time lock above %d s at start, so this refuses it here",
		flavor.Testnet.Limits().MaxTimeLock))
	if err := fs.Parse(args); err != nil {
		return err
	}
	fl := flavor.Flavor(*build)
	if fl != flavor.Default && fl != flavor.Testnet {
		return fmt.Errorf("-build %q: default or testnet", *build)
	}
	if *dir == "" || fs.NArg() != 1 {
		return errors.New("usage: signer-admin setup [-build default|testnet] -out DIR FILE")
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
	// The parser checks the default build's cap (30 days); a testnet
	// build's is 30 minutes.
	for _, s := range setups {
		if err := fl.Limits().CheckTimeLock(&s.Locked); err != nil {
			return fmt.Errorf("signer %s: %w", s.SignerName, err)
		}
	}
	// Every split of the cluster's keys has at most as many shares as the
	// file has signers. t = n is the split the threshold rule refuses
	// last, so a cluster that fails it can hold no key at all: one GCP
	// signer (1 of 1 is refused there on every chain), or one signer on
	// mainnet. The runners refuse such an order; this refuses the setup.
	for _, s := range setups {
		if err := setupwire.CheckThresholdOn(s.Platform.Platform, s.Chain.GenesisForkVersion, len(setups), len(setups)); err != nil {
			return fmt.Errorf("signer %s: a cluster of %d signer(s) can hold no key: %w", s.SignerName, len(setups), err)
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
	fprintf(out, "cluster_id 0x%x\n", clusterID)
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
