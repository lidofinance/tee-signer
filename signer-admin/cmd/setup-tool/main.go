// Command setup-tool makes and checks the binary setup of a signer
// (research/setup-phase.md in the threshold-signer-poc repo, section 2) for the
// cloud scripts in this repo. It uses the runner's decoder (backend/setupwire,
// runner/setup), so what it accepts is what the runner accepts. signer-config
// in the Dirk fork is the operator's tool (cluster ids, n setups, pins); this
// one covers one file at a time.
//
//	setup-tool encode HUMAN OUT
//	    Read a human setup file ("key = value"), write the binary setup to
//	    OUT (mode 0644) and print its setup_sha256. A file without salts
//	    gets fresh random ones: the policy salts of this signer alone (a
//	    cluster whose signers share one policy_root comes from
//	    signer-config setup) and its platform salt.
//	setup-tool check [-platform P] [-chain CHAIN_JSON] FILE
//	    Decode FILE strictly and print setup_sha256, platform and signer,
//	    policy_root and platform_commitment, and one
//	    peer_attestation_hosts line per host (on nitro
//	    "peer_attestation_hosts none" without any: its handover verifier
//	    then reaches no azure-maa or gcp-cs key set). With
//	    -platform, refuse a setup for another platform. With -chain, refuse
//	    a setup whose chain or first fork schedule differs from the runner
//	    chain.json (cloud/chains/chain.sh picks that file by chain name).
//	setup-tool show FILE
//	    Print the human form of a binary setup.
//	setup-tool chain-lines CHAIN_JSON
//	    Print the chain, safety, open and locked lines a chain.json gives,
//	    to start a human setup file from.
//
// Built without cgo (scripts/build-runner.sh), like the host agent.
package main

import (
	"context"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/lidofinance/tee-signer/governance/setupwire"
	"github.com/lidofinance/tee-signer/platform/setup"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "setup-tool:", err)
		os.Exit(1)
	}
}

func usage() error {
	return errors.New("usage: setup-tool encode HUMAN OUT | check [-platform P] [-chain CHAIN_JSON] FILE | show FILE | chain-lines CHAIN_JSON")
}

func run(args []string) error {
	if len(args) == 0 {
		return usage()
	}
	switch cmd, rest := args[0], args[1:]; cmd {
	case "encode":
		if len(rest) != 2 {
			return usage()
		}
		return encode(rest[0], rest[1])
	case "check":
		return check(rest)
	case "show":
		if len(rest) != 1 {
			return usage()
		}
		s, err := read(rest[0])
		if err != nil {
			return err
		}
		text, err := s.Format()
		if err != nil {
			return err
		}
		_, err = os.Stdout.Write(text)
		return err
	case "chain-lines":
		if len(rest) != 1 {
			return usage()
		}
		c, err := readChain(rest[0])
		if err != nil {
			return err
		}
		lines, err := setup.ChainLines(c)
		if err != nil {
			return err
		}
		fmt.Print(lines)
		return nil
	}
	return usage()
}

func encode(human, out string) error {
	text, err := os.ReadFile(human)
	if err != nil {
		return err
	}
	s, err := setupwire.ParseSetup(human, text)
	if err != nil {
		return err
	}
	if !s.Salted() {
		p, err := setupwire.NewPolicySalts(rand.Reader)
		if err != nil {
			return err
		}
		if err := s.DrawSalts(p, rand.Reader); err != nil {
			return err
		}
		fmt.Fprintln(os.Stderr, "setup-tool: the file has no salts; drew random policy salts for this signer alone and a platform salt")
	}
	raw, err := s.Encode()
	if err != nil {
		return err
	}
	if err := os.WriteFile(out, raw, 0o644); err != nil {
		return err
	}
	h, err := s.Hash()
	if err != nil {
		return err
	}
	fmt.Printf("setup_sha256 %x\n", h)
	return nil
}

func read(path string) (*setupwire.Setup, error) {
	raw, err := setup.File{Path: path}.Read(context.Background())
	if err != nil {
		return nil, err
	}
	s, err := setupwire.DecodeSetup(raw)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return s, nil
}

func readChain(path string) (*setup.ChainFile, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	c, err := setup.ParseChainFile(b)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return c, nil
}

func check(args []string) error {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	platform := fs.String("platform", "", "refuse a setup for another platform (nitro, azure, gcp, dev)")
	chain := fs.String("chain", "", "refuse a setup of another chain than this runner chain.json")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return usage()
	}
	raw, err := setup.File{Path: fs.Arg(0)}.Read(context.Background())
	if err != nil {
		return err
	}
	var s *setupwire.Setup
	if *platform != "" {
		st, err := setup.Load(raw, *platform)
		if err != nil {
			return fmt.Errorf("%s: %w", fs.Arg(0), err)
		}
		s = st.Wire
	} else if s, err = setupwire.DecodeSetup(raw); err != nil {
		return fmt.Errorf("%s: %w", fs.Arg(0), err)
	}
	if *chain != "" {
		c, err := readChain(*chain)
		if err != nil {
			return err
		}
		if err := setup.CompareChain(s, c); err != nil {
			return fmt.Errorf("%s: %w", fs.Arg(0), err)
		}
	}
	h, err := s.Hash()
	if err != nil {
		return err
	}
	pr, _ := s.PolicyRoot()
	pc, _ := s.PlatformCommitment()
	fmt.Printf("setup_sha256 %x\nplatform %s\nsigner %s\npolicy_root %x\nplatform_commitment %x\n", h, s.Platform.Platform, s.SignerName, pr, pc)
	for _, e := range s.Platform.PeerAttestationHosts {
		fmt.Printf("peer_attestation_hosts %s\n", e)
	}
	if len(s.Platform.PeerAttestationHosts) == 0 && s.Platform.Platform == setupwire.PlatformNitro {
		fmt.Println("peer_attestation_hosts none")
	}
	return nil
}
