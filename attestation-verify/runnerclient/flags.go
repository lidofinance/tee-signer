//go:build !verifierselect

// The command line flags of the tools. A runner built with verifierselect has no
// such flags, and maybe not every verifier constant they name.

package runnerclient

import (
	"errors"
	"flag"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/lidofinance/tee-signer/attestation-verify"
)

// Flags registers the attestation flags of a command line tool on fs and
// returns the Attestation they fill.
func Flags(fs *flag.FlagSet) *Attestation {
	a := &Attestation{}
	fs.StringVar(&a.Verifier, "verifier", "", `attestation verifier: "dev" (local dev runners), "azure-maa" (Azure runners), "aws-nitro" (AWS Nitro Enclaves) or "gcp-cs" (GCP Confidential Space)`)
	fs.StringVar(&a.MAAHost, "maa-host", "", "azure-maa: attestation provider host, e.g. sharedweu.weu.attest.azure.net")
	fs.StringVar(&a.CCEPolicySHA256, "cce-policy-sha256", "", "azure-maa: expected CCE policy SHA-256 (x-ms-sevsnpvm-hostdata), 64 hex digits")
	fs.StringVar(&a.ComplianceStatus, "compliance-status", "", "azure-maa: expected x-ms-compliance-status (default "+attest.ComplianceACI+")")
	fs.Var((*pcrFlag)(a), "nitro-pcr", "aws-nitro: expected PCR as INDEX=HEX (96 hex digits); repeat it, PCR0, PCR1 and PCR2 are required")
	fs.StringVar(&a.NitroRootSHA256, "nitro-root-sha256", "", "aws-nitro: SHA-256 of the AWS Nitro root certificate you expect ("+attest.NitroRootSHA256+" is the one this build pins)")
	fs.StringVar(&a.GCPImageDigest, "gcp-image-digest", "", "gcp-cs: expected container image digest, sha256:HEX")
	fs.StringVar(&a.GCPAudience, "gcp-audience", "", "gcp-cs: audience of the identity token (the runner's attest_audience, not the STS audience)")
	fs.Var((*listFlag)(&a.GCPHWModels), "gcp-hwmodel", "gcp-cs: accepted hwmodel claim, e.g. GCP_AMD_SEV; repeat it, at least one is required")
	fs.StringVar(&a.GCPIssuer, "gcp-issuer", "", "gcp-cs: token issuer, an https URL (default "+attest.ConfidentialSpaceIssuer+")")
	fs.StringVar(&a.GCPJWKSFile, "gcp-jwks-file", "", "gcp-cs: pinned key set (JWKS file) instead of the issuer's")
	fs.StringVar(&a.GCPServiceAccount, "gcp-service-account", "", "gcp-cs: service account the token must list")
	fs.StringVar(&a.SetupSHA256, "setup-sha256", "", "setup_hash the runner's identity must carry, 64 hex digits (setup-tool prints it); required for a runner with a setup")
	fs.Uint64Var(&a.MinLockedVersion, "min-locked-version", 0, "refuse a runner whose locked config group is in force at a lower version (needs -setup-sha256)")
	fs.Uint64Var(&a.MinOpenVersion, "min-open-version", 0, "refuse a runner whose open config group is in force at a lower version (needs -setup-sha256)")
	fs.BoolVar(&a.Mainnet, "mainnet", false, "the runner signs for Ethereum mainnet: an azure-maa or aws-nitro runner then needs -key-release-sha256")
	fs.StringVar(&a.KeyReleaseSHA256, "key-release-sha256", "", "key_release_hash the runner's identity must carry, 64 hex digits (the hash of the key rule you reviewed; needs -setup-sha256)")
	fs.BoolVar(&a.AllowUnpinnedSetup, "allow-unpinned-setup", false, "tests only, dev verifier only: accept a runner with a setup without -setup-sha256")
	return a
}

// pcrFlag fills Attestation.NitroPCRs from repeated -nitro-pcr INDEX=HEX.
type pcrFlag Attestation

func (p *pcrFlag) String() string {
	if p == nil {
		return ""
	}
	parts := make([]string, 0, len(p.NitroPCRs))
	for _, k := range slices.Sorted(maps.Keys(p.NitroPCRs)) {
		parts = append(parts, k+"="+p.NitroPCRs[k])
	}
	return strings.Join(parts, ",")
}

func (p *pcrFlag) Set(s string) error {
	k, v, ok := strings.Cut(s, "=")
	if !ok || k == "" || v == "" {
		return errors.New("want INDEX=HEX, for example 0=<96 hex digits>")
	}
	if _, dup := p.NitroPCRs[k]; dup {
		return fmt.Errorf("PCR %s given twice", k)
	}
	if p.NitroPCRs == nil {
		p.NitroPCRs = map[string]string{}
	}
	p.NitroPCRs[k] = v
	return nil
}

// listFlag collects a repeated string flag.
type listFlag []string

func (l *listFlag) String() string {
	if l == nil {
		return ""
	}
	return strings.Join(*l, ",")
}

func (l *listFlag) Set(s string) error {
	*l = append(*l, s)
	return nil
}
