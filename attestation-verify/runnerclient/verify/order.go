package verify

import (
	"encoding/hex"
	"net/url"
	"slices"
	"strings"

	"github.com/lidofinance/tee-signer/governance/handoverorder"
)

// Handover orders (governance/handoverorder) carry each runner's attestation
// settings in a fixed binary form. These two functions turn one into the
// other: RunnerAttestation for the runner, which checks the other runner
// with the verifier the order names; OrderRunner (order_draft.go, not in a
// runner build) for signer-admin, which drafts an order from each signer's
// cloud.json.

// RunnerAttestation is the attestation settings of a handover order's
// runner, with its setup_hash pinned.
func RunnerAttestation(p *handoverorder.Runner) Attestation {
	a := Attestation{Verifier: p.Verifier.String(), SetupSHA256: hex.EncodeToString(p.SetupHash[:])}
	switch p.Verifier {
	case handoverorder.VerifierNitro:
		a.NitroPCRs = map[string]string{
			"0": hex.EncodeToString(p.Image[:48]), "1": hex.EncodeToString(p.Image[48:96]),
			"2": hex.EncodeToString(p.Image[96:144]), "3": hex.EncodeToString(p.NitroPCR3[:]),
		}
		if p.NitroPCR8 != nil {
			a.NitroPCRs["8"] = hex.EncodeToString(p.NitroPCR8[:])
		}
	case handoverorder.VerifierAzure:
		a.MAAHost = p.MAAHost
		a.CCEPolicySHA256 = hex.EncodeToString(p.Image)
		a.ComplianceStatus = p.Compliance.String()
	case handoverorder.VerifierGCP:
		a.GCPImageDigest = "sha256:" + hex.EncodeToString(p.Image)
		a.GCPAudience = p.GCPAudience
		a.GCPHWModels = slices.Clone(p.GCPHWModels)
		a.GCPIssuer = p.GCPIssuer
		a.GCPServiceAccount = p.GCPServiceAccount
		a.GCPProjectID = p.GCPProjectID
	}
	return a
}

// Google's Confidential Space token issuer and the host of its key set
// (attest.ConfidentialSpaceIssuer and ConfidentialSpaceJWKSURL, which a
// build without platform_gcp lacks; a test keeps the two in step).
const (
	csIssuerEndpoint = "confidentialcomputing.googleapis.com:443"
	csJWKSEndpoint   = "www.googleapis.com:443"
)

// Endpoints are the host:port names that the verifier fetches from over
// HTTPS before it can check a runner, sorted: for azure-maa the MAA host
// (its openid-configuration and its key set at /certs); for gcp-cs the
// issuer and, for Google's own issuer, the host of its key set. aws-nitro
// and dev fetch nothing (the Nitro root is in the binary), and neither
// does gcp-cs with a key set file. Another gcp-cs issuer names its key set
// host only in its openid-configuration, so the list holds its issuer
// alone. A runner whose egress is limited (a Nitro enclave) must reach
// these for every runner it checks.
func (a *Attestation) Endpoints() []string {
	var out []string
	switch a.Verifier {
	case VerifierAzureMAA:
		if a.MAAHost != "" {
			out = append(out, withPort(strings.ToLower(a.MAAHost)))
		}
	case VerifierGCPCS:
		if a.GCPJWKSFile != "" {
			return nil
		}
		if a.GCPIssuer == "" {
			return []string{csIssuerEndpoint, csJWKSEndpoint}
		}
		if u, err := url.Parse(a.GCPIssuer); err == nil && u.Host != "" {
			out = append(out, withPort(strings.ToLower(u.Host)))
			if out[0] == csIssuerEndpoint {
				out = append(out, csJWKSEndpoint)
			}
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// withPort adds the https port to a host without one.
func withPort(host string) string {
	if strings.Contains(host, ":") {
		return host
	}
	return host + ":443"
}
