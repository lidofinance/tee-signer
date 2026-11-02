//go:build !verifierselect

package verify

import (
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/lidofinance/tee-signer/attestation-verify"
	"github.com/lidofinance/tee-signer/governance/handoverorder"
)

// OrderRunner is the handover order entry of a runner with these settings
// and setup_hash: the reverse of RunnerAttestation. It fills in the
// defaults the verifier would use (compliance status, issuer) and refuses
// what an order cannot carry: a pinned key set file, another Nitro root,
// PCRs besides 0 to 3 and 8, the test switch allow_unpinned_setup. The
// minimum versions stay with the verifier's own settings; an order pins
// the setup only.
func (a *Attestation) OrderRunner(name string, setupHash [32]byte) (handoverorder.Runner, error) {
	p := handoverorder.Runner{Name: name, SetupHash: setupHash}
	if err := a.foreign(); err != nil {
		return p, err
	}
	hexN := func(what, s string, n int) ([]byte, error) {
		b, err := hex.DecodeString(strings.TrimPrefix(strings.ToLower(s), "0x"))
		if err != nil || len(b) != n {
			return nil, fmt.Errorf("attestation.%s: want %d hex digits", what, 2*n)
		}
		return b, nil
	}
	switch {
	case a.AllowUnpinnedSetup:
		return p, errors.New("attestation.allow_unpinned_setup: a handover order always pins the setup")
	case a.GCPJWKSFile != "":
		return p, errors.New("attestation.gcp_jwks_file: a key set file on the operator's disk cannot go into a handover order")
	case a.NitroRootSHA256 != "" && !strings.EqualFold(a.NitroRootSHA256, attest.NitroRootSHA256):
		return p, errors.New("attestation.nitro_root_sha256: a handover order checks AWS's root only")
	}
	switch a.Verifier {
	case VerifierAWSNitro:
		p.Verifier = handoverorder.VerifierNitro
		for k := range a.NitroPCRs {
			if !slices.Contains([]string{"0", "1", "2", "3", "8"}, k) {
				return p, fmt.Errorf("attestation.nitro_pcrs: PCR%s cannot go into a handover order (PCR0 to PCR3 and PCR8 can)", k)
			}
		}
		for i := range 3 {
			b, err := hexN(fmt.Sprintf("nitro_pcrs[%d]", i), a.NitroPCRs[fmt.Sprint(i)], 48)
			if err != nil {
				return p, err
			}
			p.Image = append(p.Image, b...)
		}
		b, err := hexN("nitro_pcrs[3]", a.NitroPCRs["3"], 48)
		if err != nil {
			return p, fmt.Errorf("%w (PCR3, the parent instance's IAM role, binds the position to the operator's account)", err)
		}
		p.NitroPCR3 = [48]byte(b)
		if v, ok := a.NitroPCRs["8"]; ok {
			b, err := hexN("nitro_pcrs[8]", v, 48)
			if err != nil {
				return p, err
			}
			pcr8 := [48]byte(b)
			p.NitroPCR8 = &pcr8
		}
	case VerifierAzureMAA:
		p.Verifier = handoverorder.VerifierAzure
		s, err := a.maa()
		if err != nil {
			return p, err
		}
		if p.Image, err = hexN("cce_policy_sha256", s.hostData, 32); err != nil {
			return p, err
		}
		p.MAAHost = strings.TrimPrefix(s.issuer, "https://")
		if p.Compliance, err = handoverorder.ParseCompliance(s.compliance); err != nil {
			return p, err
		}
	case VerifierGCPCS:
		p.Verifier = handoverorder.VerifierGCP
		var err error
		if p.Image, err = hexN("gcp_image_digest", strings.TrimPrefix(strings.ToLower(a.GCPImageDigest), "sha256:"), 32); err != nil {
			return p, err
		}
		if a.GCPServiceAccount == "" || a.GCPProjectID == "" {
			return p, errors.New("attestation: gcp-cs in a handover order needs gcp_project_id and gcp_service_account, so the position is bound to the operator's project")
		}
		p.GCPAudience, p.GCPServiceAccount, p.GCPProjectID = a.GCPAudience, a.GCPServiceAccount, a.GCPProjectID
		p.GCPHWModels = slices.Sorted(slices.Values(a.GCPHWModels))
		p.GCPIssuer = a.GCPIssuer
		if p.GCPIssuer == "" {
			p.GCPIssuer = attest.ConfidentialSpaceIssuer
		}
	case VerifierDev:
		p.Verifier = handoverorder.VerifierDev
	default:
		return p, fmt.Errorf("attestation.verifier: %q, want %s", a.Verifier, verifierList)
	}
	return p, nil
}
