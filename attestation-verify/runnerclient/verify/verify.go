// Package verify checks a runner's attestation: the settings
// (Attestation), the verifier of each platform for an IDENTITY response
// (NewVerifier) and for a document with user data the caller computed
// (NewDocumentVerifier), and the setup pins. A runner links this package
// to check the other runner of a handover; the tools reach it through
// package runnerclient, which dials the runner and runs the verifier on
// every connection.
package verify

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/lidofinance/tee-signer/attestation-verify/runnerclient/internal/optset"
	"github.com/lidofinance/tee-signer/signer-protocol"
)

// The attestation verifiers.
const (
	// VerifierDev accepts the dev platform's unsigned document. It proves
	// nothing about the code that answered. Use it for local runners only.
	VerifierDev = "dev"
	// VerifierAzureMAA verifies a Microsoft Azure Attestation token.
	VerifierAzureMAA = "azure-maa"
	// VerifierAWSNitro verifies an AWS Nitro Enclaves attestation document.
	VerifierAWSNitro = "aws-nitro"
	// VerifierGCPCS verifies a Google Confidential Space attestation token.
	VerifierGCPCS = "gcp-cs"
)

// verifierList is the "want" part of the errors about the verifier name.
var verifierList = fmt.Sprintf("%q, %q, %q or %q", VerifierDev, VerifierAzureMAA, VerifierAWSNitro, VerifierGCPCS)

// Attestation says how to check a runner's attestation document. The JSON
// names are the ones of the signing client's backend.cloud.config. The settings
// of one verifier are refused on any other verifier, and a required one
// that is missing stops the start.
//
// For azure-maa the signature must come from a key of MAAHost, the token's
// issuer must be that host, and the token must bind this identity and
// nonce. Besides the settings below the verifier always requires
// x-ms-sevsnpvm-is-debuggable false, x-ms-sevsnpvm-vmpl 0 and TEE type
// sevsnpvm. Those checks have no setting.
//
// For aws-nitro the document must chain to the AWS Nitro Enclaves root
// pinned in package attest, carry the expected PCRs, the client's nonce and
// the identity's user data, and not come from a debug-mode enclave. There
// is no setting for debug mode, for accepting other PCRs or for another
// root.
//
// For gcp-cs the token must come from the issuer's key set, carry the
// audience, the expected image digest and a hardware model from the list,
// bind this identity and nonce, and say CONFIDENTIAL_SPACE, secure boot,
// STABLE support and debug status disabled-since-boot. Those last four
// have no setting.
//
// The setup settings (setup_sha256, min_locked_version, min_open_version,
// allow_unpinned_setup) work with every verifier. They check the setup
// state of the verified identity; setup.go has the rules.
type Attestation struct {
	// Verifier is "dev", "azure-maa", "aws-nitro" or "gcp-cs". Required.
	Verifier string `json:"verifier"`

	// SetupSHA256 is the setup_hash the runner's identity must carry, 64
	// hex digits: the setup_sha256 that setup-tool prints for the setup the
	// operator built. Required for a runner that reports a setup. A runner
	// without one (the flag path of tests and local runners, whose
	// setup_hash is the SHA-256 of its -config file) is accepted without
	// it, and refused with it unless that hash is the one pinned.
	SetupSHA256 string `json:"setup_sha256,omitempty"`
	// MinLockedVersion and MinOpenVersion, optional, refuse a runner whose
	// effective version of that config group is lower. The effective
	// version counts a pending update whose effective activation time has
	// passed on this machine's clock. Both need SetupSHA256.
	MinLockedVersion uint64 `json:"min_locked_version,omitempty"`
	MinOpenVersion   uint64 `json:"min_open_version,omitempty"`
	// AllowUnpinnedSetup accepts a runner that reports a setup while
	// SetupSHA256 is not set. For tests only: the dev verifier only, and
	// not together with SetupSHA256.
	AllowUnpinnedSetup bool `json:"allow_unpinned_setup,omitempty"`
	// KeyReleaseSHA256, optional, is the key_release_hash the runner's
	// identity must carry, 64 hex digits: the hash of the rule of the key
	// that releases the runner's sealing key, as the runner read it at
	// start (the Azure release policy, the AWS key policy). Pin the hash of
	// a rule you reviewed; a runner whose rule changed, or that read none,
	// is refused. GCP has no rule to read (zero hash), so a GCP runner
	// cannot be pinned this way. Needs SetupSHA256.
	KeyReleaseSHA256 string `json:"key_release_sha256,omitempty"`
	// Mainnet says the runner signs for Ethereum mainnet. An azure-maa or
	// aws-nitro runner on mainnet is then reached only with
	// KeyReleaseSHA256 set; gcp-cs never
	// needs it. The runner's identity does not name its chain, so the
	// client's settings must.
	Mainnet bool `json:"mainnet,omitempty"`

	// MAAHost is the attestation provider (the token issuer is
	// "https://" + MAAHost), for example sharedweu.weu.attest.azure.net.
	// azure-maa only, required.
	MAAHost string `json:"maa_host,omitempty"`
	// CCEPolicySHA256 is the expected x-ms-sevsnpvm-hostdata claim: the
	// SHA-256 of the runner's CCE policy, 64 hex digits (deploy.sh policy
	// prints it). It pins the container images and the runner's command
	// line. azure-maa only, required.
	CCEPolicySHA256 string `json:"cce_policy_sha256,omitempty"`
	// ComplianceStatus is the expected x-ms-compliance-status:
	// "azure-compliant-uvm" (default, confidential containers on ACI) or
	// "azure-compliant-cvm". azure-maa only.
	ComplianceStatus string `json:"compliance_status,omitempty"`

	// NitroPCRs maps a PCR index ("0" to "31", plain decimal) to the value
	// the document must hold, 96 hex digits (SHA-384). PCR0, PCR1 and PCR2
	// (image, kernel and ramdisk, application) are required and may not be
	// all zero, the value of a debug-mode enclave. Add PCR3 (the parent's
	// IAM role) or PCR8 (the EIF signing certificate) to pin them as well.
	// scripts/nitro-eif.sh prints PCR0 to PCR2 of an image. aws-nitro only,
	// required.
	NitroPCRs map[string]string `json:"nitro_pcrs,omitempty"`
	// NitroRootSHA256 is the SHA-256 of the AWS Nitro Enclaves root
	// certificate (DER) the operator expects, 64 hex digits. Optional. The
	// verifier carries one root, AWS's root G1 (attest.NitroRootSHA256), and
	// refuses to start if this value is another. aws-nitro only.
	NitroRootSHA256 string `json:"nitro_root_sha256,omitempty"`

	// GCPImageDigest is the expected submods.container.image_digest of the
	// runner image, "sha256:" and 64 hex digits (the "sha256:" is optional
	// here). gcp-cs only, required.
	GCPImageDigest string `json:"gcp_image_digest,omitempty"`
	// GCPAudience is the audience the identity token carries, the runner's
	// attest_audience (default signer-runner-identity). Never the STS
	// audience or a Workload Identity Federation name: a token with one of
	// those is a credential for the KMS key. gcp-cs only, required.
	GCPAudience string `json:"gcp_audience,omitempty"`
	// GCPHWModels lists the accepted hwmodel claims, for example
	// "GCP_AMD_SEV", "GCP_AMD_SEV_ES" or "GCP_INTEL_TDX". GCP_SHIELDED_VM,
	// a VM without memory encryption, is refused. gcp-cs only, required.
	//
	// In the three-cloud layout (Azure on AMD SEV-SNP, AWS Nitro, GCP) list
	// GCP_INTEL_TDX only, so one chip family never holds two shares: a flaw
	// in one chip family then reaches one share, not two.
	GCPHWModels []string `json:"gcp_hwmodels,omitempty"`
	// GCPIssuer is the token issuer, an https URL without path. Default
	// https://confidentialcomputing.googleapis.com. The key set comes from
	// its .well-known/openid-configuration unless GCPJWKSFile is set.
	// gcp-cs only.
	GCPIssuer string `json:"gcp_issuer,omitempty"`
	// GCPJWKSFile is a pinned key set (JWKS file) to use instead of the
	// issuer's. It does not follow Google's key rotation. gcp-cs only.
	GCPJWKSFile string `json:"gcp_jwks_file,omitempty"`
	// GCPServiceAccount, if set, must be one of the token's
	// google_service_accounts. gcp-cs only.
	GCPServiceAccount string `json:"gcp_service_account,omitempty"`
	// GCPProjectID, if set, must equal the token's submods.gce.project_id,
	// the project the runner's VM runs in. gcp-cs only.
	GCPProjectID string `json:"gcp_project_id,omitempty"`
}

// Option changes how a verifier is built.
type Option = optset.Option

// WithHTTPClient sets the HTTP client that fetches the MAA or Confidential
// Space key set (default: a client with a 15 s timeout and the system
// roots).
func WithHTTPClient(c *http.Client) Option { return func(o *optset.Options) { o.HTTP = c } }

// VerifyFunc checks an identity's attestation document. It is the type of
// signer-protocol/remote.VerifyFunc, so a VerifyFunc goes to the remote
// client as it is, and this package does not link the client.
type VerifyFunc = func(ctx context.Context, nonce []byte, id *backend.Identity) error

// foreign refuses the settings that belong to another verifier than the
// one named, so a configuration written for one platform cannot be run
// against another and leave a check out unnoticed.
func (a *Attestation) foreign() error {
	groups := []struct {
		verifier string
		names    string
		set      bool
	}{
		{VerifierAzureMAA, "maa_host, cce_policy_sha256 and compliance_status",
			a.MAAHost != "" || a.CCEPolicySHA256 != "" || a.ComplianceStatus != ""},
		{VerifierAWSNitro, "nitro_pcrs and nitro_root_sha256",
			len(a.NitroPCRs) > 0 || a.NitroRootSHA256 != ""},
		{VerifierGCPCS, "gcp_image_digest, gcp_audience, gcp_hwmodels, gcp_issuer, gcp_jwks_file, gcp_service_account and gcp_project_id",
			a.GCPImageDigest != "" || a.GCPAudience != "" || len(a.GCPHWModels) > 0 || a.GCPIssuer != "" ||
				a.GCPJWKSFile != "" || a.GCPServiceAccount != "" || a.GCPProjectID != ""},
	}
	for _, g := range groups {
		if g.set && g.verifier != a.Verifier {
			return fmt.Errorf("attestation: %s belong to the verifier %q, not %q", g.names, g.verifier, a.Verifier)
		}
	}
	return nil
}

// Validate checks the attestation settings.
func (a *Attestation) Validate() error {
	_, err := a.verifier(optset.New(nil))
	return err
}

// NewVerifier returns the verifier the settings name. A tool that checks an
// identity itself (share-import) uses it.
func (a *Attestation) NewVerifier(opts ...Option) (VerifyFunc, error) {
	return a.verifier(optset.New(opts))
}

// VerifierWith is NewVerifier with the options already applied
// (optset.New). Package runnerclient builds them once per client and
// passes the same set here.
func (a *Attestation) VerifierWith(o *optset.Options) (VerifyFunc, error) {
	return a.verifier(o)
}

func (a *Attestation) verifier(o *optset.Options) (VerifyFunc, error) {
	switch a.Verifier {
	case "":
		return nil, fmt.Errorf("attestation.verifier: not set, want %s", verifierList)
	case VerifierDev, VerifierAzureMAA, VerifierAWSNitro, VerifierGCPCS:
	default:
		return nil, fmt.Errorf("attestation.verifier: unknown verifier %q, want %s", a.Verifier, verifierList)
	}
	if err := a.foreign(); err != nil {
		return nil, err
	}
	f, ok := verifierFactories[a.Verifier]
	if !ok {
		return nil, fmt.Errorf("attestation.verifier: %q is not built into this program (build tag %s)", a.Verifier, peerTags[a.Verifier])
	}
	v, err := f(a, o)
	if err != nil {
		return nil, err
	}
	pins, err := a.setupPins()
	if err != nil {
		return nil, err
	}
	return pins.after(v, o.Now), nil
}

// verifierFactories holds the verifiers built into this program. Each
// verifier's file adds its own. A runner built with the tag verifierselect
// has only those its platform_* tags name (the handover checks the other
// image with its own platform's verifier); every other program has all four.
var verifierFactories = map[string]func(a *Attestation, o *optset.Options) (VerifyFunc, error){}

// peerTags names the build tag of each verifier, for the error above.
var peerTags = map[string]string{
	VerifierDev: "platform_dev", VerifierAzureMAA: "platform_azure", VerifierAWSNitro: "platform_aws", VerifierGCPCS: "platform_gcp",
}

// Available reports whether the verifier is built into this program.
func Available(verifier string) bool {
	_, ok := verifierFactories[verifier]
	return ok
}

// checkDocument makes the checks that need no key set or root: id carries a
// document of this platform and format, and its user data is what
// backend.IdentityUserData gives for the identity fields and nonce. A
// verifier calls it first, so a document of another platform is refused
// before the client fetches any key.
func checkDocument(nonce []byte, id *backend.Identity, platform, format, what string) error {
	if id == nil || id.Attestation == nil {
		return errors.New("runnerclient: no attestation")
	}
	a := id.Attestation
	if a.Platform != platform || a.Format != format {
		return fmt.Errorf("runnerclient: platform %q format %q is not %s", a.Platform, a.Format, what)
	}
	if !bytes.Equal(a.UserData, backend.IdentityUserData(nonce, id)) {
		return errors.New("runnerclient: attestation user data does not match the identity fields and nonce")
	}
	return nil
}
