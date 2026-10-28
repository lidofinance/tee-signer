//go:build !verifierselect || platform_gcp

package runnerclient

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"

	"github.com/lidofinance/tee-signer/attestation-verify"
	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/remote"
)

// What a Confidential Space runner puts in its attestation
// (runner/platform/gcp).
const (
	gcpPlatform = "gcp"
	gcpFormat   = "gcp-confidential-space-jwt"
	// gcpShieldedVM is the hwmodel of a Confidential Space image that runs on
	// a Shielded VM without memory encryption, so the host could read it.
	gcpShieldedVM = "GCP_SHIELDED_VM"
)

// gcpProjectID is the form of a GCP project ID.
var gcpProjectID = regexp.MustCompile(`^[a-z][a-z0-9-]{4,28}[a-z0-9]$`)

// gcpSettings are the gcp-cs settings in the form the verifier uses.
type gcpSettings struct {
	opts   attest.ConfidentialSpaceOptions
	issuer string
	pinned *attest.KeySet
}

func (a *Attestation) gcp() (gcpSettings, error) {
	var s gcpSettings

	d := strings.ToLower(a.GCPImageDigest)
	if d == "" {
		return s, errors.New("attestation.gcp_image_digest: not set (the expected image digest, sha256:HEX)")
	}
	d = strings.TrimPrefix(d, "sha256:")
	if b, err := hex.DecodeString(d); err != nil || len(b) != 32 {
		return s, errors.New("attestation.gcp_image_digest: want sha256: and 64 hex digits")
	}

	aud := a.GCPAudience
	switch {
	case aud == "":
		return s, errors.New("attestation.gcp_audience: not set (the runner's attest_audience, default signer-runner-identity)")
	case aud == attest.STSAudience:
		return s, fmt.Errorf("attestation.gcp_audience: %q is the STS audience; a token with it is a credential for the KMS key", aud)
	case strings.HasPrefix(aud, "//iam.googleapis.com/") || strings.HasPrefix(aud, "https://iam.googleapis.com/"):
		return s, fmt.Errorf("attestation.gcp_audience: %q names a Workload Identity Federation resource; a token with it is a credential for the KMS key", aud)
	}

	if len(a.GCPHWModels) == 0 {
		return s, errors.New("attestation.gcp_hwmodels: not set (the accepted hwmodel claims, for example GCP_AMD_SEV or GCP_INTEL_TDX)")
	}
	for _, m := range a.GCPHWModels {
		switch {
		case m == "" || strings.TrimSpace(m) != m:
			return s, fmt.Errorf("attestation.gcp_hwmodels: %q is not a hwmodel name", m)
		case strings.EqualFold(m, gcpShieldedVM):
			return s, fmt.Errorf("attestation.gcp_hwmodels: %s is a VM without memory encryption; the host could read the runner", gcpShieldedVM)
		}
	}

	s.issuer = a.GCPIssuer
	if s.issuer == "" {
		s.issuer = attest.ConfidentialSpaceIssuer
	}
	if u, err := url.Parse(s.issuer); err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" ||
		strings.ContainsAny(s.issuer, "?#") {
		return s, fmt.Errorf("attestation.gcp_issuer: %q is not an https URL without a path or a trailing slash", s.issuer)
	}

	if a.GCPServiceAccount != "" && (!strings.Contains(a.GCPServiceAccount, "@") || strings.ContainsAny(a.GCPServiceAccount, " \t\r\n")) {
		return s, fmt.Errorf("attestation.gcp_service_account: %q is not a service account e-mail address", a.GCPServiceAccount)
	}

	if a.GCPProjectID != "" && !gcpProjectID.MatchString(a.GCPProjectID) {
		return s, fmt.Errorf("attestation.gcp_project_id: %q is not a project ID (6 to 30 of a-z, 0-9 and -)", a.GCPProjectID)
	}

	if a.GCPJWKSFile != "" {
		b, err := os.ReadFile(a.GCPJWKSFile)
		if err != nil {
			return s, fmt.Errorf("attestation.gcp_jwks_file: %w", err)
		}
		if s.pinned, err = attest.ParseJWKS(b); err != nil {
			return s, fmt.Errorf("attestation.gcp_jwks_file: %w", err)
		}
	}

	s.opts = attest.ConfidentialSpaceOptions{
		Issuer:         s.issuer,
		Audience:       aud,
		ImageDigests:   []string{"sha256:" + d},
		HWModels:       append([]string(nil), a.GCPHWModels...),
		ServiceAccount: a.GCPServiceAccount,
		ProjectID:      a.GCPProjectID,
	}
	return s, nil
}

// gcpVerifier returns the gcp-cs verifier for the settings.
func (a *Attestation) gcpVerifier(o *options) (remote.VerifyFunc, error) {
	g, err := a.newGCP(o)
	if err != nil {
		return nil, err
	}
	return g.verify, nil
}

// gcpDocumentVerifier returns the gcp-cs document verifier.
func (a *Attestation) gcpDocumentVerifier(o *options) (DocumentVerifier, error) {
	g, err := a.newGCP(o)
	if err != nil {
		return nil, err
	}
	return g.verifyDocument, nil
}

func (a *Attestation) newGCP(o *options) (*gcpVerifier, error) {
	s, err := a.gcp()
	if err != nil {
		return nil, err
	}
	return &gcpVerifier{
		opts: s.opts,
		keys: &keySource{name: "Confidential Space", issuer: s.issuer, http: o.http, pinned: s.pinned},
	}, nil
}

// gcpVerifier checks the Confidential Space token of an IDENTITY response
// against the key set of its issuer.
type gcpVerifier struct {
	opts attest.ConfidentialSpaceOptions
	keys *keySource
}

func (g *gcpVerifier) verify(ctx context.Context, nonce []byte, id *backend.Identity) error {
	// A document that is not a Confidential Space token for this identity and
	// nonce is refused before the client asks the issuer for its keys.
	if err := checkDocument(nonce, id, gcpPlatform, gcpFormat, "a Confidential Space token"); err != nil {
		return err
	}
	return g.keys.verify(ctx, func(ks *attest.KeySet) error {
		o := g.opts
		o.Keys = ks
		// The runner puts hex(user data) in as the token's eat_nonce. The
		// STS audience was refused with the settings (gcp).
		o.Nonces = []string{hex.EncodeToString(id.Attestation.UserData)}
		_, err := attest.VerifyConfidentialSpace(string(id.Attestation.Document), o)
		return err
	})
}

// verifyDocument checks a Confidential Space token whose eat_nonce is
// hex(userData).
func (g *gcpVerifier) verifyDocument(ctx context.Context, _ []byte, userData []byte, a *backend.Attestation) error {
	if err := checkUserData(userData, a, gcpPlatform, gcpFormat, "a Confidential Space token"); err != nil {
		return err
	}
	return g.keys.verify(ctx, func(ks *attest.KeySet) error {
		o := g.opts
		o.Keys = ks
		o.Nonces = []string{hex.EncodeToString(userData)}
		_, err := attest.VerifyConfidentialSpace(string(a.Document), o)
		return err
	})
}

func init() {
	verifierFactories[VerifierGCPCS] = (*Attestation).gcpVerifier
	documentFactories[VerifierGCPCS] = (*Attestation).gcpDocumentVerifier
}
