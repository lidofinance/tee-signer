//go:build !peerselect || peer_gcp

package attest

import (
	"fmt"
	"time"
)

// Confidential Space token constants. Sources: the OIDC discovery document
// at https://confidentialcomputing.googleapis.com/.well-known/openid-configuration
// (copy in testdata/jwks/) and the token claims
// reference at
// https://docs.cloud.google.com/confidential-computing/confidential-space/docs/reference/token-claims.
const (
	ConfidentialSpaceIssuer  = "https://confidentialcomputing.googleapis.com"
	ConfidentialSpaceJWKSURL = "https://www.googleapis.com/service_accounts/v1/metadata/jwk/signer@confidentialspace-sign.iam.gserviceaccount.com"
	// STSAudience is the audience of tokens meant for workload identity
	// federation. A token with it is a credential for the KMS key behind
	// the WIF provider, so identity checks refuse it (see identity package).
	STSAudience = "https://sts.googleapis.com"

	csSWName         = "CONFIDENTIAL_SPACE"
	csDbgDisabled    = "disabled-since-boot"
	csDbgEnabled     = "enabled"
	csDefaultSupport = "STABLE"
)

// ConfidentialSpaceOptions configures VerifyConfidentialSpace.
type ConfidentialSpaceOptions struct {
	// Issuer is the token issuer. Empty means ConfidentialSpaceIssuer.
	Issuer string
	// Keys are the issuer's signing keys (pinned, or DiscoverJWKS).
	Keys *KeySet
	// Audience the token must carry. Required.
	Audience string
	// Now is the verification time; zero means time.Now().
	Now time.Time
	// Skew is the allowed clock difference; zero means DefaultSkew.
	Skew time.Duration
	// MaxAge, if positive, bounds the age of iat.
	MaxAge time.Duration
	// ImageDigests lists the accepted submods.container.image_digest
	// values ("sha256:..."). Required unless AcceptAnyImage is set.
	ImageDigests   []string
	AcceptAnyImage bool
	// SupportAttributes must all appear in
	// submods.confidential_space.support_attributes. nil means ["STABLE"]
	// (or none with AllowDebug, since debug images carry none).
	SupportAttributes []string
	// Nonces must all appear in eat_nonce. Either Nonces or MaxAge must
	// be set.
	Nonces []string
	// HWModels, if set, lists the accepted hwmodel values.
	HWModels []string
	// ServiceAccount, if set, must appear in google_service_accounts.
	ServiceAccount string
	// ProjectID, if set, must equal submods.gce.project_id: the GCP project
	// the VM runs in, which ties the token to an account.
	ProjectID string
	// AllowDebug accepts dbgstat "enabled". Never set it in production.
	AllowDebug bool
}

// ConfidentialSpaceToken is a verified Confidential Space token.
type ConfidentialSpaceToken struct {
	Claims            Claims
	Times             TokenTimes
	Subject           string
	Audience          []string
	Nonces            []string
	SWName            string
	SWVersion         []string
	HWModel           string
	DbgStat           string
	SupportAttributes []string
	ImageDigest       string
	ImageReference    string
	ServiceAccounts   []string
	ProjectID, Zone   string
	InstanceID        string
	InstanceName      string
}

// VerifyConfidentialSpace verifies a Confidential Space attestation token
// (OIDC type, RS256) and the claims that bind the workload.
func VerifyConfidentialSpace(token string, o ConfidentialSpaceOptions) (*ConfidentialSpaceToken, error) {
	switch {
	case o.Keys == nil:
		return nil, fmt.Errorf("%w: no key set", ErrConfig)
	case o.Audience == "":
		return nil, fmt.Errorf("%w: no audience", ErrConfig)
	case len(o.ImageDigests) == 0 && !o.AcceptAnyImage:
		return nil, fmt.Errorf("%w: no expected image digest", ErrConfig)
	case len(o.Nonces) == 0 && o.MaxAge <= 0:
		return nil, fmt.Errorf("%w: set Nonces or MaxAge", ErrConfig)
	}
	issuer := o.Issuer
	if issuer == "" {
		issuer = ConfidentialSpaceIssuer
	}
	c, err := verifyJWT(token, o.Keys)
	if err != nil {
		return nil, err
	}
	tt, err := checkStandard(c, issuer, o.Audience, nowOr(o.Now), skewOr(o.Skew), o.MaxAge)
	if err != nil {
		return nil, err
	}
	t := &ConfidentialSpaceToken{Claims: c, Times: tt}
	t.Subject, _ = c.str("sub")
	t.Audience, _ = c.strList("aud")
	t.Nonces, _ = c.strList("eat_nonce")
	t.SWName, _ = c.str("swname")
	t.SWVersion, _ = c.strList("swversion")
	t.HWModel, _ = c.str("hwmodel")
	t.DbgStat, _ = c.str("dbgstat")
	t.SupportAttributes, _ = c.strList("submods.confidential_space.support_attributes")
	t.ImageDigest, _ = c.str("submods.container.image_digest")
	t.ImageReference, _ = c.str("submods.container.image_reference")
	t.ServiceAccounts, _ = c.strList("google_service_accounts")
	t.ProjectID, _ = c.str("submods.gce.project_id")
	t.Zone, _ = c.str("submods.gce.zone")
	t.InstanceID, _ = c.str("submods.gce.instance_id")
	t.InstanceName, _ = c.str("submods.gce.instance_name")

	if t.SWName != csSWName {
		return nil, fmt.Errorf("%w: swname %q, want %q", ErrClaim, t.SWName, csSWName)
	}
	switch t.DbgStat {
	case csDbgDisabled:
	case csDbgEnabled:
		if !o.AllowDebug {
			return nil, fmt.Errorf("%w: dbgstat %q (debug image)", ErrDebug, t.DbgStat)
		}
	default:
		return nil, fmt.Errorf("%w: dbgstat %q, want %q", ErrDebug, t.DbgStat, csDbgDisabled)
	}
	if sb, ok := c.boolean("secboot"); !ok || !sb {
		return nil, fmt.Errorf("%w: secboot is not true", ErrClaim)
	}
	want := o.SupportAttributes
	if want == nil && !o.AllowDebug {
		want = []string{csDefaultSupport}
	}
	for _, a := range want {
		if !contains(t.SupportAttributes, a) {
			return nil, fmt.Errorf("%w: support_attributes %v lack %q", ErrClaim, t.SupportAttributes, a)
		}
	}
	if len(o.HWModels) > 0 && !contains(o.HWModels, t.HWModel) {
		return nil, fmt.Errorf("%w: hwmodel %q not in %v", ErrClaim, t.HWModel, o.HWModels)
	}
	if !o.AcceptAnyImage && !contains(o.ImageDigests, t.ImageDigest) {
		return nil, fmt.Errorf("%w: image_digest %q not in %v", ErrMeasurement, t.ImageDigest, o.ImageDigests)
	}
	if o.ServiceAccount != "" && !contains(t.ServiceAccounts, o.ServiceAccount) {
		return nil, fmt.Errorf("%w: google_service_accounts %v lack %q", ErrClaim, t.ServiceAccounts, o.ServiceAccount)
	}
	if o.ProjectID != "" && t.ProjectID != o.ProjectID {
		return nil, fmt.Errorf("%w: submods.gce.project_id %q, want %q", ErrClaim, t.ProjectID, o.ProjectID)
	}
	for _, n := range o.Nonces {
		if !contains(t.Nonces, n) {
			return nil, fmt.Errorf("%w: eat_nonce %v lacks %q", ErrNonce, t.Nonces, n)
		}
	}
	return t, nil
}
