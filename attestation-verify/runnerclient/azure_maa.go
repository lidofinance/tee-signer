//go:build !verifierselect || platform_azure

package runnerclient

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/lidofinance/tee-signer/attestation-verify"
	"github.com/lidofinance/tee-signer/attestation-verify/azureid"
	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/remote"
)

func init() {
	verifierFactories[VerifierAzureMAA] = func(a *Attestation, o *options) (remote.VerifyFunc, error) {
		m, err := a.newMAA(o)
		if err != nil {
			return nil, err
		}
		return m.verify, nil
	}
	documentFactories[VerifierAzureMAA] = func(a *Attestation, o *options) (DocumentVerifier, error) {
		m, err := a.newMAA(o)
		if err != nil {
			return nil, err
		}
		return m.verifyDocument, nil
	}
}

func (a *Attestation) newMAA(o *options) (*maaVerifier, error) {
	s, err := a.maa()
	if err != nil {
		return nil, err
	}
	return &maaVerifier{
		opts: attest.MAAOptions{Issuer: s.issuer, ComplianceStatus: s.compliance, HostData: []string{s.hostData}},
		keys: &keySource{name: "MAA", issuer: s.issuer, http: o.http},
	}, nil
}

var hostRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]*[a-z0-9])?(:[0-9]{1,5})?$`)

type maaSettings struct{ issuer, hostData, compliance string }

func (a *Attestation) maa() (maaSettings, error) {
	var s maaSettings
	host := strings.ToLower(a.MAAHost)
	switch {
	case host == "":
		return s, errors.New("attestation.maa_host: not set (the attestation provider, e.g. sharedweu.weu.attest.azure.net)")
	case !hostRE.MatchString(host):
		return s, fmt.Errorf("attestation.maa_host: %q is not a host name (no scheme, no path)", a.MAAHost)
	}
	s.issuer = "https://" + host
	h := strings.ToLower(a.CCEPolicySHA256)
	if h == "" {
		return s, errors.New("attestation.cce_policy_sha256: not set (the expected x-ms-sevsnpvm-hostdata, the SHA-256 of the CCE policy)")
	}
	if b, err := hex.DecodeString(h); err != nil || len(b) != 32 {
		return s, errors.New("attestation.cce_policy_sha256: want 64 hex digits")
	}
	s.hostData = h
	switch s.compliance = a.ComplianceStatus; s.compliance {
	case "":
		s.compliance = attest.ComplianceACI
	case attest.ComplianceACI, attest.ComplianceCVM:
	default:
		return s, fmt.Errorf("attestation.compliance_status: %q, want %q or %q", a.ComplianceStatus, attest.ComplianceACI, attest.ComplianceCVM)
	}
	return s, nil
}

// maaVerifier checks the MAA token of an IDENTITY response against the key
// set of one attestation provider.
type maaVerifier struct {
	opts attest.MAAOptions
	keys *keySource
}

func (m *maaVerifier) verify(ctx context.Context, nonce []byte, id *backend.Identity) error {
	// A document that is not an Azure token for this identity and nonce is
	// refused before the client asks the provider for its keys.
	if err := azureid.Check(nonce, id); err != nil {
		return err
	}
	return m.keys.verify(ctx, func(ks *attest.KeySet) error {
		o := m.opts
		o.Keys = ks
		_, err := azureid.Verify(nonce, id, o)
		return err
	})
}

// verifyDocument checks an MAA token that binds userData: the runtime data
// MAA hashed into the SNP report is backend.MAARuntimeData(userData), as
// for an identity.
func (m *maaVerifier) verifyDocument(ctx context.Context, _ []byte, userData []byte, a *backend.Attestation) error {
	if err := checkUserData(userData, a, azureid.Platform, azureid.Format, "an Azure MAA token"); err != nil {
		return err
	}
	return m.keys.verify(ctx, func(ks *attest.KeySet) error {
		o := m.opts
		o.Keys = ks
		o.RuntimeData = backend.MAARuntimeData(userData)
		_, err := attest.VerifyMAA(string(a.Document), o)
		return err
	})
}
