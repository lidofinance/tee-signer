package azure

// What MAA needs next to the SNP report: the VCEK certificate chain that
// vouches for the report's signing key, and the endorsements of the utility
// VM (UVM) image, which are what lets MAA say azure-compliant-uvm.
//
// Where they come from inside a confidential ACI group (sources: the
// sidecar's pkg/common/info.go and pkg/attest/platform_cert_fetcher.go, and
// hcsshim's pkg/securitypolicy/securitypolicy_options.go, which writes the
// directory):
//
//   - hcsshim creates a directory "/security-context-XXXX" in each workload
//     container and sets UVM_SECURITY_CONTEXT_DIR to it (when the group has
//     a CCE policy). It holds
//     reference-info-base64  the UVM reference info (a COSE_Sign1 document), base64
//     host-amd-cert-base64   base64 of a JSON object {vcekCert, tcbm,
//     certificateChain, cacheControl}: the VCEK certificate of
//     this host as PEM, the TCB version it is for as hex, and the
//     ASK and ARK as PEM
//     security-policy-base64 the CCE policy, base64 (the runner does not need it)
//   - Without the files, the sidecar falls back to the variables
//     UVM_REFERENCE_INFO and UVM_HOST_AMD_CERTIFICATE, and for the
//     certificates to the host's metadata endpoint (THIM).
//
// Microsoft's page on custom SKR clients says these certificates are
// "delivered from Azure host IMDS endpoint".
//
// UNVERIFIED on Azure: the file contents and the metadata endpoint come
// from source code, not from a running group.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	envSecurityContextDir = "UVM_SECURITY_CONTEXT_DIR"
	envReferenceInfo      = "UVM_REFERENCE_INFO"
	envHostAMDCert        = "UVM_HOST_AMD_CERTIFICATE"

	fileReferenceInfo = "reference-info-base64"
	fileHostAMDCert   = "host-amd-cert-base64"

	// thimURL is the host's certificate endpoint (sidecar
	// pkg/attest/platform_cert_fetcher.go, defaultLocalThimURI).
	thimURL = "http://169.254.169.254/metadata/THIM/amd/certification"
)

// Collateral is the evidence next to the report.
type Collateral struct {
	CertChain        []byte // PEM: VCEK certificate, then ASK and ARK
	UVMReferenceInfo []byte // COSE_Sign1 endorsements of the UVM image
}

// CollateralSource finds the collateral for a report. reportedTCB is the
// TCB version the report states; the VCEK certificate must be for it.
type CollateralSource interface {
	Collateral(ctx context.Context, reportedTCB uint64) (*Collateral, error)
}

// thimCerts is the JSON the host hands to the UVM (sidecar
// pkg/common/info.go, THIMCerts).
type thimCerts struct {
	VCEKCert         string `json:"vcekCert"`
	TCBM             string `json:"tcbm"`
	CertificateChain string `json:"certificateChain"`
	CacheControl     string `json:"cacheControl"`
}

// HostCollateral reads the collateral the way the sidecar does.
type HostCollateral struct {
	// Getenv returns an environment variable. nil means os.Getenv.
	Getenv func(string) string
	// Root is the directory scanned for security-context-* when
	// UVM_SECURITY_CONTEXT_DIR is not set. Empty means "/".
	Root string
	// THIMURL is the host certificate endpoint. Empty means thimURL.
	THIMURL string
	HTTP    *http.Client
}

func (h *HostCollateral) getenv(k string) string {
	if h.Getenv != nil {
		return h.Getenv(k)
	}
	return os.Getenv(k)
}

// contextDir is UVM_SECURITY_CONTEXT_DIR, else the first entry of Root
// whose name contains "security-context-", else "".
func (h *HostCollateral) contextDir() string {
	if d := h.getenv(envSecurityContextDir); d != "" {
		return d
	}
	root := h.Root
	if root == "" {
		root = "/"
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return ""
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), "security-context-") {
			return filepath.Join(root, e.Name())
		}
	}
	return ""
}

// value is the trimmed content of dir/name, else the variable env.
func (h *HostCollateral) value(dir, name, env string) string {
	if dir != "" {
		if b, err := os.ReadFile(filepath.Join(dir, name)); err == nil {
			if s := strings.TrimSpace(string(b)); s != "" {
				return s
			}
		}
	}
	return strings.TrimSpace(h.getenv(env))
}

func (h *HostCollateral) Collateral(ctx context.Context, reportedTCB uint64) (*Collateral, error) {
	dir := h.contextDir()
	refB64 := h.value(dir, fileReferenceInfo, envReferenceInfo)
	certB64 := h.value(dir, fileHostAMDCert, envHostAMDCert)

	col := &Collateral{}
	if refB64 != "" {
		ref, err := decodeBase64(refB64)
		if err != nil {
			return nil, fmt.Errorf("azure: UVM reference info is not base64: %w", err)
		}
		col.UVMReferenceInfo = ref
	}
	if len(col.UVMReferenceInfo) == 0 {
		// MAA reports azure-compliant-uvm only for a UVM it can match to an
		// endorsement, and the release policy asks for that claim, so a
		// missing endorsement is a failure here, not later.
		return nil, fmt.Errorf("azure: no UVM reference info (%s in %q, or $%s): MAA cannot report azure-compliant-uvm",
			fileReferenceInfo, dir, envReferenceInfo)
	}

	var certs *thimCerts
	if certB64 != "" {
		raw, err := decodeBase64(certB64)
		if err != nil {
			return nil, fmt.Errorf("azure: host AMD certificate is not base64: %w", err)
		}
		certs, err = parseTHIM(raw)
		if err != nil {
			return nil, fmt.Errorf("azure: host AMD certificate: %w", err)
		}
	}
	// A certificate for another TCB version than the report states would
	// fail at MAA. The sidecar fetches a fresh one then; so do we.
	if certs == nil || !tcbMatches(certs, reportedTCB) {
		fresh, err := h.fetchTHIM(ctx)
		if err != nil {
			if certs == nil {
				return nil, fmt.Errorf("azure: no host AMD certificate in %q, and the host endpoint failed: %w", dir, err)
			}
			return nil, fmt.Errorf("azure: the host AMD certificate is for another TCB version than the report (%s, report %016x), and the host endpoint failed: %w",
				certs.TCBM, reportedTCB, err)
		}
		certs = fresh
	}
	if !tcbMatches(certs, reportedTCB) {
		return nil, fmt.Errorf("azure: the host AMD certificate is for TCB version %s, the report states %016x", certs.TCBM, reportedTCB)
	}
	col.CertChain = []byte(joinPEM(certs.VCEKCert, certs.CertificateChain))
	return col, nil
}

func parseTHIM(raw []byte) (*thimCerts, error) {
	var c thimCerts
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, err
	}
	if strings.TrimSpace(c.VCEKCert) == "" || strings.TrimSpace(c.CertificateChain) == "" || c.TCBM == "" {
		return nil, errors.New("vcekCert, certificateChain or tcbm is missing")
	}
	return &c, nil
}

// tcbMatches compares the certificate's TCB version (hex) with the report's.
func tcbMatches(c *thimCerts, reportedTCB uint64) bool {
	v, err := strconv.ParseUint(strings.TrimSpace(c.TCBM), 16, 64)
	return err == nil && v == reportedTCB
}

func (h *HostCollateral) fetchTHIM(ctx context.Context) (*thimCerts, error) {
	u := h.THIMURL
	if u == "" {
		u = thimURL
	}
	b, err := httpGetWithRetry(ctx, h.HTTP, u, map[string]string{"Metadata": "true"}, nil)
	if err != nil {
		return nil, err
	}
	return parseTHIM(b)
}

// joinPEM puts the VCEK certificate and the chain together. The sidecar
// concatenates the two strings; this does the same and adds a newline if
// the first does not end with one.
func joinPEM(vcek, chain string) string {
	if !strings.HasSuffix(vcek, "\n") {
		vcek += "\n"
	}
	return vcek + chain
}

// decodeBase64 accepts standard or URL-safe base64, padded or not.
func decodeBase64(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	var firstErr error
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.RawURLEncoding} {
		b, err := enc.DecodeString(s)
		if err == nil {
			return b, nil
		}
		if firstErr == nil {
			firstErr = err
		}
	}
	return nil, firstErr
}
