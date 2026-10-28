package handoverorder

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/lidofinance/tee-signer/governance/setupwire"
)

// MaxGCPHWModels bounds the accepted hwmodel claims of a gcp-cs runner.
const MaxGCPHWModels = 4

// Verifier names the attestation check of a runner, with the names of
// attestation-verify/runnerclient.
type Verifier uint8

const (
	VerifierNitro Verifier = 1 // aws-nitro
	VerifierAzure Verifier = 2 // azure-maa
	VerifierGCP   Verifier = 3 // gcp-cs
	VerifierDev   Verifier = 4 // dev: unsigned documents, dev runners only
)

func (v Verifier) String() string {
	switch v {
	case VerifierNitro:
		return "aws-nitro"
	case VerifierAzure:
		return "azure-maa"
	case VerifierGCP:
		return "gcp-cs"
	case VerifierDev:
		return "dev"
	}
	return fmt.Sprintf("%d", v)
}

// ParseVerifier reads aws-nitro, azure-maa, gcp-cs or dev.
func ParseVerifier(s string) (Verifier, error) {
	for v := VerifierNitro; v <= VerifierDev; v++ {
		if v.String() == s {
			return v, nil
		}
	}
	return 0, fmt.Errorf("verifier %q, want aws-nitro, azure-maa, gcp-cs or dev", s)
}

// imageKind is the allowed-images kind of a verifier's measurement, 0 for
// dev.
func (v Verifier) imageKind() setupwire.ImageKind {
	switch v {
	case VerifierNitro:
		return setupwire.ImageNitro
	case VerifierAzure:
		return setupwire.ImageAzure
	case VerifierGCP:
		return setupwire.ImageGCP
	}
	return 0
}

// Compliance is the expected x-ms-compliance-status of an azure-maa entry.
type Compliance uint8

const (
	ComplianceUVM Compliance = 1 // azure-compliant-uvm, confidential containers on ACI
	ComplianceCVM Compliance = 2 // azure-compliant-cvm
)

func (c Compliance) String() string {
	switch c {
	case ComplianceUVM:
		return "azure-compliant-uvm"
	case ComplianceCVM:
		return "azure-compliant-cvm"
	}
	return fmt.Sprintf("%d", c)
}

// ParseCompliance reads azure-compliant-uvm or azure-compliant-cvm.
func ParseCompliance(s string) (Compliance, error) {
	for c := ComplianceUVM; c <= ComplianceCVM; c++ {
		if c.String() == s {
			return c, nil
		}
	}
	return 0, fmt.Errorf("compliance status %q, want azure-compliant-uvm or azure-compliant-cvm", s)
}

// Runner is the source or the target of an order: a runner named by its
// setup_hash, its image and the settings to check its attestation with.
// Which settings apply depends on Verifier; the others stay empty.
type Runner struct {
	Name      string   // a label for logs and errors
	SetupHash [32]byte // the setup_hash the runner's identity must carry
	Verifier  Verifier
	// Image is the measurement: PCR0 to PCR2 (aws-nitro, 144 bytes), the
	// CCE policy hash (azure-maa, 32), the image digest (gcp-cs, 32); none
	// for dev.
	Image []byte
	// aws-nitro: PCR3 (the parent's IAM role, in the operator's account)
	// and, optionally, PCR8 (the EIF signing certificate).
	NitroPCR3 [48]byte
	NitroPCR8 *[48]byte
	// azure-maa: the attestation provider host and the compliance status.
	MAAHost    string
	Compliance Compliance
	// gcp-cs: the token audience, the accepted hwmodels, the issuer, and
	// the service account and project the runner's VM runs as and in.
	GCPAudience       string
	GCPHWModels       []string // sorted
	GCPIssuer         string
	GCPServiceAccount string
	GCPProjectID      string
}

// AllowedImage is the runner's image as an allowed-images entry; false for
// dev.
func (r *Runner) AllowedImage() (setupwire.Image, bool) {
	k := r.Verifier.imageKind()
	if k == 0 {
		return setupwire.Image{}, false
	}
	return setupwire.Image{Kind: k, Measurement: bytes.Clone(r.Image)}, true
}

// checkText is setupwire's rule for strings: 1 to 255 bytes of printable
// ASCII without space and '#', so every value fits one line of the human
// form.
func checkText(key, s string) error {
	if len(s) == 0 || len(s) > 255 {
		return fmt.Errorf("%s: want 1 to 255 characters", key)
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; c < 0x21 || c > 0x7e || c == '#' {
			return fmt.Errorf("%s: printable ASCII only, no space or '#'", key)
		}
	}
	return nil
}

// hostRE is runnerclient's rule for an attestation provider: a lower-case
// host name without scheme or path.
var hostRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]*[a-z0-9])?(:[0-9]{1,5})?$`)

// CheckSettings applies the rules of the name, the verifier, the image and
// the verifier's settings, not those of setup_sha256.
func (r *Runner) CheckSettings() error {
	if err := checkText("name", r.Name); err != nil {
		return err
	}
	empty := func(what string, set bool) error {
		if set {
			return fmt.Errorf("%s does not apply to verifier %s", what, r.Verifier)
		}
		return nil
	}
	nitro := r.NitroPCR3 != [48]byte{} || r.NitroPCR8 != nil
	azure := r.MAAHost != "" || r.Compliance != 0
	gcp := r.GCPAudience != "" || len(r.GCPHWModels) > 0 || r.GCPIssuer != "" || r.GCPServiceAccount != "" || r.GCPProjectID != ""
	var errs []error
	if want := r.Verifier.imageKind().Size(); len(r.Image) != want {
		errs = append(errs, fmt.Errorf("image is %d bytes, verifier %s takes %d", len(r.Image), r.Verifier, want))
	}
	switch r.Verifier {
	case VerifierNitro:
		errs = append(errs, empty("azure settings", azure), empty("gcp settings", gcp))
		if r.NitroPCR3 == [48]byte{} {
			errs = append(errs, errors.New("aws-nitro needs PCR3 (the parent instance's IAM role, in the operator's account)"))
		}
		if bytes.Count(r.Image, []byte{0}) == len(r.Image) {
			errs = append(errs, errors.New("PCR0 to PCR2 are zero, the values of a debug-mode enclave"))
		}
	case VerifierAzure:
		errs = append(errs, empty("nitro settings", nitro), empty("gcp settings", gcp), checkText("maa_host", r.MAAHost))
		if !hostRE.MatchString(r.MAAHost) {
			errs = append(errs, fmt.Errorf("maa_host %q: want a host name without scheme or path", r.MAAHost))
		}
		if r.Compliance != ComplianceUVM && r.Compliance != ComplianceCVM {
			errs = append(errs, fmt.Errorf("compliance status %d, want azure-compliant-uvm or azure-compliant-cvm", r.Compliance))
		}
	case VerifierGCP:
		errs = append(errs, empty("nitro settings", nitro), empty("azure settings", azure),
			checkText("gcp_audience", r.GCPAudience), checkText("gcp_issuer", r.GCPIssuer),
			checkText("gcp_service_account", r.GCPServiceAccount), checkText("gcp_project_id", r.GCPProjectID))
		if !strings.HasPrefix(r.GCPIssuer, "https://") {
			errs = append(errs, errors.New("gcp_issuer: want an https URL"))
		}
		if n := len(r.GCPHWModels); n < 1 || n > MaxGCPHWModels {
			errs = append(errs, fmt.Errorf("%d gcp_hwmodels, want 1 to %d", n, MaxGCPHWModels))
		}
		for i, h := range r.GCPHWModels {
			errs = append(errs, checkText("gcp_hwmodels", h))
			if i > 0 && r.GCPHWModels[i-1] >= h {
				errs = append(errs, errors.New("gcp_hwmodels must be sorted, without repeats"))
			}
		}
	case VerifierDev:
		errs = append(errs, empty("nitro settings", nitro), empty("azure settings", azure), empty("gcp settings", gcp))
	default:
		return fmt.Errorf("verifier %d, want aws-nitro, azure-maa, gcp-cs or dev", r.Verifier)
	}
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}

// appendStr appends a str: len:u8 and the bytes.
func appendStr(b []byte, s string) []byte {
	b = append(b, uint8(len(s)))
	return append(b, s...)
}

// appendSettings appends a runner's verifier:u8 image settings. The caller
// checks the values first (CheckSettings).
func appendSettings(b []byte, r *Runner) []byte {
	b = append(b, uint8(r.Verifier))
	b = append(b, r.Image...)
	switch r.Verifier {
	case VerifierNitro:
		b = append(b, r.NitroPCR3[:]...)
		if r.NitroPCR8 != nil {
			b = append(b, 1)
			b = append(b, r.NitroPCR8[:]...)
		} else {
			b = append(b, 0)
		}
	case VerifierAzure:
		b = appendStr(b, r.MAAHost)
		b = append(b, uint8(r.Compliance))
	case VerifierGCP:
		b = appendStr(b, r.GCPAudience)
		b = append(b, uint8(len(r.GCPHWModels)))
		for _, h := range r.GCPHWModels {
			b = appendStr(b, h)
		}
		b = appendStr(b, r.GCPIssuer)
		b = appendStr(b, r.GCPServiceAccount)
		b = appendStr(b, r.GCPProjectID)
	}
	return b
}

// settingsReader takes fields off a byte slice. After the first error every
// read returns zero values and err keeps that error.
type settingsReader struct {
	b   []byte
	err error
}

func (r *settingsReader) fail(err error) {
	if r.err == nil {
		r.err = err
	}
}

func (r *settingsReader) take(n int) []byte {
	if r.err != nil {
		return nil
	}
	if n < 0 || n > len(r.b) {
		r.err = errShort
		return nil
	}
	v := r.b[:n]
	r.b = r.b[n:]
	return v
}

func (r *settingsReader) u8() uint8 {
	if v := r.take(1); v != nil {
		return v[0]
	}
	return 0
}

func (r *settingsReader) fixed(dst []byte) { copy(dst, r.take(len(dst))) }

func (r *settingsReader) str(what string) string {
	n := int(r.u8())
	if r.err == nil && n == 0 {
		r.fail(fmt.Errorf("handoverorder: %s is empty", what))
	}
	return string(r.take(n))
}

// readSettings reads what appendSettings writes into r's verifier, image
// and settings and returns the bytes after it. It checks the layout, not
// the values.
func readSettings(p []byte, r *Runner) ([]byte, error) {
	rd := &settingsReader{b: p}
	r.Verifier = Verifier(rd.u8())
	if rd.err == nil && (r.Verifier < VerifierNitro || r.Verifier > VerifierDev) {
		rd.fail(fmt.Errorf("handoverorder: unknown verifier %d", r.Verifier))
	}
	if n := r.Verifier.imageKind().Size(); n > 0 {
		r.Image = bytes.Clone(rd.take(n))
	}
	switch r.Verifier {
	case VerifierNitro:
		rd.fixed(r.NitroPCR3[:])
		switch rd.u8() {
		case 0:
		case 1:
			var v [48]byte
			rd.fixed(v[:])
			r.NitroPCR8 = &v
		default:
			rd.fail(errors.New("handoverorder: pcr8 presence byte is not 0 or 1"))
		}
	case VerifierAzure:
		r.MAAHost = rd.str("maa_host")
		r.Compliance = Compliance(rd.u8())
	case VerifierGCP:
		r.GCPAudience = rd.str("gcp_audience")
		n := int(rd.u8())
		if rd.err == nil && n > MaxGCPHWModels {
			rd.fail(fmt.Errorf("handoverorder: %d gcp_hwmodels, at most %d", n, MaxGCPHWModels))
			n = 0
		}
		for range n {
			r.GCPHWModels = append(r.GCPHWModels, rd.str("gcp_hwmodels"))
		}
		r.GCPIssuer = rd.str("gcp_issuer")
		r.GCPServiceAccount = rd.str("gcp_service_account")
		r.GCPProjectID = rd.str("gcp_project_id")
	}
	if rd.err != nil {
		return nil, rd.err
	}
	return rd.b, nil
}

// FormatImage writes an allowed-images entry as setupwire's human form does.
func FormatImage(im setupwire.Image) string {
	if im.Kind == setupwire.ImageNitro && len(im.Measurement) == 144 {
		return fmt.Sprintf("%s %s %s %s", im.Kind, hexOf(im.Measurement[:48]), hexOf(im.Measurement[48:96]), hexOf(im.Measurement[96:]))
	}
	return fmt.Sprintf("%s %s", im.Kind, hexOf(im.Measurement))
}

// FormatSettings is the human form of a runner's verifier, image and
// settings, each key with the prefix pre.
func FormatSettings(pre string, r *Runner) string {
	var w strings.Builder
	kv := func(k string, v any) { fmt.Fprintf(&w, "%s = %v\n", k, v) }
	kv(pre+"verifier", r.Verifier)
	if im, ok := r.AllowedImage(); ok {
		kv(pre+"image", FormatImage(im))
	}
	switch r.Verifier {
	case VerifierNitro:
		kv(pre+"nitro_pcr3", hexOf(r.NitroPCR3[:]))
		if r.NitroPCR8 != nil {
			kv(pre+"nitro_pcr8", hexOf(r.NitroPCR8[:]))
		}
	case VerifierAzure:
		kv(pre+"maa_host", r.MAAHost)
		kv(pre+"compliance_status", r.Compliance)
	case VerifierGCP:
		kv(pre+"gcp_audience", r.GCPAudience)
		for _, h := range r.GCPHWModels {
			kv(pre+"gcp_hwmodels", h)
		}
		kv(pre+"gcp_issuer", r.GCPIssuer)
		kv(pre+"gcp_service_account", r.GCPServiceAccount)
		kv(pre+"gcp_project_id", r.GCPProjectID)
	}
	return w.String()
}

var _ = hex.EncodeToString
