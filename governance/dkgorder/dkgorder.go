// Package dkgorder is the DKG order (research/setup-phase.md in the
// threshold-signer-poc repo, section 10, "Key generation"): what replaces the
// -dkg-policy file for a runner with a setup. k approvers in force sign it
// under setupwire.CtxDKGOrder, it reaches the runner over the wire
// (DKG_ORDER, package dkgmsg), and it names everything the key generation
// of one lane may use: each participant's setup_hash, image, operator key
// and attestation settings, the threshold, the path and, for Charon, the
// ENRs. Withdrawal credentials and deposit amounts are not in it: the runner
// takes them from its locked group in force (decision 13).
//
// It follows the rules of package setupwire (fixed binary form, strict
// decoder, a human form for people) but is a package of its own: only key
// generation builds link it, so the runner builds without key generation
// stay byte for byte as they were.
//
//	body        = 'D' version:u8(1) cluster_id[32] chain_hash[32] label:str
//	              path:u8 threshold:u8 not_after:u64
//	              n:u8 {participant} enr_count:u8 {enr_len:u16 enr}
//	participant = name:str setup_hash[32] operator_key[32] verifier:u8 settings
//	settings    = aws-nitro: pcr0..pcr2[144] pcr3[48] has:u8 [pcr8[48]]
//	            | azure-maa: cce_policy_sha256[32] maa_host:str compliance:u8
//	            | gcp-cs: image_digest[32] audience:str hwmodel_count:u8 {hwmodel:str}
//	                      issuer:str service_account:str project_id:str
//	            | dev: (nothing)
//	order       = 'O' version:u8(1) body_len:u32 body
//	              sig_count:u8 {position:u8 signature[64]}
//
// Integers are big endian, str is len:u8 and 1 to 255 bytes of printable
// ASCII without space or '#'. Participant i (from 0) holds the shares at
// x = i+1, as in the policy file. The image of a participant is its
// measurement in the allowed-images form of the setup: PCR0 to PCR2 (kind
// nitro), the CCE policy hash (azure), the image digest (gcp). Every one
// must be on the runner's allowed-images list in force. The dev verifier
// has no image, and only a dev runner takes it. hwmodels are sorted without
// repeats; the ENRs follow the participant order.
//
// The order's hash is SHA-256 over CtxDKGOrder and the body, so it names
// what the approvers signed. The signatures are not in it: a new approver
// set can sign the same body again, and the keys made under it keep their
// label.
package dkgorder

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/lidofinance/tee-signer/governance/setupwire"
)

const (
	Version = 1
	// MaxSize bounds a body and a signed order. Ten participants at every
	// cap take about 13 KB.
	MaxSize = 32 << 10
	// MaxParticipants is dkgmsg.MaxParticipants (runner/keygen tests check
	// that the two agree).
	MaxParticipants = 10
	// MaxENR bounds one Charon ENR.
	MaxENR = 1024
	// MaxGCPHWModels bounds the accepted hwmodel claims of a gcp-cs entry.
	MaxGCPHWModels = 4

	kindBody  = 'D'
	kindOrder = 'O'
)

// Path is what the keys of an order are for.
type Path uint8

const (
	// PathDirk: deposits only; the Dirk fork lists the accounts.
	PathDirk Path = 1
	// PathCharon: deposits, builder registrations and the Charon lock.
	PathCharon Path = 2
)

func (p Path) String() string {
	switch p {
	case PathDirk:
		return "dirk"
	case PathCharon:
		return "charon"
	}
	return fmt.Sprintf("%d", p)
}

// ParsePath reads dirk or charon.
func ParsePath(s string) (Path, error) {
	switch s {
	case "dirk":
		return PathDirk, nil
	case "charon":
		return PathCharon, nil
	}
	return 0, fmt.Errorf("path %q, want dirk or charon", s)
}

// Verifier names the attestation check of a participant, with the names of
// attest/runnerclient.
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

// Participant is one runner of the order. Which settings apply depends on
// Verifier; the others stay empty.
type Participant struct {
	Name        string   // a label for logs and errors
	SetupHash   [32]byte // the setup_hash the runner's identity must carry
	OperatorKey [32]byte // the runner's operator key (DKG_OPERATOR)
	Verifier    Verifier
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

// AllowedImage is the participant's image as an allowed-images entry; false
// for dev.
func (p *Participant) AllowedImage() (setupwire.Image, bool) {
	k := p.Verifier.imageKind()
	if k == 0 {
		return setupwire.Image{}, false
	}
	return setupwire.Image{Kind: k, Measurement: bytes.Clone(p.Image)}, true
}

// Body is what the approvers sign.
type Body struct {
	ClusterID [32]byte
	ChainHash [32]byte // setupwire.Chain.Hash of the setups
	// Label names the order for people: a lane, a cluster.
	Label     string
	Path      Path
	Threshold uint8
	// NotAfter, Unix seconds: from then on the order makes no more keys.
	NotAfter     uint64
	Participants []Participant
	CharonENRs   []string // charon path: one per participant, in order
}

// Order is a signed DKG order.
type Order struct {
	Body      Body
	Approvals []setupwire.Approval // by the approvers in force, ascending positions
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

// Check applies the body's value rules.
func (b *Body) Check() error {
	if b.ClusterID == ([32]byte{}) {
		return errors.New("dkg order: cluster_id is zero")
	}
	if err := checkText("label", b.Label); err != nil {
		return fmt.Errorf("dkg order: %w", err)
	}
	if b.Path != PathDirk && b.Path != PathCharon {
		return fmt.Errorf("dkg order: path %d, want dirk or charon", b.Path)
	}
	if b.NotAfter == 0 {
		return errors.New("dkg order: not_after is 0")
	}
	n := len(b.Participants)
	if n < 2 || n > MaxParticipants {
		return fmt.Errorf("dkg order: %d participants, want 2 to %d", n, MaxParticipants)
	}
	// A majority threshold: two disjoint groups of signers cannot both
	// reach it.
	if int(b.Threshold) < setupwire.MinThreshold || 2*int(b.Threshold) <= n || int(b.Threshold) > n {
		return fmt.Errorf("dkg order: threshold %d of %d, want more than half, at least %d and at most all",
			b.Threshold, n, setupwire.MinThreshold)
	}
	names, setups, keys := map[string]bool{}, map[[32]byte]bool{}, map[[32]byte]bool{}
	for i := range b.Participants {
		p := &b.Participants[i]
		if err := p.check(); err != nil {
			return fmt.Errorf("dkg order: participant %d: %w", i+1, err)
		}
		switch {
		case names[p.Name]:
			return fmt.Errorf("dkg order: participant %d: name %q repeats", i+1, p.Name)
		case setups[p.SetupHash]:
			return fmt.Errorf("dkg order: participant %d: setup_sha256 repeats", i+1)
		case keys[p.OperatorKey]:
			return fmt.Errorf("dkg order: participant %d: operator_key repeats", i+1)
		}
		names[p.Name], setups[p.SetupHash], keys[p.OperatorKey] = true, true, true
	}
	switch {
	case b.Path == PathDirk && len(b.CharonENRs) != 0:
		return errors.New("dkg order: charon_enrs are for the charon path")
	case b.Path == PathCharon && len(b.CharonENRs) != n:
		return fmt.Errorf("dkg order: charon_enrs lists %d nodes for %d participants", len(b.CharonENRs), n)
	}
	seen := map[string]bool{}
	for i, e := range b.CharonENRs {
		if !isENR(e) {
			return fmt.Errorf("dkg order: charon_enrs %d is not an ENR of printable ASCII up to %d characters", i+1, MaxENR)
		}
		if seen[e] {
			return fmt.Errorf("dkg order: charon_enrs %d repeats", i+1)
		}
		seen[e] = true
	}
	return nil
}

// isENR is checkText's character rule with room for MaxENR bytes, and the
// "enr:" prefix of a node record.
func isENR(s string) bool {
	if len(s) > MaxENR || !strings.HasPrefix(s, "enr:") {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; c < 0x21 || c > 0x7e || c == '#' {
			return false
		}
	}
	return true
}

func (p *Participant) check() error {
	if err := checkText("name", p.Name); err != nil {
		return err
	}
	if p.SetupHash == ([32]byte{}) {
		return errors.New("setup_sha256 is zero")
	}
	if err := setupwire.CheckKey(p.OperatorKey); err != nil {
		return fmt.Errorf("operator_key: %w", err)
	}
	return p.checkSettings()
}

// CheckSettings applies the rules of the name, the verifier, the image and
// the verifier's settings, not those of setup_sha256 and operator_key: for
// an order of another kind that names a runner the same way
// (backend/handoverorder).
func (p *Participant) CheckSettings() error {
	if err := checkText("name", p.Name); err != nil {
		return err
	}
	return p.checkSettings()
}

func (p *Participant) checkSettings() error {
	empty := func(what string, set bool) error {
		if set {
			return fmt.Errorf("%s does not apply to verifier %s", what, p.Verifier)
		}
		return nil
	}
	nitro := p.NitroPCR3 != [48]byte{} || p.NitroPCR8 != nil
	azure := p.MAAHost != "" || p.Compliance != 0
	gcp := p.GCPAudience != "" || len(p.GCPHWModels) > 0 || p.GCPIssuer != "" || p.GCPServiceAccount != "" || p.GCPProjectID != ""
	var errs []error
	if want := p.Verifier.imageKind().Size(); len(p.Image) != want {
		errs = append(errs, fmt.Errorf("image is %d bytes, verifier %s takes %d", len(p.Image), p.Verifier, want))
	}
	switch p.Verifier {
	case VerifierNitro:
		errs = append(errs, empty("azure settings", azure), empty("gcp settings", gcp))
		if p.NitroPCR3 == [48]byte{} {
			errs = append(errs, errors.New("aws-nitro needs PCR3 (the parent instance's IAM role, in the operator's account)"))
		}
		if bytes.Count(p.Image, []byte{0}) == len(p.Image) {
			errs = append(errs, errors.New("PCR0 to PCR2 are zero, the values of a debug-mode enclave"))
		}
	case VerifierAzure:
		errs = append(errs, empty("nitro settings", nitro), empty("gcp settings", gcp), checkText("maa_host", p.MAAHost))
		if !hostRE.MatchString(p.MAAHost) {
			errs = append(errs, fmt.Errorf("maa_host %q: want a host name without scheme or path", p.MAAHost))
		}
		if p.Compliance != ComplianceUVM && p.Compliance != ComplianceCVM {
			errs = append(errs, fmt.Errorf("compliance status %d, want azure-compliant-uvm or azure-compliant-cvm", p.Compliance))
		}
	case VerifierGCP:
		errs = append(errs, empty("nitro settings", nitro), empty("azure settings", azure),
			checkText("gcp_audience", p.GCPAudience), checkText("gcp_issuer", p.GCPIssuer),
			checkText("gcp_service_account", p.GCPServiceAccount), checkText("gcp_project_id", p.GCPProjectID))
		if !strings.HasPrefix(p.GCPIssuer, "https://") {
			errs = append(errs, errors.New("gcp_issuer: want an https URL"))
		}
		if n := len(p.GCPHWModels); n < 1 || n > MaxGCPHWModels {
			errs = append(errs, fmt.Errorf("%d gcp_hwmodels, want 1 to %d", n, MaxGCPHWModels))
		}
		for i, h := range p.GCPHWModels {
			errs = append(errs, checkText("gcp_hwmodels", h))
			if i > 0 && p.GCPHWModels[i-1] >= h {
				errs = append(errs, errors.New("gcp_hwmodels must be sorted, without repeats"))
			}
		}
	case VerifierDev:
		errs = append(errs, empty("nitro settings", nitro), empty("azure settings", azure), empty("gcp settings", gcp))
	default:
		return fmt.Errorf("verifier %d, want aws-nitro, azure-maa, gcp-cs or dev", p.Verifier)
	}
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}

// writer appends fields. The caller checks the values first.
type writer struct{ b []byte }

func (w *writer) u8(v uint8)   { w.b = append(w.b, v) }
func (w *writer) u16(v uint16) { w.b = binary.BigEndian.AppendUint16(w.b, v) }
func (w *writer) u32(v uint32) { w.b = binary.BigEndian.AppendUint32(w.b, v) }
func (w *writer) u64(v uint64) { w.b = binary.BigEndian.AppendUint64(w.b, v) }
func (w *writer) raw(p []byte) { w.b = append(w.b, p...) }
func (w *writer) str(s string) { w.u8(uint8(len(s))); w.b = append(w.b, s...) }

// reader takes fields off a byte slice. After the first error every read
// returns zero values and err keeps that error.
type reader struct {
	b   []byte
	err error
}

func (r *reader) fail(err error) {
	if r.err == nil {
		r.err = err
	}
}

func (r *reader) take(n int) []byte {
	if r.err != nil {
		return nil
	}
	if n < 0 || n > len(r.b) {
		r.err = errors.New("dkgorder: message too short")
		return nil
	}
	v := r.b[:n]
	r.b = r.b[n:]
	return v
}

func (r *reader) u8() uint8 {
	if v := r.take(1); v != nil {
		return v[0]
	}
	return 0
}

func (r *reader) u16() uint16 {
	if v := r.take(2); v != nil {
		return binary.BigEndian.Uint16(v)
	}
	return 0
}

func (r *reader) u32() uint32 {
	if v := r.take(4); v != nil {
		return binary.BigEndian.Uint32(v)
	}
	return 0
}

func (r *reader) u64() uint64 {
	if v := r.take(8); v != nil {
		return binary.BigEndian.Uint64(v)
	}
	return 0
}

func (r *reader) fixed(dst []byte) { copy(dst, r.take(len(dst))) }

func (r *reader) str(what string) string {
	n := int(r.u8())
	if r.err == nil && n == 0 {
		r.fail(fmt.Errorf("dkgorder: %s is empty", what))
	}
	return string(r.take(n))
}

func (r *reader) count(what string, max int) int {
	n := int(r.u8())
	if n > max {
		r.fail(fmt.Errorf("dkgorder: %d %s, at most %d", n, what, max))
		return 0
	}
	return n
}

func (r *reader) header(kind byte, what string) {
	if k := r.u8(); r.err == nil && k != kind {
		r.fail(fmt.Errorf("dkgorder: not a %s (kind byte %#02x, want %#02x)", what, k, kind))
	}
	if v := r.u8(); r.err == nil && v != Version {
		r.fail(fmt.Errorf("dkgorder: %s version %d, want %d", what, v, Version))
	}
}

func (r *reader) done() error {
	if r.err == nil && len(r.b) != 0 {
		r.err = fmt.Errorf("dkgorder: %d trailing bytes", len(r.b))
	}
	return r.err
}

// Encode checks the body and returns the bytes the approvers sign.
func (b *Body) Encode() ([]byte, error) {
	if err := b.Check(); err != nil {
		return nil, err
	}
	w := &writer{}
	b.write(w)
	if len(w.b) > MaxSize {
		return nil, fmt.Errorf("dkg order: body of %d bytes, at most %d", len(w.b), MaxSize)
	}
	return w.b, nil
}

func (b *Body) write(w *writer) {
	w.u8(kindBody)
	w.u8(Version)
	w.raw(b.ClusterID[:])
	w.raw(b.ChainHash[:])
	w.str(b.Label)
	w.u8(uint8(b.Path))
	w.u8(b.Threshold)
	w.u64(b.NotAfter)
	w.u8(uint8(len(b.Participants)))
	for i := range b.Participants {
		p := &b.Participants[i]
		w.str(p.Name)
		w.raw(p.SetupHash[:])
		w.raw(p.OperatorKey[:])
		writeSettings(w, p)
	}
	w.u8(uint8(len(b.CharonENRs)))
	for _, e := range b.CharonENRs {
		w.u16(uint16(len(e)))
		w.raw([]byte(e))
	}
}

// writeSettings writes a participant's verifier:u8 image settings.
func writeSettings(w *writer, p *Participant) {
	w.u8(uint8(p.Verifier))
	w.raw(p.Image)
	switch p.Verifier {
	case VerifierNitro:
		w.raw(p.NitroPCR3[:])
		if p.NitroPCR8 != nil {
			w.u8(1)
			w.raw(p.NitroPCR8[:])
		} else {
			w.u8(0)
		}
	case VerifierAzure:
		w.str(p.MAAHost)
		w.u8(uint8(p.Compliance))
	case VerifierGCP:
		w.str(p.GCPAudience)
		w.u8(uint8(len(p.GCPHWModels)))
		for _, h := range p.GCPHWModels {
			w.str(h)
		}
		w.str(p.GCPIssuer)
		w.str(p.GCPServiceAccount)
		w.str(p.GCPProjectID)
	}
}

// readSettings reads what writeSettings writes.
func readSettings(r *reader, p *Participant) {
	p.Verifier = Verifier(r.u8())
	if r.err == nil && (p.Verifier < VerifierNitro || p.Verifier > VerifierDev) {
		r.fail(fmt.Errorf("dkgorder: unknown verifier %d", p.Verifier))
	}
	if n := p.Verifier.imageKind().Size(); n > 0 {
		p.Image = bytes.Clone(r.take(n))
	}
	switch p.Verifier {
	case VerifierNitro:
		r.fixed(p.NitroPCR3[:])
		switch r.u8() {
		case 0:
		case 1:
			var v [48]byte
			r.fixed(v[:])
			p.NitroPCR8 = &v
		default:
			r.fail(errors.New("dkgorder: pcr8 presence byte is not 0 or 1"))
		}
	case VerifierAzure:
		p.MAAHost = r.str("maa_host")
		p.Compliance = Compliance(r.u8())
	case VerifierGCP:
		p.GCPAudience = r.str("gcp_audience")
		for range r.count("gcp_hwmodels", MaxGCPHWModels) {
			p.GCPHWModels = append(p.GCPHWModels, r.str("gcp_hwmodels"))
		}
		p.GCPIssuer = r.str("gcp_issuer")
		p.GCPServiceAccount = r.str("gcp_service_account")
		p.GCPProjectID = r.str("gcp_project_id")
	}
}

// AppendSettings appends a participant's verifier, image and verifier
// settings in the layout of a DKG order participant (the part after
// operator_key): verifier:u8 image settings. Another order that names a
// runner the same way uses it (backend/handoverorder). The caller checks
// the values first (CheckSettings).
func AppendSettings(b []byte, p *Participant) []byte {
	w := &writer{b: b}
	writeSettings(w, p)
	return w.b
}

// ReadSettings reads AppendSettings' layout into p's verifier, image and
// settings and returns the bytes after it. It checks the layout, not the
// values.
func ReadSettings(b []byte, p *Participant) ([]byte, error) {
	r := &reader{b: b}
	readSettings(r, p)
	if r.err != nil {
		return nil, r.err
	}
	return r.b, nil
}

func readBody(r *reader) *Body {
	r.header(kindBody, "dkg order body")
	b := &Body{}
	r.fixed(b.ClusterID[:])
	r.fixed(b.ChainHash[:])
	b.Label = r.str("label")
	b.Path = Path(r.u8())
	b.Threshold = r.u8()
	b.NotAfter = r.u64()
	for range r.count("participants", MaxParticipants) {
		p := Participant{Name: r.str("participant name")}
		r.fixed(p.SetupHash[:])
		r.fixed(p.OperatorKey[:])
		readSettings(r, &p)
		b.Participants = append(b.Participants, p)
	}
	for range r.count("charon_enrs", MaxParticipants) {
		n := int(r.u16())
		if r.err == nil && n > MaxENR {
			r.fail(fmt.Errorf("dkgorder: an ENR of %d bytes, at most %d", n, MaxENR))
		}
		b.CharonENRs = append(b.CharonENRs, string(r.take(n)))
	}
	return b
}

// DecodeBody reads a body strictly: it refuses input above MaxSize, a kind
// or version it does not know, counts above their caps, values Check
// refuses, trailing bytes, and anything that does not encode back to the
// same bytes.
func DecodeBody(raw []byte) (*Body, error) {
	if len(raw) > MaxSize {
		return nil, fmt.Errorf("dkgorder: body is %d bytes, at most %d", len(raw), MaxSize)
	}
	r := &reader{b: raw}
	b := readBody(r)
	if err := r.done(); err != nil {
		return nil, err
	}
	again, err := b.Encode()
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(again, raw) {
		return nil, errors.New("dkgorder: body does not encode back to the same bytes")
	}
	return b, nil
}

// Hash is the hash of an order: SHA-256 over CtxDKGOrder and its body.
func Hash(body []byte) [32]byte { return setupwire.CtxDKGOrder.Hash(body) }

// Hash encodes the body and returns its order hash.
func (b *Body) Hash() ([32]byte, error) {
	enc, err := b.Encode()
	if err != nil {
		return [32]byte{}, err
	}
	return Hash(enc), nil
}

// Matches says whether the order is for this setup's cluster and chain.
func (b *Body) Matches(s *setupwire.Setup) error {
	if b.ClusterID != s.ClusterID {
		return errors.New("dkg order: for another cluster_id")
	}
	if b.ChainHash != s.Chain.Hash() {
		return errors.New("dkg order: for another chain")
	}
	if err := setupwire.CheckThresholdOn(s.Platform.Platform, s.Chain.GenesisForkVersion, int(b.Threshold), len(b.Participants)); err != nil {
		return fmt.Errorf("dkg order: %w", err)
	}
	return nil
}

// Position is the index of the participant with this setup_hash.
func (b *Body) Position(setupHash [32]byte) (int, bool) {
	i := slices.IndexFunc(b.Participants, func(p Participant) bool { return p.SetupHash == setupHash })
	return i, i >= 0
}

// CheckImages refuses an order whose participants' images are not all on
// the allowed-images list. A dev participant has none; devOK says whether
// that is accepted (a dev runner only).
func (b *Body) CheckImages(allowed []setupwire.Image, devOK bool) error {
	for i := range b.Participants {
		p := &b.Participants[i]
		im, ok := p.AllowedImage()
		if !ok {
			if !devOK {
				return fmt.Errorf("dkg order: participant %d (%s) has the dev verifier, which only a dev runner takes", i+1, p.Name)
			}
			continue
		}
		if !slices.ContainsFunc(allowed, func(a setupwire.Image) bool {
			return a.Kind == im.Kind && bytes.Equal(a.Measurement, im.Measurement)
		}) {
			return fmt.Errorf("dkg order: participant %d (%s): its %s image is not on the allowed-images list in force", i+1, p.Name, im.Kind)
		}
	}
	return nil
}

// Wait is how long an order waits from its arrival before it acts: the
// time lock in force, and at least the images minimum (section 9). An order
// decides which setups hold new shares, as an allowed image decides which
// code runs over them, so no config makes the wait shorter than that
// minimum.
func Wait(active *setupwire.Locked) uint64 {
	return max(active.ChangeDelay(), setupwire.ImagesMinTimeLock)
}

// SignBodyHashed is SignBody in the hash-then-sign form (CtxDKGOrderHash).
func SignBodyHashed(key ed25519.PrivateKey, body []byte) [64]byte {
	return setupwire.SignApproval(key, setupwire.CtxDKGOrder, true, body)
}

// SignBody is one approver's signature over an encoded body.
func SignBody(key ed25519.PrivateKey, body []byte) [64]byte {
	var sig [64]byte
	copy(sig[:], ed25519.Sign(key, setupwire.CtxDKGOrder.Message(body)))
	return sig
}

func (o *Order) check() error {
	if err := o.Body.Check(); err != nil {
		return err
	}
	if n := len(o.Approvals); n < 1 || n > setupwire.MaxApprovers {
		return fmt.Errorf("dkg order: %d approver signatures, want 1 to %d", n, setupwire.MaxApprovers)
	}
	for i, a := range o.Approvals {
		if a.Position >= setupwire.MaxApprovers {
			return fmt.Errorf("dkg order: signature by position %d, at most %d", a.Position, setupwire.MaxApprovers-1)
		}
		if i > 0 && a.Position <= o.Approvals[i-1].Position {
			return errors.New("dkg order: approver signatures must be in ascending position order, one per approver")
		}
	}
	return nil
}

// Encode returns the signed order.
func (o *Order) Encode() ([]byte, error) {
	if err := o.check(); err != nil {
		return nil, err
	}
	body := &writer{}
	o.Body.write(body)
	w := &writer{}
	w.u8(kindOrder)
	w.u8(Version)
	w.u32(uint32(len(body.b)))
	w.raw(body.b)
	w.u8(uint8(len(o.Approvals)))
	for _, a := range o.Approvals {
		w.u8(a.Position)
		w.raw(a.Signature[:])
	}
	if len(w.b) > MaxSize {
		return nil, fmt.Errorf("dkg order: %d bytes, at most %d", len(w.b), MaxSize)
	}
	return w.b, nil
}

// Decode reads a signed order strictly. It checks the layout and the
// values, not the signatures: Verify does that against the set in force.
func Decode(raw []byte) (*Order, error) {
	if len(raw) > MaxSize {
		return nil, fmt.Errorf("dkgorder: order is %d bytes, at most %d", len(raw), MaxSize)
	}
	r := &reader{b: raw}
	r.header(kindOrder, "dkg order")
	n := r.u32()
	if r.err == nil && n > MaxSize {
		return nil, fmt.Errorf("dkgorder: body of %d bytes, at most %d", n, MaxSize)
	}
	bodyRaw := r.take(int(n))
	if r.err != nil {
		return nil, r.err
	}
	body, err := DecodeBody(bodyRaw)
	if err != nil {
		return nil, err
	}
	o := &Order{Body: *body}
	for range r.count("approver signatures", setupwire.MaxApprovers) {
		a := setupwire.Approval{Position: r.u8()}
		r.fixed(a.Signature[:])
		o.Approvals = append(o.Approvals, a)
	}
	if err := r.done(); err != nil {
		return nil, err
	}
	again, err := o.Encode()
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(again, raw) {
		return nil, errors.New("dkgorder: order does not encode back to the same bytes")
	}
	return o, nil
}

// Verify checks the signatures against the approver set in force: every
// signature verifies and at least k distinct approvers of the set signed.
func (o *Order) Verify(active *setupwire.ApproverSet) error {
	if err := o.check(); err != nil {
		return err
	}
	body, err := o.Body.Encode()
	if err != nil {
		return err
	}
	for _, a := range o.Approvals {
		if int(a.Position) >= len(active.Keys) {
			return fmt.Errorf("dkg order: signature by approver %d, the set in force has %d", a.Position, len(active.Keys))
		}
		if !setupwire.VerifyApproval(active.Keys[a.Position], setupwire.CtxDKGOrder, a.Signature, body) {
			return fmt.Errorf("dkg order: the signature of approver %d does not verify under the set in force", a.Position)
		}
	}
	if len(o.Approvals) < int(active.ApprovalsNeeded) {
		return fmt.Errorf("dkg order: %d approver signatures, approvals_needed is %d", len(o.Approvals), active.ApprovalsNeeded)
	}
	return nil
}

// IsBody reports whether raw starts like an order body, for tools that
// read either a config update or an order.
func IsBody(raw []byte) bool { return len(raw) > 0 && raw[0] == kindBody }

// IsOrder reports whether raw starts like a signed order.
func IsOrder(raw []byte) bool { return len(raw) > 0 && raw[0] == kindOrder }
