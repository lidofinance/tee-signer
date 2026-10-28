package dkgorder

import (
	"cmp"
	"encoding/hex"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/lidofinance/tee-signer/governance/setupwire"
)

// The human form, in the "key = value" lines of setupwire's: what
// signer-config show prints for the approvers and what an operator may edit
// before drafting. '#' starts a comment. Top-level keys name the order;
// each participant's keys start with participant_N. (N from 1, the share
// ID). charon_enrs repeats in participant order; gcp_hwmodels and
// approver_signature repeat and are sorted. A key that is unknown, set
// twice or that does not apply to the participant's verifier is refused.
//
//	label = charon
//	path = charon
//	threshold = 2
//	not_after = 1798761600
//	participant_1.name = azure-1
//	participant_1.setup_sha256 = 0x...
//	participant_1.operator_key = 0x...
//	participant_1.verifier = azure-maa
//	participant_1.image = azure 0x...
//	participant_1.maa_host = sharedneu.neu.attest.azure.net
//	participant_1.compliance_status = azure-compliant-uvm
//
// Format writes the canonical form, so binary -> human -> binary returns
// the same bytes.

// MaxHuman bounds a human file.
const MaxHuman = 4 * MaxSize

// verifierKeys are a participant's keys after the four every participant
// has, by verifier.
func verifierKeys(v Verifier) []string {
	switch v {
	case VerifierNitro:
		return []string{"image", "nitro_pcr3", "nitro_pcr8"}
	case VerifierAzure:
		return []string{"image", "maa_host", "compliance_status"}
	case VerifierGCP:
		return []string{"image", "gcp_audience", "gcp_hwmodels", "gcp_issuer", "gcp_service_account", "gcp_project_id"}
	}
	return nil
}

type kvLine struct {
	line int
	val  string
}

// parser holds the lines of one file by key. After the first error every
// read returns zero values and err keeps that error.
type parser struct {
	name string
	vals map[string][]kvLine
	used map[string]bool
	err  error
}

func newParser(name string, data []byte) (*parser, error) {
	if len(data) > MaxHuman {
		return nil, fmt.Errorf("%s: %d bytes, at most %d", name, len(data), MaxHuman)
	}
	p := &parser{name: name, vals: map[string][]kvLine{}, used: map[string]bool{}}
	for i, raw := range strings.Split(string(data), "\n") {
		n := i + 1
		text, _, _ := strings.Cut(raw, "#")
		for j := 0; j < len(text); j++ {
			if c := text[j]; (c < 0x20 && c != '\t' && c != '\r') || c > 0x7e {
				return nil, fmt.Errorf("%s:%d: byte %#02x: keys and values are printable ASCII", name, n, c)
			}
		}
		text = strings.TrimSpace(text)
		if text == "" {
			continue
		}
		key, val, ok := strings.Cut(text, "=")
		if !ok {
			return nil, fmt.Errorf("%s:%d: want key = value", name, n)
		}
		key, val = strings.TrimSpace(key), strings.TrimSpace(val)
		if key == "" || strings.ToLower(key) != key || strings.ContainsAny(key, " \t") {
			return nil, fmt.Errorf("%s:%d: bad key %q (keys are lower case)", name, n, key)
		}
		if val == "" {
			return nil, fmt.Errorf("%s:%d: %s: no value", name, n, key)
		}
		p.vals[key] = append(p.vals[key], kvLine{n, val})
	}
	return p, nil
}

func (p *parser) fail(line int, key string, err error) {
	if p.err == nil {
		p.err = fmt.Errorf("%s:%d: %s: %v", p.name, line, key, err)
	}
}

func (p *parser) has(prefix string) bool {
	for k := range p.vals {
		if strings.HasPrefix(k, prefix) {
			return true
		}
	}
	return false
}

// done refuses keys no field asked for, the first one by line.
func (p *parser) done() error {
	if p.err != nil {
		return p.err
	}
	line, key := 0, ""
	for k, v := range p.vals {
		if !p.used[k] && (key == "" || v[0].line < line) {
			line, key = v[0].line, k
		}
	}
	if key != "" {
		return fmt.Errorf("%s:%d: unknown key %q", p.name, line, key)
	}
	return nil
}

// one reads a key that may be set once; ok is false when it is absent.
func one[T any](p *parser, key string, parse func(string) (T, error)) (v T, ok bool) {
	if p.err != nil {
		return v, false
	}
	p.used[key] = true
	l := p.vals[key]
	switch {
	case len(l) == 0:
		return v, false
	case len(l) > 1:
		p.fail(l[1].line, key, fmt.Errorf("set again (first on line %d)", l[0].line))
		return v, false
	}
	v, err := parse(l[0].val)
	if err != nil {
		p.fail(l[0].line, key, err)
		return v, false
	}
	return v, true
}

// required reads a required key.
func required[T any](p *parser, key string, parse func(string) (T, error)) T {
	v, ok := one(p, key, parse)
	if !ok && p.err == nil {
		p.err = fmt.Errorf("%s: %s is missing", p.name, key)
	}
	return v
}

// list reads every line of a list key, in file order.
func list[T any](p *parser, key string, parse func(string) (T, error)) []T {
	if p.err != nil {
		return nil
	}
	p.used[key] = true
	var out []T
	for _, l := range p.vals[key] {
		v, err := parse(l.val)
		if err != nil {
			p.fail(l.line, key, err)
			return nil
		}
		out = append(out, v)
	}
	return out
}

func parseText(s string) (string, error) { return s, nil }

func parseUint(bits int) func(string) (uint64, error) {
	return func(s string) (uint64, error) {
		v, err := strconv.ParseUint(s, 10, bits)
		if err != nil {
			return 0, fmt.Errorf("%q: want a decimal number below 2^%d", s, bits)
		}
		return v, nil
	}
}

func parseHex(s string, n int) ([]byte, error) {
	b, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
	if err != nil || len(b) != n {
		return nil, fmt.Errorf("want %d bytes of hex", n)
	}
	return b, nil
}

func parse32(s string) ([32]byte, error) {
	b, err := parseHex(s, 32)
	if err != nil {
		return [32]byte{}, err
	}
	return [32]byte(b), nil
}

func parse48(s string) ([48]byte, error) {
	b, err := parseHex(s, 48)
	if err != nil {
		return [48]byte{}, err
	}
	return [48]byte(b), nil
}

// parseImage reads "nitro PCR0 PCR1 PCR2" or "azure|gcp HASH", the form of
// setupwire's allowed_image_measurements.
func parseImage(s string) (setupwire.Image, error) {
	f := strings.Fields(s)
	var im setupwire.Image
	switch {
	case len(f) == 4 && f[0] == "nitro":
		im.Kind = setupwire.ImageNitro
	case len(f) == 2 && f[0] == "azure":
		im.Kind = setupwire.ImageAzure
	case len(f) == 2 && f[0] == "gcp":
		im.Kind = setupwire.ImageGCP
	default:
		return im, fmt.Errorf("%q: want nitro PCR0 PCR1 PCR2, azure HASH or gcp HASH", s)
	}
	for _, h := range f[1:] {
		b, err := parseHex(h, im.Kind.Size()/(len(f)-1))
		if err != nil {
			return im, err
		}
		im.Measurement = append(im.Measurement, b...)
	}
	return im, nil
}

// parseApproval reads "POSITION SIGNATURE".
func parseApproval(s string) (setupwire.Approval, error) {
	f := strings.Fields(s)
	if len(f) != 2 {
		return setupwire.Approval{}, fmt.Errorf("%q: want POSITION SIGNATURE", s)
	}
	pos, err := parseUint(8)(f[0])
	if err != nil {
		return setupwire.Approval{}, err
	}
	sig, err := parseHex(f[1], 64)
	if err != nil {
		return setupwire.Approval{}, err
	}
	return setupwire.Approval{Position: uint8(pos), Signature: [64]byte(sig)}, nil
}

func (p *parser) body() *Body {
	b := &Body{}
	b.ClusterID = required(p, "cluster_id", parse32)
	b.ChainHash = required(p, "chain_hash", parse32)
	b.Label = required(p, "label", parseText)
	b.Path = required(p, "path", ParsePath)
	b.Threshold = uint8(required(p, "threshold", parseUint(8)))
	b.NotAfter = required(p, "not_after", parseUint(64))
	for n := 1; p.err == nil && p.has(fmt.Sprintf("participant_%d.", n)); n++ {
		if n > MaxParticipants {
			p.err = fmt.Errorf("%s: more than %d participants", p.name, MaxParticipants)
			break
		}
		b.Participants = append(b.Participants, p.participant(fmt.Sprintf("participant_%d.", n)))
	}
	b.CharonENRs = list(p, "charon_enrs", parseText)
	return b
}

func (p *parser) participant(pre string) Participant {
	o := Participant{}
	o.Name = required(p, pre+"name", parseText)
	o.SetupHash = required(p, pre+"setup_sha256", parse32)
	o.OperatorKey = required(p, pre+"operator_key", parse32)
	o.Verifier = required(p, pre+"verifier", ParseVerifier)
	if p.err != nil {
		return o
	}
	for v := VerifierNitro; v <= VerifierDev; v++ {
		for _, k := range verifierKeys(v) {
			if l := p.vals[pre+k]; len(l) > 0 && !slices.Contains(verifierKeys(o.Verifier), k) {
				p.fail(l[0].line, pre+k, fmt.Errorf("does not apply to verifier %s", o.Verifier))
				return o
			}
		}
	}
	if k := o.Verifier.imageKind(); k != 0 {
		im := required(p, pre+"image", parseImage)
		if p.err == nil && im.Kind != k {
			p.fail(p.vals[pre+"image"][0].line, pre+"image", fmt.Errorf("a %s image, verifier %s takes %s", im.Kind, o.Verifier, k))
		}
		o.Image = im.Measurement
	}
	switch o.Verifier {
	case VerifierNitro:
		o.NitroPCR3 = required(p, pre+"nitro_pcr3", parse48)
		if v, ok := one(p, pre+"nitro_pcr8", parse48); ok {
			o.NitroPCR8 = &v
		}
	case VerifierAzure:
		o.MAAHost = required(p, pre+"maa_host", parseText)
		o.Compliance = required(p, pre+"compliance_status", ParseCompliance)
	case VerifierGCP:
		o.GCPAudience = required(p, pre+"gcp_audience", parseText)
		o.GCPHWModels = list(p, pre+"gcp_hwmodels", parseText)
		slices.Sort(o.GCPHWModels)
		o.GCPIssuer = required(p, pre+"gcp_issuer", parseText)
		o.GCPServiceAccount = required(p, pre+"gcp_service_account", parseText)
		o.GCPProjectID = required(p, pre+"gcp_project_id", parseText)
	}
	return o
}

// ParseBody reads the human form of an order body. name is used in errors.
func ParseBody(name string, data []byte) (*Body, error) {
	p, err := newParser(name, data)
	if err != nil {
		return nil, err
	}
	b := p.body()
	if err := p.done(); err != nil {
		return nil, err
	}
	if _, err := b.Encode(); err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	return b, nil
}

// Parse reads the human form of a signed order.
func Parse(name string, data []byte) (*Order, error) {
	p, err := newParser(name, data)
	if err != nil {
		return nil, err
	}
	o := &Order{Body: *p.body()}
	o.Approvals = list(p, "approver_signature", parseApproval)
	slices.SortStableFunc(o.Approvals, func(a, b setupwire.Approval) int { return cmp.Compare(a.Position, b.Position) })
	if err := p.done(); err != nil {
		return nil, err
	}
	if _, err := o.Encode(); err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	return o, nil
}

// printer writes the canonical human form.
type printer struct{ b strings.Builder }

func (w *printer) kv(key string, val any) { fmt.Fprintf(&w.b, "%s = %v\n", key, val) }
func (w *printer) note(format string, args ...any) {
	fmt.Fprintf(&w.b, "# %s\n", fmt.Sprintf(format, args...))
}
func (w *printer) blank() { w.b.WriteString("\n") }

func hexOf(b []byte) string { return "0x" + hex.EncodeToString(b) }

// unixNote is the UTC time of t for a comment.
func unixNote(t uint64) string {
	if t > 253402300799 { // after 9999-12-31
		return "far future"
	}
	return time.Unix(int64(t), 0).UTC().Format(time.RFC3339)
}

// FormatImage writes an allowed-images entry as setupwire's human form does.
func FormatImage(im setupwire.Image) string {
	if im.Kind == setupwire.ImageNitro && len(im.Measurement) == 144 {
		return fmt.Sprintf("%s %s %s %s", im.Kind, hexOf(im.Measurement[:48]), hexOf(im.Measurement[48:96]), hexOf(im.Measurement[96:]))
	}
	return fmt.Sprintf("%s %s", im.Kind, hexOf(im.Measurement))
}

func formatBody(w *printer, b *Body) {
	w.note("DKG order (setup-phase.md, section 10). Approvers sign the binary form.")
	w.note("Withdrawal credentials and deposit amounts come from each signer's locked group in force.")
	w.kv("cluster_id", hexOf(b.ClusterID[:]))
	w.kv("chain_hash", hexOf(b.ChainHash[:]))
	w.kv("label", b.Label)
	w.kv("path", b.Path)
	w.kv("threshold", b.Threshold)
	w.note("not_after %s: no keys are made from then on", unixNote(b.NotAfter))
	w.kv("not_after", b.NotAfter)
	for i := range b.Participants {
		p := &b.Participants[i]
		pre := fmt.Sprintf("participant_%d.", i+1)
		w.blank()
		w.note("participant %d holds the shares at x = %d", i+1, i+1)
		w.kv(pre+"name", p.Name)
		w.kv(pre+"setup_sha256", hexOf(p.SetupHash[:]))
		w.kv(pre+"operator_key", hexOf(p.OperatorKey[:]))
		formatSettings(w, pre, p)
	}
	if len(b.CharonENRs) > 0 {
		w.blank()
		w.note("the Charon node of each participant, in participant order")
		for _, e := range b.CharonENRs {
			w.kv("charon_enrs", e)
		}
	}
}

// formatSettings writes a participant's verifier, image and settings.
func formatSettings(w *printer, pre string, p *Participant) {
	w.kv(pre+"verifier", p.Verifier)
	if im, ok := p.AllowedImage(); ok {
		w.kv(pre+"image", FormatImage(im))
	}
	switch p.Verifier {
	case VerifierNitro:
		w.kv(pre+"nitro_pcr3", hexOf(p.NitroPCR3[:]))
		if p.NitroPCR8 != nil {
			w.kv(pre+"nitro_pcr8", hexOf(p.NitroPCR8[:]))
		}
	case VerifierAzure:
		w.kv(pre+"maa_host", p.MAAHost)
		w.kv(pre+"compliance_status", p.Compliance)
	case VerifierGCP:
		w.kv(pre+"gcp_audience", p.GCPAudience)
		for _, h := range p.GCPHWModels {
			w.kv(pre+"gcp_hwmodels", h)
		}
		w.kv(pre+"gcp_issuer", p.GCPIssuer)
		w.kv(pre+"gcp_service_account", p.GCPServiceAccount)
		w.kv(pre+"gcp_project_id", p.GCPProjectID)
	}
}

// FormatSettings is the human form of a participant's verifier, image and
// settings, each key with the prefix pre: the lines a DKG order shows for
// them, for another order that names a runner the same way.
func FormatSettings(pre string, p *Participant) string {
	w := &printer{}
	formatSettings(w, pre, p)
	return w.b.String()
}

// Format checks the body and writes its human form.
func (b *Body) Format() ([]byte, error) {
	if err := b.Check(); err != nil {
		return nil, err
	}
	w := &printer{}
	formatBody(w, b)
	return []byte(w.b.String()), nil
}

// Format checks the signed order and writes its human form.
func (o *Order) Format() ([]byte, error) {
	if err := o.check(); err != nil {
		return nil, err
	}
	w := &printer{}
	formatBody(w, &o.Body)
	w.blank()
	w.note("signatures over signer-dkg-order-v1 and the body, by position")
	for _, a := range o.Approvals {
		w.kv("approver_signature", fmt.Sprintf("%d %s", a.Position, hexOf(a.Signature[:])))
	}
	return []byte(w.b.String()), nil
}
