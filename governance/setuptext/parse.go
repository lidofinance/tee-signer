// Package setuptext is the human form of setups, config groups and
// config updates: "key = value" text that operators write and approvers
// read before they sign. Only the operator tools use it (signer-admin,
// setup-tool); a runner reads the binary form (governance/setupwire) and
// never links this package (scripts/check-deps.sh, scripts/check-imports.sh).
package setuptext

import (
	"bytes"
	"cmp"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/lidofinance/tee-signer/governance/setupwire"
	backend "github.com/lidofinance/tee-signer/signer-protocol"
)

// The human form: "key = value" lines,
// as in the TA's policy files (ta/admin/taformat/policyconf.go). '#' starts
// a comment and blank lines do not count. Keys are the setup's field
// names in lower case; parts below the top
// level have dotted keys (slashing_mark_prewrite.block_slots,
// slashing_log_store.bucket). A key that is unknown, set twice, written in
// another case, or that does not apply to the platform is refused, and so
// is a missing one, except change_delay_seconds and gloas_fork_epoch,
// which are optional, and the encrypted_state_store part, present when any
// of its keys is.
//
// A list field repeats its key, one value per line. The approver list
// keeps the order of its lines; the parser sorts the other lists, which is
// the order the binary form needs, and refuses repeats.
//
// Salts: salt.NAME is the salt of the policy leaf NAME (a key of the public,
// locked or open part), platform_salt the salt of platform_commitment. A
// file gives every salt of its kind or none: an operator's setup file has
// none, and signer-admin setup draws them; Format writes them all, so a
// setup read back from its human form has the same setup_hash.
//
// Values: decimal integers; hex with or without 0x; true or false; amounts
// as "32 ETH", "0.5 ETH" or "1000000000 Gwei"; CA certificates as base64
// DER on one line; enum names as in the comments of Format's output.
//
// Format writes the canonical form. Parsing it gives the same values, so
// binary -> human -> binary returns the same bytes.

// MaxHuman bounds a human file.
const MaxHuman = 4 * setupwire.MaxSetup

var keyRE = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*$`)

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
		if !keyRE.MatchString(key) {
			if keyRE.MatchString(strings.ToLower(key)) {
				return nil, fmt.Errorf("%s:%d: key %q: keys are lower case", name, n, key)
			}
			return nil, fmt.Errorf("%s:%d: bad key %q", name, n, key)
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

// get returns the value of a key that may be set once.
func (p *parser) get(key string) (string, int, bool) {
	if p.err != nil {
		return "", 0, false
	}
	p.used[key] = true
	v := p.vals[key]
	switch {
	case len(v) == 0:
		return "", 0, false
	case len(v) > 1:
		p.fail(v[1].line, key, fmt.Errorf("set again (first on line %d)", v[0].line))
		return "", 0, false
	}
	return v[0].val, v[0].line, true
}

// has reports whether any key starts with prefix.
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

// scalar reads a required key.
func scalar[T any](p *parser, key string, parse func(string) (T, error)) T {
	var zero T
	s, n, ok := p.get(key)
	if !ok {
		if p.err == nil {
			p.err = fmt.Errorf("%s: %s is missing", p.name, key)
		}
		return zero
	}
	v, err := parse(s)
	if err != nil {
		p.fail(n, key, err)
		return zero
	}
	return v
}

// optional reads a key that may be absent.
func optional[T any](p *parser, key string, parse func(string) (T, error)) *T {
	s, n, ok := p.get(key)
	if !ok {
		return nil
	}
	v, err := parse(s)
	if err != nil {
		p.fail(n, key, err)
		return nil
	}
	return &v
}

type lined[T any] struct {
	v    T
	line int
}

// listOf reads every line of a list key, in file order.
func listOf[T any](p *parser, key string, parse func(string) (T, error)) []lined[T] {
	if p.err != nil {
		return nil
	}
	p.used[key] = true
	var out []lined[T]
	for _, l := range p.vals[key] {
		v, err := parse(l.val)
		if err != nil {
			p.fail(l.line, key, err)
			return nil
		}
		out = append(out, lined[T]{v, l.line})
	}
	return out
}

// sortedSet sorts a list and refuses repeats.
func sortedSet[T any](p *parser, key string, xs []lined[T], cmp func(a, b T) int) []T {
	slices.SortStableFunc(xs, func(a, b lined[T]) int { return cmp(a.v, b.v) })
	var out []T
	for i, x := range xs {
		if i > 0 && cmp(xs[i-1].v, x.v) == 0 {
			p.fail(x.line, key, fmt.Errorf("repeats the entry of line %d", xs[i-1].line))
			return nil
		}
		out = append(out, x.v)
	}
	return out
}

func values[T any](xs []lined[T]) []T {
	var out []T
	for _, x := range xs {
		out = append(out, x.v)
	}
	return out
}

func parseUint(bitSize int) func(string) (uint64, error) {
	return func(s string) (uint64, error) {
		v, err := strconv.ParseUint(s, 10, bitSize)
		if err != nil {
			return 0, fmt.Errorf("%q: want a decimal number below 2^%d", s, bitSize)
		}
		return v, nil
	}
}

var parseU64 = parseUint(64)

func parseText(s string) (string, error) { return s, nil }

func parseBool(s string) (bool, error) {
	switch s {
	case "true":
		return true, nil
	case "false":
		return false, nil
	}
	return false, fmt.Errorf("%q: want true or false", s)
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

func parseRoot(s string) (backend.Root, error) {
	b, err := parse32(s)
	return backend.Root(b), err
}

func parseVersion(s string) (backend.Version, error) {
	b, err := parseHex(s, 4)
	if err != nil {
		return backend.Version{}, err
	}
	return backend.Version(b), nil
}

func parseAddress(s string) (backend.Address, error) {
	b, err := parseHex(s, 20)
	if err != nil {
		return backend.Address{}, err
	}
	return backend.Address(b), nil
}

func enumValue(names []string, s string) (uint8, bool) {
	for i, n := range names {
		if n != "" && n == s {
			return uint8(i), true
		}
	}
	return 0, false
}

func enumParser(names []string, want string) func(string) (uint8, error) {
	return func(s string) (uint8, error) {
		if v, ok := enumValue(names, s); ok {
			return v, nil
		}
		return 0, fmt.Errorf("%q: want %s", s, want)
	}
}

// parseAmount reads "N ETH", "N.F ETH" (at most 9 digits of fraction, 1
// Gwei) or "N Gwei" and returns Gwei. The unit is required.
func parseAmount(s string) (uint64, error) {
	f := strings.Fields(s)
	if len(f) != 2 {
		return 0, fmt.Errorf("%q: want N ETH or N Gwei", s)
	}
	digits := func(t string) bool {
		return t != "" && strings.Trim(t, "0123456789") == ""
	}
	switch f[1] {
	case "Gwei":
		if !digits(f[0]) {
			return 0, fmt.Errorf("%q: want N Gwei", s)
		}
		return parseU64(f[0])
	case "ETH":
		whole, frac, dot := strings.Cut(f[0], ".")
		if !digits(whole) || dot && (!digits(frac) || len(frac) > 9) {
			return 0, fmt.Errorf("%q: want N ETH, with at most 9 digits after the point", s)
		}
		w, err := parseU64(whole)
		if err != nil || w > math.MaxUint64/gweiPerETH {
			return 0, fmt.Errorf("%q is too large", s)
		}
		g := w * gweiPerETH
		if dot {
			fr, _ := strconv.ParseUint(frac+strings.Repeat("0", 9-len(frac)), 10, 64)
			if g+fr < g {
				return 0, fmt.Errorf("%q is too large", s)
			}
			g += fr
		}
		return g, nil
	}
	return 0, fmt.Errorf("%q: unit %q, want ETH or Gwei", s, f[1])
}

func parseBase64(s string) ([]byte, error) {
	b, err := base64.StdEncoding.Strict().DecodeString(s)
	if err != nil {
		return nil, errors.New("want base64 (DER)")
	}
	return b, nil
}

// parseImage reads "nitro PCR0 PCR1 PCR2" or "azure|gcp|ta HASH".
func parseImage(s string) (setupwire.Image, error) {
	f := strings.Fields(s)
	if len(f) == 0 {
		return setupwire.Image{}, errors.New("want KIND MEASUREMENT")
	}
	k, ok := enumValue(imageNames, f[0])
	if !ok {
		return setupwire.Image{}, fmt.Errorf("kind %q, want nitro, azure, gcp or ta", f[0])
	}
	im := setupwire.Image{Kind: setupwire.ImageKind(k)}
	parts := 1
	if im.Kind == setupwire.ImageNitro {
		parts = 3
	}
	if len(f) != 1+parts {
		return setupwire.Image{}, fmt.Errorf("a %s image takes %d hex values", im.Kind, parts)
	}
	for _, h := range f[1:] {
		b, err := parseHex(h, im.Kind.Size()/parts)
		if err != nil {
			return setupwire.Image{}, err
		}
		im.Measurement = append(im.Measurement, b...)
	}
	return im, nil
}

// parseFork reads "EPOCH VERSION".
func parseFork(s string) (setupwire.Fork, error) {
	f := strings.Fields(s)
	if len(f) != 2 {
		return setupwire.Fork{}, errors.New("want EPOCH VERSION")
	}
	e, err := parseU64(f[0])
	if err != nil {
		return setupwire.Fork{}, err
	}
	v, err := parseVersion(f[1])
	return setupwire.Fork{Epoch: e, Version: v}, err
}

// parseApproval reads "POSITION SIGNATURE".
func parseApproval(s string) (setupwire.Approval, error) {
	f := strings.Fields(s)
	if len(f) != 2 {
		return setupwire.Approval{}, errors.New("want POSITION SIGNATURE")
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

// parseSlotTime reads "EPOCH SECONDS".
func parseSlotTime(s string) (setupwire.SlotTimeChange, error) {
	f := strings.Fields(s)
	if len(f) != 2 {
		return setupwire.SlotTimeChange{}, errors.New("want EPOCH SECONDS_PER_SLOT")
	}
	e, err := parseU64(f[0])
	if err != nil {
		return setupwire.SlotTimeChange{}, err
	}
	secs, err := parseU64(f[1])
	return setupwire.SlotTimeChange{Epoch: e, SecondsPerSlot: secs}, err
}

// salts reads salt.NAME for every name: all of them, or none (nil).
func (p *parser) salts(names []string) setupwire.Salts {
	if p.err != nil {
		return nil
	}
	given := 0
	for _, n := range names {
		if len(p.vals[saltPrefix+n]) > 0 {
			given++
		}
	}
	if given == 0 {
		for _, n := range names {
			p.used[saltPrefix+n] = true
		}
		return nil
	}
	out := make(setupwire.Salts, len(names))
	for i, n := range names {
		out[i] = scalar(p, saltPrefix+n, parse32)
	}
	return out
}

// ParseSetup reads a human setup file. name is used in errors. A file
// without salts gives a setup that passes CheckValues but not Check:
// signer-admin setup draws its salts.
func ParseSetup(name string, data []byte) (*setupwire.Setup, error) {
	p, err := newParser(name, data)
	if err != nil {
		return nil, err
	}
	version, n, ok := p.get("setup_format_version")
	switch {
	case !ok && p.err == nil:
		p.err = fmt.Errorf("%s: setup_format_version is missing", name)
	case ok && version != strconv.Itoa(setupwire.FormatVersion):
		p.fail(n, "setup_format_version", fmt.Errorf("%q, want %d", version, setupwire.FormatVersion))
	}
	s := &setupwire.Setup{}
	s.SignerName = scalar(p, "signer_name", parseText)
	s.ClusterID = scalar(p, "cluster_id", parse32)
	s.HandoverGeneration = scalar(p, "handover_generation", parseU64)
	p.chain(&s.Chain)
	p.safety(&s.Safety)
	s.MaxKeys = uint32(scalar(p, "max_keys", parseUint(32)))
	s.SlashingLogMinLockDays = uint32(scalar(p, "slashing_log_min_lock_days", parseUint(32)))
	s.SigningMode = setupwire.SigningMode(scalar(p, "signing_mode", enumParser(signingModeNames, "threshold or single")))
	p.platform(&s.Platform)
	p.locked(&s.Locked)
	p.open(&s.Open)
	s.PolicySalts = setupwire.PolicySalts{Public: p.salts(publicLeafNames), Locked: p.salts(lockedLeafNames), Open: p.salts(openLeafNames)}
	if ps := optional(p, "platform_salt", parse32); ps != nil {
		s.PlatformSalt = *ps
	}
	if err := p.done(); err != nil {
		return nil, err
	}
	if !s.Salted() {
		if err := s.CheckValues(); err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		return s, nil
	}
	if _, err := s.Encode(); err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	return s, nil
}

// ParseLocked reads a human file of the locked group's values (no salts).
func ParseLocked(name string, data []byte) (*setupwire.Locked, error) {
	p, err := newParser(name, data)
	if err != nil {
		return nil, err
	}
	l := &setupwire.Locked{}
	p.locked(l)
	if err := p.done(); err != nil {
		return nil, err
	}
	if _, err := l.Encode(); err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	return l, nil
}

// ParseOpen reads a human file of the open group's values (no salts).
func ParseOpen(name string, data []byte) (*setupwire.Open, error) {
	p, err := newParser(name, data)
	if err != nil {
		return nil, err
	}
	o := &setupwire.Open{}
	p.open(o)
	if err := p.done(); err != nil {
		return nil, err
	}
	if _, err := o.Encode(); err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	return o, nil
}

// ParseUpdateBody reads the human form of an update body (what
// FormatUpdateBody writes for signer-admin show). Without salts it passes CheckValues
// only.
func ParseUpdateBody(name string, data []byte) (*setupwire.UpdateBody, error) {
	p, err := newParser(name, data)
	if err != nil {
		return nil, err
	}
	u := p.body()
	if err := p.done(); err != nil {
		return nil, err
	}
	if u.Salts == nil {
		if err := u.CheckValues(); err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		return u, nil
	}
	if _, err := u.Encode(); err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	return u, nil
}

// ParseUpdate reads the human form of a signed update.
func ParseUpdate(name string, data []byte) (*setupwire.Update, error) {
	p, err := newParser(name, data)
	if err != nil {
		return nil, err
	}
	u := &setupwire.Update{Body: *p.body()}
	byPos := func(a, b setupwire.Approval) int { return cmp.Compare(a.Position, b.Position) }
	u.Approvals = sortedSet(p, "approver_signature", listOf(p, "approver_signature", parseApproval), byPos)
	u.NewSet = sortedSet(p, "new_key_signature", listOf(p, "new_key_signature", parseApproval), byPos)
	if err := p.done(); err != nil {
		return nil, err
	}
	if _, err := u.Encode(); err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	return u, nil
}

func (p *parser) chain(c *setupwire.Chain) {
	c.GenesisValidatorsRoot = scalar(p, "genesis_validators_root", parseRoot)
	c.GenesisForkVersion = scalar(p, "genesis_fork_version", parseVersion)
	c.GenesisTime = scalar(p, "genesis_time", parseU64)
	c.SecondsPerSlot = scalar(p, "seconds_per_slot", parseU64)
	c.SlotsPerEpoch = scalar(p, "slots_per_epoch", parseU64)
	c.Preset = setupwire.Preset(scalar(p, "preset", enumParser(presetNames, "mainnet or minimal")))
	c.VoluntaryExitForkVersion = scalar(p, "voluntary_exit_fork_version", parseVersion)
}

func (p *parser) safety(s *setupwire.Safety) {
	s.MaxSignEpochsAheadOfClock = scalar(p, "max_sign_epochs_ahead_of_clock", parseU64)
	s.SlashingMarkPrewrite.BlockSlots = scalar(p, "slashing_mark_prewrite.block_slots", parseU64)
	s.SlashingMarkPrewrite.SourceEpochs = scalar(p, "slashing_mark_prewrite.source_epochs", parseU64)
	s.SlashingMarkPrewrite.TargetEpochs = scalar(p, "slashing_mark_prewrite.target_epochs", parseU64)
}

// part reads prefix.KEY for the keys of platform pl, and refuses the keys
// of the other platforms.
func (p *parser) part(pl setupwire.Platform, prefix string, keys [][]string) map[string]string {
	if p.err != nil {
		return nil
	}
	for _, ks := range keys {
		for _, k := range ks {
			full := prefix + "." + k
			if v := p.vals[full]; len(v) > 0 && !slices.Contains(keys[pl], k) {
				p.fail(v[0].line, full, fmt.Errorf("does not apply to %s", pl))
				return nil
			}
		}
	}
	out := map[string]string{}
	for _, k := range keys[pl] {
		out[k] = scalar(p, prefix+"."+k, parseText)
	}
	return out
}

func (p *parser) store(pl setupwire.Platform, prefix string) setupwire.Store {
	v := p.part(pl, prefix, storeKeys)
	return setupwire.Store{Bucket: v["bucket"], Region: v["region"], Account: v["account"], Container: v["container"],
		Subscription: v["subscription"], ResourceGroup: v["resource_group"], Dir: v["dir"]}
}

func (p *parser) platform(c *setupwire.PlatformConfig) {
	c.Platform = scalar(p, "platform", setupwire.ParsePlatform)
	c.AllowedClientCA = sortedSet(p, "allowed_client_ca", listOf(p, "allowed_client_ca", parseBase64), bytes.Compare)
	c.SlashingLogStore = p.store(c.Platform, "slashing_log_store")
	if p.has("encrypted_state_store.") {
		st := p.store(c.Platform, "encrypted_state_store")
		c.EncryptedStateStore = &st
	}
	v := p.part(c.Platform, "sealing_key_release", keyReleaseKeys)
	c.SealingKeyRelease = setupwire.KeyRelease{Region: v["region"], KMSKeyID: v["kms_key_id"], MAAEndpoint: v["maa_endpoint"],
		AKVEndpoint: v["akv_endpoint"], KID: v["kid"], WIFProvider: v["wif_provider"], KMSKey: v["kms_key"],
		AttestAudience: v["attest_audience"]}
	if a := optional(p, "sealing_key_release.no_lock_accepted", parseBool); a != nil {
		c.SealingKeyRelease.NoLockAccepted = *a
	}
	if a := optional(p, "sealing_key_release.unsafe_single_key_accepted", parseBool); a != nil {
		c.SealingKeyRelease.UnsafeSingleKeyAccepted = *a
	}
}

func (p *parser) locked(l *setupwire.Locked) {
	l.Approvers.Keys = values(listOf(p, "approvers", parse32))
	l.Approvers.ApprovalsNeeded = uint8(scalar(p, "approvals_needed", parseUint(8)))
	l.ChangeDelaySeconds = optional(p, "change_delay_seconds", parseU64)
	l.AllowedImageMeasurements = sortedSet(p, "allowed_image_measurements", listOf(p, "allowed_image_measurements", parseImage), setupwire.CompareImages)
	l.AllowedFeeRecipients = sortedSet(p, "allowed_fee_recipients", listOf(p, "allowed_fee_recipients", parseAddress),
		func(a, b backend.Address) int { return bytes.Compare(a[:], b[:]) })
	l.BuilderGasLimitMin = scalar(p, "builder_gas_limit_min", parseU64)
	l.BuilderGasLimitMax = scalar(p, "builder_gas_limit_max", parseU64)
	l.BuilderRegistrationMaxFutureSeconds = scalar(p, "builder_registration_max_future_seconds", parseU64)
	l.MinActivationBalance = scalar(p, "min_activation_balance", parseAmount)
	l.MaxEffectiveBalance = scalar(p, "max_effective_balance", parseAmount)
	l.WithdrawalCredentials = scalar(p, "withdrawal_credentials", parseRoot)
	l.AllowedDepositAmounts = sortedSet(p, "allowed_deposit_amounts", listOf(p, "allowed_deposit_amounts", parseAmount), cmp.Compare[uint64])
	l.AllowUnverifiedNonslashableSigning = scalar(p, "allow_unverified_nonslashable_signing", parseBool)
	domains := sortedSet(p, "bare_root_domains", listOf(p, "bare_root_domains",
		enumParser(rootDomainNames, "randao, selection_proof, aggregate_and_proof, sync_committee, sync_committee_selection_proof or contribution_and_proof")),
		cmp.Compare[uint8])
	for _, d := range domains {
		l.BareRootDomains |= 1 << d
	}
	l.SlotTimeChanges = sortedSet(p, "slot_time_changes", listOf(p, "slot_time_changes", parseSlotTime),
		func(a, b setupwire.SlotTimeChange) int { return cmp.Compare(a.Epoch, b.Epoch) })
	l.AllowedBuilderRequestAuthDataRoots = sortedSet(p, "allowed_builder_request_auth_data_roots",
		listOf(p, "allowed_builder_request_auth_data_roots", parseRoot), func(a, b backend.Root) int { return bytes.Compare(a[:], b[:]) })
}

func (p *parser) open(o *setupwire.Open) {
	o.ForkSchedule = sortedSet(p, "fork_schedule", listOf(p, "fork_schedule", parseFork), func(a, b setupwire.Fork) int { return cmp.Compare(a.Epoch, b.Epoch) })
	o.GloasForkEpoch = optional(p, "gloas_fork_epoch", parseU64)
}

func (p *parser) body() *setupwire.UpdateBody {
	u := &setupwire.UpdateBody{}
	u.ClusterID = scalar(p, "cluster_id", parse32)
	u.ChainHash = scalar(p, "chain_hash", parse32)
	u.Group = setupwire.Group(scalar(p, "group", enumParser(groupNames, "locked or open")))
	u.Version = scalar(p, "version", parseU64)
	u.PrevHash = scalar(p, "prev_hash", parse32)
	u.ActivateAt = scalar(p, "activate_at", parseU64)
	switch u.Group {
	case setupwire.GroupLocked:
		u.Locked = &setupwire.Locked{}
		p.locked(u.Locked)
		u.Salts = p.salts(lockedLeafNames)
	case setupwire.GroupOpen:
		u.Open = &setupwire.Open{}
		p.open(u.Open)
		u.Salts = p.salts(openLeafNames)
	}
	return u
}
