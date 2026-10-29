package setupwire

import (
	"bytes"
	"cmp"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/buildflavor"
)

// The human form (setup-phase.md, section 2, step 1): "key = value" lines,
// as in the TA's policy files (ta/admin/taformat/policyconf.go). '#' starts
// a comment and blank lines do not count. Keys are the field names of
// attestation-prover.md ("Field names") in lower case; parts below the top
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
// none, and signer-config setup draws them; Format writes them all, so a
// setup read back from its human form has the same setup_hash.
//
// Values: decimal integers; hex with or without 0x; true or false; amounts
// as "32 ETH", "0.5 ETH" or "1000000000 Gwei"; CA certificates as base64
// DER on one line; enum names as in the comments of Format's output.
//
// Format writes the canonical form. Parsing it gives the same values, so
// binary -> human -> binary returns the same bytes.

// MaxHuman bounds a human file.
const MaxHuman = 4 * MaxSetup

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

func enumParser(names []string, want string) func(string) (uint8, error) {
	return func(s string) (uint8, error) {
		if v, ok := enumValue(names, s); ok {
			return v, nil
		}
		return 0, fmt.Errorf("%q: want %s", s, want)
	}
}

const gweiPerETH = 1_000_000_000

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

func formatAmount(g uint64) string {
	if g%gweiPerETH == 0 {
		return fmt.Sprintf("%d ETH", g/gweiPerETH)
	}
	return fmt.Sprintf("%d Gwei", g)
}

func parseBase64(s string) ([]byte, error) {
	b, err := base64.StdEncoding.Strict().DecodeString(s)
	if err != nil {
		return nil, errors.New("want base64 (DER)")
	}
	return b, nil
}

// parseImage reads "nitro PCR0 PCR1 PCR2" or "azure|gcp|ta HASH".
func parseImage(s string) (Image, error) {
	f := strings.Fields(s)
	if len(f) == 0 {
		return Image{}, errors.New("want KIND MEASUREMENT")
	}
	k, ok := enumValue(imageNames, f[0])
	if !ok {
		return Image{}, fmt.Errorf("kind %q, want nitro, azure, gcp or ta", f[0])
	}
	im := Image{Kind: ImageKind(k)}
	parts := 1
	if im.Kind == ImageNitro {
		parts = 3
	}
	if len(f) != 1+parts {
		return Image{}, fmt.Errorf("a %s image takes %d hex values", im.Kind, parts)
	}
	for _, h := range f[1:] {
		b, err := parseHex(h, im.Kind.Size()/parts)
		if err != nil {
			return Image{}, err
		}
		im.Measurement = append(im.Measurement, b...)
	}
	return im, nil
}

// parseFork reads "EPOCH VERSION".
func parseFork(s string) (Fork, error) {
	f := strings.Fields(s)
	if len(f) != 2 {
		return Fork{}, errors.New("want EPOCH VERSION")
	}
	e, err := parseU64(f[0])
	if err != nil {
		return Fork{}, err
	}
	v, err := parseVersion(f[1])
	return Fork{Epoch: e, Version: v}, err
}

// parseApproval reads "POSITION SIGNATURE".
func parseApproval(s string) (Approval, error) {
	f := strings.Fields(s)
	if len(f) != 2 {
		return Approval{}, errors.New("want POSITION SIGNATURE")
	}
	pos, err := parseUint(8)(f[0])
	if err != nil {
		return Approval{}, err
	}
	sig, err := parseHex(f[1], 64)
	if err != nil {
		return Approval{}, err
	}
	return Approval{Position: uint8(pos), Signature: [64]byte(sig)}, nil
}

// parseSlotTime reads "EPOCH SECONDS".
func parseSlotTime(s string) (SlotTimeChange, error) {
	f := strings.Fields(s)
	if len(f) != 2 {
		return SlotTimeChange{}, errors.New("want EPOCH SECONDS_PER_SLOT")
	}
	e, err := parseU64(f[0])
	if err != nil {
		return SlotTimeChange{}, err
	}
	secs, err := parseU64(f[1])
	return SlotTimeChange{Epoch: e, SecondsPerSlot: secs}, err
}

// leafNames are the leaf names of each group, in leaf order.
var (
	publicLeafNames = fieldNames((&Setup{}).publicFields())
	lockedLeafNames = fieldNames((&Locked{}).fields())
	openLeafNames   = fieldNames((&Open{}).fields())
)

func fieldNames(fs []field) []string {
	out := make([]string, len(fs))
	for i, f := range fs {
		out[i] = f.name
	}
	return out
}

// LeafNames are the names of the leaves of the public part and of the two
// groups, in leaf order.
func LeafNames() (public, locked, open []string) {
	return slices.Clone(publicLeafNames), slices.Clone(lockedLeafNames), slices.Clone(openLeafNames)
}

const saltPrefix = "salt."

// salts reads salt.NAME for every name: all of them, or none (nil).
func (p *parser) salts(names []string) Salts {
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
	out := make(Salts, len(names))
	for i, n := range names {
		out[i] = scalar(p, saltPrefix+n, parse32)
	}
	return out
}

// ParseSetup reads a human setup file. name is used in errors. A file
// without salts gives a setup that passes CheckValues but not Check:
// signer-config setup draws its salts.
func ParseSetup(name string, data []byte) (*Setup, error) {
	p, err := newParser(name, data)
	if err != nil {
		return nil, err
	}
	version, n, ok := p.get("setup_format_version")
	switch {
	case !ok && p.err == nil:
		p.err = fmt.Errorf("%s: setup_format_version is missing", name)
	case ok && version != strconv.Itoa(FormatVersion):
		p.fail(n, "setup_format_version", fmt.Errorf("%q, want %d", version, FormatVersion))
	}
	s := &Setup{}
	s.SignerName = scalar(p, "signer_name", parseText)
	s.ClusterID = scalar(p, "cluster_id", parse32)
	s.HandoverGeneration = scalar(p, "handover_generation", parseU64)
	p.chain(&s.Chain)
	p.safety(&s.Safety)
	s.MaxKeys = uint32(scalar(p, "max_keys", parseUint(32)))
	s.SlashingLogMinLockDays = uint32(scalar(p, "slashing_log_min_lock_days", parseUint(32)))
	p.platform(&s.Platform)
	p.locked(&s.Locked)
	p.open(&s.Open)
	s.PolicySalts = PolicySalts{Public: p.salts(publicLeafNames), Locked: p.salts(lockedLeafNames), Open: p.salts(openLeafNames)}
	if ps := optional(p, "platform_salt", parse32); ps != nil {
		s.PlatformSalt = *ps
	}
	if err := p.done(); err != nil {
		return nil, err
	}
	if s.unsalted() {
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

// unsalted reports whether the setup has no salt at all.
func (s *Setup) unsalted() bool {
	p := &s.PolicySalts
	return p.Public == nil && p.Locked == nil && p.Open == nil && s.PlatformSalt == [32]byte{}
}

// ParseLocked reads a human file of the locked group's values (no salts).
func ParseLocked(name string, data []byte) (*Locked, error) {
	p, err := newParser(name, data)
	if err != nil {
		return nil, err
	}
	l := &Locked{}
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
func ParseOpen(name string, data []byte) (*Open, error) {
	p, err := newParser(name, data)
	if err != nil {
		return nil, err
	}
	o := &Open{}
	p.open(o)
	if err := p.done(); err != nil {
		return nil, err
	}
	if _, err := o.Encode(); err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	return o, nil
}

// ParseUpdateBody reads the human form of an update body (what Format
// writes for signer-config show). Without salts it passes CheckValues
// only.
func ParseUpdateBody(name string, data []byte) (*UpdateBody, error) {
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
func ParseUpdate(name string, data []byte) (*Update, error) {
	p, err := newParser(name, data)
	if err != nil {
		return nil, err
	}
	u := &Update{Body: *p.body()}
	byPos := func(a, b Approval) int { return cmp.Compare(a.Position, b.Position) }
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

func (p *parser) chain(c *Chain) {
	c.GenesisValidatorsRoot = scalar(p, "genesis_validators_root", parseRoot)
	c.GenesisForkVersion = scalar(p, "genesis_fork_version", parseVersion)
	c.GenesisTime = scalar(p, "genesis_time", parseU64)
	c.SecondsPerSlot = scalar(p, "seconds_per_slot", parseU64)
	c.SlotsPerEpoch = scalar(p, "slots_per_epoch", parseU64)
	c.Preset = Preset(scalar(p, "preset", enumParser(presetNames, "mainnet or minimal")))
	c.VoluntaryExitForkVersion = scalar(p, "voluntary_exit_fork_version", parseVersion)
}

func (p *parser) safety(s *Safety) {
	s.MaxSignEpochsAheadOfClock = scalar(p, "max_sign_epochs_ahead_of_clock", parseU64)
	s.SlashingMarkPrewrite.BlockSlots = scalar(p, "slashing_mark_prewrite.block_slots", parseU64)
	s.SlashingMarkPrewrite.SourceEpochs = scalar(p, "slashing_mark_prewrite.source_epochs", parseU64)
	s.SlashingMarkPrewrite.TargetEpochs = scalar(p, "slashing_mark_prewrite.target_epochs", parseU64)
}

// The keys of the platform-dependent parts, indexed by platform.
var (
	storeKeys = [][]string{PlatformNitro: {"bucket", "region"}, PlatformAzure: {"account", "container", "subscription", "resource_group"},
		PlatformGCP: {"bucket"}, PlatformDev: {"dir"}}
	keyReleaseKeys = [][]string{PlatformNitro: {"region", "kms_key_id"}, PlatformAzure: {"maa_endpoint", "akv_endpoint", "kid"},
		PlatformGCP: {"wif_provider", "kms_key", "attest_audience"}, PlatformDev: {}}
)

// part reads prefix.KEY for the keys of platform pl, and refuses the keys
// of the other platforms.
func (p *parser) part(pl Platform, prefix string, keys [][]string) map[string]string {
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

func (p *parser) store(pl Platform, prefix string) Store {
	v := p.part(pl, prefix, storeKeys)
	return Store{Bucket: v["bucket"], Region: v["region"], Account: v["account"], Container: v["container"],
		Subscription: v["subscription"], ResourceGroup: v["resource_group"], Dir: v["dir"]}
}

func (p *parser) platform(c *PlatformConfig) {
	c.Platform = scalar(p, "platform", ParsePlatform)
	c.AllowedClientCA = sortedSet(p, "allowed_client_ca", listOf(p, "allowed_client_ca", parseBase64), bytes.Compare)
	c.SlashingLogStore = p.store(c.Platform, "slashing_log_store")
	if p.has("encrypted_state_store.") {
		st := p.store(c.Platform, "encrypted_state_store")
		c.EncryptedStateStore = &st
	}
	v := p.part(c.Platform, "sealing_key_release", keyReleaseKeys)
	c.SealingKeyRelease = KeyRelease{Region: v["region"], KMSKeyID: v["kms_key_id"], MAAEndpoint: v["maa_endpoint"],
		AKVEndpoint: v["akv_endpoint"], KID: v["kid"], WIFProvider: v["wif_provider"], KMSKey: v["kms_key"],
		AttestAudience: v["attest_audience"]}
	if a := optional(p, "sealing_key_release.no_lock_accepted", parseBool); a != nil {
		c.SealingKeyRelease.NoLockAccepted = *a
	}
	c.PeerAttestationHosts = sortedSet(p, "peer_attestation_hosts",
		listOf(p, "peer_attestation_hosts", parseEndpoint), strings.Compare)
}

func parseEndpoint(s string) (string, error) { return s, CheckEndpoint(s) }

func (p *parser) locked(l *Locked) {
	l.Approvers.Keys = values(listOf(p, "approvers", parse32))
	l.Approvers.ApprovalsNeeded = uint8(scalar(p, "approvals_needed", parseUint(8)))
	l.ChangeDelaySeconds = optional(p, "change_delay_seconds", parseU64)
	l.AllowedImageMeasurements = sortedSet(p, "allowed_image_measurements", listOf(p, "allowed_image_measurements", parseImage), compareImages)
	l.AllowedFeeRecipients = sortedSet(p, "allowed_fee_recipients", listOf(p, "allowed_fee_recipients", parseAddress),
		func(a, b backend.Address) int { return bytes.Compare(a[:], b[:]) })
	l.BuilderGasLimitMin = scalar(p, "builder_gas_limit_min", parseU64)
	l.BuilderGasLimitMax = scalar(p, "builder_gas_limit_max", parseU64)
	l.BuilderRegistrationMaxFutureSeconds = scalar(p, "builder_registration_max_future_seconds", parseU64)
	l.ExitAllowedValidators = sortedSet(p, "exit_allowed_validators", listOf(p, "exit_allowed_validators", parseU64), cmp.Compare[uint64])
	l.ExitStakeCapPerDay = scalar(p, "exit_stake_cap_per_day", parseAmount)
	l.ExitApprovalsNeeded = uint8(scalar(p, "exit_approvals_needed", parseUint(8)))
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
		func(a, b SlotTimeChange) int { return cmp.Compare(a.Epoch, b.Epoch) })
	l.AllowedBuilderRequestAuthDataRoots = sortedSet(p, "allowed_builder_request_auth_data_roots",
		listOf(p, "allowed_builder_request_auth_data_roots", parseRoot), func(a, b backend.Root) int { return bytes.Compare(a[:], b[:]) })
}

func (p *parser) open(o *Open) {
	o.ForkSchedule = sortedSet(p, "fork_schedule", listOf(p, "fork_schedule", parseFork), func(a, b Fork) int { return cmp.Compare(a.Epoch, b.Epoch) })
	o.GloasForkEpoch = optional(p, "gloas_fork_epoch", parseU64)
}

func (p *parser) body() *UpdateBody {
	u := &UpdateBody{}
	u.ClusterID = scalar(p, "cluster_id", parse32)
	u.ChainHash = scalar(p, "chain_hash", parse32)
	u.Group = Group(scalar(p, "group", enumParser(groupNames, "locked or open")))
	u.Version = scalar(p, "version", parseU64)
	u.PrevHash = scalar(p, "prev_hash", parse32)
	u.ActivateAt = scalar(p, "activate_at", parseU64)
	switch u.Group {
	case GroupLocked:
		u.Locked = &Locked{}
		p.locked(u.Locked)
		u.Salts = p.salts(lockedLeafNames)
	case GroupOpen:
		u.Open = &Open{}
		p.open(u.Open)
		u.Salts = p.salts(openLeafNames)
	}
	return u
}

// printer writes the canonical human form.
type printer struct{ b strings.Builder }

func (w *printer) kv(key string, val any) { fmt.Fprintf(&w.b, "%s = %v\n", key, val) }

// note writes a comment line. Bytes outside printable ASCII become '?', so
// text from a certificate can never start a line of its own.
func (w *printer) note(format string, args ...any) {
	s := []byte(fmt.Sprintf(format, args...))
	for i, c := range s {
		if c < 0x20 || c > 0x7e {
			s[i] = '?'
		}
	}
	fmt.Fprintf(&w.b, "# %s\n", s)
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

// Format checks the setup and writes its human form.
func (s *Setup) Format() ([]byte, error) {
	if err := s.Check(); err != nil {
		return nil, err
	}
	w := &printer{}
	w.note("Signer setup, format %d (attestation-prover.md, \"Signer changes\"). setup_hash is over policy_root", FormatVersion)
	w.note("(the salted leaves of the public part and the two groups) and platform_commitment (the private part).")
	w.kv("setup_format_version", FormatVersion)
	w.kv("signer_name", s.SignerName)
	w.kv("cluster_id", hexOf(s.ClusterID[:]))
	w.kv("handover_generation", s.HandoverGeneration)
	w.blank()
	w.note("chain: public, fixed for the life of the signer")
	c := &s.Chain
	w.kv("genesis_validators_root", hexOf(c.GenesisValidatorsRoot[:]))
	w.kv("genesis_fork_version", hexOf(c.GenesisForkVersion[:]))
	w.kv("genesis_time", c.GenesisTime)
	w.kv("seconds_per_slot", c.SecondsPerSlot)
	w.kv("slots_per_epoch", c.SlotsPerEpoch)
	w.kv("preset", c.Preset)
	w.kv("voluntary_exit_fork_version", hexOf(c.VoluntaryExitForkVersion[:]))
	w.blank()
	w.note("safety: public, fixed; the floor margin is max_sign_epochs_ahead_of_clock + 1")
	w.kv("max_sign_epochs_ahead_of_clock", s.Safety.MaxSignEpochsAheadOfClock)
	w.kv("slashing_mark_prewrite.block_slots", s.Safety.SlashingMarkPrewrite.BlockSlots)
	w.kv("slashing_mark_prewrite.source_epochs", s.Safety.SlashingMarkPrewrite.SourceEpochs)
	w.kv("slashing_mark_prewrite.target_epochs", s.Safety.SlashingMarkPrewrite.TargetEpochs)
	w.kv("max_keys", s.MaxKeys)
	w.kv("slashing_log_min_lock_days", s.SlashingLogMinLockDays)
	w.blank()
	w.note("platform: private, fixed")
	formatPlatform(w, &s.Platform)
	w.blank()
	formatLocked(w, &s.Locked)
	w.blank()
	formatOpen(w, &s.Open)
	w.blank()
	w.note("salts: one per policy leaf (the same for every signer of the cluster), and the platform salt")
	formatSalts(w, publicLeafNames, s.PolicySalts.Public)
	formatSalts(w, lockedLeafNames, s.PolicySalts.Locked)
	formatSalts(w, openLeafNames, s.PolicySalts.Open)
	w.kv("platform_salt", hexOf(s.PlatformSalt[:]))
	return []byte(w.b.String()), nil
}

func formatSalts(w *printer, names []string, salts Salts) {
	for i, n := range names {
		w.kv(saltPrefix+n, hexOf(salts[i][:]))
	}
}

func formatPlatform(w *printer, p *PlatformConfig) {
	w.kv("platform", p.Platform)
	for _, der := range p.AllowedClientCA {
		sum := sha256.Sum256(der)
		if c, err := x509.ParseCertificate(der); err == nil {
			w.note("%s, sha256 %x", c.Subject, sum)
		}
		w.kv("allowed_client_ca", base64.StdEncoding.EncodeToString(der))
	}
	formatStore(w, p.Platform, "slashing_log_store", &p.SlashingLogStore)
	if p.EncryptedStateStore != nil {
		formatStore(w, p.Platform, "encrypted_state_store", p.EncryptedStateStore)
	}
	k := &p.SealingKeyRelease
	vals := map[string]string{"region": k.Region, "kms_key_id": k.KMSKeyID, "maa_endpoint": k.MAAEndpoint,
		"akv_endpoint": k.AKVEndpoint, "kid": k.KID, "wif_provider": k.WIFProvider, "kms_key": k.KMSKey,
		"attest_audience": k.AttestAudience}
	for _, name := range keyReleaseKeys[p.Platform] {
		w.kv("sealing_key_release."+name, vals[name])
	}
	if k.NoLockAccepted {
		w.note("Cloud KMS has no lock on the key rule; this setup accepts that, and a mainnet runner starts anyway")
		w.kv("sealing_key_release.no_lock_accepted", true)
	}
	if len(p.PeerAttestationHosts) > 0 {
		w.note("hosts the handover verifier fetches key sets from; a nitro enclave reaches no other host besides its fixed routes")
	}
	for _, e := range p.PeerAttestationHosts {
		w.kv("peer_attestation_hosts", e)
	}
}

func formatStore(w *printer, pl Platform, prefix string, s *Store) {
	vals := map[string]string{"bucket": s.Bucket, "region": s.Region, "account": s.Account, "container": s.Container,
		"subscription": s.Subscription, "resource_group": s.ResourceGroup, "dir": s.Dir}
	for _, name := range storeKeys[pl] {
		w.kv(prefix+"."+name, vals[name])
	}
}

func formatLocked(w *printer, l *Locked) {
	w.note("locked: public; a change waits out the change delay")
	for _, k := range l.Approvers.Keys {
		w.kv("approvers", hexOf(k[:]))
	}
	w.kv("approvals_needed", l.Approvers.ApprovalsNeeded)
	if l.ChangeDelaySeconds != nil {
		w.kv("change_delay_seconds", *l.ChangeDelaySeconds)
	} else {
		// Both builds' values, so the text does not depend on the tool's build.
		w.note("change_delay_seconds absent: the image default, %d in a default build, %d in a testnet build",
			buildflavor.DefaultFlavorTimeLock, buildflavor.TestnetFlavorTimeLock)
	}
	for _, im := range l.AllowedImageMeasurements {
		if im.Kind == ImageNitro {
			w.kv("allowed_image_measurements", fmt.Sprintf("%s %s %s %s", im.Kind, hexOf(im.Measurement[:48]), hexOf(im.Measurement[48:96]), hexOf(im.Measurement[96:])))
		} else {
			w.kv("allowed_image_measurements", fmt.Sprintf("%s %s", im.Kind, hexOf(im.Measurement)))
		}
	}
	for _, a := range l.AllowedFeeRecipients {
		w.kv("allowed_fee_recipients", hexOf(a[:]))
	}
	w.kv("builder_gas_limit_min", l.BuilderGasLimitMin)
	w.kv("builder_gas_limit_max", l.BuilderGasLimitMax)
	w.kv("builder_registration_max_future_seconds", l.BuilderRegistrationMaxFutureSeconds)
	for _, i := range l.ExitAllowedValidators {
		w.kv("exit_allowed_validators", i)
	}
	w.kv("exit_stake_cap_per_day", formatAmount(l.ExitStakeCapPerDay))
	w.kv("exit_approvals_needed", l.ExitApprovalsNeeded)
	w.kv("min_activation_balance", formatAmount(l.MinActivationBalance))
	w.kv("max_effective_balance", formatAmount(l.MaxEffectiveBalance))
	w.kv("withdrawal_credentials", hexOf(l.WithdrawalCredentials[:]))
	for _, a := range l.AllowedDepositAmounts {
		w.kv("allowed_deposit_amounts", formatAmount(a))
	}
	w.kv("allow_unverified_nonslashable_signing", l.AllowUnverifiedNonslashableSigning)
	for bit, name := range rootDomainNames {
		if name != "" && l.BareRootDomains&(1<<bit) != 0 {
			w.kv("bare_root_domains", name)
		}
	}
	if len(l.SlotTimeChanges) > 0 {
		w.note("slot_time_changes: EPOCH SECONDS_PER_SLOT, the slot time from the first slot of EPOCH on")
	}
	for _, c := range l.SlotTimeChanges {
		w.kv("slot_time_changes", fmt.Sprintf("%d %d", c.Epoch, c.SecondsPerSlot))
	}
	if len(l.AllowedBuilderRequestAuthDataRoots) == 0 {
		w.note("allowed_builder_request_auth_data_roots absent: no BuilderRequestAuth is signed")
	} else {
		w.note("allowed_builder_request_auth_data_roots: hash_tree_root of the data of each BuilderRequestAuth the signer signs")
	}
	for _, r := range l.AllowedBuilderRequestAuthDataRoots {
		w.kv("allowed_builder_request_auth_data_roots", hexOf(r[:]))
	}
}

func formatOpen(w *printer, o *Open) {
	w.note("open: public; a change applies without a change delay")
	for _, f := range o.ForkSchedule {
		w.kv("fork_schedule", fmt.Sprintf("%d %s", f.Epoch, hexOf(f.Version[:])))
	}
	if o.GloasForkEpoch != nil {
		w.kv("gloas_fork_epoch", *o.GloasForkEpoch)
	}
}

// Format checks the group and writes its human form (no salts).
func (l *Locked) Format() ([]byte, error) {
	if err := l.Check(); err != nil {
		return nil, err
	}
	w := &printer{}
	formatLocked(w, l)
	return []byte(w.b.String()), nil
}

// Format checks the group and writes its human form (no salts).
func (o *Open) Format() ([]byte, error) {
	if err := o.Check(); err != nil {
		return nil, err
	}
	w := &printer{}
	formatOpen(w, o)
	return []byte(w.b.String()), nil
}

func formatBody(w *printer, u *UpdateBody) {
	w.note("Config update (setup-phase.md, section 6). Approvers sign the header: these fields and the root of the group's salted leaves.")
	w.kv("cluster_id", hexOf(u.ClusterID[:]))
	w.kv("chain_hash", hexOf(u.ChainHash[:]))
	w.kv("group", u.Group)
	w.kv("version", u.Version)
	w.kv("prev_hash", hexOf(u.PrevHash[:]))
	w.note("activate_at %s", unixNote(u.ActivateAt))
	w.kv("activate_at", u.ActivateAt)
	w.blank()
	names := openLeafNames
	if u.Group == GroupLocked {
		formatLocked(w, u.Locked)
		names = lockedLeafNames
	} else {
		formatOpen(w, u.Open)
	}
	w.blank()
	w.note("salts: one per leaf of the group")
	formatSalts(w, names, u.Salts)
}

// Format checks the body and writes its human form.
func (u *UpdateBody) Format() ([]byte, error) {
	if err := u.Check(); err != nil {
		return nil, err
	}
	w := &printer{}
	formatBody(w, u)
	return []byte(w.b.String()), nil
}

// Format checks the signed update and writes its human form.
func (u *Update) Format() ([]byte, error) {
	if err := u.check(); err != nil {
		return nil, err
	}
	w := &printer{}
	formatBody(w, &u.Body)
	w.blank()
	w.note("signatures over %s and the header, by position", CtxConfigUpdate)
	for _, a := range u.Approvals {
		w.kv("approver_signature", fmt.Sprintf("%d %s", a.Position, hexOf(a.Signature[:])))
	}
	for _, a := range u.NewSet {
		w.kv("new_key_signature", fmt.Sprintf("%d %s", a.Position, hexOf(a.Signature[:])))
	}
	return []byte(w.b.String()), nil
}
