package setuptext

// The printer half: the text signer-admin show prints and approvers read
// before they sign (parse.go reads it back). The values both halves use,
// the enum, leaf and key names, are here too.

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/lidofinance/tee-signer/governance/setupwire"
	"github.com/lidofinance/tee-signer/signer-protocol/buildchain"
)

// The enum names of setupwire, indexed by value.
var (
	presetNames      = setupwire.PresetNames()
	signingModeNames = setupwire.SigningModeNames()
	groupNames       = setupwire.GroupNames()
	imageNames       = setupwire.ImageKindNames()
	rootDomainNames  = setupwire.RootDomainNames()
)

const gweiPerETH = 1_000_000_000

func formatAmount(g uint64) string {
	if g%gweiPerETH == 0 {
		return fmt.Sprintf("%d ETH", g/gweiPerETH)
	}
	return fmt.Sprintf("%d Gwei", g)
}

// The leaf names of the public part and of the two groups, in leaf order.
var publicLeafNames, lockedLeafNames, openLeafNames = setupwire.LeafNames()

const saltPrefix = "salt."

// The keys of the platform-dependent parts, indexed by platform.
var (
	storeKeys = [][]string{setupwire.PlatformNitro: {"bucket", "region"}, setupwire.PlatformAzure: {"account", "container", "subscription", "resource_group"},
		setupwire.PlatformGCP: {"bucket"}, setupwire.PlatformDev: {"dir"}}
	keyReleaseKeys = [][]string{setupwire.PlatformNitro: {"region", "kms_key_id"}, setupwire.PlatformAzure: {"maa_endpoint", "akv_endpoint", "kid"},
		setupwire.PlatformGCP: {"wif_provider", "kms_key", "attest_audience"}, setupwire.PlatformDev: {}}
)

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

// FormatSetup checks the setup and writes its human form.
func FormatSetup(s *setupwire.Setup) ([]byte, error) {
	if err := s.Check(); err != nil {
		return nil, err
	}
	w := &printer{}
	w.note("Signer setup, format %d (attestation-prover.md, \"Signer changes\"). setup_hash is over policy_root", setupwire.FormatVersion)
	w.note("(the salted leaves of the public part and the two groups) and platform_commitment (the private part).")
	w.kv("setup_format_version", setupwire.FormatVersion)
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
	w.note("signing_mode: public, fixed for the life of the signer. threshold: the signer holds shares of t-of-n")
	w.note("splits with n >= 2 and refuses a 1 of 1 import order. single: the signer holds whole keys and takes")
	w.note("1 of 1 import orders only; one failed mark log, plus a hostile gateway, can then sign a slashable pair.")
	w.kv("signing_mode", s.SigningMode)
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

func formatSalts(w *printer, names []string, salts setupwire.Salts) {
	for i, n := range names {
		w.kv(saltPrefix+n, hexOf(salts[i][:]))
	}
}

func formatPlatform(w *printer, p *setupwire.PlatformConfig) {
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
	if k.UnsafeSingleKeyAccepted {
		w.note("UNSAFE: %s", setupwire.UnsafeSingleKeyWarning)
		w.kv("sealing_key_release.unsafe_single_key_accepted", true)
	}
}

func formatStore(w *printer, pl setupwire.Platform, prefix string, s *setupwire.Store) {
	vals := map[string]string{"bucket": s.Bucket, "region": s.Region, "account": s.Account, "container": s.Container,
		"subscription": s.Subscription, "resource_group": s.ResourceGroup, "dir": s.Dir}
	for _, name := range storeKeys[pl] {
		w.kv(prefix+"."+name, vals[name])
	}
}

func formatLocked(w *printer, l *setupwire.Locked) {
	w.note("locked: public; a change waits out the change delay")
	for _, k := range l.Approvers.Keys {
		w.kv("approvers", hexOf(k[:]))
	}
	w.kv("approvals_needed", l.Approvers.ApprovalsNeeded)
	if l.ChangeDelaySeconds != nil {
		w.kv("change_delay_seconds", *l.ChangeDelaySeconds)
	} else {
		// Both builds' values, so the text does not depend on the tool's build.
		w.note("change_delay_seconds absent: the image default, %d in a mainnet build, %d in a non-prod build",
			buildchain.MainnetTimeLock, buildchain.ShortTimeLock)
	}
	for _, im := range l.AllowedImageMeasurements {
		if im.Kind == setupwire.ImageNitro {
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

func formatOpen(w *printer, o *setupwire.Open) {
	w.note("open: public; a change applies without a change delay")
	for _, f := range o.ForkSchedule {
		w.kv("fork_schedule", fmt.Sprintf("%d %s", f.Epoch, hexOf(f.Version[:])))
	}
	if o.GloasForkEpoch != nil {
		w.kv("gloas_fork_epoch", *o.GloasForkEpoch)
	}
}

// FormatLocked checks the group and writes its human form (no salts).
func FormatLocked(l *setupwire.Locked) ([]byte, error) {
	if err := l.Check(); err != nil {
		return nil, err
	}
	w := &printer{}
	formatLocked(w, l)
	return []byte(w.b.String()), nil
}

// FormatOpen checks the group and writes its human form (no salts).
func FormatOpen(o *setupwire.Open) ([]byte, error) {
	if err := o.Check(); err != nil {
		return nil, err
	}
	w := &printer{}
	formatOpen(w, o)
	return []byte(w.b.String()), nil
}

func formatBody(w *printer, u *setupwire.UpdateBody) {
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
	if u.Group == setupwire.GroupLocked {
		formatLocked(w, u.Locked)
		names = lockedLeafNames
	} else {
		formatOpen(w, u.Open)
	}
	w.blank()
	w.note("salts: one per leaf of the group")
	formatSalts(w, names, u.Salts)
}

// FormatUpdateBody checks the body and writes its human form.
func FormatUpdateBody(u *setupwire.UpdateBody) ([]byte, error) {
	if err := u.Check(); err != nil {
		return nil, err
	}
	w := &printer{}
	formatBody(w, u)
	return []byte(w.b.String()), nil
}

// FormatUpdate checks the signed update and writes its human form.
func FormatUpdate(u *setupwire.Update) ([]byte, error) {
	if err := u.Check(); err != nil {
		return nil, err
	}
	w := &printer{}
	formatBody(w, &u.Body)
	w.blank()
	w.note("signatures over %s and the header, by position", setupwire.CtxConfigUpdate)
	for _, a := range u.Approvals {
		w.kv("approver_signature", fmt.Sprintf("%d %s", a.Position, hexOf(a.Signature[:])))
	}
	for _, a := range u.NewSet {
		w.kv("new_key_signature", fmt.Sprintf("%d %s", a.Position, hexOf(a.Signature[:])))
	}
	return []byte(w.b.String()), nil
}
