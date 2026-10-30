package setupwire

import (
	"bytes"
	"fmt"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/lidofinance/tee-signer/signer-protocol"
)

// Every sample survives binary -> struct -> binary. The human form is
// checked in governance/setuptext.
func TestSetupRoundTrip(t *testing.T) {
	for name, s := range samples(t) {
		b, err := s.Encode()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		got, err := DecodeSetup(b)
		if err != nil {
			t.Fatalf("%s: decode: %v", name, err)
		}
		if !reflect.DeepEqual(got, s) {
			t.Fatalf("%s: decoded\n%+v\nwant\n%+v", name, got, s)
		}
		h1, err := s.Hash()
		h2, err2 := SetupHash(b)
		if err != nil || err2 != nil || h1 != h2 || h1 == ([32]byte{}) {
			t.Fatalf("%s: setup hash: %v %v", name, err, err2)
		}
		if err := got.CheckPlatform(s.Platform.Platform); err != nil {
			t.Fatal(err)
		}
		if err := got.CheckPlatform(s.Platform.Platform%3 + 1); err == nil {
			t.Fatalf("%s: setup accepted by another platform's image", name)
		}
	}
}

// offsets are where the parts of an encoded setup start.
type offsets struct {
	publicSalts, locked, lockedEnd, open, openEnd, platformSalt, private int
}

func offsetsOf(t *testing.T, s *Setup, b []byte) offsets {
	t.Helper()
	priv := must(s.PrivateBytes())
	var o offsets
	o.private = len(b) - len(priv)
	o.platformSalt = o.private - 32
	o.openEnd = o.platformSalt - 32*NumOpenLeaves
	o.open = o.openEnd - len(must(s.Open.Encode()))
	o.lockedEnd = o.open - 32*NumLockedLeaves
	o.locked = o.lockedEnd - len(must(s.Locked.Encode()))
	o.publicSalts = 1 + publicLen
	if o.locked != o.publicSalts+32*NumPublicLeaves {
		t.Fatalf("layout: locked at %d, want %d", o.locked, o.publicSalts+32*NumPublicLeaves)
	}
	return o
}

const (
	chainLen  = 32 + 4 + 8 + 8 + 8 + 1 + 4
	safetyLen = 4 * 8
	publicLen = 1 + 32 + 8 + chainLen + safetyLen + 4 + 4 + 1
)

// Every shorter prefix and every longer form of a setup is refused, and so
// are a wrong kind, format or size.
func TestDecodeSetupBytes(t *testing.T) {
	ss := samples(t)
	for _, name := range []string{"setup-nitro", "setup-azure", "setup-gcp", "setup-dev", "setup-nitro-peers"} {
		b, err := ss[name].Encode()
		if err != nil {
			t.Fatal(err)
		}
		for i := range len(b) {
			if _, err := DecodeSetup(b[:i]); err == nil {
				t.Fatalf("%s: %d-byte prefix accepted", name, i)
			}
		}
		if _, err := DecodeSetup(append(slices.Clone(b), 0)); err == nil || !strings.Contains(err.Error(), "trailing") {
			t.Fatalf("%s: trailing byte: %v", name, err)
		}
	}
	s := ss["setup-nitro"]
	b, _ := s.Encode()
	o := offsetsOf(t, s, b)
	set := func(off int, v byte) []byte {
		c := slices.Clone(b)
		c[off] = v
		return c
	}
	zero := func(off, n int) []byte {
		c := slices.Clone(b)
		clear(c[off : off+n])
		return c
	}
	safetyAt := 2 + 32 + 8 + chainLen
	// rootsAt is the count byte of allowed_builder_request_auth_data_roots,
	// the last locked field.
	rootsAt := o.lockedEnd - 1 - 32*len(s.Locked.AllowedBuilderRequestAuthDataRoots)
	cases := []struct {
		name string
		b    []byte
		want string
	}{
		{"kind", set(0, 'X'), "not a setup"},
		{"format 0", set(1, 0), "setup format 0, want 2"},
		{"format 1 (before signing_mode)", set(1, 1), "setup format 1, want 2"},
		{"format 3", set(1, 3), "setup format 3, want 2"},
		{"empty signer name", set(o.private, 0), "signer_name is empty"},
		{"oversize", append(slices.Clone(b), make([]byte, MaxSetup)...), "at most 65536"},
		{"empty", nil, "short"},
		{"max_sign_epochs_ahead_of_clock 0", set(safetyAt+7, 0), "max_sign_epochs_ahead_of_clock 0, want 1 to 16"},
		{"max_sign_epochs_ahead_of_clock 17", set(safetyAt+7, 17), "max_sign_epochs_ahead_of_clock 17"},
		{"prewrite slots 65", set(safetyAt+15, 65), "slashing_mark_prewrite.block_slots 65, at most 64"},
		{"zero public salt", zero(o.publicSalts, 32), "public: salt 0 is zero"},
		{"zero locked salt", zero(o.lockedEnd+32*4, 32), "locked: salt 4 is zero"},
		{"zero open salt", zero(o.openEnd+32, 32), "open: salt 1 is zero"},
		{"zero platform salt", zero(o.platformSalt, 32), "platform_salt is zero"},
		{"gloas presence 2", set(o.openEnd-9, 2), "gloas_fork_epoch presence byte is 2"},
		{"allow_unverified 2", set(rootsAt-4, 2), "allow_unverified_nonslashable_signing byte is 2"},
		{"slot time count 17", set(rootsAt-1, 17), "17 slot_time_changes, at most 16"},
		{"builder request auth root count 17", set(rootsAt, 17), "17 allowed_builder_request_auth_data_roots, at most 16"},
		{"builder request auth roots repeated", func() []byte {
			c := slices.Clone(b)
			copy(c[rootsAt+33:rootsAt+65], c[rootsAt+1:rootsAt+33])
			return c
		}(), "allowed_builder_request_auth_data_roots must be sorted"},
		{"approver count 9", set(o.locked, 9), "9 approvers, at most 8"},
		{"change delay presence 2", set(o.locked+1+32*3+1, 2), "change_delay_seconds presence byte is 2"},
		{"platform 9", set(o.private+1+len(s.SignerName), 9), "unknown platform 9"},
		{"peer host count 17", set(len(b)-1, 17), "17 peer_attestation_hosts, at most 16"},
		{"peer host empty", append(set(len(b)-1, 1), 0), "peer_attestation_hosts is empty"},
	}
	for _, c := range cases {
		if _, err := DecodeSetup(c.b); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: got %v, want %q", c.name, err, c.want)
		}
	}
}

func must(b []byte, err error) []byte {
	if err != nil {
		panic(err)
	}
	return b
}

// setupRefusal is a setup the value rules refuse: the sample base changed
// by mutate.
type setupRefusal struct {
	name   string
	base   string
	mutate func(s *Setup)
	want   string
	// decode is what DecodeSetup says about the unchecked bytes: ""
	// the same as want, "any" any error, "skip" the bytes cannot
	// carry the fault.
	decode string
}

// setup returns the sample the case starts from, changed by mutate.
func (c setupRefusal) setup(t testing.TB) *Setup {
	base := c.base
	if base == "" {
		base = "setup-nitro"
	}
	s := samples(t)[base]
	c.mutate(s)
	return s
}

// Each value rule refuses its fault, in the encoder and, where the bytes
// can carry the fault, in the decoder. FormatRefusals runs the same cases
// through the human form.
func TestSetupRefusals(t *testing.T) {
	for _, c := range setupRefusals(t) {
		s := c.setup(t)
		if _, err := s.Encode(); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: encode: got %v, want %q", c.name, err, c.want)
		}
		if c.decode == "skip" {
			continue
		}
		want := c.decode
		if want == "" {
			want = c.want
		}
		_, err := DecodeSetup(rawSetup(s))
		if err == nil || want != "any" && !strings.Contains(err.Error(), want) {
			t.Errorf("%s: decode: got %v, want %q", c.name, err, want)
		}
	}
}

func setupRefusals(t testing.TB) []setupRefusal {
	ca := goldenCA(t)
	ca2 := makeCA(t, 2, "second CA", true)
	cas := [][]byte{ca, ca2}
	slices.SortFunc(cas, bytes.Compare)
	keys := func(n int) [][32]byte {
		var out [][32]byte
		for i := range n {
			out = append(out, approverPub(byte(i+1)))
		}
		return out
	}
	identity := [32]byte{1}
	nonCanonical := [32]byte{0xee}
	for i := 1; i < 31; i++ {
		nonCanonical[i] = 0xff
	}
	nonCanonical[31] = 0x7f
	return []setupRefusal{
		{"signer name case", "", func(s *Setup) { s.SignerName = "Signer-1" }, "signer_name", ""},
		{"signer name long", "", func(s *Setup) { s.SignerName = strings.Repeat("a", 129) }, "signer_name", ""},
		{"signer name empty", "", func(s *Setup) { s.SignerName = "" }, "signer_name", "signer_name is empty"},
		{"cluster id zero", "", func(s *Setup) { s.ClusterID = [32]byte{} }, "cluster_id is zero", ""},
		{"handover generation 0", "", func(s *Setup) { s.HandoverGeneration = 0 }, "handover_generation is 0", ""},
		{"preset 0", "", func(s *Setup) { s.Chain.Preset = 0 }, "preset 0", ""},
		{"preset 3", "", func(s *Setup) { s.Chain.Preset = 3 }, "preset 3", ""},
		{"seconds per slot 0", "", func(s *Setup) { s.Chain.SecondsPerSlot = 0 }, "non-zero", ""},
		{"slots per epoch 0", "", func(s *Setup) { s.Chain.SlotsPerEpoch = 0 }, "non-zero", ""},
		{"epoch length overflows", "", func(s *Setup) { s.Chain.SecondsPerSlot, s.Chain.SlotsPerEpoch = 1<<33, 1<<31 }, "overflows", ""},
		{"sign ahead 0", "", func(s *Setup) { s.Safety.MaxSignEpochsAheadOfClock = 0 }, "max_sign_epochs_ahead_of_clock 0, want 1 to 16", ""},
		{"sign ahead 17", "", func(s *Setup) { s.Safety.MaxSignEpochsAheadOfClock = 17 }, "max_sign_epochs_ahead_of_clock 17", ""},
		{"sign ahead huge", "", func(s *Setup) { s.Safety.MaxSignEpochsAheadOfClock = 1 << 63 }, "max_sign_epochs_ahead_of_clock", ""},
		{"prewrite slots 65", "", func(s *Setup) { s.Safety.SlashingMarkPrewrite.BlockSlots = 65 }, "block_slots 65, at most 64", ""},
		{"prewrite sources 9", "", func(s *Setup) { s.Safety.SlashingMarkPrewrite.SourceEpochs = 9 }, "source_epochs 9, at most 8", ""},
		{"prewrite targets 9", "", func(s *Setup) { s.Safety.SlashingMarkPrewrite.TargetEpochs = 9 }, "target_epochs 9, at most 8", ""},
		{"max keys 0", "", func(s *Setup) { s.MaxKeys = 0 }, "max_keys 0", ""},
		{"max keys above cap", "", func(s *Setup) { s.MaxKeys = MaxKeysCap + 1 }, "max_keys 8193", ""},
		{"lock days 0", "", func(s *Setup) { s.SlashingLogMinLockDays = 0 }, "slashing_log_min_lock_days 0", ""},
		{"lock days above 100 years", "", func(s *Setup) { s.SlashingLogMinLockDays = MaxLockDays + 1 }, "slashing_log_min_lock_days 36501", ""},
		{"signing mode 0", "", func(s *Setup) { s.SigningMode = 0 }, "signing_mode 0, want 1 (threshold) or 2 (single)", ""},
		{"signing mode 3", "", func(s *Setup) { s.SigningMode = 3 }, "signing_mode 3", ""},
		{"public salts missing", "", func(s *Setup) { s.PolicySalts.Public = nil }, "public: no salts", "skip"},
		{"locked salts short", "", func(s *Setup) { s.PolicySalts.Locked = s.PolicySalts.Locked[:18] }, "locked: 18 salts, want one for each of the 19 leaves", "skip"},
		{"open salt zero", "", func(s *Setup) { s.PolicySalts.Open[0] = [32]byte{} }, "open: salt 0 is zero", ""},
		{"platform salt zero", "", func(s *Setup) { s.PlatformSalt = [32]byte{} }, "platform_salt is zero", ""},
		{"platform 0", "", func(s *Setup) { s.Platform.Platform = 0 }, "platform: 0", "unknown platform 0"},
		{"platform 5", "", func(s *Setup) { s.Platform.Platform = 5 }, "platform: 5", "unknown platform 5"},
		{"nitro setup as dev", "", func(s *Setup) { s.Platform.Platform = PlatformDev }, "slashing_log_store.bucket does not apply to dev", "skip"},
		{"no CA", "", func(s *Setup) { s.Platform.AllowedClientCA = nil }, "0 allowed_client_ca", ""},
		{"5 CAs", "", func(s *Setup) {
			s.Platform.AllowedClientCA = nil
			for i := range 5 {
				s.Platform.AllowedClientCA = append(s.Platform.AllowedClientCA, makeCA(t, byte(10+i), "ca", true))
			}
			slices.SortFunc(s.Platform.AllowedClientCA, bytes.Compare)
		}, "5 allowed_client_ca", "5 allowed_client_ca certificates, at most 4"},
		{"CA not DER", "", func(s *Setup) { s.Platform.AllowedClientCA = [][]byte{{1, 2, 3}} }, "allowed_client_ca 0", ""},
		{"CA is a leaf", "", func(s *Setup) { s.Platform.AllowedClientCA = [][]byte{makeCA(t, 3, "leaf", false)} }, "not a CA certificate", ""},
		{"CAs unsorted", "", func(s *Setup) { s.Platform.AllowedClientCA = [][]byte{cas[1], cas[0]} }, "sorted", ""},
		{"CA repeated", "", func(s *Setup) { s.Platform.AllowedClientCA = [][]byte{ca, ca} }, "sorted", ""},
		{"s3 bucket case", "", func(s *Setup) { s.Platform.SlashingLogStore.Bucket = "Signer-marks" }, "slashing_log_store.bucket", ""},
		{"s3 region space", "", func(s *Setup) { s.Platform.SlashingLogStore.Region = "eu west" }, "slashing_log_store.region", ""},
		{"azure field on nitro", "", func(s *Setup) { s.Platform.SlashingLogStore.Account = "acct" }, "slashing_log_store.account does not apply to nitro", "skip"},
		{"state store on nitro", "", func(s *Setup) { s.Platform.EncryptedStateStore = &Store{Bucket: "state-1", Region: "eu-west-1"} }, "encrypted_state_store must be absent", ""},
		{"azure state store bad", "setup-azure", func(s *Setup) { s.Platform.EncryptedStateStore.Container = "x" }, "encrypted_state_store.container", ""},
		{"azure subscription upper case", "setup-azure", func(s *Setup) {
			s.Platform.SlashingLogStore.Subscription = "0B2C3D4E-5F60-4718-9A2B-3C4D5E6F7A8B"
		}, "slashing_log_store.subscription", ""},
		{"azure subscription empty", "setup-azure", func(s *Setup) { s.Platform.SlashingLogStore.Subscription = "" }, "slashing_log_store.subscription", ""},
		{"azure resource group ends with period", "setup-azure", func(s *Setup) { s.Platform.SlashingLogStore.ResourceGroup = "signer-rg." }, "slashing_log_store.resource_group", ""},
		{"azure resource group with slash", "setup-azure", func(s *Setup) { s.Platform.EncryptedStateStore.ResourceGroup = "a/b" }, "encrypted_state_store.resource_group", ""},
		{"azure resource group long", "setup-azure", func(s *Setup) { s.Platform.SlashingLogStore.ResourceGroup = strings.Repeat("g", 91) }, "slashing_log_store.resource_group", ""},
		{"azure field on gcp", "setup-gcp", func(s *Setup) { s.Platform.SlashingLogStore.Subscription = "0b2c3d4e-5f60-4718-9a2b-3c4d5e6f7a8b" }, "slashing_log_store.subscription does not apply to gcp", "skip"},
		{"kms key id with #", "", func(s *Setup) { s.Platform.SealingKeyRelease.KMSKeyID = "key#1" }, "kms_key_id", ""},
		{"maa endpoint with scheme", "setup-azure", func(s *Setup) { s.Platform.SealingKeyRelease.MAAEndpoint = "https://maa.example" }, "maa_endpoint", ""},
		{"kid with path", "setup-azure", func(s *Setup) { s.Platform.SealingKeyRelease.KID = "keys/signer" }, "sealing_key_release.kid", ""},
		{"gcp field on azure", "setup-azure", func(s *Setup) { s.Platform.SealingKeyRelease.KMSKey = "k" }, "sealing_key_release.kms_key does not apply to azure", "skip"},
		{"dev dir relative", "setup-dev", func(s *Setup) { s.Platform.SlashingLogStore.Dir = "marks" }, "not an absolute, clean path", ""},
		{"dev dir not clean", "setup-dev", func(s *Setup) { s.Platform.EncryptedStateStore.Dir = "/var/lib/../x" }, "not an absolute, clean path", ""},
		{"dev dir trailing slash", "setup-dev", func(s *Setup) { s.Platform.SlashingLogStore.Dir = "/var/lib/marks/" }, "not an absolute, clean path", ""},
		{"dev dir with space", "setup-dev", func(s *Setup) { s.Platform.SlashingLogStore.Dir = "/var/lib/my marks" }, "slashing_log_store.dir", ""},
		{"bucket on dev", "setup-dev", func(s *Setup) { s.Platform.SlashingLogStore.Bucket = "b" }, "slashing_log_store.bucket does not apply to dev", "skip"},
		{"key release on dev", "setup-dev", func(s *Setup) { s.Platform.SealingKeyRelease.Region = "eu-west-1" }, "sealing_key_release.region does not apply to dev", "skip"},
		{"peer hosts on azure", "setup-azure", func(s *Setup) { s.Platform.PeerAttestationHosts = []string{"a.example:443"} }, "peer_attestation_hosts is for nitro and dev", ""},
		{"peer hosts on gcp", "setup-gcp", func(s *Setup) { s.Platform.PeerAttestationHosts = []string{"a.example:443"} }, "peer_attestation_hosts is for nitro and dev", ""},
		{"single key accepted on azure", "setup-azure", func(s *Setup) { s.Platform.SealingKeyRelease.UnsafeSingleKeyAccepted = true }, "unsafe_single_key_accepted does not apply to azure", "skip"},
		{"17 peer hosts", "setup-nitro-peers", func(s *Setup) {
			s.Platform.PeerAttestationHosts = nil
			for i := range 17 {
				s.Platform.PeerAttestationHosts = append(s.Platform.PeerAttestationHosts, fmt.Sprintf("h%02d.example:443", i))
			}
		}, "17 peer_attestation_hosts", "17 peer_attestation_hosts, at most 16"},
		{"peer host without port", "setup-nitro-peers", func(s *Setup) { s.Platform.PeerAttestationHosts[0] = "a.example" }, "want host:port", ""},
		{"peer host upper case", "setup-nitro-peers", func(s *Setup) { s.Platform.PeerAttestationHosts[0] = "A.example:443" }, "want host:port", ""},
		{"peer host with scheme", "setup-nitro-peers", func(s *Setup) { s.Platform.PeerAttestationHosts[0] = "https://a.example:443" }, "want host:port", ""},
		{"peer host with path", "setup-nitro-peers", func(s *Setup) { s.Platform.PeerAttestationHosts[0] = "a.example:443/certs" }, "want host:port", ""},
		{"peer host port 0", "setup-nitro-peers", func(s *Setup) { s.Platform.PeerAttestationHosts[0] = "a.example:0" }, "want host:port", ""},
		{"peer host port 0443", "setup-nitro-peers", func(s *Setup) { s.Platform.PeerAttestationHosts[0] = "a.example:0443" }, "want host:port", ""},
		{"peer host port 65536", "setup-nitro-peers", func(s *Setup) { s.Platform.PeerAttestationHosts[0] = "a.example:65536" }, "above 65535", ""},
		{"peer hosts unsorted", "setup-nitro-peers", func(s *Setup) { slices.Reverse(s.Platform.PeerAttestationHosts) }, "peer_attestation_hosts must be sorted", ""},
		{"peer host repeated", "setup-nitro-peers", func(s *Setup) {
			s.Platform.PeerAttestationHosts[1] = s.Platform.PeerAttestationHosts[0]
		}, "peer_attestation_hosts must be sorted", ""},

		{"1 approver", "", func(s *Setup) { s.Locked.Approvers = ApproverSet{Keys: keys(1), ApprovalsNeeded: 2} }, "1 keys, want 2 to 8", ""},
		{"9 approvers", "", func(s *Setup) { s.Locked.Approvers = ApproverSet{Keys: keys(9), ApprovalsNeeded: 5} }, "9 keys", "9 approvers, at most 8"},
		{"approver repeated", "", func(s *Setup) { s.Locked.Approvers.Keys[2] = s.Locked.Approvers.Keys[0] }, "listed twice", ""},
		{"approver small order", "", func(s *Setup) { s.Locked.Approvers.Keys[2] = identity }, "small-order", ""},
		{"approver not canonical", "", func(s *Setup) { s.Locked.Approvers.Keys[2] = nonCanonical }, "canonical", ""},
		{"approvals needed 1", "", func(s *Setup) { s.Locked.Approvers.ApprovalsNeeded = 1 }, "approvals_needed is 1", ""},
		{"approvals needed above n", "", func(s *Setup) { s.Locked.Approvers.ApprovalsNeeded = 4 }, "approvals_needed is 4, above the 3", ""},
		{"approvals needed half of n", "", func(s *Setup) { s.Locked.Approvers = ApproverSet{Keys: keys(4), ApprovalsNeeded: 2} }, "more than half", ""},
		{"change delay above cap", "", func(s *Setup) { s.Locked.ChangeDelaySeconds = u64p(MaxTimeLock + 1) }, "change_delay_seconds " + strconv.Itoa(MaxTimeLock+1), ""},
		{"33 images", "", func(s *Setup) {
			s.Locked.AllowedImageMeasurements = nil
			for i := range 33 {
				s.Locked.AllowedImageMeasurements = append(s.Locked.AllowedImageMeasurements, Image{Kind: ImageGCP, Measurement: bytes.Repeat([]byte{byte(i)}, 32)})
			}
		}, "33 allowed_image_measurements", "33 allowed_image_measurements, at most 32"},
		{"image kind 0", "", func(s *Setup) { s.Locked.AllowedImageMeasurements[1].Kind = 0 }, "unknown kind 0", "unknown image kind 0"},
		{"image too short", "", func(s *Setup) { s.Locked.AllowedImageMeasurements[1].Measurement = make([]byte, 31) }, "is 31 bytes, want 32", "any"},
		{"images unsorted", "", func(s *Setup) { slices.Reverse(s.Locked.AllowedImageMeasurements) }, "allowed_image_measurements must be sorted", ""},
		{"image repeated", "", func(s *Setup) { s.Locked.AllowedImageMeasurements[1] = s.Locked.AllowedImageMeasurements[0] }, "allowed_image_measurements must be sorted", ""},
		{"65 fee recipients", "", func(s *Setup) {
			s.Locked.AllowedFeeRecipients = nil
			for i := range 65 {
				s.Locked.AllowedFeeRecipients = append(s.Locked.AllowedFeeRecipients, backend.Address{byte(i)})
			}
		}, "65 allowed_fee_recipients", "65 allowed_fee_recipients, at most 64"},
		{"fee recipients unsorted", "", func(s *Setup) { slices.Reverse(s.Locked.AllowedFeeRecipients) }, "allowed_fee_recipients must be sorted", ""},
		{"fee recipient repeated", "", func(s *Setup) { s.Locked.AllowedFeeRecipients[1] = s.Locked.AllowedFeeRecipients[0] }, "allowed_fee_recipients must be sorted", ""},
		{"gas min above max", "", func(s *Setup) { s.Locked.BuilderGasLimitMin = s.Locked.BuilderGasLimitMax + 1 }, "builder_gas_limit_min", ""},
		{"1025 exit validators", "", func(s *Setup) {
			s.Locked.ExitAllowedValidators = nil
			for i := range 1025 {
				s.Locked.ExitAllowedValidators = append(s.Locked.ExitAllowedValidators, uint64(i))
			}
		}, "1025 exit_allowed_validators", "1025 exit_allowed_validators entries, at most 1024"},
		{"exit validators unsorted", "", func(s *Setup) { slices.Reverse(s.Locked.ExitAllowedValidators) }, "exit_allowed_validators must be sorted", ""},
		{"exit validator repeated", "", func(s *Setup) { s.Locked.ExitAllowedValidators[1] = s.Locked.ExitAllowedValidators[0] }, "exit_allowed_validators must be sorted", ""},
		{"exit approvals 1", "", func(s *Setup) { s.Locked.ExitApprovalsNeeded = 1 }, "exit_approvals_needed 1", ""},
		{"exit approvals above n", "", func(s *Setup) { s.Locked.ExitApprovalsNeeded = 4 }, "exit_approvals_needed 4", ""},
		{"min activation 0", "", func(s *Setup) { s.Locked.MinActivationBalance = 0 }, "min_activation_balance", ""},
		{"min activation above max", "", func(s *Setup) { s.Locked.MinActivationBalance = s.Locked.MaxEffectiveBalance + 1 }, "min_activation_balance", ""},
		{"credentials prefix 0", "", func(s *Setup) { s.Locked.WithdrawalCredentials[0] = 0 }, "prefix 0x00", ""},
		{"credentials prefix 3", "", func(s *Setup) { s.Locked.WithdrawalCredentials[0] = 3 }, "prefix 0x03", ""},
		{"credentials padding", "", func(s *Setup) { s.Locked.WithdrawalCredentials[5] = 1 }, "bytes 1 to 11", ""},
		{"credentials zero address", "", func(s *Setup) { s.Locked.WithdrawalCredentials = backend.Root{2} }, "address is zero", ""},
		{"deposit 0", "", func(s *Setup) { s.Locked.AllowedDepositAmounts[0] = 0 }, "deposit amount 0", ""},
		{"deposit above max", "", func(s *Setup) { s.Locked.AllowedDepositAmounts[1] = s.Locked.MaxEffectiveBalance + 1 }, "deposit amount 2048000000001", ""},
		{"deposits unsorted", "", func(s *Setup) { slices.Reverse(s.Locked.AllowedDepositAmounts) }, "allowed_deposit_amounts must be sorted", ""},
		{"9 deposits", "", func(s *Setup) { s.Locked.AllowedDepositAmounts = []uint64{1, 2, 3, 4, 5, 6, 7, 8, 9} }, "9 allowed_deposit_amounts", "9 allowed_deposit_amounts, at most 8"},
		{"root domain attester", "", func(s *Setup) { s.Locked.BareRootDomains |= 1 << 1 }, "0x01000000", ""},
		{"root domain 15", "", func(s *Setup) { s.Locked.BareRootDomains |= 1 << 15 }, "0x0f000000", ""},
		{"slot time at epoch 0", "", func(s *Setup) { s.Locked.SlotTimeChanges = []SlotTimeChange{{0, 4}} }, "epoch 0 is the genesis slot time", ""},
		{"slot time 0 s", "", func(s *Setup) { s.Locked.SlotTimeChanges = []SlotTimeChange{{5, 0}} }, "epoch 5: seconds per slot 0", ""},
		{"slot times unsorted", "", func(s *Setup) { s.Locked.SlotTimeChanges = []SlotTimeChange{{9, 4}, {5, 3}} }, "ascending epoch order", ""},
		{"two slot times at one epoch", "", func(s *Setup) { s.Locked.SlotTimeChanges = []SlotTimeChange{{5, 4}, {5, 3}} }, "ascending epoch order", ""},
		{"slot time kept", "", func(s *Setup) { s.Locked.SlotTimeChanges = []SlotTimeChange{{5, 4}, {9, 4}} }, "epoch 9 keeps the slot time of the change before", ""},
		{"first slot time is genesis", "", func(s *Setup) { s.Locked.SlotTimeChanges = []SlotTimeChange{{5, 6}} }, "keeps the genesis slot time (6 s)", ""},
		{"17 slot times", "", func(s *Setup) {
			s.Locked.SlotTimeChanges = nil
			for i := range 17 {
				s.Locked.SlotTimeChanges = append(s.Locked.SlotTimeChanges, SlotTimeChange{uint64(10 + i), uint64(1 + i%2)})
			}
		}, "17 slot_time_changes", "17 slot_time_changes, at most 16"},
		{"slot time epoch length overflows", "", func(s *Setup) { s.Locked.SlotTimeChanges = []SlotTimeChange{{5, 1 << 62}} }, "overflows 64 bits", ""},
		{"slot time start overflows", "", func(s *Setup) { s.Locked.SlotTimeChanges = []SlotTimeChange{{1 << 62, 4}} }, "does not fit 64 bits", ""},
		{"17 builder request auth roots", "", func(s *Setup) {
			s.Locked.AllowedBuilderRequestAuthDataRoots = nil
			for i := range 17 {
				s.Locked.AllowedBuilderRequestAuthDataRoots = append(s.Locked.AllowedBuilderRequestAuthDataRoots, backend.Root{byte(i + 1)})
			}
		}, "17 allowed_builder_request_auth_data_roots", "17 allowed_builder_request_auth_data_roots, at most 16"},
		{"builder request auth roots unsorted", "", func(s *Setup) { slices.Reverse(s.Locked.AllowedBuilderRequestAuthDataRoots) },
			"allowed_builder_request_auth_data_roots must be sorted", ""},
		{"builder request auth root repeated", "", func(s *Setup) {
			s.Locked.AllowedBuilderRequestAuthDataRoots[1] = s.Locked.AllowedBuilderRequestAuthDataRoots[0]
		}, "allowed_builder_request_auth_data_roots must be sorted", ""},

		{"17 forks", "", func(s *Setup) {
			s.Open = Open{}
			for i := range 17 {
				s.Open.ForkSchedule = append(s.Open.ForkSchedule, Fork{Epoch: uint64(i)})
			}
		}, "17 fork_schedule entries", "17 fork_schedule entries, at most 16"},
		{"forks unsorted", "", func(s *Setup) { slices.Reverse(s.Open.ForkSchedule) }, "ascending epoch order", ""},
		{"two forks at one epoch", "", func(s *Setup) { s.Open.ForkSchedule[1].Epoch = 0 }, "ascending epoch order", ""},
		{"gloas not a fork", "", func(s *Setup) { s.Open.GloasForkEpoch = u64p(15) }, "gloas_fork_epoch 15", ""},
	}
}

// The hash of a group at version 0 is the root of its salted leaves; the
// chain hash covers every chain field.
func TestGroupHashes(t *testing.T) {
	s := samples(t)["setup-nitro"]
	lh, err := s.GroupHash(GroupLocked)
	if err != nil {
		t.Fatal(err)
	}
	oh, err := s.GroupHash(GroupOpen)
	if err != nil {
		t.Fatal(err)
	}
	lr, _ := s.Locked.Root(s.PolicySalts.Locked)
	or, _ := s.Open.Root(s.PolicySalts.Open)
	if lh != lr || oh != or || lh == oh {
		t.Fatal("group hashes")
	}
	if _, err := s.GroupHash(3); err == nil {
		t.Fatal("group 3 accepted")
	}
	c := s.Chain
	h := c.Hash()
	c.VoluntaryExitForkVersion[3]++
	if c.Hash() == h {
		t.Fatal("chain hash ignores the exit fork version")
	}
	if s.Locked.ChangeDelay() != DefaultTimeLock {
		t.Fatal("absent change delay is not the default")
	}
	s.Locked.ChangeDelaySeconds = u64p(0)
	if s.Locked.ChangeDelay() != 0 {
		t.Fatal("change delay 0")
	}
}

// peer_attestation_hosts: setup_hash covers every host, through
// platform_commitment only; the cap decodes back.
func TestPeerAttestationHosts(t *testing.T) {
	ss := samples(t)
	plain := ss["setup-nitro"]
	s := ss["setup-nitro-peers"]
	pr0, _ := plain.PolicyRoot()
	h0, _ := plain.Hash()
	seen := map[[32]byte]string{h0: "none"}
	for i := range s.Platform.PeerAttestationHosts {
		c := *s
		c.Platform.PeerAttestationHosts = slices.Delete(slices.Clone(s.Platform.PeerAttestationHosts), i, i+1)
		h, err := c.Hash()
		if err != nil {
			t.Fatal(err)
		}
		if prev, dup := seen[h]; dup {
			t.Fatalf("without host %d: setup_hash of %s", i, prev)
		}
		seen[h] = fmt.Sprint("without ", i)
		if pr, _ := c.PolicyRoot(); pr != pr0 {
			t.Fatal("a host changes policy_root; hosts are private")
		}
	}
	c := *s
	c.Platform.PeerAttestationHosts = nil
	for i := range MaxPeerHosts {
		c.Platform.PeerAttestationHosts = append(c.Platform.PeerAttestationHosts, fmt.Sprintf("h%02d.example:443", i))
	}
	got, err := DecodeSetup(must(c.Encode()))
	if err != nil || !reflect.DeepEqual(got.Platform.PeerAttestationHosts, c.Platform.PeerAttestationHosts) {
		t.Fatalf("16 peer_attestation_hosts: %v", err)
	}
	d := ss["setup-dev"]
	d.Platform.PeerAttestationHosts = []string{"127.0.0.1:8443"}
	if _, err := DecodeSetup(must(d.Encode())); err != nil {
		t.Fatalf("dev with peer_attestation_hosts: %v", err)
	}
}

// privateLen is the length of s's private part, without the checks.
func privateLen(s *Setup) int {
	w := &writer{}
	s.writePrivate(w)
	return len(w.b)
}

// atPrivateSize is the GCP sample with a private part of n bytes: four CA
// certificates with long names bring it near n, and the signer name, one
// byte per character, makes up the rest.
func atPrivateSize(t *testing.T, n int) *Setup {
	t.Helper()
	s := samples(t)["setup-gcp"]
	for cn := 16; cn < 1024; cn += 16 {
		var cas [][]byte
		for i := range MaxAllowedClientCA {
			cas = append(cas, makeCA(t, byte(i+1), strings.Repeat("c", cn), true))
		}
		slices.SortFunc(cas, bytes.Compare)
		s.Platform.AllowedClientCA = cas
		s.SignerName = "s"
		if fill := n - privateLen(s); fill >= 0 && fill < MaxSignerName {
			s.SignerName += strings.Repeat("s", fill)
			return s
		}
	}
	t.Fatalf("no private part of %d bytes", n)
	return nil
}

// A private part of MaxPlatformPrivate bytes is taken; one byte more is
// refused by the value checks, the encoder and the decoder.
func TestMaxPlatformPrivate(t *testing.T) {
	at := atPrivateSize(t, MaxPlatformPrivate)
	b, err := at.Encode()
	if err != nil {
		t.Fatalf("private part of %d bytes: %v", MaxPlatformPrivate, err)
	}
	got, err := DecodeSetup(b)
	if err != nil {
		t.Fatalf("private part of %d bytes: decode: %v", MaxPlatformPrivate, err)
	}
	if p, err := got.PrivateBytes(); err != nil || len(p) != MaxPlatformPrivate {
		t.Fatalf("private part: %d bytes, %v", len(p), err)
	}

	over := atPrivateSize(t, MaxPlatformPrivate+1)
	want := fmt.Sprintf("the private part (signer_name and platform) is %d bytes, at most %d", MaxPlatformPrivate+1, MaxPlatformPrivate)
	for what, err := range map[string]error{
		"CheckValues": over.CheckValues(),
		"Encode":      func() error { _, err := over.Encode(); return err }(),
		"DecodeSetup": func() error { _, err := DecodeSetup(rawSetup(over)); return err }(),
	} {
		if err == nil || !strings.Contains(err.Error(), want) || !strings.Contains(err.Error(), "allowed_client_ca") {
			t.Errorf("%s: %v, want an error with %q", what, err, want)
		}
	}
}
