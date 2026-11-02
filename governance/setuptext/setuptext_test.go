package setuptext

import (
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/lidofinance/tee-signer/governance/setupwire"
)

// replaceLine swaps the first "key = ..." line for line ("" removes it).
func replaceLine(t *testing.T, text, key, line string) string {
	t.Helper()
	lines := strings.Split(text, "\n")
	for i, l := range lines {
		if strings.HasPrefix(l, key+" = ") {
			if line == "" {
				return strings.Join(slices.Delete(lines, i, i+1), "\n")
			}
			lines[i] = line
			return strings.Join(lines, "\n")
		}
	}
	t.Fatalf("no %s line", key)
	return ""
}

// dropSalts removes every salt line.
func dropSalts(text string) string {
	var out []string
	for _, l := range strings.Split(text, "\n") {
		if !strings.HasPrefix(l, "salt.") && !strings.HasPrefix(l, "platform_salt = ") {
			out = append(out, l)
		}
	}
	return strings.Join(out, "\n")
}

func TestParseSetupRefusals(t *testing.T) {
	ss := setups(t)
	nitro := string(must(FormatSetup(ss["setup-nitro"])))
	azure := string(must(FormatSetup(ss["setup-azure"])))
	pcr := "0x" + strings.Repeat("11", 48)
	cases := []struct {
		name string
		text string
		want string
	}{
		{"unknown key", nitro + "colour = blue\n", `unknown key "colour"`},
		{"key in upper case", nitro + "K = 2\n", `key "K": keys are lower case`},
		{"key in mixed case", nitro + "Builder_Gas_Limit_Min = 1\n", "keys are lower case"},
		{"bad key", nitro + "gas-limit = 1\n", `bad key "gas-limit"`},
		{"key set twice", nitro + "approvals_needed = 2\n", "approvals_needed: set again (first on line"},
		{"format set twice", nitro + "setup_format_version = 1\n", "setup_format_version: set again"},
		{"key missing", replaceLine(t, nitro, "approvals_needed", ""), "approvals_needed is missing"},
		{"format missing", replaceLine(t, nitro, "setup_format_version", ""), "setup_format_version is missing"},
		{"format 1", replaceLine(t, nitro, "setup_format_version", "setup_format_version = 1"), `setup_format_version: "1", want 2`},
		{"signing_mode missing", replaceLine(t, nitro, "signing_mode", ""), "signing_mode is missing"},
		{"signing_mode unknown", replaceLine(t, nitro, "signing_mode", "signing_mode = solo"), `signing_mode: "solo": want threshold or single`},
		{"signing_mode as a number", replaceLine(t, nitro, "signing_mode", "signing_mode = 2"), `signing_mode: "2": want threshold or single`},
		{"old format key", nitro + "format = 2\n", `unknown key "format"`},
		{"old safety key", nitro + "max_epochs_ahead = 2\n", `unknown key "max_epochs_ahead"`},
		{"old locked key", nitro + "k = 2\n", `unknown key "k"`},
		{"peer hosts on azure", azure + "peer_attestation_hosts = a.example:443\n", "peer_attestation_hosts is for nitro and dev"},
		{"single key accepted on azure", azure + "sealing_key_release.unsafe_single_key_accepted = true\n", "unsafe_single_key_accepted does not apply to azure"},
		{"peer host without port", nitro + "peer_attestation_hosts = sharedneu.neu.attest.azure.net\n", "want host:port"},
		{"peer host as URL", nitro + "peer_attestation_hosts = https://sharedneu.neu.attest.azure.net\n", "want host:port"},
		{"peer host twice", nitro + "peer_attestation_hosts = a.example:443\npeer_attestation_hosts = a.example:443\n",
			"peer_attestation_hosts: repeats the entry of line"},
		{"no equals sign", nitro + "just text\n", "want key = value"},
		{"no value", nitro + "builder_gas_limit_min =\n", "builder_gas_limit_min: no value"},
		{"not ASCII", nitro + "signer_name = sígner\n", "printable ASCII"},
		{"control byte", nitro + "signer_name = a\x01b\n", "printable ASCII"},
		{"oversize", nitro + "#" + strings.Repeat("x", MaxHuman) + "\n", "at most"},
		{"hex too short", replaceLine(t, nitro, "cluster_id", "cluster_id = 0x01"), "want 32 bytes of hex"},
		{"hex not hex", replaceLine(t, nitro, "cluster_id", "cluster_id = 0x"+strings.Repeat("zz", 32)), "want 32 bytes of hex"},
		{"bool case", replaceLine(t, nitro, "allow_unverified_nonslashable_signing", "allow_unverified_nonslashable_signing = True"), "want true or false"},
		{"bool as number", replaceLine(t, nitro, "allow_unverified_nonslashable_signing", "allow_unverified_nonslashable_signing = 1"), "want true or false"},
		{"amount without unit", replaceLine(t, nitro, "exit_stake_cap_per_day", "exit_stake_cap_per_day = 4096"), "want N ETH or N Gwei"},
		{"amount glued to unit", replaceLine(t, nitro, "exit_stake_cap_per_day", "exit_stake_cap_per_day = 4096ETH"), "want N ETH or N Gwei"},
		{"amount unit case", replaceLine(t, nitro, "exit_stake_cap_per_day", "exit_stake_cap_per_day = 4096 eth"), `unit "eth"`},
		{"amount 10 decimals", replaceLine(t, nitro, "exit_stake_cap_per_day", "exit_stake_cap_per_day = 0.1234567891 ETH"), "at most 9 digits"},
		{"amount fraction of Gwei", replaceLine(t, nitro, "exit_stake_cap_per_day", "exit_stake_cap_per_day = 1.5 Gwei"), "want N Gwei"},
		{"amount too large", replaceLine(t, nitro, "exit_stake_cap_per_day", "exit_stake_cap_per_day = 18446744074 ETH"), "too large"},
		{"amount sign", replaceLine(t, nitro, "exit_stake_cap_per_day", "exit_stake_cap_per_day = -1 ETH"), "want N ETH"},
		{"number with sign", replaceLine(t, nitro, "builder_gas_limit_min", "builder_gas_limit_min = +5"), "want a decimal number"},
		{"number in hex", replaceLine(t, nitro, "max_keys", "max_keys = 0x10"), "want a decimal number"},
		{"number above 32 bits", replaceLine(t, nitro, "max_keys", "max_keys = 4294967296"), "below 2^32"},
		{"approvals needed above 8 bits", replaceLine(t, nitro, "approvals_needed", "approvals_needed = 258"), "below 2^8"},
		{"sign ahead out of range", replaceLine(t, nitro, "max_sign_epochs_ahead_of_clock", "max_sign_epochs_ahead_of_clock = 32"), "max_sign_epochs_ahead_of_clock 32, want 1 to 16"},
		{"platform case", replaceLine(t, nitro, "platform", "platform = Nitro"), "want nitro, azure, gcp or dev"},
		{"preset case", replaceLine(t, nitro, "preset", "preset = Minimal"), "want mainnet or minimal"},
		{"key of another platform", nitro + "sealing_key_release.kid = signer-key\n", "sealing_key_release.kid: does not apply to nitro"},
		{"store key of another platform", nitro + "slashing_log_store.account = acct\n", "slashing_log_store.account: does not apply to nitro"},
		{"unknown store key", nitro + "slashing_log_store.endpoint = http://localhost\n", `unknown key "slashing_log_store.endpoint"`},
		{"state store on nitro", nitro + "encrypted_state_store.bucket = state-1\nencrypted_state_store.region = eu-west-1\n", "encrypted_state_store must be absent"},
		{"state store part incomplete", replaceLine(t, azure, "encrypted_state_store.container", ""), "encrypted_state_store.container is missing"},
		{"fee recipient twice", nitro + "allowed_fee_recipients = 0x" + strings.Repeat("44", 1) + strings.Repeat("00", 19) + "\n", "allowed_fee_recipients: repeats the entry of line"},
		{"two forks at one epoch", nitro + "fork_schedule = 10 0x09000010\n", "fork_schedule: repeats the entry of line"},
		{"root domain twice", nitro + "bare_root_domains = randao\n", "bare_root_domains: repeats"},
		{"root domain not allowed", nitro + "bare_root_domains = attester\n", `"attester": want randao`},
		{"image kind", nitro + "allowed_image_measurements = aws 0x" + strings.Repeat("00", 32) + "\n", `kind "aws"`},
		{"nitro image with one PCR", nitro + "allowed_image_measurements = nitro " + pcr + "\n", "takes 3 hex values"},
		{"image PCR too short", nitro + "allowed_image_measurements = nitro " + pcr + " " + pcr + " 0x00\n", "want 48 bytes of hex"},
		{"fork without version", nitro + "fork_schedule = 30\n", "want EPOCH VERSION"},
		{"slot time without seconds", nitro + "slot_time_changes = 300\n", "want EPOCH SECONDS_PER_SLOT"},
		{"slot times at one epoch", nitro + "slot_time_changes = 300 4\nslot_time_changes = 300 3\n", "slot_time_changes: repeats the entry of line"},
		{"slot time kept", nitro + "slot_time_changes = 300 4\nslot_time_changes = 400 4\n", "keeps the slot time of the change before"},
		{"builder request auth root twice", nitro + "allowed_builder_request_auth_data_roots = 0x52" + strings.Repeat("00", 31) + "\n", "allowed_builder_request_auth_data_roots: repeats the entry of line"},
		{"builder request auth root short", nitro + "allowed_builder_request_auth_data_roots = 0x52\n", "want 32 bytes of hex"},
		{"CA not base64", replaceLine(t, nitro, "allowed_client_ca", "allowed_client_ca = not*base64"), "want base64"},
		{"CA with bad padding", replaceLine(t, nitro, "allowed_client_ca", "allowed_client_ca = AB=="), "want base64"},
		{"value rule", replaceLine(t, nitro, "approvals_needed", "approvals_needed = 1"), "approvals_needed is 1"},
		{"approver repeated", nitro + "approvers = " + hexOf(must32(approverPub(1))) + "\n", "listed twice"},
		{"salt missing", replaceLine(t, nitro, "salt.genesis_time", ""), "salt.genesis_time is missing"},
		{"salt zero", replaceLine(t, nitro, "salt.fork_schedule", "salt.fork_schedule = 0x"+strings.Repeat("00", 32)), "open: salt 0 is zero"},
		{"salt short", replaceLine(t, nitro, "salt.approvers", "salt.approvers = 0x01"), "want 32 bytes of hex"},
		{"salt of no leaf", nitro + "salt.colour = 0x" + strings.Repeat("01", 32) + "\n", `unknown key "salt.colour"`},
		{"platform salt missing", replaceLine(t, nitro, "platform_salt", ""), "platform_salt is zero"},
		{"only the platform salt", dropSalts(nitro) + "platform_salt = 0x" + strings.Repeat("01", 32) + "\n", "public: no salts"},
	}
	for _, c := range cases {
		if _, err := ParseSetup("setup.conf", []byte(c.text)); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: got %v, want %q", c.name, err, c.want)
		}
	}
	// Comments, blank lines, spacing, CRLF and the order of lines and of
	// list entries do not matter; non-ASCII in a comment is fine.
	lines := strings.Split(strings.TrimSpace(nitro), "\n")
	slices.Reverse(lines)
	for i := range lines {
		lines[i] = "  " + strings.Replace(lines[i], " = ", "\t=   ", 1) + "   # nöte\r"
	}
	got, err := ParseSetup("shuffled", []byte(strings.Join(lines, "\n")))
	if err != nil {
		t.Fatal(err)
	}
	want := ss["setup-nitro"]
	// The approver list keeps its line order, which the reversal changed.
	slices.Reverse(want.Locked.Approvers.Keys)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("shuffled file:\n%+v\nwant\n%+v", got, want)
	}
}

// A file without salts (what an operator writes) reads to a setup that
// passes the value rules and waits for its salts.
func TestParseSetupWithoutSalts(t *testing.T) {
	s := setups(t)["setup-azure"]
	text := dropSalts(string(must(FormatSetup(s))))
	got, err := ParseSetup("setup.conf", []byte(text))
	if err != nil {
		t.Fatal(err)
	}
	if got.PolicySalts.Public != nil || got.PlatformSalt != ([32]byte{}) {
		t.Fatal("salts from nowhere")
	}
	if _, err := got.Encode(); err == nil || !strings.Contains(err.Error(), "no salts") {
		t.Fatalf("encode without salts: %v", err)
	}
	got.PolicySalts, got.PlatformSalt = s.PolicySalts, s.PlatformSalt
	if !reflect.DeepEqual(got, s) {
		t.Fatal("values differ")
	}
	if _, err := ParseSetup("setup.conf", []byte(text+"approvals_needed = 1\n")); err == nil {
		t.Fatal("a value rule is skipped without salts")
	}
}

func TestParseGroups(t *testing.T) {
	l := setups(t)["setup-nitro"].Locked
	l.SlotTimeChanges = []setupwire.SlotTimeChange{{Epoch: 500, SecondsPerSlot: 4}}
	text := must(FormatLocked(&l))
	got, err := ParseLocked("locked.conf", text)
	if err != nil || !reflect.DeepEqual(*got, l) {
		t.Fatalf("locked: %v", err)
	}
	o := setups(t)["setup-nitro"].Open
	otext := must(FormatOpen(&o))
	gotOpen, err := ParseOpen("open.conf", otext)
	if err != nil || !reflect.DeepEqual(*gotOpen, o) {
		t.Fatalf("open: %v", err)
	}
	if empty, err := ParseOpen("open.conf", nil); err != nil || len(empty.ForkSchedule) != 0 || empty.GloasForkEpoch != nil {
		t.Fatalf("empty open group: %v", err)
	}
	for _, c := range []struct {
		name  string
		parse func() error
		want  string
	}{
		{"open key in a locked file", func() error {
			_, err := ParseLocked("l", append(text, "fork_schedule = 1 0x01000000\n"...))
			return err
		}, `unknown key "fork_schedule"`},
		{"locked key in an open file", func() error { _, err := ParseOpen("o", append(otext, "approvals_needed = 2\n"...)); return err }, `unknown key "approvals_needed"`},
		{"setup key in a group file", func() error { _, err := ParseLocked("l", append(text, "platform = gcp\n"...)); return err }, `unknown key "platform"`},
		{"salt in a group file", func() error {
			_, err := ParseLocked("l", append(text, "salt.approvers = 0x0101010101010101010101010101010101010101010101010101010101010101\n"...))
			return err
		}, `unknown key "salt.approvers"`},
		{"empty locked file", func() error { _, err := ParseLocked("l", nil); return err }, "approvals_needed is missing"},
		{"gloas without its fork", func() error { _, err := ParseOpen("o", []byte("gloas_fork_epoch = 3\n")); return err }, "gloas_fork_epoch 3"},
	} {
		if err := c.parse(); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: got %v, want %q", c.name, err, c.want)
		}
	}
}

func TestParseUpdateRefusals(t *testing.T) {
	u := updates(t)["update-open"]
	text := string(must(FormatUpdate(u)))
	cases := []struct {
		name string
		text string
		want string
	}{
		{"group unknown", replaceLine(t, text, "group", "group = both"), "want locked or open"},
		{"locked key in an open update", text + "approvals_needed = 2\n", `unknown key "approvals_needed"`},
		{"locked salt in an open update", text + "salt.approvers = 0x" + strings.Repeat("01", 32) + "\n", `unknown key "salt.approvers"`},
		{"salt missing", replaceLine(t, text, "salt.gloas_fork_epoch", ""), "salt.gloas_fork_epoch is missing"},
		{"no salts", dropSalts(text), "update: no salts"},
		{"signature without position", replaceLine(t, text, "approver_signature", "approver_signature = "+hexOf(make([]byte, 64))), "want POSITION SIGNATURE"},
		{"signature position 8", replaceLine(t, text, "approver_signature", "approver_signature = 8 "+hexOf(make([]byte, 64))), "position 8"},
		{"signature short", replaceLine(t, text, "approver_signature", "approver_signature = 0 0x00"), "want 64 bytes of hex"},
		{"same position twice", text + "approver_signature = 1 " + hexOf(make([]byte, 64)) + "\n", "repeats the entry"},
		{"version 0", replaceLine(t, text, "version", "version = 0"), "version 0"},
		{"no signatures", replaceLine(t, replaceLine(t, text, "approver_signature", ""), "approver_signature", ""), "0 approver signatures"},
	}
	for _, c := range cases {
		if _, err := ParseUpdate("update.txt", []byte(c.text)); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: got %v, want %q", c.name, err, c.want)
		}
	}
	if _, err := ParseUpdateBody("body.txt", []byte(text)); err == nil || !strings.Contains(err.Error(), "unknown key") {
		t.Fatalf("signatures in a body file: %v", err)
	}
}

// Text from a certificate goes into a comment of the human form. A subject
// with a line break must not add a line of its own.
func TestFormatCommentInjection(t *testing.T) {
	s := setups(t)["setup-nitro"]
	s.Platform.AllowedClientCA = [][]byte{makeCA(t, 9, "evil\napprovals_needed = 3\napprovers = "+hexOf(must32(approverPub(7))), true)}
	text, err := FormatSetup(s)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseSetup("setup.conf", text)
	if err != nil {
		t.Fatalf("%v\n%s", err, text)
	}
	if !reflect.DeepEqual(got, s) {
		t.Fatal("the certificate subject changed the parsed setup")
	}
}

func TestAmounts(t *testing.T) {
	for _, c := range []struct {
		in   string
		want uint64
	}{
		{"32 ETH", 32 * eth}, {"0.5 ETH", eth / 2}, {"0.000000001 ETH", 1}, {"1.000000001 ETH", eth + 1},
		{"7 Gwei", 7}, {"0 ETH", 0}, {"18446744073 ETH", 18446744073 * eth}, {"18446744073.709551615 ETH", maxU},
	} {
		got, err := parseAmount(c.in)
		if err != nil || got != c.want {
			t.Errorf("%q: got %d %v, want %d", c.in, got, err, c.want)
		}
		back, err := parseAmount(formatAmount(got))
		if err != nil || back != got {
			t.Errorf("%q: format %q does not read back", c.in, formatAmount(got))
		}
	}
	for _, in := range []string{"18446744073.709551616 ETH", ". ETH", "1. ETH", ".5 ETH", "1 Wei", "1e9 Gwei", "", "ETH"} {
		if _, err := parseAmount(in); err == nil {
			t.Errorf("%q accepted", in)
		}
	}
}

// peer_attestation_hosts may come in any order; the parser sorts
// them.
func TestParsePeerHosts(t *testing.T) {
	ss := setups(t)
	nitro := string(must(FormatSetup(ss["setup-nitro"])))
	text := nitro + "peer_attestation_hosts = www.googleapis.com:443\npeer_attestation_hosts = sharedneu.neu.attest.azure.net:443\n" +
		"peer_attestation_hosts = confidentialcomputing.googleapis.com:443\n"
	got, err := ParseSetup("peers.conf", []byte(text))
	if err != nil {
		t.Fatal(err)
	}
	want := ss["setup-nitro-peers"]
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parsed\n%+v\nwant\n%+v", got.Platform, want.Platform)
	}
	out := string(must(FormatSetup(want)))
	if !strings.Contains(out, "\npeer_attestation_hosts = sharedneu.neu.attest.azure.net:443\n") {
		t.Fatalf("human form:\n%s", out)
	}
	if strings.Contains(nitro, "peer_attestation_hosts") || !strings.Contains(nitro, "\nsetup_format_version = 2\n") {
		t.Fatal("a setup without hosts names them, or another format")
	}
}
