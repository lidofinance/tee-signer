package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/lidofinance/tee-signer/signer-protocol"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/governance/setupwire"
)

// tool runs signer-admin with args and returns what it printed.
func tool(t *testing.T, args ...string) (string, error) {
	t.Helper()
	var b bytes.Buffer
	err := run(args, &b)
	return b.String(), err
}

// mustTool runs signer-admin and fails the test on an error.
func mustTool(t *testing.T, args ...string) string {
	t.Helper()
	out, err := tool(t, args...)
	if err != nil {
		t.Fatalf("signer-admin %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return out
}

// failTool runs signer-admin, wants an error, and returns the output and
// the error text together.
func failTool(t *testing.T, args ...string) string {
	t.Helper()
	out, err := tool(t, args...)
	if err == nil {
		t.Fatalf("signer-admin %s passed:\n%s", strings.Join(args, " "), out)
	}
	return out + err.Error()
}

func wantIn(t *testing.T, out string, subs ...string) {
	t.Helper()
	for _, s := range subs {
		if !strings.Contains(out, s) {
			t.Fatalf("output lacks %q:\n%s", s, out)
		}
	}
}

// count is the number of lines of out that match re.
func count(out, re string) int {
	n := 0
	r := regexp.MustCompile(re)
	for _, l := range strings.Split(out, "\n") {
		if r.MatchString(l) {
			n++
		}
	}
	return n
}

// caDER is a CA certificate for the setups' allowed_client_ca.
func caDER(t *testing.T) []byte {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "signer-admin test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// approver is a test approver: its key file (mode 0600) and public key.
type approver struct {
	file string
	pub  string // 0x and 64 hex digits
}

func approvers(t *testing.T, dir string, n int) []approver {
	t.Helper()
	var out []approver
	for i := 1; i <= n; i++ {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(dir, fmt.Sprintf("approver-%d.key", i))
		if err := os.WriteFile(p, fmt.Appendf(nil, "%x\n", priv.Seed()), 0o600); err != nil {
			t.Fatal(err)
		}
		out = append(out, approver{file: p, pub: fmt.Sprintf("0x%x", pub)})
	}
	return out
}

// lockedText is a locked group in the human form.
func lockedText(set []approver, k, timeLock int, fees ...string) string {
	var b strings.Builder
	for _, a := range set {
		fmt.Fprintf(&b, "approvers = %s\n", a.pub)
	}
	fmt.Fprintf(&b, "approvals_needed = %d\nchange_delay_seconds = %d\n", k, timeLock)
	for _, f := range fees {
		fmt.Fprintf(&b, "allowed_fee_recipients = %s\n", f)
	}
	b.WriteString(`builder_gas_limit_min = 30000000
builder_gas_limit_max = 60000000
builder_registration_max_future_seconds = 3600
exit_stake_cap_per_day = 4096 ETH
exit_approvals_needed = 2
min_activation_balance = 32 ETH
max_effective_balance = 2048 ETH
withdrawal_credentials = 0x0200000000000000000000004242424242424242424242424242424242424242
allow_unverified_nonslashable_signing = false
`)
	return b.String()
}

const (
	fee1 = "0x4300000000000000000000000000000000000000"
	fee2 = "0x4500000000000000000000000000000000000000"
	fee3 = "0x4600000000000000000000000000000000000000"
	fee4 = "0x4700000000000000000000000000000000000000"
)

// The test chain: 4 s slots, 2 slots per epoch, genesis 1000 epochs ago.
const (
	secondsPerSlot = 4
	slotsPerEpoch  = 2
)

func genesisTime() int64 { return time.Now().Unix() - 1000*secondsPerSlot*slotsPerEpoch }

// openText is an open group: the genesis fork at 0, and one more fork per
// epoch given.
func openText(forkEpochs ...uint64) string {
	s := "fork_schedule = 0 0x01000010\n"
	for i, e := range forkEpochs {
		s += fmt.Sprintf("fork_schedule = %d 0x0%d000010\n", e, i+2)
	}
	return s
}

// setupText is a setup file of the dev platform with one section per name;
// each signer's stores are below dir/NAME.
func setupText(dir string, ca []byte, genesis int64, locked string, names ...string) string {
	var b strings.Builder
	mode := "threshold"
	if len(names) == 1 {
		mode = "single"
	}
	fmt.Fprintf(&b, `# a test cluster
setup_format_version = 2
signing_mode = %s
handover_generation = 1
genesis_validators_root = 0x4b36000000000000000000000000000000000000000000000000000000000000
genesis_fork_version = 0x00000010
genesis_time = %d
seconds_per_slot = %d
slots_per_epoch = %d
preset = minimal
voluntary_exit_fork_version = 0x04000010
max_sign_epochs_ahead_of_clock = 2
slashing_mark_prewrite.block_slots = 16
slashing_mark_prewrite.source_epochs = 2
slashing_mark_prewrite.target_epochs = 2
platform = dev
allowed_client_ca = %s
max_keys = 16
slashing_log_min_lock_days = 7
`, mode, genesis, secondsPerSlot, slotsPerEpoch, base64.StdEncoding.EncodeToString(ca))
	b.WriteString(locked)
	b.WriteString(openText())
	for _, n := range names {
		fmt.Fprintf(&b, "\n[signer %s]\nslashing_log_store.dir = %s\nencrypted_state_store.dir = %s\n", n,
			filepath.Join(dir, n, "marks"), filepath.Join(dir, n, "state-copy"))
	}
	return b.String()
}

func writeFile(t *testing.T, path, text string) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(text), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeJSONFile(t *testing.T, path string, v any) string {
	t.Helper()
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return writeFile(t, path, string(b))
}

// readAttestation is the attestation section of a cloud.json.
func readAttestation(t *testing.T, path string) map[string]any {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var top struct {
		Attestation map[string]any `json:"attestation"`
	}
	if err := json.Unmarshal(b, &top); err != nil {
		t.Fatal(err)
	}
	return top.Attestation
}

// setupHashes reads the "NAME setup_sha256 HEX PATH" lines of setup.
func setupHashes(out string) map[string]string {
	m := map[string]string{}
	for _, l := range strings.Split(out, "\n") {
		f := strings.Fields(l)
		if len(f) == 4 && f[1] == "setup_sha256" {
			m[f[0]] = f[2]
		}
	}
	return m
}

// bodyHash is the body_sha256 a subcommand printed.
func bodyHash(t *testing.T, out string) string {
	t.Helper()
	m := regexp.MustCompile(`body_sha256 ([0-9a-f]{64})`).FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("no body_sha256 in:\n%s", out)
	}
	return m[1]
}

// craftSpec describes an update made by hand, to send what draft and
// assemble would refuse.
type craftSpec struct {
	setup   string // a setup file of the cluster
	group   setupwire.Group
	version uint64
	// prev is the prev_hash; zero: the setup's group (version 0).
	prev [32]byte
	// open is the open group of an open update; nil: the setup's.
	open *setupwire.Open
	// set is the active approver set in order; signers are the positions
	// in it that sign.
	set     []approver
	signers []int
}

// craft signs and encodes the update of spec and returns its file.
func craft(t *testing.T, spec craftSpec) string {
	t.Helper()
	s, err := setupwire.DecodeSetup(mustRead(t, spec.setup))
	if err != nil {
		t.Fatal(err)
	}
	b := setupwire.UpdateBody{ClusterID: s.ClusterID, ChainHash: s.Chain.Hash(), Group: spec.group, Version: spec.version,
		PrevHash: spec.prev, ActivateAt: uint64(time.Now().Unix())}
	if b.PrevHash == ([32]byte{}) {
		b.PrevHash, _ = s.GroupHash(spec.group)
	}
	if spec.group == setupwire.GroupLocked {
		b.Locked = &s.Locked
	} else {
		b.Open = &s.Open
		if spec.open != nil {
			b.Open = spec.open
		}
	}
	if err := b.DrawSalts(rand.Reader); err != nil {
		t.Fatal(err)
	}
	u := setupwire.Update{Body: b}
	for _, i := range spec.signers {
		seed, err := hex.DecodeString(strings.TrimSpace(string(mustRead(t, spec.set[i].file))))
		if err != nil {
			t.Fatal(err)
		}
		sig, err := b.Sign(ed25519.NewKeyFromSeed(seed))
		if err != nil {
			t.Fatal(err)
		}
		u.Approvals = append(u.Approvals, setupwire.Approval{Position: uint8(i), Signature: sig})
	}
	signed, err := u.Encode()
	if err != nil {
		t.Fatal(err)
	}
	return writeFile(t, filepath.Join(t.TempDir(), "crafted.signed"), string(signed))
}

func mustRead(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// clientPKI makes a client root CA, an admin intermediate under it
// (clientAuth and backend.AdminClientOID) and one admin client certificate
// the intermediate issued, as PEM files in dir: the certificate file holds
// the leaf and the intermediate. It returns the root in DER for the
// setups' allowed_client_ca. signingLeaf issues a signing certificate
// under the same root.
func clientPKI(t *testing.T, dir string) (ca []byte, cert, key string) {
	t.Helper()
	_, ca, cert, key = clientPKIWith(t, dir)
	return ca, cert, key
}

// clientPKIWith is clientPKI that returns the PKI too, to issue more.
func clientPKIWith(t *testing.T, dir string) (p *testPKI, ca []byte, cert, key string) {
	t.Helper()
	p = newPKI(t)
	writePKI(t, dir, p)
	cert, key = filepath.Join(dir, "client.pem"), filepath.Join(dir, "client-key.pem")
	p.issue(t, cert, key, true)
	return p, p.rootDER, cert, key
}

// testPKI is a client root with an admin and a signing intermediate.
type testPKI struct {
	rootDER          []byte
	rootKey          *ecdsa.PrivateKey
	admin, signing   *x509.Certificate
	adminK, signingK *ecdsa.PrivateKey
}

var pkiSerial int64 = 10

func newCert(t *testing.T, tmpl, parent *x509.Certificate, pub *ecdsa.PublicKey, signer *ecdsa.PrivateKey) []byte {
	t.Helper()
	pkiSerial++
	tmpl.SerialNumber = big.NewInt(pkiSerial)
	tmpl.NotBefore, tmpl.NotAfter = time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour)
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, signer)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func ecKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func newPKI(t *testing.T) *testPKI {
	t.Helper()
	p := &testPKI{rootKey: ecKey(t), adminK: ecKey(t), signingK: ecKey(t)}
	rootTmpl := &x509.Certificate{Subject: pkix.Name{CommonName: "signer-admin test client CA"},
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	p.rootDER = newCert(t, rootTmpl, rootTmpl, &p.rootKey.PublicKey, p.rootKey)
	root, err := x509.ParseCertificate(p.rootDER)
	if err != nil {
		t.Fatal(err)
	}
	inter := func(name string, key *ecdsa.PrivateKey, marks []asn1.ObjectIdentifier) *x509.Certificate {
		der := newCert(t, &x509.Certificate{Subject: pkix.Name{CommonName: name}, IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true,
			KeyUsage: x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, UnknownExtKeyUsage: marks},
			root, &key.PublicKey, p.rootKey)
		c, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	p.admin = inter("signer-admin test admin CA", p.adminK, []asn1.ObjectIdentifier{backend.AdminClientOID})
	p.signing = inter("signer-admin test signing CA", p.signingK, nil)
	return p
}

// writePKI keeps the root, both intermediates and their keys in dir/pki,
// for tests that issue more certificates with signer-admin itself.
func writePKI(t *testing.T, dir string, p *testPKI) {
	t.Helper()
	d := filepath.Join(dir, "pki")
	if err := os.MkdirAll(d, 0o700); err != nil {
		t.Fatal(err)
	}
	key := func(k *ecdsa.PrivateKey) []byte {
		der, err := x509.MarshalPKCS8PrivateKey(k)
		if err != nil {
			t.Fatal(err)
		}
		return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	}
	certPEM := func(der []byte) []byte { return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}) }
	for name, b := range map[string][]byte{
		"root-ca.pem": certPEM(p.rootDER), "admin-ca.pem": certPEM(p.admin.Raw), "signing-ca.pem": certPEM(p.signing.Raw),
	} {
		writeFile(t, filepath.Join(d, name), string(b))
	}
	for name, b := range map[string][]byte{"root-ca-key.pem": key(p.rootKey), "admin-ca-key.pem": key(p.adminK), "signing-ca-key.pem": key(p.signingK)} {
		if err := os.WriteFile(filepath.Join(d, name), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// issue writes a client certificate (leaf and intermediate) and its key:
// an admin certificate under the admin intermediate, or a signing one.
func (p *testPKI) issue(t *testing.T, cert, key string, admin bool) {
	t.Helper()
	k := ecKey(t)
	inter, ik := p.signing, p.signingK
	tmpl := &x509.Certificate{Subject: pkix.Name{CommonName: "signer-admin"},
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	if admin {
		inter, ik = p.admin, p.adminK
		tmpl.UnknownExtKeyUsage = []asn1.ObjectIdentifier{backend.AdminClientOID}
	}
	der := newCert(t, tmpl, inter, &k.PublicKey, ik)
	keyDER, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, cert, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))+
		string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: inter.Raw})))
	if err := os.WriteFile(key, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
}
