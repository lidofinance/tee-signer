package approver

import (
	"bytes"
	"crypto/ed25519"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lidofinance/tee-signer/governance/setupwire"
	"github.com/lidofinance/tee-signer/signer-admin/approver/fakeagent"
)

// approverContexts are the five kinds an approver signs.
var approverContexts = []setupwire.Context{setupwire.CtxConfigUpdate, setupwire.CtxDKGOrder, setupwire.CtxHandoverOrder,
	setupwire.CtxImportOrder, setupwire.CtxTAExitApproval}

func useAgent(t *testing.T, path string) {
	t.Helper()
	old := AgentSocket
	AgentSocket = func() (string, error) { return path, nil }
	t.Cleanup(func() { AgentSocket = old })
}

// An openpgp: key signs every kind in the hashed form through the agent:
// the agent gets the 32-byte message as a SHA-256 digest, the signature
// passes the runner's verifier and equals the file key's signature with
// the same seed (Ed25519 is deterministic). The direct form, a wrong
// keygrip and a malformed URI are refused.
func TestOpenPGPSignsHashedForm(t *testing.T) {
	seed := bytes.Repeat([]byte{0x22}, 32)
	agent := fakeagent.Start(t, seed)
	useAgent(t, agent.Path)
	s, err := Open("openpgp:" + strings.ToLower(agent.Grip))
	if err != nil {
		t.Fatal(err)
	}
	if !s.Public().Equal(agent.Public()) || !HashedOnly(s) {
		t.Fatal("public key or hashed-only flag")
	}
	priv := ed25519.NewKeyFromSeed(seed)
	// A body long enough that the direct form could not go to a card.
	body := bytes.Repeat([]byte("an order of 1,024 validators "), 3000)
	for _, c := range approverContexts {
		sig, err := Sign(s, c, true, body)
		if err != nil {
			t.Fatalf("%s: %v", c, err)
		}
		if !setupwire.VerifyApproval(Key(s), c, sig, body) {
			t.Fatalf("%s: the runner's verifier refuses the signature", c)
		}
		if sig != setupwire.SignApproval(priv, c, true, body) {
			t.Fatalf("%s: not the signature of the same key in a file", c)
		}
		if ok, hashed := Verify(Key(s), c, sig, body); !ok || !hashed {
			t.Fatalf("%s: Verify %v %v", c, ok, hashed)
		}
		last, desc, _ := agent.Last()
		if !bytes.Equal(last, setupwire.ApprovalMessage(c, true, body)) || len(last) != 32 {
			t.Fatalf("%s: the agent signed %x", c, last)
		}
		if !strings.Contains(desc, "signer-admin") {
			t.Fatalf("key description %q", desc)
		}
	}
	if _, err := Sign(s, setupwire.CtxImportOrder, false, body); err == nil || !strings.Contains(err.Error(), "hashed form only") {
		t.Fatalf("direct form: %v", err)
	}
	if _, err := s.Sign(make([]byte, 61)); err == nil {
		t.Fatal("signed a 61-byte message")
	}
	if _, err := Open("openpgp:" + strings.Repeat("AB", 20)); err == nil || !strings.Contains(err.Error(), "No secret key") {
		t.Fatalf("unknown keygrip: %v", err)
	}
	if _, err := Open("openpgp:0x1234"); err == nil || !strings.Contains(err.Error(), "KEYGRIP") {
		t.Fatalf("short keygrip: %v", err)
	}
}

// The agent's s-expressions: an Ed25519 key with the 0x40 prefix, a
// Curve25519 key refused, a signature with a short r padded back.
func TestSexp(t *testing.T) {
	pub := bytes.Repeat([]byte{7}, 32)
	k, err := ed25519FromSexp([]byte("(10:public-key(3:ecc(5:curve7:Ed25519)(5:flags5:eddsa)(1:q33:\x40" + string(pub) + ")))"))
	if err != nil || !bytes.Equal(k, pub) {
		t.Fatalf("Ed25519: %x %v", k, err)
	}
	if _, err := ed25519FromSexp([]byte("(10:public-key(3:ecc(5:curve10:Curve25519)(1:q33:\x40" + string(pub) + ")))")); err == nil || !strings.Contains(err.Error(), "signing subkey") {
		t.Fatalf("Curve25519: %v", err)
	}
	if _, err := ed25519FromSexp([]byte("(10:public-key(3:rsa(1:n1:\x01)(1:e1:\x03)))")); err == nil {
		t.Fatal("RSA key taken")
	}
	r, s := bytes.Repeat([]byte{1}, 31), bytes.Repeat([]byte{2}, 32)
	sig, err := ed25519SigFromSexp([]byte("(7:sig-val(5:eddsa(1:r31:" + string(r) + ")(1:s32:" + string(s) + ")))"))
	if err != nil || !bytes.Equal(sig, append(append([]byte{0}, r...), s...)) {
		t.Fatalf("signature: %x %v", sig, err)
	}
	if got := assuanUnescape("a%25b%0Ac%2"); string(got) != "a%b\nc%2" {
		t.Fatalf("unescape %q", got)
	}
	if got := assuanEscape("a b+c%\n"); got != "a+b%2Bc%25%0A" {
		t.Fatalf("escape %q", got)
	}
}

// With GnuPG installed: a fresh Ed25519 key in a temporary GNUPGHOME, in
// the agent's own store (no card), signs every kind through the real
// gpg-agent, and its exported public key gives the same approver key. No
// network, no card; skipped without gpg.
func TestOpenPGPRealAgent(t *testing.T) {
	for _, p := range []string{"gpg", "gpgconf", "gpg-agent"} {
		if _, err := exec.LookPath(p); err != nil {
			t.Skip("GnuPG is not installed")
		}
	}
	// gpg-agent's socket must fit a unix socket path.
	home, err := os.MkdirTemp("", "gnupg")
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("GNUPGHOME", home)
	t.Cleanup(func() {
		exec.Command("gpgconf", "--kill", "gpg-agent").Run()
		os.RemoveAll(home)
	})
	if err := os.Chmod(home, 0o700); err != nil {
		t.Fatal(err)
	}
	gpg := func(args ...string) string {
		t.Helper()
		out, err := exec.Command("gpg", append([]string{"--batch", "--no-tty", "--pinentry-mode", "loopback", "--passphrase", ""}, args...)...).Output()
		if err != nil {
			t.Fatalf("gpg %s: %v", strings.Join(args, " "), err)
		}
		return string(out)
	}
	// A primary key that signs and certifies, and an Ed25519 signing
	// subkey: the subkey is the approver key, as on a card.
	gpg("--quick-gen-key", "approver test <approver@test.invalid>", "ed25519", "sign,cert", "never")
	fpr := colonField(gpg("--with-colons", "--list-secret-keys"), "fpr", 0)
	gpg("--quick-add-key", fpr, "ed25519", "sign", "never")
	listing := gpg("--with-colons", "--with-keygrip", "--list-secret-keys")
	subFpr, subGrip := colonField(listing, "fpr", 1), colonField(listing, "grp", 1)

	s, err := Open("openpgp:" + subGrip)
	if err != nil {
		t.Fatal(err)
	}
	body := []byte("a body")
	for _, c := range approverContexts {
		sig, err := Sign(s, c, true, body)
		if err != nil {
			t.Fatalf("%s: %v", c, err)
		}
		if !setupwire.VerifyApproval(Key(s), c, sig, body) {
			t.Fatalf("%s: the runner's verifier refuses gpg-agent's signature", c)
		}
	}

	for _, armor := range []bool{false, true} {
		args := []string{"--export", fpr}
		if armor {
			args = append([]string{"--armor"}, args...)
		}
		path := filepath.Join(t.TempDir(), "pub")
		if err := os.WriteFile(path, []byte(gpg(args...)), 0o644); err != nil {
			t.Fatal(err)
		}
		data, _ := os.ReadFile(path)
		keys, err := OpenPGPEd25519Keys(data)
		if err != nil {
			t.Fatalf("armor %v: %v", armor, err)
		}
		if len(keys) != 2 || keys[0].Subkey || !keys[0].CanSign || !keys[1].Subkey || !keys[1].CanSign {
			t.Fatalf("armor %v: keys %+v", armor, keys)
		}
		k, err := SelectOpenPGPKey(keys, "")
		if err != nil {
			t.Fatal(err)
		}
		if !k.Public.Equal(s.Public()) || !strings.EqualFold(strings.ToUpper(fpr2hex(k)), subFpr) {
			t.Fatalf("armor %v: the export's signing subkey %s is not the agent's key", armor, k.KeyID())
		}
		if p, err := SelectOpenPGPKey(keys, fpr); err != nil || p.Subkey {
			t.Fatalf("by the primary's fingerprint: %+v %v", p, err)
		}
		if p, err := SelectOpenPGPKey(keys, subFpr[24:]); err != nil || !p.Subkey {
			t.Fatalf("by the subkey's key ID: %+v %v", p, err)
		}
	}
}

func fpr2hex(k OpenPGPKey) string {
	const digits = "0123456789ABCDEF"
	var b strings.Builder
	for _, c := range k.Fingerprint {
		b.WriteByte(digits[c>>4])
		b.WriteByte(digits[c&15])
	}
	return b.String()
}

// colonField is field 10 of the n-th record of type typ in gpg's
// --with-colons output (fingerprint or keygrip).
func colonField(out, typ string, n int) string {
	for _, l := range strings.Split(out, "\n") {
		f := strings.Split(l, ":")
		if len(f) > 9 && f[0] == typ {
			if n == 0 {
				return f[9]
			}
			n--
		}
	}
	return ""
}
