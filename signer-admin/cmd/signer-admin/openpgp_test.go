package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/governance/dkgorder"
	"github.com/lidofinance/tee-signer/governance/setupwire"
	adminapprover "github.com/lidofinance/tee-signer/signer-admin/approver"
	"github.com/lidofinance/tee-signer/signer-admin/approver/fakeagent"
	"github.com/lidofinance/tee-signer/tee-signer/handoverorder"
)

// An approver whose key is on an OpenPGP card (a fake gpg-agent with the
// seed of approver 1) signs every kind with sign -key openpgp:KEYGRIP: sign
// picks the hashed form, assemble and show take the signatures with
// approver 0's direct ones, and the fake runners take the config update.
// approver-key prints the setup's approvers line from the keygrip and from
// an exported public key.
func TestOpenPGPApprover(t *testing.T) {
	fc := newFakeCluster(t)
	cl := fc.cluster
	mustTool(t, "pin", "-cluster", cl)
	seed, err := hex.DecodeString(strings.TrimSpace(string(mustRead(t, fc.keys[1].file))))
	if err != nil {
		t.Fatal(err)
	}
	agent := fakeagent.Start(t, seed)
	old := adminapprover.AgentSocket
	adminapprover.AgentSocket = func() (string, error) { return agent.Path, nil }
	t.Cleanup(func() { adminapprover.AgentSocket = old })
	card := "openpgp:" + agent.Grip

	wantIn(t, mustTool(t, "approver-key", "-key", card), "approvers = "+fc.keys[1].pub)
	export := writeFile(t, fc.path("approver.pgp"), string(ed25519Export(agent.Public())))
	wantIn(t, mustTool(t, "approver-key", "-openpgp", export), "primary Ed25519 key", "sign flag true", "approvers = "+fc.keys[1].pub)

	// signBoth: approver 0 from its file, approver 1 on the card.
	signBoth := func(body string) []string {
		t.Helper()
		mustTool(t, "sign", "-key", fc.keys[0].file, body)
		wantIn(t, mustTool(t, "sign", "-key", card, body), "hashed form only", "with key "+fc.keys[1].pub[2:])
		sigs := []string{fmt.Sprintf("%s.%s.sig", body, fc.keys[0].pub[2:10]), fmt.Sprintf("%s.%s.sig", body, fc.keys[1].pub[2:10])}
		wantIn(t, string(mustRead(t, sigs[1])), "form = hashed")
		return sigs
	}
	assemble := func(body, signed string, want string) {
		t.Helper()
		wantIn(t, mustTool(t, append([]string{"assemble", "-out", signed, body}, signBoth(body)...)...), want)
		wantIn(t, mustTool(t, "show", "-active", body+".active", signed), "signatures: complete and valid")
	}

	// A config update, which the fake runners take.
	file := writeFile(t, fc.path("fees.conf"), lockedText(fc.keys[:3], 2, 0, fee1, fee2))
	body := fc.path("update.bin")
	mustTool(t, "draft", "-cluster", cl, "-group", "locked", "-margin", "0s", "-out", body, file)
	assemble(body, fc.path("update.signed"), "approvers 0,1 of 3 (k 2)")
	if out := mustTool(t, "push", "-cluster", cl, fc.path("update.signed")); count(out, `^s[123] accepted: locked v1/[0-9a-f]{8} in force$`) != 3 {
		t.Fatalf("push:\n%s", out)
	}

	// An import order and an exit approval.
	pk, _, splitPath := split(t, fc.dir, 3, 4, []string{"s1", "s2", "s3", "s4"})
	imp := fc.path("import.bin")
	mustTool(t, "import-draft", "-cluster", cl, "-signer", "s2", "-split", splitPath, "-out", imp)
	assemble(imp, fc.path("import.signed"), "2 approvers")
	exit := fc.path("exit.bin")
	mustTool(t, "exit-draft", "-cluster", cl, "-pubkey", pk.String(), "-index", "7", "-epoch", "1000", "-balance", "32000000000", "-out", exit)
	assemble(exit, fc.path("exit.signed"), "exit_approvals_needed 2")

	// A DKG order and a handover order over s1's setup, whose locked
	// group (version 0) holds the same approvers.
	raw := mustRead(t, filepath.Join(fc.dir, "setups", "s1.setup"))
	s, err := setupwire.DecodeSetup(raw)
	if err != nil {
		t.Fatal(err)
	}
	notAfter := uint64(time.Now().Add(24 * time.Hour).Unix())
	ob := &dkgorder.Body{ClusterID: s.ClusterID, ChainHash: s.Chain.Hash(), Label: "card", Path: dkgorder.PathDirk, Threshold: 3, NotAfter: notAfter}
	for _, n := range names {
		var sh [32]byte
		hex.Decode(sh[:], []byte(fc.hashes[n]))
		pub, _, _ := ed25519.GenerateKey(rand.Reader)
		ob.Participants = append(ob.Participants, dkgorder.Participant{Name: n, SetupHash: sh, OperatorKey: [32]byte(pub), Verifier: dkgorder.VerifierDev})
	}
	enc, err := ob.Encode()
	if err != nil {
		t.Fatal(err)
	}
	order := writeFile(t, fc.path("order.bin"), string(enc))
	writeJSONFile(t, order+".active", activeFile{Setup: hex.EncodeToString(raw)})
	assemble(order, fc.path("order.signed"), "approvers 0,1 of 3")

	sh, err := setupwire.SetupHash(raw)
	if err != nil {
		t.Fatal(err)
	}
	var target [32]byte
	rand.Read(target[:])
	hb := &handoverorder.Body{ClusterID: s.ClusterID, ChainHash: s.Chain.Hash(), NotAfter: notAfter,
		Source: handoverorder.Runner{Name: "s1", SetupHash: sh, Verifier: dkgorder.VerifierDev},
		Target: handoverorder.Runner{Name: "s1b", SetupHash: target, Verifier: dkgorder.VerifierDev}}
	if enc, err = hb.Encode(); err != nil {
		t.Fatal(err)
	}
	handover := writeFile(t, fc.path("handover.bin"), string(enc))
	writeJSONFile(t, handover+".active", activeFile{Setup: hex.EncodeToString(raw)})
	assemble(handover, fc.path("handover.signed"), "approvers 0,1 of 3 (k 2)")

	if _, _, n := agent.Last(); n != 5 {
		t.Fatalf("the card signed %d messages, want one per kind", n)
	}
}

// ed25519Export is a minimal binary OpenPGP export of an Ed25519 primary
// key: the key packet, a user ID and a self-signature's hashed key flags
// (sign and certify). The signature's MPIs are left out; approver-key reads
// the flags only.
func ed25519Export(pub ed25519.PublicKey) []byte {
	packet := func(tag byte, body []byte) []byte { return append([]byte{0xc0 | tag, byte(len(body))}, body...) }
	key := append([]byte{4, 0x65, 0, 0, 0, 22, 9, 0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x0f, 0x01, 0x01, 0x07, 0x40}, pub...)
	sig := []byte{4, 0x13, 22, 8, 0, 3, 2, 27, 0x03, 0, 0}
	out := packet(6, key)
	out = append(out, packet(13, []byte("approver"))...)
	return append(out, packet(2, sig)...)
}
