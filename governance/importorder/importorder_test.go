package importorder

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lidofinance/tee-signer/governance/setupwire"
	"github.com/lidofinance/tee-signer/signer-protocol"
)

var update = flag.Bool("update", false, "rewrite testdata/vector.txt")

func approver(id byte) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{id}, 32))
}

// sample is the order of the test vector: two validators, a 3-of-4 split,
// share index 2, signed by approvers 1 and 2 (seeds 0x01.., 0x02..).
func sample(t *testing.T) (*Order, []byte) {
	t.Helper()
	v1 := backend.Pubkey{0xa1}
	v2 := backend.Pubkey{0xa2}
	b := Body{ClusterID: [32]byte{0xc1}, ChainHash: [32]byte{0xc2}, Target: [32]byte{0x7a}, NotAfter: 1_800_000_000,
		T: 3, N: 4, ShareIndex: 2, Validators: []Entry{
			{Pubkey: v1, CommitmentsHash: CommitmentsHash([]backend.Pubkey{v1, {0xb1}, {0xb2}})},
			{Pubkey: v2, CommitmentsHash: CommitmentsHash([]backend.Pubkey{v2, {0xb3}, {0xb4}})}}}
	body, err := b.Encode()
	if err != nil {
		t.Fatal(err)
	}
	o := &Order{Body: b}
	for _, id := range []byte{1, 2} {
		o.Approvals = append(o.Approvals, setupwire.Approval{Position: id - 1, Signature: SignBody(approver(id), body)})
	}
	return o, body
}

// The vector in testdata (for the Dirk fork's signer-config): body, order
// hash, signed order. The decoder reads the order back and it verifies
// under approvers 1 and 2 with k = 2.
func TestVector(t *testing.T) {
	o, body := sample(t)
	raw, err := o.Encode()
	if err != nil {
		t.Fatal(err)
	}
	h := Hash(body)
	got := "body " + hex.EncodeToString(body) + "\nhash " + hex.EncodeToString(h[:]) + "\norder " + hex.EncodeToString(raw) + "\n"
	path := filepath.Join("testdata", "vector.txt")
	if *update {
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run with -update)", err)
	}
	if string(want) != got {
		t.Fatal("testdata/vector.txt differs from what the code makes")
	}
	back, err := Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	set := setupwire.ApproverSet{ApprovalsNeeded: 2}
	for _, id := range []byte{1, 2, 3} {
		set.Keys = append(set.Keys, [32]byte(approver(id).Public().(ed25519.PublicKey)))
	}
	if err := back.Verify(&set); err != nil {
		t.Fatal(err)
	}
	set.ApprovalsNeeded = 3
	if err := back.Verify(&set); err == nil {
		t.Fatal("two signatures passed with approvals_needed 3")
	}
}

func TestStrict(t *testing.T) {
	o, body := sample(t)
	raw, _ := o.Encode()
	for name, b := range map[string]func(*Body){
		"2t = n":       func(b *Body) { b.T, b.N = 2, 4 },
		"t > n":        func(b *Body) { b.T = 5 },
		"index 0":      func(b *Body) { b.ShareIndex = 0 },
		"index > n":    func(b *Body) { b.ShareIndex = 5 },
		"no validator": func(b *Body) { b.Validators = nil },
		"twice":        func(b *Body) { b.Validators[1].Pubkey = b.Validators[0].Pubkey },
		"no cluster":   func(b *Body) { b.ClusterID = [32]byte{} },
		"no target":    func(b *Body) { b.Target = [32]byte{} },
		"no expiry":    func(b *Body) { b.NotAfter = 0 },
	} {
		c := o.Body
		c.Validators = append([]Entry(nil), o.Body.Validators...)
		b(&c)
		if _, err := c.Encode(); err == nil {
			t.Errorf("%s: encoded", name)
		}
	}
	for name, r := range map[string][]byte{
		"trailing":  append(append([]byte{}, raw...), 0),
		"truncated": raw[:len(raw)-1],
		"body kind": append([]byte{kindBody}, raw[1:]...),
	} {
		if _, err := Decode(r); err == nil {
			t.Errorf("%s: decoded", name)
		}
	}
	if _, err := DecodeBody(append(append([]byte{}, body...), 0)); err == nil || !strings.Contains(err.Error(), "validators") {
		t.Errorf("body with a trailing byte: %v", err)
	}
}

// A hash-then-sign signature counts like a direct one; one made under
// another kind's hashed context does not. An approver signs 32 bytes,
// whatever the order's size.
func TestHashedSignature(t *testing.T) {
	o, body := sample(t)
	set := setupwire.ApproverSet{ApprovalsNeeded: 2}
	for _, id := range []byte{1, 2, 3} {
		set.Keys = append(set.Keys, [32]byte(approver(id).Public().(ed25519.PublicKey)))
	}
	o.Approvals[1].Signature = SignBodyHashed(approver(2), body)
	if err := o.Verify(&set); err != nil {
		t.Fatalf("direct and hashed: %v", err)
	}
	if m := setupwire.ApprovalMessage(setupwire.CtxImportOrder, true, body); len(m) != 32 {
		t.Fatalf("hashed message of %d bytes", len(m))
	}
	o.Approvals[1].Signature = setupwire.SignApproval(approver(2), setupwire.CtxHandoverOrder, true, body)
	if err := o.Verify(&set); err == nil {
		t.Fatal("a signature under the handover order's hashed context verified")
	}
}
