package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lidofinance/tee-signer/governance/importorder"
	"github.com/lidofinance/tee-signer/governance/setupwire"
	cloud "github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/wire"
)

// goldenNitroSetup is a Nitro setup of the setupwire tests. Its
// allowed_image_measurements lists the nitro image whose PCR0 to PCR2 are
// all 0x11.
var goldenNitroSetup = filepath.Join("..", "..", "..", "governance", "setupwire", "testdata", "setup-nitro.bin")

// orderFor writes a 1 of 1 import order for the setup target of cluster
// id, and a commitments file with its one point. The tool reads both
// before it dials; the runner would check the signature.
func orderFor(t *testing.T, target, id [32]byte) (order, commitments string) {
	t.Helper()
	var pk cloud.Pubkey
	if err := pk.UnmarshalText([]byte(testPubkey)); err != nil {
		t.Fatal(err)
	}
	o := importorder.Order{
		Body: importorder.Body{ClusterID: id, Target: target, NotAfter: 4_000_000_000, T: 1, N: 1, ShareIndex: 1,
			Validators: []importorder.Entry{{Pubkey: pk, CommitmentsHash: importorder.CommitmentsHash([]cloud.Pubkey{pk})}}},
		Approvals: []setupwire.Approval{{Position: 0}},
	}
	raw, err := o.Encode()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	order, commitments = filepath.Join(dir, "order.signed"), filepath.Join(dir, "commitments.txt")
	if err := os.WriteFile(order, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(commitments, []byte(testPubkey+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return order, commitments
}

// share-import refuses a cloud verifier without -setup, an image pin the
// setup does not list, a missing -order, an order for another setup and a
// missing -updates folder, before it reaches the runner. A listed pin with
// an order for the setup goes on to the runner, whose dev document the
// Nitro verifier refuses.
func TestShareImportChecksImagePin(t *testing.T) {
	raw, err := os.ReadFile(goldenNitroSetup)
	if err != nil {
		t.Fatal(err)
	}
	s, err := setupwire.DecodeSetup(raw)
	if err != nil {
		t.Fatal(err)
	}
	h, err := s.Hash()
	if err != nil {
		t.Fatal(err)
	}
	f := startPlainFake(t, flagPathState())
	pins := func(b string) []string {
		var out []string
		for i := range 3 {
			out = append(out, "-nitro-pcr", string(rune('0'+i))+"="+strings.Repeat(b, 48))
		}
		return out
	}
	order, comm := orderFor(t, h, s.ClusterID)
	otherOrder, otherComm := orderFor(t, [32]byte{7}, s.ClusterID)
	base := []string{"-addr", f.addr(), "-pubkey", testPubkey, "-share-file", shareFile(t), "-verifier", "aws-nitro"}
	run := func(args ...string) (string, error) {
		return tool(t, append(append([]string{}, base...), args...)...)
	}
	for _, tc := range []struct {
		args []string
		want string
	}{
		{pins("11"), "needs -setup"},
		{append(pins("22"), "-setup", goldenNitroSetup, "-order", order, "-commitments", comm), "allowed_image_measurements"},
		{append(pins("11"), "-setup", goldenNitroSetup), "needs -order"},
		{append(pins("11"), "-setup", goldenNitroSetup, "-order", otherOrder, "-commitments", otherComm), "is an import order for setup"},
		{append(pins("11"), "-setup", goldenNitroSetup, "-updates", filepath.Join(t.TempDir(), "none"), "-order", order, "-commitments", comm), "-updates"},
	} {
		out, err := run(tc.args...)
		if err == nil || !strings.Contains(out, tc.want) {
			t.Fatalf("%v: %v, want %q:\n%s", tc.args, err, tc.want, out)
		}
	}
	if _, seen := f.count(wire.TypeIdentity); seen != 0 {
		t.Fatalf("%d identity requests reached the runner", seen)
	}
	out, err := run(append(pins("11"), "-setup", goldenNitroSetup, "-order", order, "-commitments", comm)...)
	if err == nil || strings.Contains(out, "allowed_image_measurements") || !strings.Contains(out, "locked version 0") {
		t.Fatalf("a listed pin: %v\n%s", err, out)
	}
	if _, seen := f.count(wire.TypeIdentity); seen == 0 {
		t.Fatal("a listed pin did not reach the runner")
	}
}
