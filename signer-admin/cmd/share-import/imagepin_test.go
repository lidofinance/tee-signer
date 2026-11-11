package main

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/lidofinance/tee-signer/signer-protocol/wire"
)

// goldenNitroSetup is a Nitro setup of the setupwire tests. Its
// allowed_image_measurements lists the nitro image whose PCR0 to PCR2 are
// all 0x11.
var goldenNitroSetup = filepath.Join("..", "..", "..", "governance", "setupwire", "testdata", "setup-nitro.bin")

// share-import refuses a cloud verifier without -setup, and an image pin
// the setup does not list, before it reaches the runner. A listed pin
// goes on to the runner, whose dev document the Nitro verifier refuses.
func TestShareImportChecksImagePin(t *testing.T) {
	f := startPlainFake(t, flagPathState())
	pins := func(b string) []string {
		var out []string
		for i := range 3 {
			out = append(out, "-nitro-pcr", string(rune('0'+i))+"="+strings.Repeat(b, 48))
		}
		return out
	}
	base := []string{"-addr", f.addr(), "-pubkey", testPubkey, "-share-file", shareFile(t), "-verifier", "aws-nitro"}
	for _, tc := range []struct {
		args []string
		want string
	}{
		{pins("11"), "needs -setup"},
		{append(pins("22"), "-setup", goldenNitroSetup), "allowed_image_measurements"},
	} {
		out, err := tool(t, append(append([]string{}, base...), tc.args...)...)
		if err == nil || !strings.Contains(out, tc.want) {
			t.Fatalf("%v: %v, want %q:\n%s", tc.args, err, tc.want, out)
		}
	}
	if _, seen := f.count(wire.TypeIdentity); seen != 0 {
		t.Fatalf("%d identity requests reached the runner", seen)
	}
	out, err := tool(t, append(append(base, pins("11")...), "-setup", goldenNitroSetup)...)
	if err == nil || strings.Contains(out, "allowed_image_measurements") {
		t.Fatalf("a listed pin: %v\n%s", err, out)
	}
	if _, seen := f.count(wire.TypeIdentity); seen == 0 {
		t.Fatal("a listed pin did not reach the runner")
	}
}
