package main

import (
	"bytes"
	"encoding/hex"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lidofinance/tee-signer/governance/handoverorder"
)

// updateHandoverBodies rewrites testdata/golden/handover-bodies.hex from
// this tree's codec.
var updateHandoverBodies = flag.Bool("update-handover-bodies", false, "rewrite testdata/golden/handover-bodies.hex")

// goldenHandoverBodies are handover order bodies of each verifier kind.
func goldenHandoverBodies() []handoverorder.Body {
	var pcr3 [48]byte
	pcr3[0] = 0x33
	bodies := []handoverorder.Body{
		{ClusterID: [32]byte{1}, ChainHash: [32]byte{2}, NotAfter: 1_800_000_000,
			Source: handoverorder.Runner{Name: "signer-1", SetupHash: [32]byte{3}, Verifier: handoverorder.VerifierDev},
			Target: handoverorder.Runner{Name: "signer-1b", SetupHash: [32]byte{4}, Verifier: handoverorder.VerifierDev}},
		{ClusterID: [32]byte{5}, ChainHash: [32]byte{6}, NotAfter: 1_800_003_600,
			Source: handoverorder.Runner{Name: "signer-2", SetupHash: [32]byte{7}, Verifier: handoverorder.VerifierNitro,
				Image: bytes.Repeat([]byte{0x2a}, 144), NitroPCR3: pcr3},
			Target: handoverorder.Runner{Name: "signer-2b", SetupHash: [32]byte{8}, Verifier: handoverorder.VerifierNitro,
				Image: bytes.Repeat([]byte{0x2b}, 144), NitroPCR3: pcr3}},
	}
	return bodies
}

// TestGoldenHandoverBodies holds the encoding of handover order bodies
// fixed: a change to the codec changes the hex lines, and with them the
// hash approvers sign.
func TestGoldenHandoverBodies(t *testing.T) {
	path := filepath.Join("testdata", "golden", "handover-bodies.hex")
	bodies := goldenHandoverBodies()
	if *updateHandoverBodies {
		var b strings.Builder
		for _, body := range bodies {
			enc, err := body.Encode()
			if err != nil {
				t.Fatal(err)
			}
			b.WriteString(hex.EncodeToString(enc))
			b.WriteByte('\n')
		}
		if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want := strings.Fields(string(mustRead(t, path)))
	if len(want) != len(bodies) {
		t.Fatalf("%d bodies, %d lines in handover-bodies.hex (go test -run TestGoldenHandoverBodies -update-handover-bodies)", len(bodies), len(want))
	}
	for i, b := range bodies {
		enc, err := b.Encode()
		if err != nil {
			t.Fatal(err)
		}
		if got := hex.EncodeToString(enc); got != want[i] {
			t.Errorf("body %d: the codec writes %s, the golden file has %s", i, got, want[i])
		}
		back, err := handoverorder.DecodeBody(enc)
		if err != nil || back.Target.Name != b.Target.Name {
			t.Errorf("body %d does not read back: %v", i, err)
		}
	}
}
