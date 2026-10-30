package setuptext

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lidofinance/tee-signer/governance/setupwire"
)

// vectorsPath is the attestation statement vectors file. setupwire's
// TestStatementVectors makes every value in it but the human forms; this
// test makes those and checks that each one reads to the bytes next to it.
// -update rewrites them in place.
const vectorsPath = "../../attestation-verify/docs/attestation-statement-vectors.json"

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestStatementHuman(t *testing.T) {
	if setupwire.MaxTimeLock < 172800 {
		t.Skip("the sample's change delay (48 hours) is above the cap of this build flavour")
	}
	path := filepath.FromSlash(vectorsPath)
	raw := readFile(t, path)
	type setupVec struct {
		Human string `json:"human"`
		Bytes string `json:"bytes"`
	}
	var v struct {
		Setup  setupVec `json:"setup"`
		Update struct {
			Human  string `json:"human"`
			Signed string `json:"signed"`
		} `json:"update"`
		AzureSetup setupVec `json:"azure_setup"`
		NitroSetup setupVec `json:"nitro_setup"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	out := raw
	// check compares a human form in the file with what the code makes and,
	// with -update, puts the new one in its place.
	check := func(what, have string, want []byte) {
		if have == string(want) {
			return
		}
		if !*update {
			t.Errorf("%s: the human form in %s differs from what the code makes (run with -update after a deliberate change)", what, vectorsPath)
			return
		}
		o, _ := json.Marshal(have)
		n, _ := json.Marshal(string(want))
		if bytes.Count(out, o) != 1 {
			t.Fatalf("%s: the human form is not in the file once", what)
		}
		out = bytes.Replace(out, o, n, 1)
	}
	for _, c := range []struct {
		what string
		vec  setupVec
	}{{"setup", v.Setup}, {"azure_setup", v.AzureSetup}, {"nitro_setup", v.NitroSetup}} {
		b := unhex(t, c.vec.Bytes)
		s, err := setupwire.DecodeSetup(b)
		if err != nil {
			t.Fatalf("%s: %v", c.what, err)
		}
		check(c.what, c.vec.Human, must(FormatSetup(s)))
		if p, err := ParseSetup("vectors", []byte(c.vec.Human)); err != nil || !bytes.Equal(must(p.Encode()), b) {
			t.Errorf("%s: the human form does not read to the bytes: %v", c.what, err)
		}
	}
	signed := unhex(t, v.Update.Signed)
	u, err := setupwire.DecodeUpdate(signed)
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	check("update", v.Update.Human, must(FormatUpdate(u)))
	if p, err := ParseUpdate("vectors", []byte(v.Update.Human)); err != nil || !bytes.Equal(must(p.Encode()), signed) {
		t.Errorf("update: the human form does not read to the bytes: %v", err)
	}
	if *update && !bytes.Equal(out, raw) {
		if err := os.WriteFile(path, out, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}
