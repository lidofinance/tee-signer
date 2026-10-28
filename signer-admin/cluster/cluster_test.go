package cluster

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/wire"
	wireadmin "github.com/lidofinance/tee-signer/signer-protocol/wire/admin"
)

const setupsDir = "../../governance/setupwire/testdata"

func writeJSON(t *testing.T, path string, v any) {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatal(err)
	}
}

// copySetup puts a setup of the setupwire vectors next to cluster.json.
func copySetup(t *testing.T, dir, from, to string) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(setupsDir, from))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, to), b, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestLoad(t *testing.T) {
	dir := t.TempDir()
	copySetup(t, dir, "setup-dev.bin", "a.setup")
	copySetup(t, dir, "setup-dev.bin", "b.setup")
	signer := func(name, setup string) map[string]string {
		return map[string]string{"name": name, "cloud": name + "/cloud.json", "setup": setup}
	}
	path := filepath.Join(dir, "cluster.json")
	writeJSON(t, path, map[string]any{"signers": []any{signer("a", "a.setup"), signer("b", "b.setup")}})
	c, err := Load(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Members) != 2 || c.Members[1].Name != "b" || c.Members[0].CloudPath != filepath.Join(dir, "a/cloud.json") ||
		c.Updates != filepath.Join(dir, "updates") || c.Members[0].SetupHash == ([32]byte{}) {
		t.Fatalf("cluster %+v", c)
	}
	if c, err := Load(path, []string{"b"}); err != nil || len(c.Members) != 1 || c.Members[0].Name != "b" {
		t.Fatalf("-signers b: %+v %v", c, err)
	}
	if _, err := Load(path, []string{"c"}); err == nil || !strings.Contains(err.Error(), `"c" is not a signer`) {
		t.Fatalf("-signers c: %v", err)
	}
	writeJSON(t, path, map[string]any{"signers": []any{signer("a", "a.setup"), signer("a", "b.setup")}})
	if _, err := Load(path, nil); err == nil || !strings.Contains(err.Error(), "listed twice") {
		t.Fatalf("a name twice: %v", err)
	}
	writeJSON(t, path, map[string]any{"signers": []any{signer("a", "a.setup")}, "extra": 1})
	if _, err := Load(path, nil); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("unknown field: %v", err)
	}
}

// fakeRT answers by message type.
type fakeRT map[wire.MsgType]error

func (f fakeRT) RoundTrip(_ context.Context, t wire.MsgType, _ []byte) ([]byte, error) {
	return nil, f[t]
}

func refused(c backend.Status) error { return backend.Refused(c, "test") }

func TestProbeVerdicts(t *testing.T) {
	ctx := context.Background()
	for name, tc := range map[string]struct {
		rt   fakeRT
		want ProbeResult
		ok   bool
	}{
		"admin, setup":    {fakeRT{0x7f: refused(backend.StatusForbidden), wireadmin.TypeConfigUpdate: refused(backend.StatusBadRequest)}, ProbeResult{Admin: true, Setup: true}, true},
		"admin, no setup": {fakeRT{0x7f: refused(backend.StatusForbidden), wireadmin.TypeConfigUpdate: refused(backend.StatusUnsupported)}, ProbeResult{Admin: true}, true},
		"signing":         {fakeRT{0x7f: refused(backend.StatusForbidden), wireadmin.TypeConfigUpdate: refused(backend.StatusForbidden)}, ProbeResult{}, false},
	} {
		got, err := Probe(ctx, tc.rt)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		got.Answer = ""
		if got != tc.want || got.OK() != tc.ok {
			t.Errorf("%s: %+v (ok %v), want %+v", name, got, got.OK(), tc.want)
		}
	}
	if _, err := Probe(ctx, fakeRT{0x7f: refused(backend.StatusUnsupported), wireadmin.TypeConfigUpdate: refused(backend.StatusBadRequest)}); err == nil {
		t.Fatal("UNSUPPORTED for an unknown type passed")
	}
	if _, err := Probe(ctx, fakeRT{0x7f: nil}); err == nil {
		t.Fatal("an OK answer to an unknown type passed")
	}
}
