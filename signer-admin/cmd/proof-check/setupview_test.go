package main

import (
	"bytes"
	"encoding/json"
	"math"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/attestation-verify/runnerclient"
	cloud "github.com/lidofinance/tee-signer/signer-protocol"
)

// fullState has every field of the setup state set: locked version 2 with
// version 3 pending until 2027-01-15T08:00:00Z, open version 1, a pending
// handover order, a key-release hash, a key origin.
var fullState = cloud.SetupState{
	SetupHash: cloud.Root{0x5e, 0x70},
	Locked: cloud.ConfigGroup{Version: 2, Hash: cloud.Root{1},
		Pending: cloud.PendingUpdate{Version: 3, Hash: cloud.Root{2}, EffectiveAt: 1_800_000_000}},
	Open:            cloud.ConfigGroup{Version: 1, Hash: cloud.Root{3}},
	ApproverSetHash: cloud.Root{4},
	Order:           cloud.Order{Kind: 1, Hash: cloud.Root{5}, ActAt: 1_900_000_000},
	KeyReleaseHash:  cloud.Root{6},
	KeyOrigin:       cloud.KeyOrigin{Generated: 3, OrdersHash: cloud.Root{7}},
}

var fullAtt = &runnerclient.Attestation{Verifier: runnerclient.VerifierDev,
	SetupSHA256: "5e70" + strings.Repeat("0", 60), MinLockedVersion: 2}

// documentedSetup is the example of the proof file's "setup" object in the
// comment of setupView, compacted.
func documentedSetup(t *testing.T) []byte {
	t.Helper()
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	in := false
	for _, l := range strings.Split(string(src), "\n") {
		switch {
		case l == "//\t\"setup\": {":
			in = true
			b.WriteString("{")
		case in && l == "//\t}":
			b.WriteString("}")
			in = false
		case in:
			b.WriteString(strings.TrimPrefix(l, "//\t"))
		}
	}
	var out bytes.Buffer
	if err := json.Compact(&out, []byte(b.String())); err != nil {
		t.Fatalf("the documented example %q: %v", b.String(), err)
	}
	return out.Bytes()
}

// The proof file's setup object has the documented shape, byte for byte.
func TestProofFileSetupShape(t *testing.T) {
	before := time.Unix(1_800_000_000-1, 0)
	got, err := json.Marshal(viewOf(&fullState, fullAtt, before))
	if err != nil {
		t.Fatal(err)
	}
	if want := documentedSetup(t); !bytes.Equal(got, want) {
		t.Fatalf("setup object\n got %s\nwant %s (the example in setupView's comment)", got, want)
	}
	r := result{Name: "aws-2", OK: true, Setup: viewOf(&fullState, fullAtt, before)}
	if l := setupLine(r); l != "locked=v2 open=v1 approvers=04000000 pending=locked:v3@2027-01-15T08:00:00Z order=handover@2030-03-17T17:46:40Z keys=generated:3,imported:0" {
		t.Fatalf("log line %q", l)
	}

	// Once the effective time has passed, the update counts as in force,
	// while the runner still reports it as pending.
	v := viewOf(&fullState, fullAtt, time.Unix(1_800_000_000, 0))
	if v.Locked.Version != 2 || v.Locked.EffectiveVersion != 3 || v.Locked.Pending == nil {
		t.Fatalf("in force: %+v", v.Locked)
	}
	r.Setup = v
	if l := setupLine(r); strings.Contains(l, "pending=") || !strings.Contains(l, "locked=v3") {
		t.Fatalf("log line in force %q", l)
	}

	// Nothing pending, no order, no key-release hash, no pin: those fields
	// are left out, and the log line says unpinned.
	quiet := fullState
	quiet.Locked.Pending, quiet.Order, quiet.KeyReleaseHash = cloud.PendingUpdate{}, cloud.Order{}, cloud.Root{}
	quiet.KeyOrigin = cloud.KeyOrigin{}
	got, _ = json.Marshal(viewOf(&quiet, &runnerclient.Attestation{Verifier: runnerclient.VerifierDev, AllowUnpinnedSetup: true}, before))
	want := `{"setup_hash":"5e700000","pinned":false,"flag_path":false,` +
		`"locked":{"version":2,"effective_version":2,"hash":"01000000","min_version":0},` +
		`"open":{"version":1,"effective_version":1,"hash":"03000000","min_version":0},"approver_set_hash":"04000000"}`
	if string(got) != want {
		t.Fatalf("quiet state\n got %s\nwant %s", got, want)
	}

	// A saturated time is capped at 2^63-1, so a reader with int64 fields
	// still reads the file.
	far := fullState
	far.Locked.Pending.EffectiveAt = math.MaxUint64
	if v := viewOf(&far, fullAtt, before); v.Locked.Pending.EffectiveAtUnix != math.MaxInt64 {
		t.Fatalf("saturated time %d", v.Locked.Pending.EffectiveAtUnix)
	}

	// The flag path: setup_hash and flag_path only.
	got, _ = json.Marshal(viewOf(&cloud.SetupState{SetupHash: cloud.Root{0xc0, 0xff, 0xee, 0x01}}, &runnerclient.Attestation{}, before))
	if string(got) != `{"setup_hash":"c0ffee01","pinned":false,"flag_path":true}` {
		t.Fatalf("flag path %s", got)
	}
}
