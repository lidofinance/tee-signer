package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lidofinance/tee-signer/governance/setupwire"
	cloud "github.com/lidofinance/tee-signer/signer-protocol"
)

// An EIP-3076 file reduces to each validator's maxima, entries of one
// validator merged; a validator without history carries none, one the file
// does not list is an error, and so is a source above its target.
func TestInterchange(t *testing.T) {
	pk1, pk2 := "0x"+strings.Repeat("a1", 48), "0x"+strings.Repeat("b2", 48)
	file := func(body string) string {
		p := filepath.Join(t.TempDir(), "ic.json")
		if err := os.WriteFile(p, []byte(`{"metadata":{"interchange_format_version":"5","genesis_validators_root":"0x`+
			strings.Repeat("11", 32)+`"},"data":[`+body+`]}`), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	ic, err := loadInterchange(file(`{"pubkey":"` + pk1 + `","signed_blocks":[{"slot":"100"},{"slot":"90"}],"signed_attestations":[{"source_epoch":"3","target_epoch":"4"}]},` +
		`{"pubkey":"` + pk1 + `","signed_blocks":[],"signed_attestations":[{"source_epoch":"4","target_epoch":"5"}]},` +
		`{"pubkey":"` + pk2 + `","signed_blocks":[],"signed_attestations":[]}`))
	if err != nil {
		t.Fatal(err)
	}
	var p1, p2, p3 cloud.Pubkey
	_ = p1.UnmarshalText([]byte(pk1))
	_ = p2.UnmarshalText([]byte(pk2))
	p3[0] = 1
	w, err := ic.markOf(p1)
	if err != nil || w == nil || *w != (cloud.Watermark{HasBlock: true, BlockSlot: 100, HasAttestation: true, SourceEpoch: 4, TargetEpoch: 5}) {
		t.Fatalf("validator 1: %+v %v", w, err)
	}
	if w, err := ic.markOf(p2); err != nil || w != nil {
		t.Fatalf("validator 2: %+v %v", w, err)
	}
	if _, err := ic.markOf(p3); err == nil {
		t.Fatal("a validator the file does not list")
	}
	if _, err := loadInterchange(file(`{"pubkey":"` + pk1 + `","signed_blocks":[],"signed_attestations":[{"source_epoch":"6","target_epoch":"5"}]}`)); err == nil {
		t.Fatal("a source above its target")
	}
}

// import refuses an interchange file of another chain: its maxima would
// lift the runner's floor for votes of the wrong chain. With -conn the
// chain comes from -genesis-validators-root.
func TestImportRefusesInterchangeOfAnotherChain(t *testing.T) {
	fc := newFakeCluster(t)
	cl := fc.cluster
	mustTool(t, "pin", "-cluster", cl)
	pk, shares, _ := split(t, fc.dir, 3, 4, []string{"s1", "s2", "s3", "s4"})
	sharesFile := fc.path("shares.txt")
	if err := os.WriteFile(sharesFile, fmt.Appendf(nil, "%s 7 0x%x\n", pk, shares[0].Secret), 0o600); err != nil {
		t.Fatal(err)
	}
	setup, err := setupwire.DecodeSetup(mustRead(t, fc.path("setups/s1.setup")))
	if err != nil {
		t.Fatal(err)
	}
	ours := hex.EncodeToString(setup.Chain.GenesisValidatorsRoot[:])
	other := strings.Repeat("11", 32)
	if ours == other {
		t.Fatal("test setup uses the other root")
	}
	icFile := func(root string) string {
		p := filepath.Join(t.TempDir(), "ic.json")
		body := `{"metadata":{"interchange_format_version":"5","genesis_validators_root":"0x` + root + `"},"data":[{"pubkey":"` + pk.String() +
			`","signed_blocks":[],"signed_attestations":[{"source_epoch":"3","target_epoch":"4"}]}]}`
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	byCluster := func(ic string) []string {
		return []string{"import", "-cluster", cl, "-signer", "s1", "-shares", sharesFile, "-interchange", ic}
	}
	wantIn(t, failTool(t, byCluster(icFile(other))...), "is not the runner's chain")
	if out, _ := tool(t, byCluster(icFile(ours))...); strings.Contains(out, "is not the runner's chain") {
		t.Fatalf("the setup's own chain refused:\n%s", out)
	}
	conn := fc.path("s1/cloud.json")
	byConn := func(ic string, extra ...string) []string {
		return append([]string{"import", "-conn", conn, "-shares", sharesFile, "-interchange", ic}, extra...)
	}
	wantIn(t, failTool(t, byConn(icFile(ours))...), "needs -genesis-validators-root")
	wantIn(t, failTool(t, byConn(icFile(other), "-genesis-validators-root", "0x"+ours)...), "is not the runner's chain")
	if out, _ := tool(t, byConn(icFile(ours), "-genesis-validators-root", "0x"+ours)...); strings.Contains(out, "is not the runner's chain") {
		t.Fatalf("-conn with the right root refused:\n%s", out)
	}
}
