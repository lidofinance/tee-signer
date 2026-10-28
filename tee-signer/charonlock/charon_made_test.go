package charonlock

import (
	"os"
	"strings"
	"testing"
)

// TestCharonMadeLocks recomputes the hashes of locks that Charon itself
// wrote: the files in CHARON_LOCKS (comma separated), made by
// scripts/charon-lock-test.sh with the local obolnetwork/charon:v1.11.0
// image (`charon create cluster`, no network). Skipped without them.
func TestCharonMadeLocks(t *testing.T) {
	env := os.Getenv("CHARON_LOCKS")
	if env == "" {
		t.Skip("CHARON_LOCKS not set (scripts/charon-lock-test.sh sets it)")
	}
	for _, p := range strings.Split(env, ",") {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		l, err := Parse(b)
		if err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		if err := l.VerifyHashes(); err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		if err := l.VerifyBLS(); err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		// Writing it back and reading it again keeps every hash.
		out, err := l.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		l2, err := Parse(out)
		if err != nil {
			t.Fatalf("%s rewritten: %v", p, err)
		}
		if err := l2.VerifyHashes(); err != nil {
			t.Fatalf("%s rewritten: %v", p, err)
		}
		t.Logf("%s: %d operators, threshold %d, %d validators, deposit amounts %v, compounding %v: config, definition and lock hashes recompute; shares, registrations, deposits and signature_aggregate verify",
			p, len(l.Definition.Operators), l.Definition.Threshold, len(l.Validators), l.Definition.DepositAmounts, l.Definition.Compounding)
	}
}
