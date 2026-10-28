package keygen

import (
	"context"
	"testing"

	"github.com/lidofinance/tee-signer/governance/dkgorder"
	"github.com/lidofinance/tee-signer/signer-protocol"
)

// TKGRESULT-01: COMMIT names its session only, and the server picks the
// manager from the outer order hash. A session finished under order A,
// committed through order B's manager, must not activate its shares: B's
// manager refuses it and A's commit still works.
func TestDKGCommitRefusesSessionOfAnotherOrder(t *testing.T) {
	ns := orderCluster(t)
	rawA, hA := signOrder(t, orderBody(ns, dkgorder.PathDirk, "lane-a"), 1, 2)
	rawB, hB := signOrder(t, orderBody(ns, dkgorder.PathDirk, "lane-b"), 1, 2)
	pushAll(t, ns, rawA)
	pushAll(t, ns, rawB)
	fins := finishIn(t, ns, hA, 1)
	q := confirms(fins)
	ctx := context.Background()
	for i, n := range ns {
		_, err := inOrder{n, hB}.DKGCommit(ctx, q)
		wantRefused(t, err, backend.StatusPolicyPubkey, "another order")
		if got := len(n.testRunner.keys); got != 0 {
			t.Fatalf("runner %d: %d keys loaded after a commit through another order", i+1, got)
		}
	}
	for i, n := range ns {
		keys, err := inOrder{n, hA}.DKGCommit(ctx, q)
		if err != nil || len(keys) != 1 {
			t.Fatalf("runner %d: commit under its own order: %d keys, %v", i+1, len(keys), err)
		}
	}
}
