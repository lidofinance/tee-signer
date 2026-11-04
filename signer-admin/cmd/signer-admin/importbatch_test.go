package main

import (
	"fmt"
	"os"
	"testing"

	"github.com/lidofinance/tee-signer/signer-core/core"
	"github.com/lidofinance/tee-signer/signer-core/software"
	wireadmin "github.com/lidofinance/tee-signer/signer-protocol/wire/admin"
)

// import sends the shares in IMPORT_SHARES_SEALED requests that fit a
// frame to a runner that takes it (900 shares need two), and one
// IMPORT_SHARE_SEALED per share to an older runner, which refuses the
// batch type.
func TestImportBatchOrOneByOne(t *testing.T) {
	for _, batch := range []bool{false, true} {
		t.Run(fmt.Sprint("batch ", batch), func(t *testing.T) {
			fc := newFakeCluster(t)
			r := fc.runners["s1"]
			if batch {
				r.ServeBatch()
			}
			mustTool(t, "pin", "-cluster", fc.cluster)
			n := 3
			if batch {
				n = 900
			}
			var lines []byte
			for i := range n {
				sk, err := software.NewSecret()
				if err != nil {
					t.Fatal(err)
				}
				pk, err := core.PubkeyOf(sk)
				if err != nil {
					t.Fatal(err)
				}
				lines = fmt.Appendf(lines, "%s %d 0x%x\n", pk, i+1, sk)
			}
			sharesFile := fc.path("shares.txt")
			if err := os.WriteFile(sharesFile, lines, 0o600); err != nil {
				t.Fatal(err)
			}
			out := mustTool(t, "import", "-cluster", fc.cluster, "-signer", "s1", "-shares", sharesFile)
			wantIn(t, out, fmt.Sprintf("imported %d shares", n))
			batches, singles := 1, n // the probe, and one request per share
			if batch {
				batches, singles = 3, 0
			}
			if r.Seen(wireadmin.TypeImportBatch) != batches || r.Seen(wireadmin.TypeImportSealed) != singles || len(r.Keys()) != n {
				t.Fatalf("%d batch requests, %d single ones, %d keys; want %d, %d, %d", r.Seen(wireadmin.TypeImportBatch),
					r.Seen(wireadmin.TypeImportSealed), len(r.Keys()), batches, singles, n)
			}
		})
	}
}
