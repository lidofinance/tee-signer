//go:build testnet

package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/governance/dkgorder"
	"github.com/lidofinance/tee-signer/signer-protocol/remote"
)

// TestE2EMeasureStateCopyOrders measures state copy v2 under DKG orders on
// three testnet key generation dev runners with setups, each with its copy
// in a file store (the setup's state_store). Two orders share the runners:
// a Dirk lane (sessions of 64 keys, then their deposits) and Charon
// (sessions of 64 keys, then one lock over several of them). Then runner 1
// restarts with its state directory wiped, from the copy alone. Copy
// figures are runner 1's: the file store keeps every object, so the growth
// of its folder is what a session uploaded.
//
//	E2E_MEASURE=1 [E2E_MEASURE_SESSIONS=8] [E2E_MEASURE_OUT=file.tsv] \
//	  RUNNER_TESTNET_DKG_BIN=... go test -tags testnet -run TestE2EMeasureStateCopyOrders ./e2e
//
// E2E_MEASURE_SESSIONS is the number of sessions of each order (default 16,
// so 1,024 keys each). The Charon lock covers the first 8 Charon sessions,
// 512 validators: one lock holds at most about 640 (dkgmsg.MaxLock).
func TestE2EMeasureStateCopyOrders(t *testing.T) {
	if os.Getenv("E2E_MEASURE") == "" {
		t.Skip("E2E_MEASURE=1 runs the measurement")
	}
	const per = 64
	sessions := 16
	if v, err := strconv.Atoi(os.Getenv("E2E_MEASURE_SESSIONS")); err == nil && v > 0 {
		sessions = v
	}
	c := newChain(t) // a devnet, which a testnet runner takes
	lock := uint64(orderTimeLock)
	k := newOrderClusterWith(t, c, orderOpts{bin: "dev-testnet-dkg", timeLock: &lock, testnet: true, maxValidators: uint32(2*sessions*per + 64)})
	copyDir := filepath.Join(k.dir, "signer-1", "state-copy")
	usage := func() (n, b int64) {
		_ = filepath.WalkDir(copyDir, func(_ string, d fs.DirEntry, err error) error {
			if err == nil && !d.IsDir() {
				if fi, err := d.Info(); err == nil {
					n, b = n+1, b+fi.Size()
				}
			}
			return nil
		})
		return
	}
	bin, _ := tools(t)
	coord := func(args ...string) time.Duration {
		t.Helper()
		cmd := exec.Command(bin, append(args, "-platform", "dev")...)
		start := time.Now()
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("dkg-coordinator %s: %v\n%s", args[0], err, out)
		}
		return time.Since(start)
	}
	type row struct {
		what                 string
		held                 int
		ms                   int64
		objects, bytes       int64
		copyObjects, copyLen int64
	}
	var rows []row
	held := 0
	step := func(what string, f func() time.Duration) {
		n0, b0 := usage()
		d := f()
		n1, b1 := usage()
		rows = append(rows, row{what, held, d.Milliseconds(), n1 - n0, b1 - b0, n1, b1})
	}

	dirkCfg := k.useOrder(t, "dirk", signOrderBody(t, k.orderBody(t, "dirk-measure", dkgorder.PathDirk, nil), 1, 2))
	charonCfg := k.useOrder(t, "charon", signOrderBody(t, k.orderBody(t, "charon-measure", dkgorder.PathCharon,
		[]string{"enr:-test-1", "enr:-test-2", "enr:-test-3"}), 2, 3))
	fork := fmt.Sprintf("%x", c.cfg.GenesisForkVersion[:])
	var charonResults []string
	for s := 1; s <= sessions; s++ {
		dr := filepath.Join(k.dir, fmt.Sprintf("dirk-%03d.json", s))
		step("dirk keygen", func() time.Duration {
			return coord("keygen", "-config", dirkCfg, "-count", fmt.Sprint(per), "-out", dr)
		})
		held += per
		step("dirk deposits", func() time.Duration {
			return coord("deposits", "-config", dirkCfg, "-result", dr, "-fork-version", fork, "-out", dr+".deposits")
		})
		cr := filepath.Join(k.dir, fmt.Sprintf("charon-%03d.json", s))
		step("charon keygen", func() time.Duration {
			return coord("keygen", "-config", charonCfg, "-count", fmt.Sprint(per), "-out", cr)
		})
		held += per
		charonResults = append(charonResults, cr)
	}
	cluster, _ := json.Marshal(map[string]any{"name": "measure", "fork_version": "0x" + fork, "fee_recipient": feeHex(c),
		"gas_limit": 60_000_000, "registration_timestamp": c.cfg.GenesisTime})
	clusterFile := filepath.Join(k.dir, "cluster.json")
	if err := os.WriteFile(clusterFile, cluster, 0o600); err != nil {
		t.Fatal(err)
	}
	step("charon lock", func() time.Duration {
		return coord("charon-lock", "-config", charonCfg, "-result", strings.Join(charonResults[:min(8, len(charonResults))], ","), "-cluster", clusterFile,
			"-out", filepath.Join(k.dir, "cluster-lock.json"))
	})

	// Runner 1 restarts from the copy alone.
	r := k.runners[0]
	r.stop()
	if err := os.RemoveAll(r.stateDir); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	r.start()
	cl, err := newTLSClient(k.addrs[0], k.cliCfg, remote.DevVerifier, remote.WithTimeout(30*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()
	waitReady(t, cl)
	ready := time.Since(start)
	keys, err := cl.PublicKeys(context.Background())
	if err != nil || len(keys) != held {
		t.Fatalf("after the restart from the copy: %d keys of %d, %v", len(keys), held, err)
	}
	restore := ""
	for _, line := range strings.Split(r.logText(), "\n") {
		if strings.Contains(line, "state copy") && strings.Contains(line, "took_ms") {
			restore = line
		}
	}

	out := "what\theld_before\tms\tcopy_objects_written\tcopy_bytes_written\tcopy_objects\tcopy_bytes\n"
	for _, x := range rows {
		out += fmt.Sprintf("%s\t%d\t%d\t%d\t%d\t%d\t%d\n", x.what, x.held, x.ms, x.objects, x.bytes, x.copyObjects, x.copyLen)
	}
	out += fmt.Sprintf("restart wiped\t%d\t%d\t\t\t\t\n", held, ready.Milliseconds())
	if p := os.Getenv("E2E_MEASURE_OUT"); p != "" {
		if err := os.WriteFile(p, []byte(out), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	t.Logf("%d sessions of %d keys per order, %d keys held\n%s", sessions, per, held, out)
	t.Logf("runner 1 restore line: %s", restore)
	for _, what := range []string{"dirk keygen", "dirk deposits", "charon keygen"} {
		var ms, bs []int64
		for _, x := range rows {
			if x.what == what {
				ms, bs = append(ms, x.ms), append(bs, x.bytes)
			}
		}
		slices.Sort(ms)
		slices.Sort(bs)
		t.Logf("%s: %d sessions, median %d ms (%d to %d), upload median %d B (%d to %d)", what, len(ms),
			ms[len(ms)/2], ms[0], ms[len(ms)-1], bs[len(bs)/2], bs[0], bs[len(bs)-1])
	}
}
