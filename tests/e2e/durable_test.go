package e2e

// The durable state copy (-state-store, runner/statestore),
// slashing-log/docs/durable-state.md.

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/signer-core/core"
	"github.com/lidofinance/tee-signer/signer-core/software"
	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/remote"
	"github.com/lidofinance/tee-signer/slashing-log/wormfake"
)

// The dev platform: the state directory is wiped between two runs, the
// share comes back from the state copy before the mark log claim, and the
// runner signs on from the log's mark without a new import.
func TestE2EDurableStateDev(t *testing.T) {
	c := newChain(t)
	sk, _ := software.NewSecret()
	pk, _ := core.PubkeyOf(sk)
	logDir := t.TempDir()
	addr := fmt.Sprintf("tcp:127.0.0.1:%d", freePort(t))
	r := newRunner(t, "durable", c, addr, "-mark-store", "file:"+logDir, "-mark-signer", "s1", "-state-store", "file:"+logDir)
	ls := lostState{c: c, r: r, connect: func() *remote.Client { return client(t, addr) }, load: plainImport(t, sk, pk),
		records: func() int { return len(logRecords(t, logDir, "s1")) }, restored: true}
	ls.run(t, pk)
	if !strings.Contains(r.logText(), "state copy: newest commit") {
		t.Fatal("no restore line in the runner log")
	}
	r.stop()

	// Another image (another key release) opens no commit: it stops.
	other := newRunner(t, "durable-other-image", c, fmt.Sprintf("tcp:127.0.0.1:%d", freePort(t)),
		"-mark-store", "file:"+logDir, "-mark-signer", "s1", "-state-store", "file:"+logDir, "-platform-opt", "measurement=another-image")
	other.start()
	if !waitExit(t, other, 20*time.Second) || !strings.Contains(other.logText(), "none opens under this key release") {
		t.Fatal("a runner of another image started on the state copy")
	}
	t.Logf("another image: %s", lastLine(other.logText(), "runner:"))
}

// The GCP debug build: launcher, STS and KMS faked, the federated token
// used on KMS and the bucket directly (no service account), the mark log
// and the state copy in one bucket with a locked retention policy, under
// marks/ and state/. The VM's disk is lost; the share comes back.
func TestE2EDurableStateGCP(t *testing.T) {
	c := newChain(t)
	sk, _ := software.NewSecret()
	pk, _ := core.PubkeyOf(sk)
	const image = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	g := fakeGoogle(t, image)
	srv := wormfake.New(wormfake.GCS, "signer-marks")
	t.Cleanup(srv.Close)
	store := "gcs:bucket=signer-marks,endpoint=" + srv.URL
	sock := filepath.Join(t.TempDir(), "gcp.sock")
	r := newRunnerOn(t, runnerBinary(t, "gcp-debug"), "gcp-durable", c, "unix:"+sock, "-platform", "gcp",
		"-mark-store", store, "-mark-signer", "signer-3", "-state-store", store,
		"-platform-opt", "socket="+fakeLauncher(t, image),
		"-platform-opt", "wif_provider=//iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/p/providers/q",
		"-platform-opt", "kms_key=projects/p/locations/l/keyRings/r/cryptoKeys/sealing",
		"-platform-opt", "test_google_url="+g.URL)
	load := func(cl *remote.Client) {
		t.Helper()
		if _, err := adminOf(cl).ImportShareSealed(ctx, backend.ImportShareRequest{Pubkey: pk, Secret: sk, Index: 7}, pk, acceptAny); err != nil {
			t.Fatal(err)
		}
	}
	ls := lostState{c: c, r: r, connect: func() *remote.Client { return client(t, "unix:"+sock) }, load: load,
		records: func() int { return len(srv.Names()) }, restored: true}
	ls.run(t, pk)
	states := 0
	for _, n := range srv.Names() {
		if strings.HasPrefix(n, "state/signer-3/") {
			states++
		}
	}
	if states == 0 {
		t.Fatal("no state copy object in the bucket")
	}
	t.Logf("GCS fake: %d objects, %d of them state copy objects under state/signer-3/", len(srv.Names()), states)
}
