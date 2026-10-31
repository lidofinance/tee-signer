package e2e

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/signer-core/core"
	"github.com/lidofinance/tee-signer/signer-core/software"
	"github.com/lidofinance/tee-signer/signer-protocol"
)

// logRecords lists the record files of signer s in a file mark log.
func logRecords(t *testing.T, dir, s string) []string {
	t.Helper()
	ents, _ := os.ReadDir(filepath.Join(dir, "marks", s))
	var out []string
	for _, e := range ents {
		if !strings.HasPrefix(e.Name(), ".tmp-") {
			out = append(out, e.Name())
		}
	}
	sort.Strings(out)
	return out
}

func waitExit(t *testing.T, r *runner, within time.Duration) (exited bool) {
	t.Helper()
	done := make(chan struct{})
	go func() { r.cmd.Wait(); close(done) }()
	select {
	case <-done:
		r.log.Close()
		r.cmd = nil
		return true
	case <-time.After(within):
		return false
	}
}

// The mark log on the dev platform (a file log): restart while the chain
// does not finalize, fail closed at start, a rolled-back log, a clone, and
// an outage while running.
func TestE2EMarkLog(t *testing.T) {
	c := newChain(t)
	sk, _ := software.NewSecret()
	pk, _ := core.PubkeyOf(sk)
	sign := func(cl backend.Backend, m backend.Message) error {
		_, err := cl.Sign(ctx, c.req(pk, m))
		return err
	}

	// Restart in non-finality: the source stays at s0 the whole time. With
	// the floor alone the restarted runner refuses every vote (source below
	// the floor); with the mark log it signs again once the target passes
	// the floor's target bound.
	nonFinal := func(name string, flags ...string) (signedAfter int, firstAfter uint64, r *runner) {
		addr := fmt.Sprintf("tcp:127.0.0.1:%d", freePort(t))
		r = newRunner(t, name, c, addr, flags...)
		r.start()
		cl := client(t, addr)
		waitReady(t, cl)
		if _, err := adminOf(cl).ImportShare(ctx, backend.ImportShareRequest{Pubkey: pk, Secret: sk, Index: 7}); err != nil {
			t.Fatal(err)
		}
		// A fresh runner refuses everything up to clock epoch + 2 (its
		// restart floor), so the first votes go three epochs later.
		e0 := c.stableEpoch(t) + 3
		s0 := e0 - 1 // at the first start's floor: the source no vote moves after
		for e := e0; e < e0+2; e++ {
			c.waitEpoch(t, e)
			if err := sign(cl, att(s0, e, 0x10)); err != nil {
				t.Fatalf("%s before the restart, target %d: %v", name, e, err)
			}
		}
		r.stop()
		r.start()
		cl = client(t, addr)
		waitReady(t, cl)
		start := c.stableEpoch(t)
		for e := start; e < start+6; e++ {
			c.waitEpoch(t, e)
			err := sign(cl, att(s0, e, 0x20))
			t.Logf("%s after the restart, target %d (source %d): %s", name, e, s0, short(err))
			if err == nil {
				signedAfter++
				if firstAfter == 0 {
					firstAfter = e - start
				}
			}
		}
		return signedAfter, firstAfter, r
	}
	floorOnly, _, _ := nonFinal("floor-only")
	logDir := t.TempDir()
	withLog, first, r1 := nonFinal("marklog", "-mark-store", "file:"+logDir, "-mark-signer", "s1")
	t.Logf("non-finality restart: floor only signed %d of 6 epochs; with the mark log %d of 6, first at epoch +%d", floorOnly, withLog, first)
	if floorOnly != 0 || withLog < 3 {
		t.Fatalf("floor only %d, mark log %d", floorOnly, withLog)
	}
	if !strings.Contains(r1.logText(), "restart from the mark log") {
		t.Fatal("no restart line from the mark log")
	}
	recs := logRecords(t, logDir, "s1")
	t.Logf("records written in %d epochs of signing: %d", 8, len(recs))
	if len(recs) < 3 || len(recs) > 20 {
		t.Fatalf("%d records", len(recs))
	}

	// A host rollback of the log (a file log can be rolled back; a locked
	// bucket cannot): the newest records go. The sealed hint in the
	// platform store remembers the version written, so the runner refuses
	// to start.
	r1.stop()
	for _, f := range recs[len(recs)-2:] {
		p := filepath.Join(logDir, "marks", "s1", f)
		_ = os.Chmod(p, 0o600)
		if err := os.Remove(p); err != nil {
			t.Fatal(err)
		}
	}
	r1.start()
	if !waitExit(t, r1, 20*time.Second) || !strings.Contains(r1.logText(), "records hidden or listing stale") {
		t.Fatal("runner started on a log missing its newest records")
	}

	// Store unreachable at start: the runner does not start.
	addr := fmt.Sprintf("tcp:127.0.0.1:%d", freePort(t))
	bad := filepath.Join(t.TempDir(), "not-a-dir")
	_ = os.WriteFile(bad, []byte("x"), 0o600)
	r2 := newRunner(t, "store-down", c, addr, "-mark-store", "file:"+bad, "-mark-signer", "s2")
	r2.start()
	if !waitExit(t, r2, 20*time.Second) {
		t.Fatal("runner started with its mark store unreachable")
	}
}

// A clone from the same sealed state, on the same mark log: the second
// instance's claim takes the log over, the first one's next write
// conflicts, and no target is signed twice.
func TestE2EMarkLogClone(t *testing.T) {
	c := newChain(t)
	sk, _ := software.NewSecret()
	pk, _ := core.PubkeyOf(sk)
	logDir := t.TempDir()
	flags := []string{"-mark-store", "file:" + logDir, "-mark-signer", "node-1"}
	addrA := fmt.Sprintf("tcp:127.0.0.1:%d", freePort(t))
	addrB := fmt.Sprintf("tcp:127.0.0.1:%d", freePort(t))
	a := newRunner(t, "a", c, addrA, flags...)
	a.start()
	ca := client(t, addrA)
	waitReady(t, ca)
	if _, err := adminOf(ca).ImportShare(ctx, backend.ImportShareRequest{Pubkey: pk, Secret: sk, Index: 7}); err != nil {
		t.Fatal(err)
	}
	e0 := c.stableEpoch(t) + 3
	c.waitEpoch(t, e0+1)
	if _, err := ca.Sign(ctx, c.req(pk, att(e0, e0+1, 0xa0))); err != nil {
		t.Fatal(err)
	}
	b := newRunner(t, "b", c, addrB, flags...)
	if out, err := exec.Command("cp", "-a", a.stateDir, b.stateDir).CombinedOutput(); err != nil {
		t.Fatalf("copy state: %v %s", err, out)
	}
	b.start()
	cb := client(t, addrB)
	waitReady(t, cb)
	doubles, aSigned, bSigned := 0, 0, 0
	start := c.stableEpoch(t)
	for e := start; e < start+6; e++ {
		c.waitEpoch(t, e)
		_, errA := ca.Sign(ctx, c.req(pk, att(e-1, e, 0xa1)))
		_, errB := cb.Sign(ctx, c.req(pk, att(e-1, e, 0xb1)))
		if errA == nil {
			aSigned++
		}
		if errB == nil {
			bSigned++
		}
		if errA == nil && errB == nil {
			doubles++
		}
		t.Logf("target %d: a %s | b %s", e, short(errA), short(errB))
	}
	t.Logf("clone on one mark log: a signed %d, b signed %d, targets signed twice %d", aSigned, bSigned, doubles)
	if doubles != 0 || bSigned == 0 {
		t.Fatalf("doubles %d, b signed %d", doubles, bSigned)
	}
	if !strings.Contains(a.logText(), "another instance wrote this signer's log") {
		t.Fatal("runner a does not report losing the log")
	}
}

// The store goes down while the runner runs: it keeps signing inside the
// mark it committed, refuses above it, and signs again once the store is
// back.
func TestE2EMarkLogOutage(t *testing.T) {
	c := newChain(t)
	sk, _ := software.NewSecret()
	pk, _ := core.PubkeyOf(sk)
	logDir := t.TempDir()
	addr := fmt.Sprintf("tcp:127.0.0.1:%d", freePort(t))
	r := newRunner(t, "outage", c, addr, "-mark-store", "file:"+logDir, "-mark-signer", "s")
	r.start()
	cl := client(t, addr)
	waitReady(t, cl)
	if _, err := adminOf(cl).ImportShare(ctx, backend.ImportShareRequest{Pubkey: pk, Secret: sk, Index: 7}); err != nil {
		t.Fatal(err)
	}
	e0 := c.stableEpoch(t) + 3
	c.waitEpoch(t, e0)
	if _, err := cl.Sign(ctx, c.req(pk, att(e0-1, e0, 0x01))); err != nil {
		t.Fatal(err)
	}
	h, _ := cl.Health(ctx)
	t.Logf("mark log: %s", h.Record)
	// Down: the record directory refuses writes.
	dir := filepath.Join(logDir, "marks", "s")
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	refused, signed := 0, 0
	for e := e0 + 1; e < e0+5; e++ {
		c.waitEpoch(t, e)
		_, err := cl.Sign(ctx, c.req(pk, att(e0-1, e, 0x02)))
		t.Logf("store down, target %d: %s", e, short(err))
		if err == nil {
			signed++
		} else {
			wantRefused(t, err, backend.StatusStorage)
			refused++
		}
	}
	if refused == 0 {
		t.Fatal("signed past the committed mark with the store down")
	}
	_ = os.Chmod(dir, 0o700)
	e := c.stableEpoch(t)
	c.waitEpoch(t, e+1)
	if _, err := cl.Sign(ctx, c.req(pk, att(e0-1, e+1, 0x03))); err != nil {
		t.Fatalf("after the store came back: %v", err)
	}
	t.Logf("outage: %d signed inside the committed mark, %d refused above it, signing again after recovery", signed, refused)
}
