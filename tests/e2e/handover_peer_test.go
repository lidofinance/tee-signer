package e2e

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/remote"
)

// Helpers of the handover gate (handover_gate_test.go).

// slashCheck is the slashing checker: per signer position and validator,
// every message each runner of that position signed. They hold the same
// share, so together they must never sign a double vote, a surround or two
// blocks of one slot.
type slashCheck struct {
	mu   sync.Mutex
	atts map[slashKey][]slashAtt
	blks map[slashKey]map[uint64]backend.Root
	sigs int
	// blocks counts the block signatures among sigs.
	blocks int
	bad    []string
}

type slashKey struct {
	signer int
	pk     backend.Pubkey
}

type slashAtt struct {
	source, target uint64
	root           backend.Root
}

func (c *slashCheck) add(signer int, pk backend.Pubkey, m backend.Message, root backend.Root, who string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sigs++
	k := slashKey{signer, pk}
	switch v := m.(type) {
	case *backend.AttestationData:
		a := slashAtt{v.Source.Epoch, v.Target.Epoch, root}
		for _, o := range c.atts[k] {
			switch {
			case o.target == a.target && o.root != a.root:
				c.bad = append(c.bad, fmt.Sprintf("%s signer %d validator %s: double vote at target %d", who, signer, pk.String()[:12], a.target))
			case o.source < a.source && a.target < o.target, a.source < o.source && o.target < a.target:
				c.bad = append(c.bad, fmt.Sprintf("%s signer %d validator %s: (%d,%d) and (%d,%d) surround", who, signer, pk.String()[:12],
					o.source, o.target, a.source, a.target))
			}
		}
		c.atts[k] = append(c.atts[k], a)
	case *backend.BeaconBlockHeader:
		c.blocks++
		if c.blks[k] == nil {
			c.blks[k] = map[uint64]backend.Root{}
		}
		if o, ok := c.blks[k][v.Slot]; ok && o != root {
			c.bad = append(c.bad, fmt.Sprintf("%s signer %d validator %s: two blocks at slot %d", who, signer, pk.String()[:12], v.Slot))
		}
		c.blks[k][v.Slot] = root
	}
}

// lastAtt is the attestation of the highest target signer signed for pk.
func (c *slashCheck) lastAtt(signer int, pk backend.Pubkey) (slashAtt, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var best slashAtt
	as := c.atts[slashKey{signer, pk}]
	for _, a := range as {
		if a.target > best.target {
			best = a
		}
	}
	return best, len(as) > 0
}

// peerProc is one runner process with its unix socket.
type peerProc struct {
	r    *runner
	addr string // tcp, mutual TLS (tools, coordinator)
	sock string // unix, plain (the test)
	cl   *remote.Client
}

// startPeerAt starts a runner with its mutual TLS address addr and a unix
// socket.
func startPeerAt(t *testing.T, bin, name, dir, setupFile, addr string) *peerProc {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	p := &peerProc{addr: addr, sock: "unix:" + filepath.Join(dir, "runner.sock")}
	p.r = &runner{t: t, name: name, bin: bin, stateDir: filepath.Join(dir, "state"), logPath: filepath.Join(dir, name+".log")}
	p.r.args = []string{"-platform", "dev", "-setup", "file:" + setupFile, "-state-dir", p.r.stateDir, "-listen", p.addr + "," + p.sock}
	t.Cleanup(func() {
		p.r.stop()
		b, _ := os.ReadFile(p.r.logPath)
		if d := os.Getenv("HANDOVER_LOG_DIR"); d != "" {
			// The whole log of every runner, kept past the test's folder.
			if err := os.WriteFile(filepath.Join(d, name+".log"), b, 0o600); err != nil {
				t.Log(err)
			}
		}
		if t.Failed() {
			if len(b) > 20000 {
				b = b[len(b)-20000:]
			}
			t.Logf("---- %s log (end) ----\n%s", name, b)
		}
	})
	p.start(t)
	return p
}

// start starts the runner and waits until it answers PUBLIC_KEYS on its
// socket.
func (p *peerProc) start(t *testing.T) {
	t.Helper()
	p.r.start()
	var err error
	if p.cl, err = remote.New(p.sock, remote.WithTimeout(60*time.Second)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { p.cl.Close() })
	deadline := time.Now().Add(30 * time.Second)
	for {
		if _, err = p.cl.PublicKeys(ctx); err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s does not answer: %v", p.r.name, err)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func (p *peerProc) restart(t *testing.T) {
	t.Helper()
	p.r.stop()
	p.cl.Close()
	p.start(t)
}

// runTool runs a tool; its stdout and stderr go to the log.
func runTool(t *testing.T, bin string, args ...string) (string, error) {
	t.Helper()
	cmd := exec.Command(bin, args...)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	start := time.Now()
	err := cmd.Run()
	t.Logf("%s %s (%v):\n%s", filepath.Base(bin), args[0], time.Since(start).Round(time.Millisecond), strings.TrimSpace(out.String()))
	return out.String(), err
}
