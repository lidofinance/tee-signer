package agentclient

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/platform-aws/hostagent"
	"github.com/lidofinance/tee-signer/platform/filestore"
)

// SETUP: the agent hands over the setup bytes it holds; the Nitro setup
// channel reads them before the platform exists.
func TestSetupChannel(t *testing.T) {
	dir := t.TempDir()
	st, err := filestore.New(filepath.Join(dir, "blobs"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	serve := func(name string, srv *hostagent.Server) string {
		sock := filepath.Join(dir, name)
		l, err := net.Listen("unix", sock)
		if err != nil {
			t.Fatal(err)
		}
		go srv.Serve(ctx, l)
		return "unix:" + sock
	}
	setupBytes := []byte("S\x02 the setup bytes, whatever they are")
	exitFile := filepath.Join(dir, "last-exit.txt")
	addr := serve("agent.sock", &hostagent.Server{Store: st, Exit: hostagent.ExitFile(exitFile, nil),
		Setup: func() ([]byte, error) { return setupBytes, nil }})

	ch := &SetupChannel{Addr: addr}
	got, err := ch.Read(ctx)
	if err != nil || !slices.Equal(got, setupBytes) {
		t.Fatalf("read: %q %v", got, err)
	}
	if ch.String() != "host agent "+addr {
		t.Fatal(ch.String())
	}
	// A refused setup reaches the parent's exit file.
	ch.ReportExit("runner: setup refused: setupwire: 3 trailing bytes")
	if b, err := os.ReadFile(exitFile); err != nil || !strings.Contains(string(b), "setup refused") {
		t.Fatalf("exit file: %q %v", b, err)
	}

	// An agent without a setup: a clear error at once, no retries.
	none := serve("none.sock", &hostagent.Server{Store: st})
	start := time.Now()
	if _, err := (&SetupChannel{Addr: none, Retry: time.Hour}).Read(ctx); err == nil || !strings.Contains(err.Error(), "-setup FILE") {
		t.Fatalf("agent without setup: %v", err)
	}
	if time.Since(start) > 10*time.Second {
		t.Fatal("waited for an agent that answered")
	}
	// An agent whose setup source fails: its error, no retries.
	failing := serve("failing.sock", &hostagent.Server{Store: st, Setup: func() ([]byte, error) { return nil, errors.New("disk gone") }})
	if _, err := (&SetupChannel{Addr: failing, Retry: time.Hour}).Read(ctx); err == nil || !strings.Contains(err.Error(), "disk gone") {
		t.Fatalf("failing agent: %v", err)
	}

	// An agent that comes up late: the channel tries again until it answers.
	late := filepath.Join(dir, "late.sock")
	go func() {
		time.Sleep(300 * time.Millisecond)
		l, err := net.Listen("unix", late)
		if err != nil {
			return
		}
		go (&hostagent.Server{Store: st, Setup: func() ([]byte, error) { return setupBytes, nil }}).Serve(ctx, l)
	}()
	rctx, rcancel := context.WithTimeout(ctx, 20*time.Second)
	defer rcancel()
	if got, err := (&SetupChannel{Addr: "unix:" + late, Retry: 50 * time.Millisecond}).Read(rctx); err != nil || !slices.Equal(got, setupBytes) {
		t.Fatalf("late agent: %v", err)
	}
	// No agent at all: the channel gives up when its context ends.
	dctx, dcancel := context.WithTimeout(ctx, 200*time.Millisecond)
	defer dcancel()
	if _, err := (&SetupChannel{Addr: "unix:" + filepath.Join(dir, "nobody.sock"), Retry: 20 * time.Millisecond}).Read(dctx); err == nil ||
		!strings.Contains(err.Error(), "no setup from the host agent") {
		t.Fatalf("no agent: %v", err)
	}
}
