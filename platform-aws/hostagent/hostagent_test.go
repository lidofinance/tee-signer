package hostagent

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/lidofinance/tee-signer/platform"
	"github.com/lidofinance/tee-signer/platform/filestore"
)

func TestAgentStoreOverUnixSocket(t *testing.T) {
	dir := t.TempDir()
	st, err := filestore.New(filepath.Join(dir, "blobs"))
	if err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(dir, "agent.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv := &Server{Store: st, Creds: func(context.Context) (Credentials, error) {
		return Credentials{AccessKeyID: "AKIDEXAMPLE", SecretAccessKey: "x", SessionToken: "y"}, nil
	}}
	go srv.Serve(ctx, l)

	c, err := NewClient("unix:" + sock)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Get("shares/aa"); !errors.Is(err, platform.ErrNotFound) {
		t.Fatalf("missing key: %v", err)
	}
	if err := c.Put("shares/aa", []byte{1, 2, 3}); err != nil {
		t.Fatal(err)
	}
	if err := c.Put("wm/aa", []byte{4}); err != nil {
		t.Fatal(err)
	}
	v, err := c.Get("shares/aa")
	if err != nil || !reflect.DeepEqual(v, []byte{1, 2, 3}) {
		t.Fatal(v, err)
	}
	keys, err := c.List("shares/")
	if err != nil || !reflect.DeepEqual(keys, []string{"shares/aa"}) {
		t.Fatal(keys, err)
	}
	cr, err := c.Credentials(ctx)
	if err != nil || cr.AccessKeyID != "AKIDEXAMPLE" {
		t.Fatal(cr, err)
	}
	if err := c.Put("../escape", []byte{1}); err == nil {
		t.Fatal("path escape accepted")
	}
}

// The runner's fatal error line reaches the parent as one printable line of
// at most MaxExitText bytes, in the exit file and nowhere else; an agent
// without a sink refuses EXIT.
func TestExitReport(t *testing.T) {
	dir := t.TempDir()
	st, err := filestore.New(filepath.Join(dir, "blobs"))
	if err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(dir, "agent.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	exitFile := filepath.Join(dir, "last-exit.txt")
	srv := &Server{Store: st, Exit: ExitFile(exitFile, nil)}
	go srv.Serve(ctx, l)
	c, err := NewClient("unix:" + sock)
	if err != nil {
		t.Fatal(err)
	}

	line := "runner: mark log s3://b: claim: s3log: 403 Forbidden AccessDenied: Access Denied\n\x1b[2Jnext" + strings.Repeat("x", 3000)
	if err := c.ReportExit(line); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(exitFile)
	if err != nil {
		t.Fatal(err)
	}
	got := strings.TrimSuffix(string(b), "\n")
	_, text, _ := strings.Cut(got, " ")
	if !strings.HasPrefix(text, "runner: mark log s3://b: claim: s3log: 403 Forbidden AccessDenied: Access Denied??[2Jnext") ||
		len(text) != MaxExitText || strings.ContainsAny(got, "\n\x1b") {
		t.Fatalf("exit file %q", b)
	}
	if fi, _ := os.Stat(exitFile); fi.Mode().Perm() != 0o600 {
		t.Fatalf("exit file mode %v", fi.Mode())
	}
	// The store still works on the same connection.
	if err := c.Put("shares/aa", []byte{1}); err != nil {
		t.Fatal(err)
	}

	sock2 := filepath.Join(dir, "agent2.sock")
	l2, err := net.Listen("unix", sock2)
	if err != nil {
		t.Fatal(err)
	}
	go (&Server{Store: st}).Serve(ctx, l2)
	c2, _ := NewClient("unix:" + sock2)
	if err := c2.ReportExit("runner: x"); err == nil {
		t.Fatal("EXIT accepted without a sink")
	}
}
