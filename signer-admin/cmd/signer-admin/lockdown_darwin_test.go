//go:build darwin

package main

import (
	"io"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/lidofinance/tee-signer/signer-admin/internal/lockdown"
)

// memoryLocks counts the calls of lockdown.LockMemory, which on macOS
// writes a line about swap to stderr. The tests that read stderr want it
// empty, so they count the call instead of making it.
var memoryLocks int

func init() {
	lockdown.LockMemory = func(io.Writer) { memoryLocks++ }
}

// coreDumpsOff fails the test unless RLIMIT_CORE is 0, soft and hard.
// The hard limit cannot be raised again, so in one test run only the
// first command under test has to lower it itself.
func coreDumpsOff(t *testing.T, after string) {
	t.Helper()
	var rl unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_CORE, &rl); err != nil {
		t.Fatal(err)
	}
	if rl.Cur != 0 || rl.Max != 0 {
		t.Fatalf("core dumps are still on after %s: RLIMIT_CORE %d/%d", after, rl.Cur, rl.Max)
	}
}

// split turns core dumps off before it reads a keystore.
func TestSplitDisablesCoreDumps(t *testing.T) {
	e := newSplitEnv(t, "scrypt")
	locks := memoryLocks
	mustTool(t, e.args("-chain", "devnet", "-t", "2", "-n", "3", "-signers", "a,b,c")...)
	coreDumpsOff(t, "split")
	if memoryLocks != locks+1 {
		t.Fatalf("split called LockMemory %d times, want once", memoryLocks-locks)
	}
}

// import turns core dumps off before it reads the plaintext shares file,
// whether or not the import goes through.
func TestImportDisablesCoreDumps(t *testing.T) {
	fc := newFakeCluster(t)
	mustTool(t, "pin", "-cluster", fc.cluster)
	shares := writePrivate(t, filepath.Join(fc.dir, "shares.txt"), "")
	mustTool(t, "import", "-cluster", fc.cluster, "-signer", "s1", "-shares", shares)
	coreDumpsOff(t, "import")
}
