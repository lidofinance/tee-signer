//go:build linux

package main

import (
	"io"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/lidofinance/tee-signer/signer-admin/internal/lockdown"
)

// memoryLocks counts the calls of lockdown.LockMemory: mlockall would hold
// the test binary in RAM for the rest of the run.
var memoryLocks int

func init() {
	lockdown.LockMemory = func(io.Writer) { memoryLocks++ }
}

// readSecret turns core dumps off and locks memory before it reads the
// share: afterwards RLIMIT_CORE is 0, soft and hard, and the process is not
// dumpable.
func TestReadSecretDisablesCoreDumps(t *testing.T) {
	locks := memoryLocks
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 1, 0, 0, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := readSecret(shareFile(t)); err != nil {
		t.Fatal(err)
	}
	var rl unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_CORE, &rl); err != nil {
		t.Fatal(err)
	}
	d, err := unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if rl.Cur != 0 || rl.Max != 0 || d != 0 {
		t.Fatalf("core dumps still on after readSecret: RLIMIT_CORE %d/%d, dumpable %d", rl.Cur, rl.Max, d)
	}
	if memoryLocks != locks+1 {
		t.Fatalf("readSecret locked memory %d times, want once", memoryLocks-locks)
	}
}
