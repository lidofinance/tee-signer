//go:build darwin

package main

import (
	"io"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/lidofinance/tee-signer/signer-admin/internal/lockdown"
)

// memoryLocks counts the calls of lockdown.LockMemory, which on macOS
// would write a line about swap to stderr.
var memoryLocks int

func init() {
	lockdown.LockMemory = func(io.Writer) { memoryLocks++ }
}

// readSecret turns core dumps off before it reads the share: afterwards
// RLIMIT_CORE is 0, soft and hard.
func TestReadSecretDisablesCoreDumps(t *testing.T) {
	locks := memoryLocks
	if _, err := readSecret(shareFile(t)); err != nil {
		t.Fatal(err)
	}
	var rl unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_CORE, &rl); err != nil {
		t.Fatal(err)
	}
	if rl.Cur != 0 || rl.Max != 0 {
		t.Fatalf("core dumps still on after readSecret: RLIMIT_CORE %d/%d", rl.Cur, rl.Max)
	}
	if memoryLocks != locks+1 {
		t.Fatalf("readSecret called LockMemory %d times, want once", memoryLocks-locks)
	}
}
