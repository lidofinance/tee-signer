//go:build linux

package main

import (
	"io"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// memoryLocks counts the calls of lockMemory. The tests run in one process
// and mlockall would hold the whole test binary in RAM for the rest of the
// run, so they count the call instead of making it.
var memoryLocks int

func init() {
	lockMemory = func(io.Writer) { memoryLocks++ }
}

// coreDumpsOff reports whether the process can no longer write a core
// dump: RLIMIT_CORE is 0, soft and hard, and the process is not dumpable.
func coreDumpsOff(t *testing.T) (ok bool, why string) {
	t.Helper()
	var rl unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_CORE, &rl); err != nil {
		t.Fatal(err)
	}
	d, err := unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if rl.Cur != 0 || rl.Max != 0 || d != 0 {
		return false, "RLIMIT_CORE " + itoa(rl.Cur) + "/" + itoa(rl.Max) + ", dumpable " + itoa(uint64(d))
	}
	return true, ""
}

func itoa(v uint64) string {
	if v == ^uint64(0) {
		return "unlimited"
	}
	s := ""
	for v >= 10 {
		s = string(rune('0'+v%10)) + s
		v /= 10
	}
	return string(rune('0'+v)) + s
}

// makeDumpable makes the test process dumpable again, so the next command
// under test has to turn it off itself. RLIMIT_CORE cannot be raised once
// its hard limit is 0, so that part of the check is the first command's.
func makeDumpable(t *testing.T) {
	t.Helper()
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 1, 0, 0, 0); err != nil {
		t.Fatal(err)
	}
}

// split turns core dumps off before it reads a keystore: after a split the
// process has RLIMIT_CORE 0 and is not dumpable.
func TestSplitDisablesCoreDumps(t *testing.T) {
	makeDumpable(t)
	e := newSplitEnv(t, "scrypt")
	locks := memoryLocks
	mustTool(t, e.args("-chain", "devnet", "-t", "2", "-n", "3", "-signers", "a,b,c")...)
	if ok, why := coreDumpsOff(t); !ok {
		t.Fatalf("core dumps are still on after split: %s", why)
	}
	if memoryLocks != locks+1 {
		t.Fatalf("split locked memory %d times, want once", memoryLocks-locks)
	}
}

// The real lockMemory: under a finite RLIMIT_MEMLOCK it locks nothing and
// says so; under an unlimited one (root) it locks, which this process
// cannot undo, so that case is left to the operator machine.
func TestLockMemoryWarnsUnderLimit(t *testing.T) {
	var rl unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_MEMLOCK, &rl); err != nil {
		t.Fatal(err)
	}
	if rl.Max == unix.RLIM_INFINITY {
		t.Skip("RLIMIT_MEMLOCK is unlimited here; lockMemoryOS would lock the test process")
	}
	var b strings.Builder
	lockMemoryOS(&b)
	wantIn(t, b.String(), "warning: the locked memory limit is", "memory is not locked, keep swap off")
}

// import turns core dumps off before it reads the plaintext shares file,
// whether or not the import goes through.
func TestImportDisablesCoreDumps(t *testing.T) {
	makeDumpable(t)
	fc := newFakeCluster(t)
	mustTool(t, "pin", "-cluster", fc.cluster)
	shares := writePrivate(t, filepath.Join(fc.dir, "shares.txt"), "")
	mustTool(t, "import", "-cluster", fc.cluster, "-signer", "s1", "-shares", shares)
	if ok, why := coreDumpsOff(t); !ok {
		t.Fatalf("core dumps are still on after import: %s", why)
	}
}
