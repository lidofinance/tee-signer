//go:build linux

package lockdown

import (
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// The real LockMemory: under a finite RLIMIT_MEMLOCK it locks nothing and
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
	for _, s := range []string{"warning: the locked memory limit is", "memory is not locked, keep swap off"} {
		if !strings.Contains(b.String(), s) {
			t.Fatalf("output lacks %q:\n%s", s, b.String())
		}
	}
}
