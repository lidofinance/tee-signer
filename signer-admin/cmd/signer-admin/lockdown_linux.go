//go:build linux

package main

import (
	"fmt"
	"io"

	"golang.org/x/sys/unix"
)

// lockSecrets is what a command runs before it holds a plaintext key or
// share: core dumps off, and the process's memory locked in RAM when the
// system allows it, with a warning on warn when it does not.
func lockSecrets(warn io.Writer) error {
	if err := disableCoreDumps(); err != nil {
		return err
	}
	lockMemory(warn)
	return nil
}

// disableCoreDumps sets RLIMIT_CORE to 0, soft and hard, and marks the
// process not dumpable: a crash, an out of memory kill or a kill -SEGV
// writes no core file with the keys in it, and /proc/PID/mem is closed to
// the other processes of the same user.
func disableCoreDumps() error {
	if err := unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{Cur: 0, Max: 0}); err != nil {
		return fmt.Errorf("RLIMIT_CORE: %w", err)
	}
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		return fmt.Errorf("PR_SET_DUMPABLE: %w", err)
	}
	return nil
}

// lockMemory locks the process's pages in RAM. Tests replace it: the test
// binary would stay locked for the rest of the run.
var lockMemory = lockMemoryOS

// lockMemoryOS locks the process's pages, present and future, in RAM
// (mlockall), so none of them reaches a swap device. It needs an unlimited
// RLIMIT_MEMLOCK (root, or ulimit -l unlimited): under a finite limit a
// later allocation past the limit would fail and end the process, so with
// one it warns and locks nothing.
func lockMemoryOS(warn io.Writer) {
	const keep = "; memory is not locked, keep swap off"
	var rl unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_MEMLOCK, &rl); err != nil {
		fmt.Fprintf(warn, "warning: RLIMIT_MEMLOCK: %v%s\n", err, keep)
		return
	}
	if rl.Max != unix.RLIM_INFINITY {
		fmt.Fprintf(warn, "warning: the locked memory limit is %d bytes%s (run as root or under ulimit -l unlimited to lock it)\n", rl.Max, keep)
		return
	}
	if rl.Cur != rl.Max {
		rl.Cur = rl.Max
		if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &rl); err != nil {
			fmt.Fprintf(warn, "warning: RLIMIT_MEMLOCK: %v%s\n", err, keep)
			return
		}
	}
	if err := unix.Mlockall(unix.MCL_CURRENT | unix.MCL_FUTURE); err != nil {
		fmt.Fprintf(warn, "warning: mlockall: %v%s\n", err, keep)
	}
}
