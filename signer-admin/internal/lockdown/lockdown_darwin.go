//go:build darwin

package lockdown

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"golang.org/x/sys/unix"
)

// Secrets on macOS: core dumps off, then what LockMemory says about the
// memory on warn. macOS has no switch like Linux's PR_SET_DUMPABLE, and
// Secrets does not stop a debugger of the same user.
func Secrets(warn io.Writer) error {
	if err := disableCoreDumps(); err != nil {
		return err
	}
	LockMemory(warn)
	return nil
}

// disableCoreDumps sets RLIMIT_CORE to 0, soft and hard: a crash or a
// kill -SEGV writes no core file with the keys in it.
func disableCoreDumps() error {
	if err := unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{Cur: 0, Max: 0}); err != nil {
		return fmt.Errorf("RLIMIT_CORE: %w", err)
	}
	return nil
}

// LockMemory has the name of the Linux hook, so the tests replace it the
// same way, but on macOS it locks nothing and only reports (memoryNote).
var LockMemory = memoryNote

// memoryNote says on warn what keeps the keys in memory off a disk.
// macOS has no mlockall, and mlock of single buffers would leave out the
// Go heap and the stacks, so no page is locked. What is left is the swap
// encryption, which this reads from the kernel (vm.swapusage), and
// FileVault for the hibernation image, which it does not check.
func memoryNote(warn io.Writer) {
	enc, err := swapEncrypted()
	switch {
	case err != nil:
		fmt.Fprintf(warn, "warning: memory is not locked and vm.swapusage does not say whether swap is encrypted (%v); the keys can reach a disk\n", err)
	case !enc:
		fmt.Fprintln(warn, "warning: memory is not locked and swap is not encrypted; the keys can reach a disk")
	default:
		fmt.Fprintln(warn, "note: memory is not locked on macOS; swap is encrypted, the hibernation image only with FileVault on")
	}
}

// swapEncrypted reads the sysctl vm.swapusage.
func swapEncrypted() (bool, error) {
	raw, err := unix.SysctlRaw("vm.swapusage")
	if err != nil {
		return false, err
	}
	return parseSwapUsage(raw)
}

// parseSwapUsage returns xsu_encrypted of a struct xsw_usage
// (sys/sysctl.h): three uint64 (total, avail, used), the uint32 page size,
// then the 4-byte boolean. Both macOS architectures are little endian.
func parseSwapUsage(raw []byte) (bool, error) {
	const size, encrypted = 32, 28
	if len(raw) != size {
		return false, errors.New("unknown struct xsw_usage size")
	}
	return binary.LittleEndian.Uint32(raw[encrypted:]) != 0, nil
}
