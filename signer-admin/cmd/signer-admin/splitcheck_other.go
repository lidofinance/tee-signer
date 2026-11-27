//go:build !darwin

package main

import (
	"fmt"
	"syscall"
)

// osSwaps is the file that lists the active swap devices (proc(5)).
const osSwaps = "/proc/swaps"

// tmpfsMagic is the f_type of tmpfs (linux/magic.h).
const tmpfsMagic = 0x01021994

// checkOutFS refuses a folder that is not on tmpfs, so the shares never
// reach a disk.
func checkOutFS(dir string) error {
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return err
	}
	if int64(st.Type) != tmpfsMagic {
		return fmt.Errorf("%s is not on tmpfs; split writes the shares only to tmpfs", dir)
	}
	return nil
}
