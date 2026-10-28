//go:build linux && (amd64 || arm64)

package filestore

import (
	"os"
	"runtime"
	"syscall"
)

// sysSyncfs is syncfs(2)'s number, which the syscall package does not
// list (golang.org/x/sys/unix does, but only AWS builds may link it,
// scripts/check-deps.sh).
func sysSyncfs() uintptr {
	if runtime.GOARCH == "arm64" {
		return 267
	}
	return 306
}

// syncFS flushes the file system that holds dir: the data and metadata of
// every file written there.
func syncFS(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	if _, _, e := syscall.Syscall(sysSyncfs(), d.Fd(), 0, 0); e != 0 {
		return &os.PathError{Op: "syncfs", Path: dir, Err: e}
	}
	return nil
}
