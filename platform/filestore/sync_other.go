//go:build !(linux && (amd64 || arm64))

package filestore

import "syscall"

// syncFS flushes every file system (sync(2)): syncfs(2) is used on Linux
// amd64 and arm64 only.
func syncFS(string) error {
	syscall.Sync()
	return nil
}
