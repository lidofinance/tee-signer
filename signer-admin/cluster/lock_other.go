//go:build !unix || aix || solaris

package cluster

import "os"

// tryLock on an OS without flock (Go's syscall has none for AIX and
// Solaris): no build target of signer-admin is one, so it does not lock.
// Two runs editing the same cloud.json at once there can lose one edit.
func tryLock(*os.File) (bool, error) { return true, nil }

// syncDir does nothing here.
func syncDir(string) error { return nil }
