//go:build unix && !aix && !solaris

package cluster

import (
	"errors"
	"os"
	"syscall"
)

// tryLock takes an exclusive flock on f without waiting. false: another
// open file holds it.
func tryLock(f *os.File) (bool, error) {
	for {
		err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		switch {
		case err == nil:
			return true, nil
		case errors.Is(err, syscall.EWOULDBLOCK):
			return false, nil
		case errors.Is(err, syscall.EINTR):
			continue
		default:
			return false, err
		}
	}
}

// syncDir fsyncs a directory, so a rename in it is on disk. Some network
// and FUSE file systems refuse fsync on a directory (EINVAL, ENOTSUP);
// there the rename stands as the file system keeps it, and that is no error.
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	err = d.Sync()
	if errors.Is(err, syscall.EINVAL) || errors.Is(err, syscall.ENOTSUP) {
		return nil
	}
	return err
}
