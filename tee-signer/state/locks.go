//go:build !lockcheck

package state

import "sync"

// namedMutex uses the order checker only in lockcheck test builds.
type namedMutex[N interface{ LockName() string }] = sync.Mutex
