//go:build !lockcheck

package server

import "sync"

// namedMutex uses the order checker only in lockcheck test builds.
type namedMutex[N interface{ LockName() string }] = sync.Mutex
