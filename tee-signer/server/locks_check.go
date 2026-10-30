//go:build lockcheck

package server

import "github.com/lidofinance/tee-signer/devkit/lockorder"

// namedMutex uses the order checker only in lockcheck test builds.
type namedMutex[N interface{ LockName() string }] = lockorder.Mutex[N]

type namedRWMutex[N interface{ LockName() string }] = lockorder.RWMutex[N]
