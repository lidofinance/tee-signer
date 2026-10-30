//go:build lockcheck

// Package lockorder holds mutexes with a name, for a lock order check in
// tests. Built with the tag lockcheck, every Lock records which named
// locks its goroutine holds; taking B while holding A records the order
// A before B. An acquisition that closes a cycle in the observed orders
// panics with the cycle and the stacks of its earlier edges. This catches
// direct inversions (including TKGORDER-02) and cycles across several paths
// without hitting the deadlock. Without the tag the check compiles to nothing.
//
// The name comes from a type parameter, so the zero value is ready and
// every instance of a struct field shares one name and one order:
//
//	type ordersMu struct{}
//
//	func (ordersMu) LockName() string { return "keygen.Orders.mu" }
//
//	mu lockorder.Mutex[ordersMu]
package lockorder

import "sync"

// Namer names a lock.
type Namer interface{ LockName() string }

// Mutex is a sync.Mutex named by N for the order check.
type Mutex[N Namer] struct{ mu sync.Mutex }

func (m *Mutex[N]) Lock() {
	acquire(m, nameOf[N]())
	m.mu.Lock()
}

func (m *Mutex[N]) TryLock() bool {
	if !m.mu.TryLock() {
		return false
	}
	held(m, nameOf[N]())
	return true
}

func (m *Mutex[N]) Unlock() {
	release(m)
	m.mu.Unlock()
}

// RWMutex is a sync.RWMutex named by N for the order check. A read lock
// counts in the order like a write lock.
type RWMutex[N Namer] struct{ mu sync.RWMutex }

func (m *RWMutex[N]) Lock() {
	acquire(m, nameOf[N]())
	m.mu.Lock()
}

func (m *RWMutex[N]) Unlock() {
	release(m)
	m.mu.Unlock()
}

func (m *RWMutex[N]) RLock() {
	acquire(m, nameOf[N]())
	m.mu.RLock()
}

func (m *RWMutex[N]) RUnlock() {
	release(m)
	m.mu.RUnlock()
}

func nameOf[N Namer]() string {
	var n N
	return n.LockName()
}
