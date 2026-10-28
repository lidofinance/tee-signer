//go:build lockcheck

package lockorder

import (
	"bytes"
	"fmt"
	"runtime"
	"strconv"
	"sync"
)

// Enabled reports whether this build checks the lock order.
const Enabled = true

type holding struct {
	lock any
	name string
}

var (
	mu sync.Mutex
	// byG are the locks each goroutine holds, in the order it took them.
	byG = map[uint64][]holding{}
	// before[a][b]: a goroutine took b while it held a, at the stack.
	before = map[string]map[string]string{}
)

func goid() uint64 {
	var buf [64]byte
	b := buf[:runtime.Stack(buf[:], false)]
	b = bytes.TrimPrefix(b, []byte("goroutine "))
	if i := bytes.IndexByte(b, ' '); i > 0 {
		b = b[:i]
	}
	id, _ := strconv.ParseUint(string(b), 10, 64)
	return id
}

func stack() string {
	buf := make([]byte, 8<<10)
	return string(buf[:runtime.Stack(buf, false)])
}

// acquire checks the order before the goroutine waits for name.
func acquire(lock any, name string) {
	g := goid()
	mu.Lock()
	for _, h := range byG[g] {
		if h.name == name {
			continue
		}
		if at, ok := before[name][h.name]; ok {
			mu.Unlock()
			panic(fmt.Sprintf("lockorder: %s taken while holding %s, but %s was taken while holding %s at:\n%s\nnow at:\n%s",
				name, h.name, h.name, name, at, stack()))
		}
		if before[h.name] == nil {
			before[h.name] = map[string]string{}
		}
		if _, ok := before[h.name][name]; !ok {
			before[h.name][name] = stack()
		}
	}
	byG[g] = append(byG[g], holding{lock, name})
	mu.Unlock()
}

// held records a lock taken without waiting (TryLock): it adds no order.
func held(lock any, name string) {
	g := goid()
	mu.Lock()
	byG[g] = append(byG[g], holding{lock, name})
	mu.Unlock()
}

// release forgets the lock, on the goroutine that holds it (Go lets
// another goroutine unlock).
func release(lock any) {
	g := goid()
	mu.Lock()
	defer mu.Unlock()
	if drop(g, lock) {
		return
	}
	for other := range byG {
		if drop(other, lock) {
			return
		}
	}
}

func drop(g uint64, lock any) bool {
	hs := byG[g]
	for i := len(hs) - 1; i >= 0; i-- {
		if hs[i].lock == lock {
			hs = append(hs[:i], hs[i+1:]...)
			if len(hs) == 0 {
				delete(byG, g)
			} else {
				byG[g] = hs
			}
			return true
		}
	}
	return false
}

// Reset forgets every recorded order (tests).
func Reset() {
	mu.Lock()
	before = map[string]map[string]string{}
	mu.Unlock()
}
