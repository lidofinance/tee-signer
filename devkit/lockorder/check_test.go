//go:build lockcheck

package lockorder

import (
	"strings"
	"testing"
)

type nameA struct{}

func (nameA) LockName() string { return "a" }

type nameB struct{}

func (nameB) LockName() string { return "b" }

// Two locks taken in both orders panic on the second order, with no
// deadlock needed: the two paths run one after the other.
func TestInversionPanics(t *testing.T) {
	Reset()
	var a Mutex[nameA]
	var b RWMutex[nameB]
	a.Lock()
	b.RLock()
	b.RUnlock()
	a.Unlock()
	defer func() {
		r := recover()
		if r == nil || !strings.Contains(r.(string), "a taken while holding b") {
			t.Fatalf("no inversion reported: %v", r)
		}
	}()
	b.Lock()
	a.Lock()
}

// The same order again, and two instances of one name, pass.
func TestSameOrderPasses(t *testing.T) {
	Reset()
	var a, a2 Mutex[nameA]
	var b Mutex[nameB]
	for range 2 {
		a.Lock()
		b.Lock()
		b.Unlock()
		a.Unlock()
	}
	a.Lock()
	a2.Lock()
	a2.Unlock()
	a.Unlock()
}
