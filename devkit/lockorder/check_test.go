//go:build lockcheck

package lockorder

import (
	"fmt"
	"strings"
	"sync"
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
	defer b.Unlock()
	a.Lock()
}

type nameC struct{}

func (nameC) LockName() string { return "c" }

type nameD struct{}

func (nameD) LockName() string { return "d" }

// Each pair is observed on a separate path and goroutine. Closing the
// cycle must panic before the final lock can block.
func TestLongCyclePanics(t *testing.T) {
	for _, n := range []int{3, 4} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			Reset()
			var a Mutex[nameA]
			var b Mutex[nameB]
			var c Mutex[nameC]
			var d Mutex[nameD]
			locks := []sync.Locker{&a, &b, &c, &d}[:n]
			for i := 0; i+1 < n; i++ {
				done := make(chan struct{})
				go func() {
					locks[i].Lock()
					locks[i+1].Lock()
					locks[i+1].Unlock()
					locks[i].Unlock()
					close(done)
				}()
				<-done
			}
			locks[n-1].Lock()
			defer locks[n-1].Unlock()
			defer func() {
				r := recover()
				want := strings.Join([]string{"a", "b", "c", "d"}[:n], " -> ") + " -> a"
				if r == nil || !strings.Contains(fmt.Sprint(r), want) {
					t.Fatalf("missing cycle %s: %v", want, r)
				}
				for i := 0; i+1 < n; i++ {
					edge := fmt.Sprintf("%c before %c at:", 'a'+i, 'a'+i+1)
					if !strings.Contains(fmt.Sprint(r), edge) {
						t.Errorf("missing earlier edge %s: %v", edge, r)
					}
				}
			}()
			locks[0].Lock()
		})
	}
}

// Shared destinations in an acyclic graph must not look like a cycle.
func TestBranchedOrderPasses(t *testing.T) {
	Reset()
	var a Mutex[nameA]
	var b Mutex[nameB]
	var c Mutex[nameC]
	var d Mutex[nameD]
	for _, pair := range [][2]sync.Locker{{&a, &b}, {&a, &c}, {&b, &d}, {&c, &d}, {&c, &b}} {
		pair[0].Lock()
		pair[1].Lock()
		pair[1].Unlock()
		pair[0].Unlock()
	}
}

func TestRefusedAcquisitionDoesNotRecordOrder(t *testing.T) {
	Reset()
	var a Mutex[nameA]
	var b Mutex[nameB]
	var c Mutex[nameC]
	c.Lock()
	b.Lock()
	b.Unlock()
	c.Unlock()

	func() {
		a.Lock()
		defer a.Unlock()
		b.Lock()
		defer b.Unlock()
		defer func() {
			if r := recover(); r == nil || !strings.Contains(fmt.Sprint(r), "c -> b -> c") {
				t.Fatalf("missing cycle: %v", r)
			}
		}()
		c.Lock()
		c.Unlock()
	}()

	// a -> c was never taken above. c -> a remains a valid order.
	c.Lock()
	defer c.Unlock()
	a.Lock()
	a.Unlock()
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
