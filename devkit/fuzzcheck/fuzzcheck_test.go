package fuzzcheck

import (
	"testing"
	"time"
)

var sink []byte

func TestBounded(t *testing.T) {
	Bounded(t, 10, func() { sink = make([]byte, 100) })
	ft := &testing.T{}
	done := make(chan bool)
	go func() {
		defer func() { done <- ft.Failed() }()
		Bounded(ft, 10, func() { sink = make([]byte, 1<<20) })
	}()
	if !<-done {
		t.Fatal("a 1 MiB allocation for 10 bytes passed")
	}
}

func TestInputLimit(t *testing.T) {
	for s, want := range map[string]time.Duration{"": InputLimit, "250ms": 250 * time.Millisecond, "3s": 3 * time.Second} {
		if got, err := inputLimit(s); err != nil || got != want {
			t.Errorf("inputLimit(%q) = %v, %v; want %v", s, got, err, want)
		}
	}
	for _, s := range []string{"1", "x", "0s", "-1s"} {
		if _, err := inputLimit(s); err == nil {
			t.Errorf("inputLimit(%q) passed", s)
		}
	}
}

func TestArm(t *testing.T) {
	fired := make(chan struct{})
	arm(10*time.Millisecond, func() { close(fired) })
	select {
	case <-fired:
	case <-time.After(10 * time.Second):
		t.Fatal("the timer did not fire")
	}
	stop := arm(50*time.Millisecond, func() { t.Error("the timer fired after stop") })
	stop()
	time.Sleep(200 * time.Millisecond)
}
