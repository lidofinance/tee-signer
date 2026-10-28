package fuzzcheck

import "testing"

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
