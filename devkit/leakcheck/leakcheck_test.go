package leakcheck

import (
	"testing"
	"time"
)

func park(stop chan struct{}) { <-stop }

func TestRunningFindsAGoroutine(t *testing.T) {
	stop := make(chan struct{})
	go park(stop)
	time.Sleep(10 * time.Millisecond)
	if left := Running("github.com/lidofinance/tee-signer/devkit/leakcheck"); len(left) != 1 {
		t.Fatalf("%d goroutines found, want 1", len(left))
	}
	close(stop)
	if left := wait([]string{"github.com/lidofinance/tee-signer/devkit/leakcheck"}, time.Second); left != "" {
		t.Fatalf("the goroutine did not end:\n%s", left)
	}
}
