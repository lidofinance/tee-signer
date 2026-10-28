// Package leakcheck finds goroutines a package's tests left running. A
// test binary's TestMain calls Main: after the tests, every goroutine
// that runs code of the package must end within a grace period, or the
// binary fails with their stacks. A connection handler that never
// returns (a stalled peer, a lock never released) shows up here even
// when no test waits for it. Only tests import it.
package leakcheck

import (
	"fmt"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"
)

// Grace is how long Main waits for the goroutines to end.
var Grace = 10 * time.Second

// Main runs the tests, then fails the binary when a goroutine with a
// frame in one of pkgs (import paths) is still running after Grace.
func Main(m *testing.M, pkgs ...string) {
	code := m.Run()
	if code == 0 {
		if left := wait(pkgs, Grace); left != "" {
			fmt.Fprintf(os.Stderr, "leakcheck: goroutines still running after the tests:\n%s\n", left)
			code = 1
		}
	}
	os.Exit(code)
}

// wait returns the stacks of the goroutines in pkgs that still run after
// grace, or "" when there are none.
func wait(pkgs []string, grace time.Duration) string {
	deadline := time.Now().Add(grace)
	for {
		left := Running(pkgs...)
		if len(left) == 0 {
			return ""
		}
		if time.Now().After(deadline) {
			return strings.Join(left, "\n\n")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// Running returns the stacks of the goroutines, other than the caller,
// with a frame in one of pkgs. Test functions' own goroutines
// (testing.tRunner) do not count.
func Running(pkgs ...string) []string {
	buf := make([]byte, 1<<20)
	for {
		n := runtime.Stack(buf, true)
		if n < len(buf) {
			buf = buf[:n]
			break
		}
		buf = make([]byte, 2*len(buf))
	}
	var out []string
	for i, g := range strings.Split(string(buf), "\n\n") {
		if i == 0 || strings.Contains(g, "testing.tRunner") || strings.Contains(g, "testing.(*M).") {
			continue
		}
		for _, p := range pkgs {
			if strings.Contains(g, p+".") {
				out = append(out, g)
				break
			}
		}
	}
	return out
}
