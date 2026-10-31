package fuzzcheck

import (
	"flag"
	"fmt"
	"os"
	"runtime"
	"sync"
	"testing"
	"time"
)

// InputLimit is the time one fuzz input may take by default. The
// environment variable FUZZ_INPUT_LIMIT (a Go duration, such as 500ms or
// 3s) sets another.
const InputLimit = 2 * time.Second

// watchLimit is the input limit, or 0 when Watch does nothing: go test
// runs without -fuzz and FUZZ_INPUT_LIMIT is unset. Without -fuzz, go test
// runs the seed corpus and its -timeout stops a test that hangs; setting
// FUZZ_INPUT_LIMIT replays saved inputs under the limit too.
var watchLimit = sync.OnceValues(func() (time.Duration, error) {
	env, set := os.LookupEnv("FUZZ_INPUT_LIMIT")
	f := flag.Lookup("test.fuzz")
	if !set && (f == nil || f.Value.String() == "") {
		return 0, nil
	}
	return inputLimit(env)
})

// inputLimit parses FUZZ_INPUT_LIMIT: empty means InputLimit.
func inputLimit(s string) (time.Duration, error) {
	if s == "" {
		return InputLimit, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("FUZZ_INPUT_LIMIT=%q: want a positive Go duration such as 1s", s)
	}
	return d, nil
}

// Watch stops the fuzz input that t runs if it takes longer than the
// input limit (InputLimit, or FUZZ_INPUT_LIMIT). Call it first in the
// function passed to f.Fuzz. An input that loops forever never returns to
// the test, so when the limit passes a timer prints every goroutine's
// stack and ends the process with exit status 2. When fuzzing, go test
// then reports "fuzzing process hung or terminated unexpectedly" and
// writes the input to testdata/fuzz/<target>/, as for a crash; go test
// does not show the fuzzing process's output, so replay the input with
// FUZZ_INPUT_LIMIT set to see the stacks. Without the timer, go test
// -fuzz passes when an input hangs: at -fuzztime it stops the stuck
// process and reports no failure.
func Watch(t testing.TB) {
	limit, err := watchLimit()
	if err != nil {
		t.Fatal(err)
	}
	if limit == 0 {
		return
	}
	name := t.Name()
	t.Cleanup(arm(limit, func() { tooSlow(name, limit) }))
}

// arm calls fire after limit unless the returned stop runs first.
func arm(limit time.Duration, fire func()) (stop func()) {
	tm := time.AfterFunc(limit, fire)
	return func() { tm.Stop() }
}

// tooSlow ends the process: the input of test name ran longer than limit.
func tooSlow(name string, limit time.Duration) {
	buf := make([]byte, 1<<20)
	buf = buf[:runtime.Stack(buf, true)]
	fmt.Fprintf(os.Stderr, "fuzzcheck: %s: one input ran longer than %v (FUZZ_INPUT_LIMIT): it loops or is too slow\n\n%s\n", name, limit, buf)
	os.Exit(2)
}
