package main

import (
	"errors"
	"testing"
)

// The host gets the line main prints for a start error, and for a panic of
// the main goroutine its runtime error text only; the panic goes on.
func TestReportExit(t *testing.T) {
	var got []string
	report := func(s string) { got = append(got, s) }

	reportExit(report, nil, nil)
	reportExit(report, nil, errors.New("mark log s3://b: claim: s3log: PUT /x: 403 Forbidden AccessDenied: Access Denied"))
	func() {
		defer func() {
			if recover() == nil {
				t.Error("panic swallowed")
			}
		}()
		var m map[string]int
		defer func() { reportExit(report, recover(), nil) }()
		m["x"] = 1
	}()
	func() {
		defer func() { _ = recover() }()
		defer func() { reportExit(report, recover(), nil) }()
		panic("secret 0123abcd")
	}()
	want := []string{
		"runner: mark log s3://b: claim: s3log: PUT /x: 403 Forbidden AccessDenied: Access Denied",
		"runner: panic: assignment to entry in nil map",
		"runner: panic",
	}
	if len(got) != len(want) {
		t.Fatalf("reports %q", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("report %d: %q, want %q", i, got[i], want[i])
		}
	}
}
