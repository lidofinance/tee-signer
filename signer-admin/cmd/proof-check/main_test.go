package main

import (
	"strings"
	"testing"
)

func TestTidyHidesAddressesAndLongHex(t *testing.T) {
	in := "dial tcp 192.0.2.17:7100: i/o timeout, key 0123456789abcdef0123456789abcdef, host 10.0.0.4"
	got := tidy(in)
	for _, bad := range []string{"192.0.2.17", "10.0.0.4", "0123456789abcdef0123456789abcdef"} {
		if strings.Contains(got, bad) {
			t.Errorf("%q still holds %q", got, bad)
		}
	}
	if !strings.Contains(got, "<ip>") || !strings.Contains(got, "01234567…") {
		t.Errorf("unexpected text %q", got)
	}
}

func TestTidyShortens(t *testing.T) {
	if got := tidy(strings.Repeat("word ", 100)); len([]rune(got)) > 162 {
		t.Errorf("not shortened: %d characters", len([]rune(got)))
	}
}
