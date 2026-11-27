//go:build darwin

package lockdown

import (
	"encoding/binary"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// Secrets sets RLIMIT_CORE to 0, soft and hard, and writes one line about
// the memory.
func TestSecretsDisablesCoreDumps(t *testing.T) {
	var b strings.Builder
	if err := Secrets(&b); err != nil {
		t.Fatal(err)
	}
	var rl unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_CORE, &rl); err != nil {
		t.Fatal(err)
	}
	if rl.Cur != 0 || rl.Max != 0 {
		t.Fatalf("RLIMIT_CORE %d/%d after Secrets, want 0/0", rl.Cur, rl.Max)
	}
	if !strings.Contains(b.String(), "memory is not locked") || strings.Count(b.String(), "\n") != 1 {
		t.Fatalf("output: %q, want one line with \"memory is not locked\"", b.String())
	}
}

// The kernel answers vm.swapusage with a struct that parseSwapUsage takes.
// The note follows its answer: a note with encrypted swap, else a warning.
func TestMemoryNoteFollowsSwapUsage(t *testing.T) {
	enc, err := swapEncrypted()
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	memoryNote(&b)
	want := "warning: memory is not locked and swap is not encrypted"
	if enc {
		want = "note: memory is not locked on macOS; swap is encrypted"
	}
	if !strings.HasPrefix(b.String(), want) {
		t.Fatalf("swap encrypted %v, output %q, want it to start with %q", enc, b.String(), want)
	}
}

func TestParseSwapUsage(t *testing.T) {
	raw := make([]byte, 32)
	binary.LittleEndian.PutUint32(raw[24:], 16384)
	if enc, err := parseSwapUsage(raw); err != nil || enc {
		t.Fatalf("encrypted 0: got %v, %v", enc, err)
	}
	raw[28] = 1
	if enc, err := parseSwapUsage(raw); err != nil || !enc {
		t.Fatalf("encrypted 1: got %v, %v", enc, err)
	}
	for _, n := range []int{0, 28, 31, 40} {
		if _, err := parseSwapUsage(make([]byte, n)); err == nil {
			t.Fatalf("%d bytes: no error", n)
		}
	}
}
