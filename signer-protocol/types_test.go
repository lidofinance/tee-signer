package backend

import (
	"strings"
	"testing"
)

// A wrong-length value is refused without echoing it: callers parse
// fields of files that also hold secrets.
func TestParseHexErrorHidesInput(t *testing.T) {
	const in = "0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	var pk Pubkey
	err := pk.UnmarshalText([]byte(in))
	if err == nil {
		t.Fatal("a 32-byte value parsed as a pubkey")
	}
	if strings.Contains(err.Error(), "0123456789abcdef") {
		t.Fatalf("error shows the input: %v", err)
	}
	if !strings.Contains(err.Error(), "want 48 hex bytes") {
		t.Fatalf("error does not say what it wants: %v", err)
	}
}
