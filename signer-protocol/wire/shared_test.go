package wire

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

// writes records each slice passed to Write, without copying it.
type writes [][]byte

func (w *writes) Write(p []byte) (int, error) {
	*w = append(*w, p)
	return len(p), nil
}

// WriteSharedFrame puts the same bytes on the wire as WriteFrame. A large
// payload goes to the writer as the caller's slice, not a copy, so many
// connections can write one shared payload; a small one goes in a single
// Write with its header.
func TestWriteSharedFrame(t *testing.T) {
	for _, n := range []int{0, 5, sharedCopyMax, sharedCopyMax + 1, MaxFrame - headerLen} {
		payload := bytes.Repeat([]byte{0xab}, n)
		f := Frame{Type: TypePublicKeys | ResponseFlag, ID: 9, Payload: payload}
		var want, got bytes.Buffer
		if err := WriteFrame(&want, f); err != nil {
			t.Fatal(err)
		}
		if err := WriteSharedFrame(&got, f); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got.Bytes(), want.Bytes()) {
			t.Fatalf("payload %d bytes: WriteSharedFrame and WriteFrame differ", n)
		}
		var w writes
		if err := WriteSharedFrame(&w, f); err != nil {
			t.Fatal(err)
		}
		if n <= sharedCopyMax {
			if len(w) != 1 {
				t.Fatalf("payload %d bytes: %d writes, want 1", n, len(w))
			}
			continue
		}
		if len(w) != 2 || &w[1][0] != &payload[0] {
			t.Fatalf("payload %d bytes: the payload was copied (%d writes)", n, len(w))
		}
	}
	if err := WriteSharedFrame(io.Discard, Frame{Payload: make([]byte, MaxFrame)}); !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("oversized write: %v", err)
	}
}
