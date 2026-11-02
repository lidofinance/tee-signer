package relayclient

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"
)

func TestFrameRoundTrip(t *testing.T) {
	var b bytes.Buffer
	for _, n := range []int{1, 48, MaxDatagram} {
		p := bytes.Repeat([]byte{byte(n)}, n)
		if err := WriteFrame(&b, p); err != nil {
			t.Fatal(err)
		}
		got, err := ReadFrame(&b, make([]byte, MaxDatagram), MaxDatagram)
		if err != nil || !bytes.Equal(got, p) {
			t.Fatalf("%d octets: %v", n, err)
		}
	}
	if err := WriteFrame(&b, nil); !errors.Is(err, ErrFrame) {
		t.Fatalf("empty frame written: %v", err)
	}
	cases := map[string][]byte{
		"zero length":  {0, 0},
		"over the cap": binary.BigEndian.AppendUint16(nil, MaxDatagram+1),
	}
	for name, raw := range cases {
		if _, err := ReadFrame(bytes.NewReader(raw), make([]byte, MaxDatagram), MaxDatagram); !errors.Is(err, ErrFrame) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if _, err := ReadFrame(bytes.NewReader([]byte{0, 5, 1, 2}), make([]byte, MaxDatagram), MaxDatagram); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("cut frame: %v", err)
	}
	if _, err := ReadFrame(bytes.NewReader([]byte{0}), make([]byte, MaxDatagram), MaxDatagram); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("cut header: %v", err)
	}
}

func TestPrintable(t *testing.T) {
	if got := Printable([]byte("ok\x00\x1b[31m\xff"), 6); got != "ok??[3" {
		t.Fatalf("got %q", got)
	}
}
