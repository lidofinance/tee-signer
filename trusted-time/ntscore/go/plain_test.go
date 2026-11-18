//go:build nts

package ntscore

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
	"time"
)

// Plain NTP (RFC 5905 section 7.3) without NTS: the request, the check of
// the response and the measurement, one by one. The tests of the Rust
// core's ntp.rs and FFI (plain_*) and of nts/plain_test.go on main.

const plainTransmit = NTPTimestamp(0x1122_3344_5566_7788)

// plainResponse is a plain server response to transmit: the header of r
// with the request's transmit timestamp as origin, and nothing after it.
func plainResponse(transmit NTPTimestamp, r serverReply) []byte {
	var origin [8]byte
	binary.BigEndian.PutUint64(origin[:], uint64(transmit))
	return replyHeader(&r, origin)
}

func plainRequest() *PlainRequest {
	_, r := BuildPlainRequest(plainTransmit)
	return r
}

func TestPlainRequestIsTheHeaderAlone(t *testing.T) {
	packet, req := BuildPlainRequest(plainTransmit)
	want := make([]byte, 48)
	want[0] = 0x23 // LI 0, VN 4, mode 3
	binary.BigEndian.PutUint64(want[40:], uint64(plainTransmit))
	if !bytes.Equal(packet, want) || len(packet) != PlainRequestLen {
		t.Fatalf("request %x", packet)
	}
	if req.Transmit() != plainTransmit || req.Answered() {
		t.Fatalf("pending: transmit %x, answered %v", req.Transmit(), req.Answered())
	}
	// Our own request is mode 3: refused as an answer, and the request
	// stays open.
	if _, err := req.Verify(packet); !errors.Is(err, ErrBadMode) || req.Answered() {
		t.Fatalf("the request as its own answer: %v", err)
	}
}

func TestPlainResponseGivesASampleWithoutCookies(t *testing.T) {
	req := plainRequest()
	resp := plainResponse(plainTransmit, goodReply())
	v, err := req.Verify(resp)
	if err != nil || v.Time == nil || v.Kiss != "" {
		t.Fatalf("%+v, %v", v, err)
	}
	s := v.Time
	if s.Leap != 0 || s.Stratum != 2 || s.Precision != -20 || s.Origin != plainTransmit || s.Transmit != 0xec00_0010_8000_1000 || len(s.Cookies) != 0 {
		t.Fatalf("time %+v", s)
	}
	if !req.Answered() {
		t.Fatal("not answered")
	}
	// The same response again is a replay.
	if _, err := req.Verify(resp); !errors.Is(err, ErrAlreadyAnswered) {
		t.Fatalf("replay: %v", err)
	}
}

func TestPlainResponseIgnoresWhatFollowsTheHeader(t *testing.T) {
	// An RFC 7822 field, a legacy MAC, or junk: none of it is read.
	for _, tail := range [][]byte{make([]byte, 20), {0xff, 0xff, 0xff}, {0x01, 0x04, 0x00, 0x24}} {
		p := append(plainResponse(plainTransmit, goodReply()), tail...)
		if v, err := plainRequest().Verify(p); err != nil || v.Time == nil {
			t.Fatalf("tail %x: %+v, %v", tail, v, err)
		}
	}
	p := append(plainResponse(plainTransmit, goodReply()), make([]byte, NTPMaxResponseLen-48)...)
	if _, err := plainRequest().Verify(p); err != nil {
		t.Fatalf("the longest response: %v", err)
	}
	if _, err := plainRequest().Verify(append(p, 0)); !errors.Is(err, ErrTooLong) {
		t.Fatalf("one octet over: %v", err)
	}
}

func TestPlainResponseRefusalsLeaveTheRequestOpen(t *testing.T) {
	req := plainRequest()
	ok := plainResponse(plainTransmit, goodReply())
	for _, c := range []struct {
		change func(b []byte)
		want   error
		text   string
	}{
		{func(b []byte) { b[0] = 0b00_011_100 }, ErrBadVersion, "version 3"},
		{func(b []byte) { b[0] = 0b00_100_011 }, ErrBadMode, "mode 3"},
		{func(b []byte) { b[31] ^= 1 }, ErrOriginMismatch, ""},
		{func(b []byte) { b[24] ^= 0x80 }, ErrOriginMismatch, ""},
		{func(b []byte) { b[0] |= 3 << 6 }, ErrUnsynchronized, ""},
		{func(b []byte) { b[1] = 16 }, ErrBadStratum, "stratum 16"},
		{func(b []byte) { b[1] = 255 }, ErrBadStratum, "stratum 255"},
	} {
		b := append([]byte(nil), ok...)
		c.change(b)
		_, err := req.Verify(b)
		if !errors.Is(err, c.want) || (c.text != "" && !bytes.Contains([]byte(err.Error()), []byte(c.text))) {
			t.Fatalf("want %v (%s), got %v", c.want, c.text, err)
		}
	}
	if _, err := req.Verify(ok[:47]); !errors.Is(err, ErrTooShort) {
		t.Fatalf("47 octets: %v", err)
	}
	if _, err := req.Verify(nil); !errors.Is(err, ErrTooShort) {
		t.Fatalf("no octets: %v", err)
	}
	if req.Answered() {
		t.Fatal("a refused response answered the request")
	}
	if _, err := req.Verify(ok); err != nil {
		t.Fatalf("the real response after the refusals: %v", err)
	}
}

func TestPlainKissOfDeath(t *testing.T) {
	kiss := goodReply()
	kiss.leap, kiss.stratum = 3, 0
	for code, want := range map[string]string{"RATE": "RATE", "DENY": "DENY", "RSTR": "RSTR", "NTS\x00": "NTSN", "\x01\x02\x03\x04": "????"} {
		copy(kiss.referenceID[:], code)
		req := plainRequest()
		// What follows the header is ignored in a kiss too.
		v, err := req.Verify(append(plainResponse(plainTransmit, kiss), bytes.Repeat([]byte{0xff}, 12)...))
		if err != nil || v.Kiss != want || v.KissAuthentic || v.Time != nil {
			t.Fatalf("%q: %+v, %v", code, v, err)
		}
		// A kiss closes a plain request: whoever could forge it could forge
		// the answer as well.
		if !req.Answered() {
			t.Fatalf("%q: the request is still open", code)
		}
	}
	// A kiss must still match our transmit timestamp.
	b := plainResponse(plainTransmit, kiss)
	b[24] ^= 1
	if _, err := plainRequest().Verify(b); !errors.Is(err, ErrOriginMismatch) {
		t.Fatalf("a kiss with another origin: %v", err)
	}
}

// The verdict of a plain response measures like an NTS one: the Rust FFI's
// plain_round_trip_with_measurement and plain_refusals_kiss_and_sample_checks.
func TestPlainRoundTripWithMeasurement(t *testing.T) {
	const ms = int64(time.Millisecond)
	pivot := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC).UnixNano()
	reply := goodReply()
	req := plainRequest()
	v, err := req.Verify(plainResponse(plainTransmit, reply))
	if err != nil {
		t.Fatal(err)
	}
	s, err := Measure(v.Time, 5*ms, 25*ms, pivot)
	if err != nil {
		t.Fatal(err)
	}
	if s.Stratum != 2 || s.Precision != -20 || s.Leap != 0 || s.CookiesReceived != 0 || s.CookiesHeld != 0 {
		t.Fatalf("sample %+v", s)
	}
	t2, _ := NTPTimestamp(reply.receive).UnixNanos(pivot)
	t3, _ := NTPTimestamp(reply.transmit).UnixNanos(pivot)
	if int64(s.Delay) != 20*ms-(t3-t2) {
		t.Fatalf("delay %v", s.Delay)
	}
	if d := s.Offset - ((t2-5*ms)+(t3-25*ms))/2; d > 1 || d < -1 {
		t.Fatalf("offset %d", s.Offset)
	}
	if s.Bound < s.Delay/2+s.RootDelay/2+s.RootDispersion {
		t.Fatalf("bound %v", s.Bound)
	}
	// A zero reference timestamp passes the header and fails the
	// measurement: the request is answered by then.
	req = plainRequest()
	zero := goodReply()
	zero.reference = 0
	v, err = req.Verify(plainResponse(plainTransmit, zero))
	if err != nil || !req.Answered() {
		t.Fatalf("zero reference timestamp, the header: %v", err)
	}
	if _, err := Measure(v.Time, 0, ms, pivot); !errors.Is(err, ErrNeverSynchronized) {
		t.Fatalf("zero reference timestamp, the measurement: %v", err)
	}
}
