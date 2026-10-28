//go:build nts

package ntscore

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/lidofinance/tee-signer/devkit/fuzzcheck"
)

// Fuzz targets for the two parsers of untrusted bytes and for the
// measurement. go test runs them on the seed corpus; go test
// -fuzz=FuzzVerifyResponse -tags nts ./ntscore (or scripts/fuzz.sh) runs
// the engine. A panic is a failure; so is a response the verifier accepts
// that is not the real one, and a sample whose bound misses the truth.

// fuzzRequest is a fixed request: the same transmit timestamp and Unique
// Identifier every time, so the one response the verifier may accept is
// the seed (or the seed with octets after its end).
func fuzzRequest(t testing.TB) (*PendingRequest, []byte, []byte) {
	t.Helper()
	packet, req := requestWith(t, 1, testTransmit, uid(1))
	read := serverReadRequest(testC2S, packet)
	if read == nil {
		t.Fatal("the server refuses the request")
	}
	r := goodReply()
	r.cookies = [][]byte{rep(0xaa, 100), rep(0xbb, 100)}
	return req, serverResponse(testS2C, read, &r), kissOfDeath(read, "RATE", true)
}

func FuzzVerifyResponse(f *testing.F) {
	_, good, kod := fuzzRequest(f)
	f.Add(good)
	f.Add(kod)
	f.Add(good[:60])
	f.Add(good[:48])
	f.Add([]byte{})
	f.Add(bytes.Repeat([]byte{0xff}, NTPMaxResponseLen+1))
	s2c, err := NewSIVKey(testS2C)
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		fuzzcheck.Watch(t)
		req, good, _ := fuzzRequest(t)
		v, err := req.Verify(s2c, data)
		switch {
		case err != nil:
			if req.Answered() {
				t.Fatal("a refused response answered the request")
			}
		case v.Time != nil:
			if len(data) < len(good) || !bytes.Equal(data[:len(good)], good) {
				t.Fatalf("accepted %x", data)
			}
			if n := len(v.Time.Cookies); n < 1 || n > 2 {
				t.Fatalf("%d cookies", n)
			}
		default:
			if data[1] != 0 || len(v.Kiss) != 4 || req.Answered() {
				t.Fatalf("KoD %q from stratum %d, answered %v", v.Kiss, data[1], req.Answered())
			}
		}
		// After an accepted time response every further one is a replay;
		// after a refused one or a KoD the real response still comes through.
		accepted := err == nil && v.Time != nil
		if _, err2 := req.Verify(s2c, good); (err2 != nil) != accepted {
			t.Fatalf("after %v (accepted %v) the real response gave %v", err, accepted, err2)
		}
	})
}

func FuzzKEResponse(f *testing.F) {
	good := goodKEResponse()
	f.Add(good)
	f.Add(good[:5])
	f.Add([]byte{0x80, 0x00, 0x00, 0x00})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		fuzzcheck.Watch(t)
		n, done, err := KEComplete(data)
		if err == nil && done {
			if n > len(data) || n > KEMaxResponseLen {
				t.Fatalf("response length %d of %d octets", n, len(data))
			}
			// The complete prefix parses or is refused, never panics; what
			// follows it is never read by the length walk.
			checkKE(t, data[:n])
			// The framing is a prefix walk: every shorter prefix is
			// incomplete and no error, every longer one is complete at n;
			// and a complete response is never refused for its framing.
			for _, k := range []int{0, 1, n / 2, n - 1} {
				if k < 0 || k >= n {
					continue
				}
				if _, d, e := KEComplete(data[:k]); d || e != nil {
					t.Fatalf("prefix of %d of a response complete at %d: done %v, %v", k, n, d, e)
				}
			}
			if n2, d2, e2 := KEComplete(data[:n]); n2 != n || !d2 || e2 != nil {
				t.Fatalf("the complete prefix alone: %d, %v, %v", n2, d2, e2)
			}
			if _, perr := ParseKEResponse(data[:n]); errors.Is(perr, ErrKETruncated) || errors.Is(perr, ErrKETrailingData) {
				t.Fatalf("a complete response refused for its framing: %v", perr)
			}
		}
		if _, perr := ParseKEResponse(data); perr == nil && (!done || err != nil || n != len(data)) {
			t.Fatalf("parsed, but the framing says done %v at %d of %d, %v", done, n, len(data), err)
		}
		checkKE(t, data)
	})
}

// FuzzEncryptedPart: the parser of the decrypted part of a response (the
// new cookies, other fields skipped) is behind the authenticator, which
// FuzzVerifyResponse never passes. Here the plaintext is sealed under the
// test S2C key, so every input reaches it. A response is accepted only as
// a time response with at most placeholders + 1 cookies of 1 to 1024
// octets, and a refusal leaves the request open.
func FuzzEncryptedPart(f *testing.F) {
	f.Add([]byte{}, uint8(16), uint8(1))
	f.Add(testField(ExtCookie, rep(0xaa, 100)), uint8(16), uint8(1))
	f.Add(append(testField(ExtCookie, rep(0xaa, 12)), testField(ExtCookie, rep(0xbb, 1024))...), uint8(1), uint8(7))
	f.Add(testField(0x0504, rep(0xcc, 20)), uint8(31), uint8(0))
	s2c, err := NewSIVKey(testS2C)
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, plain []byte, nonceLen, placeholders uint8) {
		fuzzcheck.Watch(t)
		ph := int(placeholders) % (MaxPlaceholders + 1)
		packet, req := requestWith(t, ph, testTransmit, uid(1))
		read := serverReadRequest(testC2S, packet)
		if read == nil {
			t.Fatal("the server refuses the request")
		}
		r := goodReply()
		r.nonce = rep(0x4e, 1+int(nonceLen)%32)
		r.rawPlaintext = append([]byte{}, plain...)
		v, err := req.Verify(s2c, serverResponse(testS2C, read, &r))
		if err != nil {
			if req.Answered() {
				t.Fatal("a refused response answered the request")
			}
			return
		}
		if v.Time == nil {
			t.Fatalf("a sealed answer with stratum 2 is not a time response: %+v", v)
		}
		if n := len(v.Time.Cookies); n < 1 || n > ph+1 {
			t.Fatalf("%d cookies for %d placeholders", n, ph)
		}
		for _, c := range v.Time.Cookies {
			if len(c) < 1 || len(c) > MaxCookieLen {
				t.Fatalf("a cookie of %d octets", len(c))
			}
		}
	})
}

// FuzzMeasure: answers built from a known truth reach the measurement
// directly (FuzzVerifyResponse changes whole packets, so almost none get
// past the authenticator to it; the crash of #12 was here). The local
// clock reads t1 when real time is t1 + off; the request takes out ns,
// the server holds it hold ns, the answer takes back ns; the server's
// clock is off by e, within the root dispersion it states. Whatever the
// values, Measure must not panic, and a sample it takes must hold the
// true offset within its bound.
func FuzzMeasure(f *testing.F) {
	f.Add(int64(1000*sec), int64(5*ms), uint32(10_000_000), uint32(1_000_000), uint32(9_000_000), uint32(0x100), uint32(0x200), uint32(1234), int8(-20), uint8(2), false)
	f.Add(int64(0), int64(0), uint32(0), uint32(0), uint32(0), uint32(0), uint32(0), uint32(0), int8(-128), uint8(1), true)
	f.Add(int64(-1), int64(-1), uint32(1<<32-1), uint32(1<<32-1), uint32(1<<32-1), uint32(1<<32-1), uint32(1<<32-1), uint32(1<<32-1), int8(127), uint8(15), true)
	f.Fuzz(func(t *testing.T, t1, skew int64, out, hold, back, rootDelay, rootDisp, eRaw uint32, precision int8, stratum uint8, slow bool) {
		fuzzcheck.Watch(t)
		t1 %= 1 << 52 // the local clock: about 52 days either way of 0
		off := testNow - t1 + skew%int64(24*time.Hour)
		disp := NTPShort(rootDisp).Nanos()
		e := int64(eRaw) % (disp + 1)
		if slow {
			e = -e
		}
		t2 := t1 + off + int64(out) + e
		t3 := t2 + int64(hold)
		t4 := t1 + int64(out) + int64(hold) + int64(back)
		r := &TimeResponse{
			Stratum: stratum, Precision: precision, RootDelay: NTPShort(rootDelay), RootDispersion: NTPShort(rootDisp),
			Reference: NTPFromUnixNanos(t2 - 10*sec), Origin: 1, Receive: NTPFromUnixNanos(t2), Transmit: NTPFromUnixNanos(t3),
		}
		m, err := Measure(r, t1, t4, testNow)
		if err != nil {
			return
		}
		if m.Bound < 0 || m.Delay < 0 || m.T4 != t4 {
			t.Fatalf("sample %+v", m)
		}
		if d := m.Offset - off; d > int64(m.Bound) || -d > int64(m.Bound) {
			t.Fatalf("true offset %d, measured %d, bound %v (sample %+v)", off, m.Offset, m.Bound, m)
		}
	})
}
