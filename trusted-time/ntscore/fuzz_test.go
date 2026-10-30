//go:build nts

package ntscore

import (
	"bytes"
	"testing"
)

// Fuzz targets for the two parsers of untrusted bytes. go test runs them
// on the seed corpus; go test -fuzz=FuzzVerifyResponse -tags nts ./nts
// runs the engine. A panic is a failure; so is a response the verifier
// accepts that is not the real one.

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
		n, done, err := KEComplete(data)
		if err == nil && done {
			if n > len(data) || n > KEMaxResponseLen {
				t.Fatalf("response length %d of %d octets", n, len(data))
			}
			// The complete prefix parses or is refused, never panics; what
			// follows it is never read by the length walk.
			checkKE(t, data[:n])
		}
		checkKE(t, data)
	})
}
