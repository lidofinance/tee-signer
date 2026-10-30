//go:build nts

package nts

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
func fuzzRequest(t testing.TB) (*pendingRequest, []byte, []byte) {
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
	s2c, err := newSIVKey(testS2C)
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		req, good, _ := fuzzRequest(t)
		v, err := req.verify(s2c, data)
		switch {
		case err != nil:
			if req.answered {
				t.Fatal("a refused response answered the request")
			}
		case v.time != nil:
			if len(data) < len(good) || !bytes.Equal(data[:len(good)], good) {
				t.Fatalf("accepted %x", data)
			}
			if n := len(v.time.cookies); n < 1 || n > 2 {
				t.Fatalf("%d cookies", n)
			}
		default:
			if data[1] != 0 || len(v.kiss) != 4 || req.answered {
				t.Fatalf("KoD %q from stratum %d, answered %v", v.kiss, data[1], req.answered)
			}
		}
		// After an accepted time response every further one is a replay;
		// after a refused one or a KoD the real response still comes through.
		accepted := err == nil && v.time != nil
		if _, err2 := req.verify(s2c, good); (err2 != nil) != accepted {
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
		n, done, err := keResponseLength(data)
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
