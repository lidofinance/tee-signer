//go:build nts

package nts

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/lidofinance/tee-signer/trusted-time/nts/ntstest"
)

// NTPv4 with NTS: the client request built by the package, the response
// built by the test server below, checked by the package. The tests are
// the Rust core's tests/ntp.rs, before the port,
// and the test server is its common/mod.rs: the server side written from
// the RFC apart from the client code, on ntstest's independent AES-SIV, so
// the two sides check each other.

// Test keys (not secret).
var (
	testC2S = []byte{
		0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
		0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78, 0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2, 0xe1, 0xf0,
	}
	testS2C = []byte{
		0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
		0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
	}
)

const (
	testTransmit = 0x5eed_1234_9abc_def0
)

var testNonce = bytes.Repeat([]byte{0x4e}, 16)

func testKey(t testing.TB, raw []byte) *sivKey {
	t.Helper()
	k, err := newSIVKey(raw)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func rep(b byte, n int) []byte { return bytes.Repeat([]byte{b}, n) }

func uid(seed byte) [uniqueIDLen]byte {
	var u [uniqueIDLen]byte
	for i := range u {
		u[i] = seed*31 + byte(i)
	}
	return u
}

// testField is an extension field (RFC 7822 section 7.5): type, whole
// length, body, zero padding to 4 octets.
func testField(typ uint16, body []byte) []byte {
	padded := (len(body) + 3) / 4 * 4
	f := binary.BigEndian.AppendUint16(nil, typ)
	f = binary.BigEndian.AppendUint16(f, uint16(4+padded))
	f = append(f, body...)
	return append(f, make([]byte, padded-len(body))...)
}

// clientRequest is what a server reads from a client request.
type clientRequest struct {
	transmit                     [8]byte
	uniqueID, cookie             []byte
	placeholders, placeholderLen int
}

// serverReadRequest reads a client request the way a server would and
// checks the authenticator with c2s. nil if anything is wrong.
func serverReadRequest(c2s, packet []byte) *clientRequest {
	if len(packet) < 48 || packet[0]&0x3f != 4<<3|3 {
		return nil
	}
	r := &clientRequest{}
	copy(r.transmit[:], packet[40:48])
	var uniqueID, cookie []byte
	for at := 48; at < len(packet); {
		if at+4 > len(packet) {
			return nil
		}
		typ := binary.BigEndian.Uint16(packet[at:])
		l := int(binary.BigEndian.Uint16(packet[at+2:]))
		if l < 16 || l%4 != 0 || at+l > len(packet) {
			return nil
		}
		body := packet[at+4 : at+l]
		switch typ {
		case 0x0104:
			uniqueID = body
		case 0x0204:
			cookie = body
		case 0x0304:
			r.placeholders++
			r.placeholderLen = len(body)
		case 0x0404:
			if len(body) < 4 {
				return nil
			}
			nl, cl := int(binary.BigEndian.Uint16(body)), int(binary.BigEndian.Uint16(body[2:]))
			ctAt := 4 + (nl+3)/4*4
			if 4+nl > len(body) || ctAt+cl > len(body) {
				return nil
			}
			plain, ok := ntstest.Open(c2s, packet[:at], body[4:4+nl], body[ctAt:ctAt+cl])
			if !ok || len(plain) != 0 || at+l != len(packet) || uniqueID == nil || cookie == nil {
				return nil
			}
			r.uniqueID, r.cookie = uniqueID, cookie
			return r
		default:
			return nil
		}
		at += l
	}
	return nil
}

// serverReply is a server response, field by field. goodReply is a good
// response from a stratum 2 server with one 100-octet cookie.
type serverReply struct {
	leap, version, mode, stratum uint8
	poll, precision              int8
	rootDelay, rootDispersion    uint32
	referenceID                  [4]byte
	reference, receive, transmit uint64
	nonce                        []byte   // the server's AEAD nonce
	padByte                      byte     // fills the nonce and ciphertext padding (0 is correct)
	additionalPadding            []byte   // after the ciphertext, inside the authenticator
	cookies                      [][]byte // sent as encrypted NTS Cookie fields
	rawPlaintext                 []byte   // if set, the plaintext of the encrypted part instead of the cookies
	plainFields                  [][]byte // whole fields between the Unique Identifier and the authenticator
	afterAuth                    []byte   // octets after the authenticator (unauthenticated)
	noUniqueID, noAuthenticator  bool     // leave the field out
}

func goodReply() serverReply {
	return serverReply{
		version: 4, mode: 4, stratum: 2, poll: 6, precision: -20,
		rootDelay: 0x0000_0a00, rootDispersion: 0x0000_0500,
		referenceID: [4]byte{192, 0, 2, 7},
		reference:   0xec00_0000_1000_0000, receive: 0xec00_0010_8000_0000, transmit: 0xec00_0010_8000_1000,
		nonce:   rep(0x3c, 16),
		cookies: [][]byte{rep(0xc1, 100)},
	}
}

// replyHeader is the 48-octet header (RFC 5905 section 7.3).
func replyHeader(r *serverReply, origin [8]byte) []byte {
	h := []byte{r.leap<<6 | r.version<<3 | r.mode, r.stratum, byte(r.poll), byte(r.precision)}
	h = binary.BigEndian.AppendUint32(h, r.rootDelay)
	h = binary.BigEndian.AppendUint32(h, r.rootDispersion)
	h = append(h, r.referenceID[:]...)
	h = binary.BigEndian.AppendUint64(h, r.reference)
	h = append(h, origin[:]...)
	h = binary.BigEndian.AppendUint64(h, r.receive)
	return binary.BigEndian.AppendUint64(h, r.transmit)
}

// serverResponse is a response to req, authenticated and encrypted with
// key (the S2C key for a good response).
func serverResponse(key []byte, req *clientRequest, r *serverReply) []byte {
	p := replyHeader(r, req.transmit)
	if !r.noUniqueID {
		p = append(p, testField(0x0104, req.uniqueID)...)
	}
	for _, f := range r.plainFields {
		p = append(p, f...)
	}
	if !r.noAuthenticator {
		plain := r.rawPlaintext
		if plain == nil {
			for _, c := range r.cookies {
				plain = append(plain, testField(0x0204, c)...)
			}
		}
		ct := ntstest.Seal(key, p, r.nonce, plain)
		pad := func(b []byte) []byte {
			v := append([]byte(nil), b...)
			for len(v)%4 != 0 {
				v = append(v, r.padByte)
			}
			return v
		}
		body := binary.BigEndian.AppendUint16(nil, uint16(len(r.nonce)))
		body = binary.BigEndian.AppendUint16(body, uint16(len(ct)))
		body = append(body, pad(r.nonce)...)
		body = append(body, pad(ct)...)
		body = append(body, r.additionalPadding...)
		p = append(p, testField(0x0404, body)...)
	}
	return append(p, r.afterAuth...)
}

// kissOfDeath is a Kiss-o'-Death response (RFC 5905 section 7.4): leap 3,
// stratum 0, the code in the reference ID, our origin, and the Unique
// Identifier if asked.
func kissOfDeath(req *clientRequest, code string, withUniqueID bool) []byte {
	r := goodReply()
	r.leap, r.stratum = 3, 0
	copy(r.referenceID[:], code)
	r.noUniqueID, r.noAuthenticator = !withUniqueID, true
	return serverResponse(testS2C, req, &r)
}

// requestWith is a request with a 100-octet cookie. The same arguments
// give the same bytes and an equal pending state.
func requestWith(t testing.TB, placeholders int, transmit uint64, uniqueID [uniqueIDLen]byte) ([]byte, *pendingRequest) {
	t.Helper()
	in := requestInput{transmit: ntpTimestamp(transmit), uniqueID: uniqueID, cookie: rep(0xc0, 100), placeholders: placeholders}
	copy(in.nonce[:], testNonce)
	packet, req, err := buildRequest(testKey(t, testC2S), &in)
	if err != nil {
		t.Fatal(err)
	}
	return packet, req
}

// request is the standard request (one placeholder), its pending state,
// and what the test server reads from it.
func request(t testing.TB) ([]byte, *pendingRequest, *clientRequest) {
	t.Helper()
	packet, req := requestWith(t, 1, testTransmit, uid(1))
	read := serverReadRequest(testC2S, packet)
	if read == nil {
		t.Fatal("the server refuses the request")
	}
	return packet, req, read
}

func pending(t testing.TB) *pendingRequest {
	_, req, _ := request(t)
	return req
}

func verify(t testing.TB, packet []byte) (verdict, error) {
	return pending(t).verify(testKey(t, testS2C), packet)
}

// timeOf is the time response of a verdict, or a failure.
func timeOf(t testing.TB, v verdict, err error) *timeResponse {
	t.Helper()
	if err != nil || v.time == nil {
		t.Fatalf("expected a time sample, got %+v, %v", v, err)
	}
	return v.time
}

// mustTime verifies packet against a fresh standard request and returns
// its time response.
func mustTime(t testing.TB, packet []byte) *timeResponse {
	t.Helper()
	v, err := verify(t, packet)
	return timeOf(t, v, err)
}

// mustTimeReq is mustTime against req with s2c.
func mustTimeReq(t testing.TB, req *pendingRequest, s2c *sivKey, packet []byte) *timeResponse {
	t.Helper()
	v, err := req.verify(s2c, packet)
	return timeOf(t, v, err)
}

func replyWith(t testing.TB, r serverReply) []byte {
	_, _, read := request(t)
	return serverResponse(testS2C, read, &r)
}

// wantErr fails unless err wraps want.
func wantErr(t testing.TB, what string, err, want error) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("%s: got %v, want %v", what, err, want)
	}
}

func TestPlaceholdersFitIn1280Octets(t *testing.T) {
	// 48 + 36 + 40 + 8 * (4 + 104) = 988: a cookie of the RFC's suggested
	// size leaves room for all seven.
	if maxPlaceholders(104) != 7 || requestLen(104, 7) != 988 {
		t.Fatalf("104: %d placeholders, %d octets", maxPlaceholders(104), requestLen(104, 7))
	}
	// 48 + 36 + 40 + (p + 1) * (4 + 1024) <= 1280 only for p = 0.
	if maxPlaceholders(maxCookieLen) != 0 || requestLen(maxCookieLen, 0) != 1152 {
		t.Fatalf("1024: %d placeholders, %d octets", maxPlaceholders(maxCookieLen), requestLen(maxCookieLen, 0))
	}
	// 48 + 36 + 40 + 4 * 288 = 1276.
	if maxPlaceholders(284) != 3 {
		t.Fatalf("284: %d placeholders", maxPlaceholders(284))
	}
	// A tiny cookie still makes a 16-octet field (RFC 7822 section 7.5.1.4).
	if fieldLen(1) != 16 || fieldLen(12) != 16 || fieldLen(13) != 20 {
		t.Fatalf("field lengths %d %d %d", fieldLen(1), fieldLen(12), fieldLen(13))
	}
}

func TestHeaderFields(t *testing.T) {
	b := make([]byte, ntpHeaderLen)
	b[0] = 0b10_100_100
	b[1] = 2
	b[3] = 0xe9
	copy(b[4:8], []byte{0, 1, 0, 0})
	copy(b[12:16], "GPS\x00")
	binary.BigEndian.PutUint64(b[24:32], 7)
	h := parseHeader(b)
	if h.leap != 2 || h.version != 4 || h.mode != 4 || h.stratum != 2 || h.precision != -23 {
		t.Fatalf("header %+v", h)
	}
	if h.rootDelay != 0x0001_0000 || string(h.referenceID[:]) != "GPS\x00" || h.origin != 7 {
		t.Fatalf("header %+v", h)
	}
}

func TestRequestLayout(t *testing.T) {
	packet, req, read := request(t)
	// 48 header + 36 Unique Identifier + 2 * 104 cookie and placeholder + 40 authenticator.
	if len(packet) != 48+36+2*104+40 {
		t.Fatalf("request of %d octets", len(packet))
	}
	if packet[0] != 0x23 {
		t.Fatalf("first octet %#02x, want leap 0, version 4, mode 3", packet[0])
	}
	if !allZero(packet[1:40]) {
		t.Fatal("header fields other than transmit are not zero")
	}
	if binary.BigEndian.Uint64(packet[40:48]) != testTransmit {
		t.Fatal("transmit timestamp")
	}
	u := uid(1)
	if !bytes.Equal(read.uniqueID, u[:]) || !bytes.Equal(read.cookie, rep(0xc0, 100)) || read.placeholders != 1 || read.placeholderLen != 100 {
		t.Fatalf("the server read %+v", read)
	}
	if req.transmit != testTransmit || req.answered {
		t.Fatalf("pending %+v", req)
	}
	// Field order and types: UID, cookie, placeholder, authenticator.
	for i, at := range []int{48, 84, 188, 292} {
		want := []uint16{extUniqueID, extCookie, extPlaceholder, extAuth}[i]
		if got := binary.BigEndian.Uint16(packet[at:]); got != want {
			t.Fatalf("field at %d: type %#04x, want %#04x", at, got, want)
		}
	}
	// The placeholder body is zeros.
	if !allZero(packet[192:292]) {
		t.Fatal("placeholder body is not zero")
	}
	// Authenticator: nonce length 16, ciphertext length 16 (tag only), our nonce.
	if !bytes.Equal(packet[292:300], []byte{0x04, 0x04, 0, 40, 0, 16, 0, 16}) || !bytes.Equal(packet[300:316], testNonce) {
		t.Fatalf("authenticator %x", packet[292:316])
	}
	// Only the C2S key verifies it.
	if serverReadRequest(testS2C, packet) != nil {
		t.Fatal("the S2C key verified the request")
	}
}

func TestRequestIsDeterministicAndDependsOnEveryInput(t *testing.T) {
	a, _ := requestWith(t, 1, testTransmit, uid(1))
	if b, _ := requestWith(t, 1, testTransmit, uid(1)); !bytes.Equal(a, b) {
		t.Fatal("two requests from the same input differ")
	}
	if b, _ := requestWith(t, 1, testTransmit+1, uid(1)); bytes.Equal(a, b) {
		t.Fatal("the transmit timestamp did not change the request")
	}
	if b, _ := requestWith(t, 1, testTransmit, uid(2)); bytes.Equal(a, b) {
		t.Fatal("the Unique Identifier did not change the request")
	}
	if b, _ := requestWith(t, 2, testTransmit, uid(1)); len(a) == len(b) {
		t.Fatal("a placeholder did not change the length")
	}
}

func TestRequestLimits(t *testing.T) {
	c2s := testKey(t, testC2S)
	in := requestInput{transmit: testTransmit, uniqueID: uid(1), cookie: rep(1, 100), placeholders: 8}
	copy(in.nonce[:], testNonce)
	_, _, err := buildRequest(c2s, &in)
	wantErr(t, "8 placeholders", err, errTooManyPlaceholders)
	in.placeholders = 7
	p, _, err := buildRequest(c2s, &in)
	if err != nil || len(p) != 48+36+8*104+40 {
		t.Fatalf("7 placeholders: %d octets, %v", len(p), err)
	}
	if read := serverReadRequest(testC2S, p); read == nil || read.placeholders != 7 {
		t.Fatalf("the server read %+v", read)
	}

	in.cookie = rep(1, maxCookieLen)
	in.placeholders = 1
	_, _, err = buildRequest(c2s, &in)
	wantErr(t, "1024-octet cookie with a placeholder", err, errRequestTooLong)
	in.placeholders = 0
	if p, _, err = buildRequest(c2s, &in); err != nil || len(p) > NTPMaxRequestLen {
		t.Fatalf("1024-octet cookie alone: %d octets, %v", len(p), err)
	}
	in.cookie = nil
	_, _, err = buildRequest(c2s, &in)
	wantErr(t, "no cookie", err, errBadCookie)
	in.cookie = rep(1, maxCookieLen+1)
	_, _, err = buildRequest(c2s, &in)
	wantErr(t, "1025-octet cookie", err, errBadCookie)

	// A cookie whose length is not a multiple of 4 is padded, and so is
	// each placeholder.
	in.cookie = rep(9, 101)
	in.placeholders = 2
	p, _, err = buildRequest(c2s, &in)
	if err != nil {
		t.Fatal(err)
	}
	read := serverReadRequest(testC2S, p)
	if read == nil || len(read.cookie) != 104 || !bytes.Equal(read.cookie[:101], rep(9, 101)) || !allZero(read.cookie[101:]) {
		t.Fatalf("odd cookie: %+v", read)
	}
	if read.placeholders != 2 || read.placeholderLen != 104 {
		t.Fatalf("odd cookie placeholders: %+v", read)
	}
}

func TestRoundTrip(t *testing.T) {
	_, req, read := request(t)
	r := goodReply()
	r.leap, r.stratum, r.precision = 1, 3, -24
	r.rootDelay, r.rootDispersion = 0x0001_8000, 0x0000_0042
	r.cookies = [][]byte{rep(0xaa, 100), rep(0xbb, 104)}
	packet := serverResponse(testS2C, read, &r)
	s := mustTimeReq(t, req, testKey(t, testS2C), packet)
	if s.leap != 1 || s.stratum != 3 || s.precision != -24 {
		t.Fatalf("sample %+v", s)
	}
	if s.rootDelay != 0x0001_8000 || s.rootDelay.nanos() != 1_500_000_000 || s.rootDispersion != 0x0000_0042 {
		t.Fatalf("root values %+v", s)
	}
	if uint64(s.reference) != r.reference || uint64(s.origin) != testTransmit || uint64(s.receive) != r.receive || uint64(s.transmit) != r.transmit {
		t.Fatalf("timestamps %+v", s)
	}
	if len(s.cookies) != 2 || !bytes.Equal(s.cookies[0], rep(0xaa, 100)) || !bytes.Equal(s.cookies[1], rep(0xbb, 104)) {
		t.Fatalf("cookies %v", s.cookies)
	}
	if !req.answered {
		t.Fatal("not answered")
	}
}

func TestLeapIndicatorValues(t *testing.T) {
	for _, leap := range []uint8{0, 1, 2} {
		r := goodReply()
		r.leap = leap
		if got := mustTime(t, replyWith(t, r)).leap; got != leap {
			t.Fatalf("leap %d read as %d", leap, got)
		}
	}
}

func TestCookiesUpToPlaceholdersPlusOne(t *testing.T) {
	s2c := testKey(t, testS2C)
	for placeholders := 0; placeholders <= MaxPlaceholders; placeholders++ {
		packet, req := requestWith(t, placeholders, testTransmit, uid(3))
		read := serverReadRequest(testC2S, packet)
		if read == nil {
			t.Fatal("the server refuses the request")
		}
		cookies := func(n int) [][]byte {
			var out [][]byte
			for i := 0; i < n; i++ {
				out = append(out, rep(byte(i+1), 100))
			}
			return out
		}
		r := goodReply()
		r.cookies = cookies(placeholders + 2)
		_, err := req.verify(s2c, serverResponse(testS2C, read, &r))
		wantErr(t, "too many cookies", err, errTooManyCookies)
		r.cookies = cookies(placeholders + 1)
		if got := len(mustTimeReq(t, req, s2c, serverResponse(testS2C, read, &r)).cookies); got != placeholders+1 {
			t.Fatalf("%d placeholders: %d cookies", placeholders, got)
		}
	}
}

// Every single-octet change of a valid response is refused. The one
// exception the RFC allows: stratum 2 changed to 0 makes it a KoD, which
// still has our Unique Identifier and origin and gives no time.
func TestEveryChangedOctetIsRefused(t *testing.T) {
	r := goodReply()
	r.cookies = [][]byte{rep(0xaa, 100), rep(0xbb, 100)}
	good := replyWith(t, r)
	mustTime(t, good)
	s2c := testKey(t, testS2C)
	refused, kod := 0, 0
	for i := range good {
		for _, mask := range []byte{0x01, 0x02, 0x04, 0x10, 0x40, 0x80, 0xff} {
			m := append([]byte(nil), good...)
			m[i] ^= mask
			v, err := pending(t).verify(s2c, m)
			switch {
			case err != nil:
				refused++
			case v.kiss != "":
				if i != 1 || m[1] != 0 {
					t.Fatalf("octet %d xor %#02x: a KoD, but only stratum 0 makes one", i, mask)
				}
				// The reference ID 192.0.2.7 is not printable: shown as "????".
				if v.kiss != "????" {
					t.Fatalf("KoD code %q", v.kiss)
				}
				kod++
			default:
				t.Fatalf("octet %d xor %#02x was accepted", i, mask)
			}
		}
	}
	if kod != 1 || refused+kod != len(good)*7 {
		t.Fatalf("%d refused, %d KoD of %d", refused, kod, len(good)*7)
	}
	t.Logf("%d octets x 7 masks: %d refused, %d KoD", len(good), refused, kod)
}

func TestWrongUniqueID(t *testing.T) {
	_, req, read := request(t)
	s2c := testKey(t, testS2C)
	r := goodReply()
	other := *read
	u := uid(9)
	other.uniqueID = u[:]
	_, err := req.verify(s2c, serverResponse(testS2C, &other, &r))
	wantErr(t, "other Unique Identifier", err, errUniqueIDMismatch)
	// A shorter or longer echo is not ours either.
	for _, n := range []int{16, 31, 36} {
		u := uid(1)
		echo := make([]byte, n)
		copy(echo, u[:])
		other.uniqueID = echo
		_, err := req.verify(s2c, serverResponse(testS2C, &other, &r))
		wantErr(t, "echo of "+string(rune('0'+n/10))+string(rune('0'+n%10))+" octets", err, errUniqueIDMismatch)
	}
	missing := goodReply()
	missing.noUniqueID = true
	_, err = req.verify(s2c, serverResponse(testS2C, read, &missing))
	wantErr(t, "missing", err, errMissingUniqueID)
	u1 := uid(1)
	twice := goodReply()
	twice.plainFields = [][]byte{testField(extUniqueID, u1[:])}
	_, err = req.verify(s2c, serverResponse(testS2C, read, &twice))
	wantErr(t, "twice", err, errDuplicateUniqueID)
	// After all of these the real response is still accepted.
	mustTimeReq(t, req, s2c, serverResponse(testS2C, read, &r))
}

func TestWrongOrigin(t *testing.T) {
	_, req, read := request(t)
	other := *read
	binary.BigEndian.PutUint64(other.transmit[:], testTransmit^1)
	r := goodReply()
	_, err := req.verify(testKey(t, testS2C), serverResponse(testS2C, &other, &r))
	wantErr(t, "other origin", err, errOriginMismatch)
}

func TestReplayedResponse(t *testing.T) {
	_, req, read := request(t)
	s2c := testKey(t, testS2C)
	r := goodReply()
	packet := serverResponse(testS2C, read, &r)
	// A refused packet first does not use up the request.
	if _, err := req.verify(s2c, packet[:60]); err == nil {
		t.Fatal("a cut packet was accepted")
	}
	mustTimeReq(t, req, s2c, packet)
	_, err := req.verify(s2c, packet)
	wantErr(t, "replay", err, errAlreadyAnswered)
	// The same response against a later request: other transmit timestamp,
	// other Unique Identifier.
	_, next := requestWith(t, 1, testTransmit+1, uid(2))
	_, err = next.verify(s2c, packet)
	wantErr(t, "later request", err, errOriginMismatch)
	_, sameTransmit := requestWith(t, 1, testTransmit, uid(2))
	_, err = sameTransmit.verify(s2c, packet)
	wantErr(t, "same transmit, other identifier", err, errUniqueIDMismatch)
}

func TestTruncatedPackets(t *testing.T) {
	packet := replyWith(t, goodReply())
	for n := 0; n < len(packet); n++ {
		_, err := verify(t, packet[:n])
		if err == nil {
			t.Fatalf("length %d accepted", n)
		}
		if n < 48 && !errors.Is(err, errTooShort) {
			t.Fatalf("length %d: %v", n, err)
		}
	}
	// The header alone: no Unique Identifier.
	_, err := verify(t, packet[:48])
	wantErr(t, "header alone", err, errMissingUniqueID)
}

func TestOversizedAndMalformedFields(t *testing.T) {
	good := replyWith(t, goodReply())
	long := append(append([]byte(nil), good...), make([]byte, NTPMaxResponseLen+1-len(good))...)
	_, err := verify(t, long)
	wantErr(t, "2049 octets", err, errTooLong)

	// Cookies: too long, empty.
	r := goodReply()
	r.cookies = [][]byte{rep(1, maxCookieLen+4)}
	_, err = verify(t, replyWith(t, r))
	wantErr(t, "long cookie", err, errBadCookie)
	r.cookies = [][]byte{{}}
	_, err = verify(t, replyWith(t, r))
	wantErr(t, "empty cookie", err, errBadCookie)

	// Plain fields: length not a multiple of 4, under 16, past the end.
	for _, bad := range [][]byte{
		{0x7f, 0x00, 0x00, 0x11},
		{0x7f, 0x00, 0x00, 0x0c, 0, 0, 0, 0, 0, 0, 0, 0},
		{0x7f, 0x00, 0x00, 0x04},
		{0x7f, 0x00, 0x00, 0x00},
	} {
		r := goodReply()
		r.plainFields = [][]byte{bad}
		_, err := verify(t, replyWith(t, r))
		wantErr(t, "bad plain field", err, errBadExtensionField)
	}
	r = goodReply()
	r.noAuthenticator = true
	pastEnd := append(replyWith(t, r), 0x7f, 0x00, 0x01, 0x00, 0, 0, 0, 0)
	_, err = verify(t, pastEnd)
	wantErr(t, "field past the end", err, errBadExtensionField)

	// Encrypted fields: a length that is not a multiple of 4, too short,
	// past the end.
	for _, raw := range [][]byte{
		{0x02, 0x04, 0x00, 0x06, 0xaa, 0xbb, 0, 0},
		{0x02, 0x04, 0x00, 0x02},
		{0x02, 0x04, 0x00, 0x10, 1, 2, 3, 4},
		{0x02, 0x04},
	} {
		r := goodReply()
		r.rawPlaintext = raw
		_, err := verify(t, replyWith(t, r))
		wantErr(t, "bad encrypted field", err, errBadEncryptedField)
	}
}

func TestOtherEncryptedFieldsAreSkipped(t *testing.T) {
	// A 4-octet unknown field and an encrypted placeholder, then a cookie.
	raw := []byte{0x7e, 0x00, 0x00, 0x04}
	raw = append(raw, testField(extPlaceholder, make([]byte, 8))...)
	raw = append(raw, testField(extCookie, rep(0xcc, 100))...)
	r := goodReply()
	r.rawPlaintext = raw
	s := mustTime(t, replyWith(t, r))
	if len(s.cookies) != 1 || !bytes.Equal(s.cookies[0], rep(0xcc, 100)) {
		t.Fatalf("cookies %v", s.cookies)
	}
}

func TestKissOfDeathPackets(t *testing.T) {
	_, _, read := request(t)
	s2c := testKey(t, testS2C)
	for _, code := range []string{"RATE", "NTSN", "DENY", "RSTR", "STEP"} {
		req := pending(t)
		packet := kissOfDeath(read, code, true)
		v, err := req.verify(s2c, packet)
		if err != nil || v.kiss != code {
			t.Fatalf("%s: %+v, %v", code, v, err)
		}
		if req.answered || v.kissAuthentic {
			t.Fatalf("a KoD without an authenticator: answered %v, authentic %v", req.answered, v.kissAuthentic)
		}
		// The same KoD again is a KoD again, and the real response is still
		// taken after it: a forged KoD cannot close the request.
		if v, err := req.verify(s2c, packet); err != nil || v.kiss != code {
			t.Fatalf("%s again: %+v, %v", code, v, err)
		}
		r := goodReply()
		mustTimeReq(t, req, s2c, serverResponse(testS2C, read, &r))
	}
	// Without our Unique Identifier, with another one, or with another
	// origin: refused.
	_, err := verify(t, kissOfDeath(read, "DENY", false))
	wantErr(t, "KoD without identifier", err, errMissingUniqueID)
	other := *read
	u := uid(7)
	other.uniqueID = u[:]
	_, err = verify(t, kissOfDeath(&other, "DENY", true))
	wantErr(t, "KoD with another identifier", err, errUniqueIDMismatch)
	other = *read
	other.transmit = [8]byte{}
	_, err = verify(t, kissOfDeath(&other, "DENY", true))
	wantErr(t, "KoD with another origin", err, errOriginMismatch)
	// A KoD with an authenticator that verifies is an authentic KoD; with
	// one that does not verify it is a KoD, but not an authentic one.
	r := goodReply()
	r.stratum = 0
	copy(r.referenceID[:], "RATE")
	if v, err := verify(t, replyWith(t, r)); err != nil || v.kiss != "RATE" || !v.kissAuthentic {
		t.Fatalf("authenticated KoD: %+v, %v", v, err)
	}
	if v, err := verify(t, serverResponse(testC2S, read, &r)); err != nil || v.kiss != "RATE" || v.kissAuthentic {
		t.Fatalf("KoD with a bad authenticator: %+v, %v", v, err)
	}
}

func TestUnsynchronizedOrBadStratumIsRefused(t *testing.T) {
	r := goodReply()
	r.leap = 3
	_, err := verify(t, replyWith(t, r))
	wantErr(t, "leap 3", err, errUnsynchronized)
	for _, stratum := range []uint8{16, 17, 255} {
		r := goodReply()
		r.stratum = stratum
		_, err := verify(t, replyWith(t, r))
		wantErr(t, "high stratum", err, errBadStratum)
	}
	for _, stratum := range []uint8{1, 15} {
		r := goodReply()
		r.stratum = stratum
		if got := mustTime(t, replyWith(t, r)).stratum; got != stratum {
			t.Fatalf("stratum %d read as %d", stratum, got)
		}
	}
}

func TestVersionAndMode(t *testing.T) {
	r := goodReply()
	r.version = 3
	_, err := verify(t, replyWith(t, r))
	wantErr(t, "version 3", err, errBadVersion)
	for _, mode := range []uint8{0, 1, 2, 3, 5, 6, 7} {
		r := goodReply()
		r.mode = mode
		_, err := verify(t, replyWith(t, r))
		wantErr(t, "mode", err, errBadMode)
	}
}

// RFC 8915 section 5.7: the client MUST discard unauthenticated extension
// fields, the ones after the authenticator. They do not change the result.
func TestFieldsAfterTheAuthenticatorAreDiscarded(t *testing.T) {
	u := uid(5)
	after := testField(extCookie, rep(0xee, 100))
	after = append(after, testField(extUniqueID, u[:])...)
	after = append(after, 0xde, 0xad, 0xbe)
	r := goodReply()
	r.afterAuth = after
	s := mustTime(t, replyWith(t, r))
	if len(s.cookies) != 1 || !bytes.Equal(s.cookies[0], rep(0xc1, 100)) {
		t.Fatalf("cookies %v", s.cookies)
	}
}

// Cookies must come encrypted (RFC 8915 section 5.7). One in the clear,
// before the authenticator, is skipped.
func TestACookieInTheClearIsNotUsed(t *testing.T) {
	r := goodReply()
	r.plainFields = [][]byte{testField(extCookie, rep(0xdd, 100))}
	s := mustTime(t, replyWith(t, r))
	if len(s.cookies) != 1 || !bytes.Equal(s.cookies[0], rep(0xc1, 100)) {
		t.Fatalf("cookies %v", s.cookies)
	}
}

func TestAuthenticatorChecks(t *testing.T) {
	_, _, read := request(t)
	// Signed with the wrong key.
	r := goodReply()
	_, err := verify(t, serverResponse(testC2S, read, &r))
	wantErr(t, "wrong key", err, errNotAuthentic)
	// No authenticator.
	r = goodReply()
	r.noAuthenticator = true
	_, err = verify(t, replyWith(t, r))
	wantErr(t, "no authenticator", err, errMissingAuthenticator)
	// No cookie.
	r = goodReply()
	r.cookies = nil
	_, err = verify(t, replyWith(t, r))
	wantErr(t, "no cookie", err, errNoCookies)
	// Server nonces of other lengths, padded with zeros.
	for _, n := range []int{1, 12, 13, 24, 32} {
		r := goodReply()
		r.nonce = rep(0x77, n)
		mustTime(t, replyWith(t, r))
	}
	// Padding that is not zero, in the nonce or in the Additional Padding.
	r = goodReply()
	r.nonce, r.padByte = rep(0x77, 13), 1
	_, err = verify(t, replyWith(t, r))
	wantErr(t, "nonce padding", err, errBadAuthenticator)
	r = goodReply()
	r.additionalPadding = make([]byte, 8)
	mustTime(t, replyWith(t, r))
	r.additionalPadding = []byte{0, 0, 0, 1}
	_, err = verify(t, replyWith(t, r))
	wantErr(t, "additional padding", err, errBadAuthenticator)
	// A zero-length nonce (RFC 5297 section 6.1: at least 1 octet).
	r = goodReply()
	r.nonce = []byte{}
	_, err = verify(t, replyWith(t, r))
	wantErr(t, "empty nonce", err, errBadAuthenticator)
}

// The association's cookie jar: each cookie goes out once, the request
// asks for enough placeholders to refill the jar, and the response's
// cookies come in newest last, the oldest beyond MaxCookies dropped.
func TestCookieJar(t *testing.T) {
	a := &Association{c2s: testKey(t, testC2S), s2c: testKey(t, testS2C)}
	for i := 0; i < 8; i++ {
		a.cookies = append(a.cookies, rep(byte(i+1), 100))
	}
	random := make([]byte, RequestRandomLen)
	for i, want := range []int{0, 1, 2} {
		// The jar loses a cookie each time nothing comes back.
		packet, req, cookie, err := a.newRequest(random)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(cookie, read(packet).cookie) {
			t.Fatal("the cookie returned is not the one in the request")
		}
		read := serverReadRequest(testC2S, packet)
		if read == nil || read.placeholders != want || !bytes.Equal(read.cookie, rep(byte(i+1), 100)) || req.placeholders != want {
			t.Fatalf("request %d: %+v", i, read)
		}
	}
	if a.Cookies() != 5 {
		t.Fatalf("%d cookies held", a.Cookies())
	}
	if held := a.keepCookies([][]byte{rep(0xa1, 100), rep(0xa2, 100), rep(0xa3, 100), rep(0xa4, 100)}); held != MaxCookies {
		t.Fatalf("%d held after a refill", held)
	}
	if !bytes.Equal(a.cookies[0], rep(5, 100)) || !bytes.Equal(a.cookies[7], rep(0xa4, 100)) {
		t.Fatalf("jar %x", a.cookies)
	}
	// A request that never left the process gives its cookie back, at the
	// front of the jar.
	_, _, c, err := a.newRequest(random)
	if err != nil {
		t.Fatal(err)
	}
	a.returnCookie(c)
	if a.Cookies() != MaxCookies || !bytes.Equal(a.cookies[0], c) {
		t.Fatalf("returned cookie: %d held", a.Cookies())
	}
	for i := 0; i < 8; i++ {
		if _, _, _, err := a.newRequest(random); err != nil {
			t.Fatal(err)
		}
	}
	_, _, _, err = a.newRequest(random)
	if !errors.Is(err, &Error{Code: CodeNoCookie}) {
		t.Fatalf("empty jar: %v", err)
	}
	if _, _, _, err := a.newRequest(random[:3]); err == nil {
		t.Fatal("short random accepted")
	}
}

// read is serverReadRequest with the test C2S key, or a failure.
func read(packet []byte) *clientRequest {
	r := serverReadRequest(testC2S, packet)
	if r == nil {
		return &clientRequest{}
	}
	return r
}
