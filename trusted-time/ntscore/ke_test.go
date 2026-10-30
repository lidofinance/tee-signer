//go:build nts

package ntscore

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strings"
	"testing"
)

// NTS-KE records: the client request read back by the test code, server
// responses built here from RFC 8915 section 4, checked by the package.
// The tests are the Rust core's tests/ke.rs, before the port.

// keRec is one record: critical bit and type, body length, body.
func keRec(critical bool, typ uint16, body []byte) []byte {
	if critical {
		typ |= RecCritical
	}
	r := binary.BigEndian.AppendUint16(nil, typ)
	r = binary.BigEndian.AppendUint16(r, uint16(len(body)))
	return append(r, body...)
}

func keEOM() []byte { return keRec(true, RecEOM, nil) }

// goodKERecords is the records of a good response, without End of
// Message: next protocol NTPv4, AEAD 15, then the cookies.
func goodKERecords(cookies [][]byte) [][]byte {
	r := [][]byte{keRec(true, RecNextProtocol, []byte{0, 0}), keRec(true, RecAEAD, []byte{0, aeadSIVCMAC256})}
	for _, c := range cookies {
		r = append(r, keRec(false, RecCookie, c))
	}
	return r
}

func eightCookies() [][]byte {
	var out [][]byte
	for i := 0; i < 8; i++ {
		out = append(out, rep(byte(i+1), 100))
	}
	return out
}

// goodKEResponse is a good response with eight 100-octet cookies.
func goodKEResponse() []byte {
	return bytes.Join(append(goodKERecords(eightCookies()), keEOM()), nil)
}

type splitRecord struct {
	critical bool
	typ      uint16
	body     []byte
}

// splitRecords is the records of a message. It fails the test if malformed.
func splitRecords(t testing.TB, buf []byte) []splitRecord {
	t.Helper()
	var out []splitRecord
	for len(buf) > 0 {
		if len(buf) < 4 {
			t.Fatal("record header cut")
		}
		typ := binary.BigEndian.Uint16(buf)
		n := int(binary.BigEndian.Uint16(buf[2:]))
		if len(buf) < 4+n {
			t.Fatal("record body cut")
		}
		out = append(out, splitRecord{typ&RecCritical != 0, typ &^ RecCritical, buf[4 : 4+n]})
		buf = buf[4+n:]
	}
	return out
}

func parseRecords(records ...[]byte) (*KEResponse, error) {
	return ParseKEResponse(bytes.Join(records, nil))
}

// with is a good response (one cookie) with extra records added before
// End of Message.
func with(extra ...[]byte) [][]byte {
	r := goodKERecords([][]byte{rep(7, 100)})
	r = append(r, extra...)
	return append(r, keEOM())
}

func wantKEErr(t testing.TB, what string, err, want error, inMessage string) {
	t.Helper()
	if !errors.Is(err, want) || !strings.Contains(err.Error(), inMessage) {
		t.Fatalf("%s: got %v, want %v with %q", what, err, want, inMessage)
	}
}

func TestKERequestAsTheServerReadsIt(t *testing.T) {
	req := KERequest()
	got := splitRecords(t, req)
	want := []splitRecord{{true, RecNextProtocol, []byte{0, 0}}, {true, RecAEAD, []byte{0, 15}}, {true, RecEOM, []byte{}}}
	if len(got) != len(want) {
		t.Fatalf("%d records", len(got))
	}
	for i := range want {
		if got[i].critical != want[i].critical || got[i].typ != want[i].typ || !bytes.Equal(got[i].body, want[i].body) {
			t.Fatalf("record %d: %+v", i, got[i])
		}
	}
	if n, done, err := KEComplete(req); err != nil || !done || n != len(req) {
		t.Fatalf("length %d %v %v", n, done, err)
	}
}

func TestKERoundTrip(t *testing.T) {
	records := goodKERecords(eightCookies())
	records = append(records, keRec(true, RecServer, []byte("ntp1.example.net")), keRec(false, RecPort, []byte{0x04, 0xd2}), keEOM())
	buf := bytes.Join(records, nil)
	r, err := ParseKEResponse(buf)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Cookies) != 8 || r.Dropped != 0 {
		t.Fatalf("%d cookies, %d dropped", len(r.Cookies), r.Dropped)
	}
	for i, c := range r.Cookies {
		if !bytes.Equal(c, rep(byte(i+1), 100)) {
			t.Fatalf("cookie %d: %x", i, c)
		}
	}
	if r.Server != "ntp1.example.net" || r.Port != 1234 {
		t.Fatalf("server %q port %d", r.Server, r.Port)
	}
	if n, done, err := KEComplete(buf); err != nil || !done || n != len(buf) {
		t.Fatalf("length %d %v %v", n, done, err)
	}
}

func TestKEDefaultsWithoutServerAndPort(t *testing.T) {
	r, err := ParseKEResponse(goodKEResponse())
	if err != nil || r.Port != 0 || r.Server != "" {
		t.Fatalf("%+v %v", r, err)
	}
}

func TestKERecordsInAnyOrder(t *testing.T) {
	// Only End of Message has a fixed place (section 4.1.1).
	records := goodKERecords([][]byte{rep(1, 64), rep(2, 64)})
	for i, j := 0, len(records)-1; i < j; i, j = i+1, j-1 {
		records[i], records[j] = records[j], records[i]
	}
	r, err := parseRecords(append(records, keEOM())...)
	if err != nil || len(r.Cookies) != 2 {
		t.Fatalf("%+v %v", r, err)
	}
}

func TestKEResponseLengthWaitsForEndOfMessage(t *testing.T) {
	buf := goodKEResponse()
	for n := 0; n < len(buf); n++ {
		if l, done, err := KEComplete(buf[:n]); l != 0 || done || err != nil {
			t.Fatalf("prefix %d: %d %v %v", n, l, done, err)
		}
		if _, err := ParseKEResponse(buf[:n]); !errors.Is(err, ErrKETruncated) {
			t.Fatalf("prefix %d: %v", n, err)
		}
	}
	more := append(append([]byte(nil), buf...), 1, 2, 3)
	if l, done, err := KEComplete(more); l != len(buf) || !done || err != nil {
		t.Fatalf("with trailing octets: %d %v %v", l, done, err)
	}
	_, err := ParseKEResponse(more)
	wantKEErr(t, "trailing octets", err, ErrKETrailingData, "after End of Message")
}

func TestKEErrorAndWarningRecords(t *testing.T) {
	for _, code := range []uint16{0, 1, 2, 0x1234} {
		body := binary.BigEndian.AppendUint16(nil, code)
		_, err := parseRecords(with(keRec(true, RecError, body))...)
		wantKEErr(t, "error record", err, ErrKEServerError, "server error "+itoa(int(code)))
		_, err = parseRecords(with(keRec(true, RecWarning, body))...)
		wantKEErr(t, "warning record", err, ErrKEServerWarning, "server warning "+itoa(int(code)))
	}
	// An Error record alone, as a server sends it.
	_, err := parseRecords(keRec(true, RecError, []byte{0, 1}), keEOM())
	wantKEErr(t, "error alone", err, ErrKEServerError, "server error 1")
	_, err = parseRecords(with(keRec(true, RecError, []byte{0}))...)
	wantKEErr(t, "error with a 1-octet body", err, ErrKEBadRecordBody, "record 2")
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for ; n > 0; n /= 10 {
		b = append([]byte{byte('0' + n%10)}, b...)
	}
	return string(b)
}

func TestKEUnknownRecords(t *testing.T) {
	_, err := parseRecords(with(keRec(true, 0x1234, []byte("x")))...)
	wantKEErr(t, "unknown critical", err, ErrKEUnknownCritical, "4660")
	if _, err := parseRecords(with(keRec(false, 0x1234, []byte("x")), keRec(false, 0x7fff, nil))...); err != nil {
		t.Fatal(err)
	}
}

func TestKEMissingRecords(t *testing.T) {
	np := keRec(true, RecNextProtocol, []byte{0, 0})
	aead := keRec(true, RecAEAD, []byte{0, 15})
	cookie := keRec(false, RecCookie, rep(1, 16))
	eom := keEOM()
	_, err := parseRecords(aead, cookie, eom)
	wantKEErr(t, "no protocol", err, ErrKEMissingRecord, "Next Protocol")
	_, err = parseRecords(np, cookie, eom)
	wantKEErr(t, "no AEAD", err, ErrKEMissingRecord, "AEAD")
	_, err = parseRecords(np, aead, eom)
	wantKEErr(t, "no cookie", err, ErrKEMissingRecord, "cookie")
	_, err = parseRecords(np, aead, cookie)
	wantKEErr(t, "no End of Message", err, ErrKETruncated, "before End of Message")
	_, err = ParseKEResponse(nil)
	wantKEErr(t, "empty", err, ErrKETruncated, "")
}

func TestKEWrongProtocolOrAEAD(t *testing.T) {
	response := func(np, aead []byte) error {
		_, err := parseRecords(keRec(true, RecNextProtocol, np), keRec(true, RecAEAD, aead), keRec(false, RecCookie, rep(1, 16)), keEOM())
		return err
	}
	if err := response([]byte{0, 0}, []byte{0, 15}); err != nil {
		t.Fatal(err)
	}
	wantKEErr(t, "protocol 1", response([]byte{0, 1}, []byte{0, 15}), ErrKEWrongProtocol, "protocol 1")
	wantKEErr(t, "protocol 0x8000", response([]byte{0, 0, 0x80, 0}, []byte{0, 15}), ErrKEWrongProtocol, "protocol 32768")
	wantKEErr(t, "no protocol", response(nil, []byte{0, 15}), ErrKENoCommonProtocol, "")
	wantKEErr(t, "odd protocol body", response([]byte{0}, []byte{0, 15}), ErrKEBadRecordBody, "record 1")
	wantKEErr(t, "AEAD 16", response([]byte{0, 0}, []byte{0, 16}), ErrKEWrongAEAD, "AEAD 16")
	wantKEErr(t, "AEAD 30", response([]byte{0, 0}, []byte{0, 30}), ErrKEWrongAEAD, "AEAD 30")
	wantKEErr(t, "no AEAD", response([]byte{0, 0}, nil), ErrKENoCommonAEAD, "")
	wantKEErr(t, "two AEADs", response([]byte{0, 0}, []byte{0, 15, 0, 15}), ErrKEBadRecordBody, "record 4")
	wantKEErr(t, "odd AEAD body", response([]byte{0, 0}, []byte{0, 15, 0}), ErrKEBadRecordBody, "record 4")
}

func TestKECriticalBits(t *testing.T) {
	// Next Protocol and End of Message MUST have it (sections 4.1.2, 4.1.1).
	r := goodKERecords([][]byte{rep(1, 16)})
	r[0] = keRec(false, RecNextProtocol, []byte{0, 0})
	_, err := parseRecords(append(r, keEOM())...)
	wantKEErr(t, "Next Protocol without the bit", err, ErrKECriticalBitMissing, "Next Protocol")
	r = goodKERecords([][]byte{rep(1, 16)})
	_, err = parseRecords(append(r, keRec(false, RecEOM, nil))...)
	wantKEErr(t, "End of Message without the bit", err, ErrKEBadEOM, "")
	r = goodKERecords([][]byte{rep(1, 16)})
	_, err = parseRecords(append(r, keRec(true, RecEOM, []byte{0, 0}))...)
	wantKEErr(t, "End of Message with a body", err, ErrKEBadEOM, "")
	// AEAD, cookie, server and port may come with or without it.
	_, err = parseRecords(keRec(true, RecNextProtocol, []byte{0, 0}), keRec(false, RecAEAD, []byte{0, 15}),
		keRec(true, RecCookie, rep(1, 16)), keRec(true, RecServer, []byte("192.0.2.1")), keRec(true, RecPort, []byte{0, 123}), keEOM())
	if err != nil {
		t.Fatal(err)
	}
}

func TestKEDuplicateRecords(t *testing.T) {
	for _, dup := range [][]byte{keRec(true, RecNextProtocol, []byte{0, 0}), keRec(true, RecAEAD, []byte{0, 15})} {
		_, err := parseRecords(with(dup)...)
		wantKEErr(t, "duplicate", err, ErrKEDuplicateRecord, "repeated")
	}
	server := keRec(false, RecServer, []byte("a.example"))
	_, err := parseRecords(with(server, server)...)
	wantKEErr(t, "two servers", err, ErrKEDuplicateRecord, "record 6")
	port := keRec(false, RecPort, []byte{0, 123})
	_, err = parseRecords(with(port, port)...)
	wantKEErr(t, "two ports", err, ErrKEDuplicateRecord, "record 7")
}

func TestKEBadBodies(t *testing.T) {
	_, err := parseRecords(with(keRec(false, RecCookie, nil))...)
	wantKEErr(t, "empty cookie", err, ErrKEBadRecordBody, "cookie of 0 octets")
	for _, name := range []string{"", "fe80::1%eth0", "a b", "x\x00y", "time.example.com/"} {
		_, err := parseRecords(with(keRec(false, RecServer, []byte(name)))...)
		wantKEErr(t, "server name "+name, err, ErrKEBadRecordBody, "record 6")
	}
	_, err = parseRecords(with(keRec(false, RecServer, rep('a', 256)))...)
	wantKEErr(t, "256-octet server name", err, ErrKEBadRecordBody, "record 6")
	if _, err := parseRecords(with(keRec(false, RecServer, rep('a', 255)))...); err != nil {
		t.Fatal(err)
	}
	for _, good := range []string{"192.0.2.1", "2001:db8::1", "time.example.com", "xn--bcher-kva.example"} {
		if r, err := parseRecords(with(keRec(false, RecServer, []byte(good)))...); err != nil || r.Server != good {
			t.Fatalf("server name %q: %v", good, err)
		}
	}
	for _, port := range [][]byte{{0, 0}, {1}, {0, 1, 2}} {
		_, err := parseRecords(with(keRec(false, RecPort, port))...)
		wantKEErr(t, "bad port", err, ErrKEBadRecordBody, "record 7")
	}
}

func TestKECaps(t *testing.T) {
	// A cookie or any record body over 1024 octets.
	_, err := parseRecords(with(keRec(false, RecCookie, rep(1, 1025)))...)
	wantKEErr(t, "1025-octet cookie", err, ErrKERecordTooLong, "at most 1024")
	_, err = parseRecords(with(keRec(false, 0x2222, rep(1, 1025)))...)
	wantKEErr(t, "1025-octet unknown record", err, ErrKERecordTooLong, "record 8738")
	if _, err := parseRecords(with(keRec(false, RecCookie, rep(1, 1024)))...); err != nil {
		t.Fatal(err)
	}
	_, _, err = KEComplete(keRec(false, 0x2222, rep(1, 1025)))
	wantKEErr(t, "length of a long record", err, ErrKERecordTooLong, "")

	// More than 64 records: 4 in with, plus 61 unknown ones.
	filler := func(n int) [][]byte {
		var out [][]byte
		for i := 0; i < n; i++ {
			out = append(out, keRec(false, 0x2222, nil))
		}
		return out
	}
	if _, err := parseRecords(with(filler(60)...)...); err != nil {
		t.Fatal(err)
	}
	_, err = parseRecords(with(filler(61)...)...)
	wantKEErr(t, "65 records", err, ErrKETooManyRecords, "")
	_, _, err = KEComplete(bytes.Join(with(filler(61)...), nil))
	wantKEErr(t, "length of 65 records", err, ErrKETooManyRecords, "")

	// More than 65536 octets: 64 records of 1028 octets are 65792.
	_, err = ParseKEResponse(make([]byte, KEMaxResponseLen+1))
	wantKEErr(t, "65537 octets", err, ErrKETooLong, "")
	var long []byte
	for i := 0; i < 64; i++ {
		long = append(long, keRec(false, 0x2222, rep(1, 1024))...)
	}
	if l, done, err := KEComplete(long[:KEMaxResponseLen-1]); l != 0 || done || err != nil {
		t.Fatalf("one octet under the cap, incomplete: %d %v %v", l, done, err)
	}
	_, _, err = KEComplete(long)
	wantKEErr(t, "65792 octets", err, ErrKETooLong, "")
	_, _, err = KEComplete(long[:KEMaxResponseLen])
	wantKEErr(t, "the cap, incomplete", err, ErrKETooLong, "")

	// Twenty cookies: eight kept, twelve counted.
	var cookies [][]byte
	for i := 0; i < 20; i++ {
		cookies = append(cookies, rep(byte(i+1), 32))
	}
	r, err := parseRecords(append(goodKERecords(cookies), keEOM())...)
	if err != nil || len(r.Cookies) != 8 || r.Dropped != 12 || !bytes.Equal(r.Cookies[7], rep(8, 32)) {
		t.Fatalf("%+v %v", r, err)
	}
}

func TestKEExporterValues(t *testing.T) {
	if ExporterLabel != "EXPORTER-network-time-security" || ALPN != "ntske/1" || KEPort != 4460 || KeyLen != 32 {
		t.Fatalf("%q %q %d %d", ExporterLabel, ALPN, KEPort, KeyLen)
	}
	if !bytes.Equal(ExporterContext(false), []byte{0, 0, 0, 15, 0}) || !bytes.Equal(ExporterContext(true), []byte{0, 0, 0, 15, 1}) {
		t.Fatalf("%x %x", ExporterContext(false), ExporterContext(true))
	}
}

// A key of the wrong length is refused before it reaches AES (the Rust
// core's keys.rs: only 32 octets make a key).
func TestSIVKeyLength(t *testing.T) {
	for _, n := range []int{0, 16, 31, 33, 64} {
		if _, err := NewSIVKey(make([]byte, n)); err == nil {
			t.Fatalf("a %d-octet key was accepted", n)
		}
	}
	if _, err := NewSIVKey(make([]byte, 32)); err != nil {
		t.Fatal(err)
	}
}
