//go:build nts

package nts

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
		typ |= recCritical
	}
	r := binary.BigEndian.AppendUint16(nil, typ)
	r = binary.BigEndian.AppendUint16(r, uint16(len(body)))
	return append(r, body...)
}

func keEOM() []byte { return keRec(true, recEOM, nil) }

// goodKERecords is the records of a good response, without End of
// Message: next protocol NTPv4, AEAD 15, then the cookies.
func goodKERecords(cookies [][]byte) [][]byte {
	r := [][]byte{keRec(true, recNextProtocol, []byte{0, 0}), keRec(true, recAEAD, []byte{0, aeadSIVCMAC256})}
	for _, c := range cookies {
		r = append(r, keRec(false, recCookie, c))
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
		out = append(out, splitRecord{typ&recCritical != 0, typ &^ recCritical, buf[4 : 4+n]})
		buf = buf[4+n:]
	}
	return out
}

func parseRecords(records ...[]byte) (*keResponse, error) {
	return parseKEResponse(bytes.Join(records, nil))
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
	want := []splitRecord{{true, recNextProtocol, []byte{0, 0}}, {true, recAEAD, []byte{0, 15}}, {true, recEOM, []byte{}}}
	if len(got) != len(want) {
		t.Fatalf("%d records", len(got))
	}
	for i := range want {
		if got[i].critical != want[i].critical || got[i].typ != want[i].typ || !bytes.Equal(got[i].body, want[i].body) {
			t.Fatalf("record %d: %+v", i, got[i])
		}
	}
	if n, done, err := keResponseLength(req); err != nil || !done || n != len(req) {
		t.Fatalf("length %d %v %v", n, done, err)
	}
}

func TestKERoundTrip(t *testing.T) {
	records := goodKERecords(eightCookies())
	records = append(records, keRec(true, recServer, []byte("ntp1.example.net")), keRec(false, recPort, []byte{0x04, 0xd2}), keEOM())
	buf := bytes.Join(records, nil)
	r, err := parseKEResponse(buf)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.cookies) != 8 || r.dropped != 0 {
		t.Fatalf("%d cookies, %d dropped", len(r.cookies), r.dropped)
	}
	for i, c := range r.cookies {
		if !bytes.Equal(c, rep(byte(i+1), 100)) {
			t.Fatalf("cookie %d: %x", i, c)
		}
	}
	if r.server != "ntp1.example.net" || r.port != 1234 {
		t.Fatalf("server %q port %d", r.server, r.port)
	}
	if n, done, err := keResponseLength(buf); err != nil || !done || n != len(buf) {
		t.Fatalf("length %d %v %v", n, done, err)
	}
}

func TestKEDefaultsWithoutServerAndPort(t *testing.T) {
	r, err := parseKEResponse(goodKEResponse())
	if err != nil || r.port != 0 || r.server != "" {
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
	if err != nil || len(r.cookies) != 2 {
		t.Fatalf("%+v %v", r, err)
	}
}

func TestKEResponseLengthWaitsForEndOfMessage(t *testing.T) {
	buf := goodKEResponse()
	for n := 0; n < len(buf); n++ {
		if l, done, err := keResponseLength(buf[:n]); l != 0 || done || err != nil {
			t.Fatalf("prefix %d: %d %v %v", n, l, done, err)
		}
		if _, err := parseKEResponse(buf[:n]); !errors.Is(err, errKETruncated) {
			t.Fatalf("prefix %d: %v", n, err)
		}
	}
	more := append(append([]byte(nil), buf...), 1, 2, 3)
	if l, done, err := keResponseLength(more); l != len(buf) || !done || err != nil {
		t.Fatalf("with trailing octets: %d %v %v", l, done, err)
	}
	_, err := parseKEResponse(more)
	wantKEErr(t, "trailing octets", err, errKETrailingData, "after End of Message")
}

func TestKEErrorAndWarningRecords(t *testing.T) {
	for _, code := range []uint16{0, 1, 2, 0x1234} {
		body := binary.BigEndian.AppendUint16(nil, code)
		_, err := parseRecords(with(keRec(true, recError, body))...)
		wantKEErr(t, "error record", err, errKEServerError, "server error "+itoa(int(code)))
		_, err = parseRecords(with(keRec(true, recWarning, body))...)
		wantKEErr(t, "warning record", err, errKEServerWarning, "server warning "+itoa(int(code)))
	}
	// An Error record alone, as a server sends it.
	_, err := parseRecords(keRec(true, recError, []byte{0, 1}), keEOM())
	wantKEErr(t, "error alone", err, errKEServerError, "server error 1")
	_, err = parseRecords(with(keRec(true, recError, []byte{0}))...)
	wantKEErr(t, "error with a 1-octet body", err, errKEBadRecordBody, "record 2")
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
	wantKEErr(t, "unknown critical", err, errKEUnknownCritical, "4660")
	if _, err := parseRecords(with(keRec(false, 0x1234, []byte("x")), keRec(false, 0x7fff, nil))...); err != nil {
		t.Fatal(err)
	}
}

func TestKEMissingRecords(t *testing.T) {
	np := keRec(true, recNextProtocol, []byte{0, 0})
	aead := keRec(true, recAEAD, []byte{0, 15})
	cookie := keRec(false, recCookie, rep(1, 16))
	eom := keEOM()
	_, err := parseRecords(aead, cookie, eom)
	wantKEErr(t, "no protocol", err, errKEMissingRecord, "Next Protocol")
	_, err = parseRecords(np, cookie, eom)
	wantKEErr(t, "no AEAD", err, errKEMissingRecord, "AEAD")
	_, err = parseRecords(np, aead, eom)
	wantKEErr(t, "no cookie", err, errKEMissingRecord, "cookie")
	_, err = parseRecords(np, aead, cookie)
	wantKEErr(t, "no End of Message", err, errKETruncated, "before End of Message")
	_, err = parseKEResponse(nil)
	wantKEErr(t, "empty", err, errKETruncated, "")
}

func TestKEWrongProtocolOrAEAD(t *testing.T) {
	response := func(np, aead []byte) error {
		_, err := parseRecords(keRec(true, recNextProtocol, np), keRec(true, recAEAD, aead), keRec(false, recCookie, rep(1, 16)), keEOM())
		return err
	}
	if err := response([]byte{0, 0}, []byte{0, 15}); err != nil {
		t.Fatal(err)
	}
	wantKEErr(t, "protocol 1", response([]byte{0, 1}, []byte{0, 15}), errKEWrongProtocol, "protocol 1")
	wantKEErr(t, "protocol 0x8000", response([]byte{0, 0, 0x80, 0}, []byte{0, 15}), errKEWrongProtocol, "protocol 32768")
	wantKEErr(t, "no protocol", response(nil, []byte{0, 15}), errKENoCommonProtocol, "")
	wantKEErr(t, "odd protocol body", response([]byte{0}, []byte{0, 15}), errKEBadRecordBody, "record 1")
	wantKEErr(t, "AEAD 16", response([]byte{0, 0}, []byte{0, 16}), errKEWrongAEAD, "AEAD 16")
	wantKEErr(t, "AEAD 30", response([]byte{0, 0}, []byte{0, 30}), errKEWrongAEAD, "AEAD 30")
	wantKEErr(t, "no AEAD", response([]byte{0, 0}, nil), errKENoCommonAEAD, "")
	wantKEErr(t, "two AEADs", response([]byte{0, 0}, []byte{0, 15, 0, 15}), errKEBadRecordBody, "record 4")
	wantKEErr(t, "odd AEAD body", response([]byte{0, 0}, []byte{0, 15, 0}), errKEBadRecordBody, "record 4")
}

func TestKECriticalBits(t *testing.T) {
	// Next Protocol and End of Message MUST have it (sections 4.1.2, 4.1.1).
	r := goodKERecords([][]byte{rep(1, 16)})
	r[0] = keRec(false, recNextProtocol, []byte{0, 0})
	_, err := parseRecords(append(r, keEOM())...)
	wantKEErr(t, "Next Protocol without the bit", err, errKECriticalBitMissing, "Next Protocol")
	r = goodKERecords([][]byte{rep(1, 16)})
	_, err = parseRecords(append(r, keRec(false, recEOM, nil))...)
	wantKEErr(t, "End of Message without the bit", err, errKEBadEOM, "")
	r = goodKERecords([][]byte{rep(1, 16)})
	_, err = parseRecords(append(r, keRec(true, recEOM, []byte{0, 0}))...)
	wantKEErr(t, "End of Message with a body", err, errKEBadEOM, "")
	// AEAD, cookie, server and port may come with or without it.
	_, err = parseRecords(keRec(true, recNextProtocol, []byte{0, 0}), keRec(false, recAEAD, []byte{0, 15}),
		keRec(true, recCookie, rep(1, 16)), keRec(true, recServer, []byte("192.0.2.1")), keRec(true, recPort, []byte{0, 123}), keEOM())
	if err != nil {
		t.Fatal(err)
	}
}

func TestKEDuplicateRecords(t *testing.T) {
	for _, dup := range [][]byte{keRec(true, recNextProtocol, []byte{0, 0}), keRec(true, recAEAD, []byte{0, 15})} {
		_, err := parseRecords(with(dup)...)
		wantKEErr(t, "duplicate", err, errKEDuplicateRecord, "repeated")
	}
	server := keRec(false, recServer, []byte("a.example"))
	_, err := parseRecords(with(server, server)...)
	wantKEErr(t, "two servers", err, errKEDuplicateRecord, "record 6")
	port := keRec(false, recPort, []byte{0, 123})
	_, err = parseRecords(with(port, port)...)
	wantKEErr(t, "two ports", err, errKEDuplicateRecord, "record 7")
}

func TestKEBadBodies(t *testing.T) {
	_, err := parseRecords(with(keRec(false, recCookie, nil))...)
	wantKEErr(t, "empty cookie", err, errKEBadRecordBody, "cookie of 0 octets")
	for _, name := range []string{"", "fe80::1%eth0", "a b", "x\x00y", "time.example.com/"} {
		_, err := parseRecords(with(keRec(false, recServer, []byte(name)))...)
		wantKEErr(t, "server name "+name, err, errKEBadRecordBody, "record 6")
	}
	_, err = parseRecords(with(keRec(false, recServer, rep('a', 256)))...)
	wantKEErr(t, "256-octet server name", err, errKEBadRecordBody, "record 6")
	if _, err := parseRecords(with(keRec(false, recServer, rep('a', 255)))...); err != nil {
		t.Fatal(err)
	}
	for _, good := range []string{"192.0.2.1", "2001:db8::1", "time.example.com", "xn--bcher-kva.example"} {
		if r, err := parseRecords(with(keRec(false, recServer, []byte(good)))...); err != nil || r.server != good {
			t.Fatalf("server name %q: %v", good, err)
		}
	}
	for _, port := range [][]byte{{0, 0}, {1}, {0, 1, 2}} {
		_, err := parseRecords(with(keRec(false, recPort, port))...)
		wantKEErr(t, "bad port", err, errKEBadRecordBody, "record 7")
	}
}

func TestKECaps(t *testing.T) {
	// A cookie or any record body over 1024 octets.
	_, err := parseRecords(with(keRec(false, recCookie, rep(1, 1025)))...)
	wantKEErr(t, "1025-octet cookie", err, errKERecordTooLong, "at most 1024")
	_, err = parseRecords(with(keRec(false, 0x2222, rep(1, 1025)))...)
	wantKEErr(t, "1025-octet unknown record", err, errKERecordTooLong, "record 8738")
	if _, err := parseRecords(with(keRec(false, recCookie, rep(1, 1024)))...); err != nil {
		t.Fatal(err)
	}
	_, _, err = keResponseLength(keRec(false, 0x2222, rep(1, 1025)))
	wantKEErr(t, "length of a long record", err, errKERecordTooLong, "")

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
	wantKEErr(t, "65 records", err, errKETooManyRecords, "")
	_, _, err = keResponseLength(bytes.Join(with(filler(61)...), nil))
	wantKEErr(t, "length of 65 records", err, errKETooManyRecords, "")

	// More than 65536 octets: 64 records of 1028 octets are 65792.
	_, err = parseKEResponse(make([]byte, KEMaxResponseLen+1))
	wantKEErr(t, "65537 octets", err, errKETooLong, "")
	var long []byte
	for i := 0; i < 64; i++ {
		long = append(long, keRec(false, 0x2222, rep(1, 1024))...)
	}
	if l, done, err := keResponseLength(long[:KEMaxResponseLen-1]); l != 0 || done || err != nil {
		t.Fatalf("one octet under the cap, incomplete: %d %v %v", l, done, err)
	}
	_, _, err = keResponseLength(long)
	wantKEErr(t, "65792 octets", err, errKETooLong, "")
	_, _, err = keResponseLength(long[:KEMaxResponseLen])
	wantKEErr(t, "the cap, incomplete", err, errKETooLong, "")

	// Twenty cookies: eight kept, twelve counted.
	var cookies [][]byte
	for i := 0; i < 20; i++ {
		cookies = append(cookies, rep(byte(i+1), 32))
	}
	r, err := parseRecords(append(goodKERecords(cookies), keEOM())...)
	if err != nil || len(r.cookies) != 8 || r.dropped != 12 || !bytes.Equal(r.cookies[7], rep(8, 32)) {
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
		if _, err := newSIVKey(make([]byte, n)); err == nil {
			t.Fatalf("a %d-octet key was accepted", n)
		}
	}
	if _, err := newSIVKey(make([]byte, 32)); err != nil {
		t.Fatal(err)
	}
}
