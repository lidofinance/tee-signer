//go:build nts

package nts

import (
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
)

// The NTPv4 client request and the check of the server response, with the
// NTS extension fields (RFC 8915 section 5, RFC 7822, RFC 5905). This file
// is the port of the Rust core's ntp.rs and time.rs: no socket, no clock,
// no random numbers. Query (query.go) moves the bytes and supplies every
// random value: the transmit timestamp, the Unique Identifier and the AEAD
// nonce. buildRequest returns the packet and a pendingRequest that checks
// the response.
//
// A request carries, in this order: the 48-octet header, a Unique
// Identifier, one NTS Cookie, zero to seven Cookie Placeholders, and the
// NTS Authenticator over all of it with the C2S key. A response must echo
// the Unique Identifier and carry an authenticator with the S2C key, and
// its encrypted part holds the new cookies (RFC 8915 section 5.7).

// Lengths and limits of the exchange.
const (
	// ntpHeaderLen is the NTP header; extension fields start after it
	// (RFC 5905 section 7.3, RFC 7822 section 7.5).
	ntpHeaderLen = 48
	// ntpVersion is NTP version 4 (RFC 5905 section 7.3). NTS is defined
	// for NTPv4 only (RFC 8915 section 5).
	ntpVersion = 4
	// Association modes (RFC 5905 section 7.3, figure 10): 3 client, 4
	// server.
	modeClient = 3
	modeServer = 4
	// leapUnsynchronized is leap indicator 3: clock unsynchronized (RFC
	// 5905 section 7.3, figure 9).
	leapUnsynchronized = 3
	// maxStratum is the highest stratum of a synchronized server. 16 is
	// unsynchronized and 17 to 255 are reserved (RFC 5905 section 7.3,
	// figure 11). 0 marks a Kiss-o'-Death packet (section 7.4).
	maxStratum = 15

	// Extension field types of NTS (RFC 8915 sections 5.3 to 5.6,
	// registered in section 7.5).
	extUniqueID    = 0x0104
	extCookie      = 0x0204
	extPlaceholder = 0x0304
	extAuth        = 0x0404

	// uniqueIDLen is the Unique Identifier we send. RFC 8915 section 5.3:
	// at least 32 octets from a CSPRNG.
	uniqueIDLen = 32
	// nonceLen is the AEAD nonce we send. RFC 8915 section 5.6: a client
	// nonce of at least N_REQ octets (16 for AES-SIV-CMAC-256, whose N_MAX
	// has no limit, RFC 5297 section 6.1) needs no Additional Padding.
	nonceLen = 16
	// MaxPlaceholders is the most Cookie Placeholders in one request. RFC
	// 8915 section 5.7: the client SHOULD NOT include more than seven.
	MaxPlaceholders = 7
	// NTPMaxRequestLen is the longest request we build. RFC 8915 section
	// 5.7: senders SHOULD send fewer placeholders if needed to avoid
	// fragmentation, and 1280 octets is the IPv6 minimum MTU.
	NTPMaxRequestLen = 1280
	// NTPMaxResponseLen is the longest response we accept (our cap). The
	// server sends at most one cookie more than the placeholders we sent
	// (RFC 8915 section 5.7), so a response is about as long as the
	// request.
	NTPMaxResponseLen = 2048
	// RequestRandomLen is the random input of one request: the transmit
	// timestamp, the Unique Identifier and the nonce.
	RequestRandomLen = 8 + uniqueIDLen + nonceLen

	// fieldHeaderLen is the type and length of an extension field, two
	// octets each (RFC 7822 section 7.5).
	fieldHeaderLen = 4
	// minFieldLen is the shortest extension field outside the encrypted
	// part: 16 octets when no MAC follows (RFC 7822 section 7.5.1.4). RFC
	// 8915 section 5.6 lets encrypted fields be shorter.
	minFieldLen = 16
	// authLengthsLen is Nonce Length and Ciphertext Length of the
	// authenticator, two octets each (RFC 8915 section 5.6).
	authLengthsLen = 4
	// sivTagLen is the synthetic IV that leads AES-SIV output (RFC 5297
	// section 2.6); it is also the authentication tag.
	sivTagLen = 16
	// requestAuthFieldLen is the authenticator we send: field header, the
	// two lengths, our nonce, and a ciphertext that is only the tag (we
	// encrypt no fields).
	requestAuthFieldLen = fieldHeaderLen + authLengthsLen + nonceLen + sivTagLen
)

// Why a request could not be built or a response was refused. Query wraps
// a refusal of a response in an *Error with CodeNTP; the real response may
// still come after it.
var (
	errTooManyPlaceholders  = fmt.Errorf("more than %d cookie placeholders", MaxPlaceholders)
	errRequestTooLong       = fmt.Errorf("NTS request longer than %d octets", NTPMaxRequestLen)
	errAlreadyAnswered      = errors.New("request already answered (replay)")
	errTooShort             = errors.New("NTP packet shorter than its header")
	errTooLong              = fmt.Errorf("NTP packet longer than %d octets", NTPMaxResponseLen)
	errBadVersion           = errors.New("NTP version is not 4")
	errBadMode              = errors.New("NTP mode is not 4 (server)")
	errOriginMismatch       = errors.New("origin timestamp is not our transmit timestamp")
	errBadExtensionField    = errors.New("malformed NTP extension field")
	errDuplicateUniqueID    = errors.New("two Unique Identifier fields")
	errMissingUniqueID      = errors.New("no authenticated Unique Identifier")
	errUniqueIDMismatch     = errors.New("Unique Identifier is not ours")
	errMissingAuthenticator = errors.New("no NTS authenticator")
	errBadAuthenticator     = errors.New("malformed NTS authenticator")
	errNotAuthentic         = errors.New("authenticator does not verify")
	errBadEncryptedField    = errors.New("malformed encrypted extension field")
	errBadCookie            = errors.New("cookie empty or too long")
	errTooManyCookies       = errors.New("more cookies than placeholders plus one")
	errNoCookies            = errors.New("no new cookie")
	errUnsynchronized       = errors.New("server clock unsynchronized (leap indicator 3)")
	errBadStratum           = errors.New("stratum above 15")
)

// ---- NTP time formats (RFC 5905 section 6) ----
//
// An NTP timestamp on the wire holds 32 bits of seconds and 32 bits of
// fraction. The seconds wrap every 2^32 seconds (about 136 years), so the
// wire value does not say which era it is in; era 0 ends on 2036-02-07
// 06:28:16 UTC. RFC 5905 section 6: the era is found from a nearby time the
// receiver already knows, and the difference of two timestamps is right as
// long as they are less than about 68 years apart. unixNanos takes such a
// nearby time (the pivot) for that reason. The arithmetic runs in big.Int
// where int64 would overflow.

// unixEpochNTPSeconds is from the NTP prime epoch (1900-01-01 00:00 UTC,
// era 0) to the Unix epoch 1970-01-01 (RFC 5905 section 6, figure 4).
const unixEpochNTPSeconds = 2_208_988_800

var (
	bigNanos      = big.NewInt(1_000_000_000)
	bigUnits      = new(big.Int).Lsh(big.NewInt(1), 32) // fraction units per second: 2^-32 s
	bigTwo64      = new(big.Int).Lsh(big.NewInt(1), 64)
	bigEpochNanos = new(big.Int).Mul(big.NewInt(unixEpochNTPSeconds), bigNanos)
)

// ntpTimestamp is seconds since the start of its era in the high 32 bits,
// the fraction of a second (2^-32 s units) in the low 32.
type ntpTimestamp uint64

// ntpFromUnixNanos is the timestamp of nanoseconds since the Unix epoch.
// The era is dropped, as on the wire. The fraction is rounded up, so
// unixNanos with any pivot within about 68 years gives back the same
// nanoseconds (one unit, 2^-32 s, is shorter than a nanosecond).
func ntpFromUnixNanos(unixNanos int64) ntpTimestamp {
	x := new(big.Int).Add(big.NewInt(unixNanos), bigEpochNanos)
	x.Lsh(x, 32)
	units := ceilDivBig(x, bigNanos)
	// The low 64 bits are the wire value: seconds modulo 2^32 and the
	// fraction. Mod is Euclidean, so a time before 1900 wraps as on the wire.
	return ntpTimestamp(units.Mod(units, bigTwo64).Uint64())
}

// unixNanos is nanoseconds since the Unix epoch, rounded down. The era is
// the one that puts the result within 2^31 seconds (about 68 years) of
// pivot, a time the caller already trusts to that degree (RFC 5905 section
// 6). false if the result does not fit in an int64.
func (t ntpTimestamp) unixNanos(pivot int64) (int64, bool) {
	p := new(big.Int).Add(big.NewInt(pivot), bigEpochNanos)
	p.Lsh(p, 32)
	pivotUnits := p.Div(p, bigNanos) // Div is Euclidean: floor for a positive divisor
	// The wrapping difference to the pivot's wire value is the signed
	// distance to the nearest timestamp with these low 64 bits.
	low := new(big.Int).Mod(pivotUnits, bigTwo64).Uint64()
	delta := int64(uint64(t) - low)
	units := new(big.Int).Add(pivotUnits, big.NewInt(delta))
	n := units.Mul(units, bigNanos)
	n.Div(n, bigUnits)
	n.Sub(n, bigEpochNanos)
	if !n.IsInt64() {
		return 0, false
	}
	return n.Int64(), true
}

// sub is t - earlier in 2^-32 s units, modulo 2^64 and read as signed. It
// is right across an era boundary when the two are less than 2^31 seconds
// apart (RFC 5905 section 6).
func (t ntpTimestamp) sub(earlier ntpTimestamp) ntpDuration {
	return ntpDuration(int64(uint64(t) - uint64(earlier)))
}

// ntpDuration is a signed difference of two NTP timestamps, in 2^-32 s
// units.
type ntpDuration int64

// nanos is the duration in nanoseconds, rounded toward minus infinity. It
// always fits: 2^63 units are about 2.1 * 10^18 ns.
func (d ntpDuration) nanos() int64 {
	n := big.NewInt(int64(d))
	n.Mul(n, bigNanos)
	n.Div(n, bigUnits)
	return n.Int64()
}

// ntpShort is the NTP short format (RFC 5905 section 6): 16 bits of
// seconds, 16 bits of fraction. Root delay and root dispersion use it.
type ntpShort uint32

// nanos is the value in nanoseconds, rounded down. At most 65536 s.
func (s ntpShort) nanos() int64 { return int64(uint64(s) * 1_000_000_000 >> 16) }

// ceilDivBig is n / d rounded toward plus infinity, for d > 0.
func ceilDivBig(n, d *big.Int) *big.Int {
	q, m := new(big.Int).DivMod(n, d, new(big.Int))
	if m.Sign() > 0 {
		q.Add(q, big.NewInt(1))
	}
	return q
}

// ---- The request ----

// requestInput is what buildRequest takes.
type requestInput struct {
	// transmit is the transmit timestamp of the request: a random value,
	// not the local clock. The server copies it into the origin timestamp
	// of its response, and the check of that copy refuses responses to
	// other requests (RFC 5905 section 8). The caller keeps its own clock
	// reading of the send time.
	transmit ntpTimestamp
	// uniqueID is new for each request (RFC 8915 section 5.3).
	uniqueID [uniqueIDLen]byte
	// nonce is the AEAD nonce of the authenticator (RFC 8915 section 5.6).
	nonce [nonceLen]byte
	// cookie is sent once (RFC 8915 sections 5.4, 5.7).
	cookie []byte
	// placeholders asks for that many more cookies (RFC 8915 section
	// 5.5): at most MaxPlaceholders, and at most maxPlaceholders for this
	// cookie.
	placeholders int
}

// pad4 is n rounded up to a multiple of 4. NTP extension fields and the
// parts of the NTS authenticator are padded to 4-octet words (RFC 7822
// section 7.5, RFC 8915 section 5.6).
func pad4(n int) int { return (n + 3) &^ 3 }

// fieldLen is the length of an extension field with a body of n octets:
// the header, the body padded to 4 octets and to the 16-octet minimum of
// RFC 7822 section 7.5.1.4.
func fieldLen(n int) int { return fieldHeaderLen + max(pad4(n), minFieldLen-fieldHeaderLen) }

// requestLen is the length of a request with a cookie of cookieLen octets
// and placeholders placeholders.
func requestLen(cookieLen, placeholders int) int {
	return ntpHeaderLen + fieldLen(uniqueIDLen) + requestAuthFieldLen + fieldLen(cookieLen)*(placeholders+1)
}

// maxPlaceholders is the most placeholders a request with a cookie of
// cookieLen octets can carry: at most MaxPlaceholders, and few enough that
// the request fits in NTPMaxRequestLen octets (RFC 8915 section 5.7).
func maxPlaceholders(cookieLen int) int {
	for p := MaxPlaceholders; p > 0; p-- {
		if requestLen(cookieLen, p) <= NTPMaxRequestLen {
			return p
		}
	}
	return 0
}

// appendField appends one extension field: type, length of the whole
// field, the body, zero padding to a multiple of 4 and to the 16-octet
// minimum (RFC 7822 section 7.5).
func appendField(b []byte, typ uint16, body []byte) []byte {
	n := fieldLen(len(body))
	b = binary.BigEndian.AppendUint16(b, typ)
	b = binary.BigEndian.AppendUint16(b, uint16(n))
	b = append(b, body...)
	return append(b, make([]byte, n-fieldHeaderLen-len(body))...)
}

// buildRequest builds a client request (RFC 8915 section 5.7) and the
// state that checks its response.
//
// The header has leap indicator 0, version 4, mode 3 and the caller's
// transmit timestamp; all other header fields are zero. Then the Unique
// Identifier, the cookie and the placeholders, all authenticated and not
// encrypted (section 5.7), and last the authenticator: AES-SIV over the
// header and those fields with the C2S key and the caller's nonce, with no
// encrypted fields (section 5.6).
func buildRequest(c2s *sivKey, in *requestInput) ([]byte, *pendingRequest, error) {
	if in.placeholders < 0 || in.placeholders > MaxPlaceholders {
		return nil, nil, errTooManyPlaceholders
	}
	if len(in.cookie) < 1 || len(in.cookie) > maxCookieLen {
		return nil, nil, errBadCookie
	}
	n := requestLen(len(in.cookie), in.placeholders)
	if n > NTPMaxRequestLen {
		return nil, nil, errRequestTooLong
	}
	out := make([]byte, 0, n)
	// RFC 5905 section 7.3: LI (2 bits), VN (3 bits), mode (3 bits), then
	// stratum, poll, precision, root delay, root dispersion, reference ID,
	// and the reference, origin and receive timestamps, all zero here
	// (octets 1 to 39). The transmit timestamp is octets 40 to 47.
	out = append(out, ntpVersion<<3|modeClient)
	out = append(out, make([]byte, ntpHeaderLen-1-8)...)
	out = binary.BigEndian.AppendUint64(out, uint64(in.transmit))
	out = appendField(out, extUniqueID, in.uniqueID[:])
	out = appendField(out, extCookie, in.cookie)
	// Section 5.5: a placeholder body has the cookie's length and SHOULD be
	// all zeros.
	placeholder := make([]byte, len(in.cookie))
	for i := 0; i < in.placeholders; i++ {
		out = appendField(out, extPlaceholder, placeholder)
	}
	// Section 5.6: A is the packet so far, N our nonce, P empty. The output
	// is the 16-octet tag. Nonce and tag are multiples of 4, so there is no
	// padding, and the nonce is N_REQ long, so no Additional Padding.
	ct := c2s.Seal([][]byte{out, in.nonce[:]}, nil)
	body := make([]byte, 0, requestAuthFieldLen-fieldHeaderLen)
	body = binary.BigEndian.AppendUint16(body, nonceLen)
	body = binary.BigEndian.AppendUint16(body, uint16(len(ct)))
	body = append(body, in.nonce[:]...)
	body = append(body, ct...)
	out = appendField(out, extAuth, body)
	if len(out) != n {
		return nil, nil, errRequestTooLong
	}
	return out, &pendingRequest{transmit: in.transmit, uniqueID: in.uniqueID, placeholders: in.placeholders}, nil
}

// pendingRequest is a request that was built and may be waiting for its
// response. verify checks responses and accepts at most one.
type pendingRequest struct {
	transmit     ntpTimestamp
	uniqueID     [uniqueIDLen]byte
	placeholders int
	answered     bool
}

// verdict is what a valid response gives: a Kiss-o'-Death code (RFC 5905
// section 7.4, no time), or a time response.
type verdict struct {
	// kiss is the reference ID of a Kiss-o'-Death as 4 octets, "" for a
	// time response. The KoD matched our Unique Identifier and origin
	// timestamp. kissAuthentic says whether it also carried an
	// authenticator that verifies with the S2C key: RFC 8915 section 5.7
	// has servers send NTSN without one, and lets the client act on a KoD
	// whose Unique Identifier matches, but a server that holds the
	// cookie's keys can authenticate a RATE, DENY or RSTR, and only those
	// are worth a backoff; the rest anyone on the path can forge.
	kiss          string
	kissAuthentic bool
	time          *timeResponse
}

// timeResponse is the fields of an authentic server response, as on the
// wire (RFC 5905 section 7.3). The error bound is computed by measure.
type timeResponse struct {
	leap           uint8 // never leapUnsynchronized (that is refused)
	stratum        uint8 // 1 to 15
	precision      int8  // log2 seconds
	rootDelay      ntpShort
	rootDispersion ntpShort
	reference      ntpTimestamp // when the server clock was last set
	origin         ntpTimestamp // our transmit timestamp
	receive        ntpTimestamp // T2
	transmit       ntpTimestamp // T3
	cookies        [][]byte     // new cookies from the encrypted part, 1 to 1 + placeholders
}

// ntpHeader is the NTP header (RFC 5905 section 7.3).
type ntpHeader struct {
	leap, version, mode, stratum uint8
	precision                    int8
	rootDelay, rootDispersion    ntpShort
	referenceID                  [4]byte
	reference, origin            ntpTimestamp
	receive, transmit            ntpTimestamp
}

// parseHeader reads the header; b holds at least ntpHeaderLen octets.
func parseHeader(b []byte) ntpHeader {
	h := ntpHeader{
		leap:           b[0] >> 6,
		version:        (b[0] >> 3) & 0x07,
		mode:           b[0] & 0x07,
		stratum:        b[1],
		precision:      int8(b[3]),
		rootDelay:      ntpShort(binary.BigEndian.Uint32(b[4:])),
		rootDispersion: ntpShort(binary.BigEndian.Uint32(b[8:])),
		reference:      ntpTimestamp(binary.BigEndian.Uint64(b[16:])),
		origin:         ntpTimestamp(binary.BigEndian.Uint64(b[24:])),
		receive:        ntpTimestamp(binary.BigEndian.Uint64(b[32:])),
		transmit:       ntpTimestamp(binary.BigEndian.Uint64(b[40:])),
	}
	copy(h.referenceID[:], b[12:16])
	return h
}

// kissCode is the reference ID of a Kiss-o'-Death as text: the 4 octets,
// each outside printable ASCII shown as '?', so a code goes into logs and
// labels as it is without carrying control characters there.
func kissCode(id [4]byte) string {
	var out [4]byte
	for i, c := range id {
		if c < 0x20 || c > 0x7e {
			c = '?'
		}
		out[i] = c
	}
	return string(out[:])
}

// authenticator is the NTS authenticator of a response, located in the
// packet. start is where the field starts, counted from the start of the
// packet: the associated data is everything before it (RFC 8915 section
// 5.6).
type authenticator struct {
	start     int
	nonce, ct []byte
}

func allZero(b []byte) bool {
	var acc byte
	for _, x := range b {
		acc |= x
	}
	return acc == 0
}

// parseAuthenticator reads the body of an authenticator field (RFC 8915
// section 5.6): Nonce Length, Ciphertext Length, the nonce and the
// ciphertext each zero-padded to 4 octets, then Additional Padding.
func parseAuthenticator(body []byte, start int) (*authenticator, error) {
	if len(body) < authLengthsLen {
		return nil, errBadAuthenticator
	}
	nl, cl := int(binary.BigEndian.Uint16(body)), int(binary.BigEndian.Uint16(body[2:]))
	// RFC 5297 section 6.1: N_MIN is 1 octet. The ciphertext holds at
	// least the 16-octet tag.
	if nl == 0 || cl < sivTagLen {
		return nil, errBadAuthenticator
	}
	nonceEnd, ctStart := authLengthsLen+nl, authLengthsLen+pad4(nl)
	ctEnd, rest := ctStart+cl, ctStart+pad4(cl)
	if rest > len(body) {
		return nil, errBadAuthenticator
	}
	// The padding is zero (section 5.6) and outside the AEAD input, so a
	// change to it would not fail the tag check. It is checked here instead.
	// Mode 4 packets need no Additional Padding; if there is some, it must
	// be zero too.
	if !allZero(body[nonceEnd:ctStart]) || !allZero(body[ctEnd:rest]) || !allZero(body[rest:]) {
		return nil, errBadAuthenticator
	}
	return &authenticator{start: start, nonce: body[authLengthsLen:nonceEnd], ct: body[ctStart:ctEnd]}, nil
}

// parseFields walks the extension fields after the header (RFC 7822
// section 7.5) and returns the Unique Identifier (nil if none) and the
// authenticator (nil if none). It stops at the first authenticator: RFC
// 8915 section 5.7 says the client MUST discard unauthenticated extension
// fields, which are the ones after it, so they are not read at all. Unknown
// fields before it, and NTS fields a server should not send in the clear
// (cookies, placeholders), are skipped (RFC 7822 section 7.5: SHOULD ignore
// an unknown type).
func parseFields(packet []byte) (uid []byte, auth *authenticator, err error) {
	for at := ntpHeaderLen; at < len(packet); {
		if at+fieldHeaderLen > len(packet) {
			return nil, nil, errBadExtensionField
		}
		typ := binary.BigEndian.Uint16(packet[at:])
		n := int(binary.BigEndian.Uint16(packet[at+2:]))
		// RFC 7822 section 7.5: the length counts the whole field, which is
		// zero-padded to a multiple of 4; section 7.5.1.4: at least 16.
		if n%4 != 0 || n < minFieldLen || at+n > len(packet) {
			return nil, nil, errBadExtensionField
		}
		body := packet[at+fieldHeaderLen : at+n]
		switch typ {
		case extUniqueID:
			if uid != nil {
				return nil, nil, errDuplicateUniqueID
			}
			uid = body
		case extAuth:
			auth, err = parseAuthenticator(body, at)
			return uid, auth, err
		}
		at += n
	}
	return uid, nil, nil
}

// encryptedCookies is the cookies in the decrypted part. RFC 8915 section
// 5.6: it holds extension fields in RFC 7822 form that may be shorter than
// 16 octets but are a multiple of 4. Fields other than NTS Cookie are
// skipped. Section 5.7: no more than one plus the placeholders we sent.
func encryptedCookies(plain []byte, maxCookies int) ([][]byte, error) {
	var cookies [][]byte
	for at := 0; at < len(plain); {
		if at+fieldHeaderLen > len(plain) {
			return nil, errBadEncryptedField
		}
		typ := binary.BigEndian.Uint16(plain[at:])
		n := int(binary.BigEndian.Uint16(plain[at+2:]))
		if n%4 != 0 || n < fieldHeaderLen || at+n > len(plain) {
			return nil, errBadEncryptedField
		}
		if typ == extCookie {
			if len(cookies) >= maxCookies {
				return nil, errTooManyCookies
			}
			c := plain[at+fieldHeaderLen : at+n]
			if len(c) < 1 || len(c) > maxCookieLen {
				return nil, errBadCookie
			}
			cookies = append(cookies, append([]byte(nil), c...))
		}
		at += n
	}
	return cookies, nil
}

// verify checks a response to this request with the S2C key.
//
// In order: length, version 4 and mode 4, origin timestamp equal to our
// transmit timestamp, the extension fields, and our Unique Identifier
// before the authenticator (constant-time compares). Stratum 0 then gives
// a Kiss-o'-Death and no time. Otherwise the authenticator must verify
// with the S2C key over the header and the fields before it; then the
// decrypted fields give the new cookies, and leap indicator 3 and stratum
// above 15 are refused.
//
// A refused response changes nothing, so the real response can still
// come. After one is accepted every further one is refused as a replay.
func (r *pendingRequest) verify(s2c *sivKey, packet []byte) (verdict, error) {
	if r.answered {
		return verdict{}, errAlreadyAnswered
	}
	if len(packet) > NTPMaxResponseLen {
		return verdict{}, errTooLong
	}
	if len(packet) < ntpHeaderLen {
		return verdict{}, errTooShort
	}
	h := parseHeader(packet)
	if h.version != ntpVersion {
		return verdict{}, fmt.Errorf("%w: version %d", errBadVersion, h.version)
	}
	if h.mode != modeServer {
		return verdict{}, fmt.Errorf("%w: mode %d", errBadMode, h.mode)
	}
	// RFC 5905 section 8: a response whose origin timestamp is not the
	// transmit timestamp we sent is bogus. Ours is random, so this is also
	// a 64-bit check against forged responses.
	var want [8]byte
	binary.BigEndian.PutUint64(want[:], uint64(r.transmit))
	if subtle.ConstantTimeCompare(packet[24:32], want[:]) != 1 {
		return verdict{}, errOriginMismatch
	}
	uid, auth, err := parseFields(packet)
	if err != nil {
		return verdict{}, err
	}
	// RFC 8915 section 5.7: the Unique Identifier must match ours, in a
	// normal response and in a KoD. Exactly ours: not a prefix, not padded.
	if uid == nil {
		return verdict{}, errMissingUniqueID
	}
	if len(uid) != uniqueIDLen || subtle.ConstantTimeCompare(uid, r.uniqueID[:]) != 1 {
		return verdict{}, errUniqueIDMismatch
	}
	if h.stratum == 0 {
		// A Kiss-o'-Death (RFC 5905 section 7.4): no time in it. RFC 8915
		// section 5.7 requires the matching Unique Identifier only after
		// the server has sent authentic responses; we always require it.
		// It does not answer the request: the identifier and the origin
		// travel in the clear, so anyone on the path can forge one, and
		// the real answer, should it follow, is still taken. An
		// authenticator, if there is one, is checked, and the verdict says
		// whether it verified.
		v := verdict{kiss: kissCode(h.referenceID)}
		if auth != nil {
			_, v.kissAuthentic = s2c.Open([][]byte{packet[:auth.start], auth.nonce}, auth.ct)
		}
		return v, nil
	}
	if auth == nil {
		return verdict{}, errMissingAuthenticator
	}
	plain, ok := s2c.Open([][]byte{packet[:auth.start], auth.nonce}, auth.ct)
	if !ok {
		return verdict{}, errNotAuthentic
	}
	cookies, err := encryptedCookies(plain, r.placeholders+1)
	if err != nil {
		return verdict{}, err
	}
	if h.leap == leapUnsynchronized {
		return verdict{}, errUnsynchronized
	}
	if h.stratum > maxStratum {
		return verdict{}, fmt.Errorf("%w: stratum %d", errBadStratum, h.stratum)
	}
	if len(cookies) == 0 {
		return verdict{}, errNoCookies
	}
	r.answered = true
	return verdict{time: &timeResponse{
		leap: h.leap, stratum: h.stratum, precision: h.precision,
		rootDelay: h.rootDelay, rootDispersion: h.rootDispersion,
		reference: h.reference, origin: h.origin, receive: h.receive, transmit: h.transmit,
		cookies: cookies,
	}}, nil
}
