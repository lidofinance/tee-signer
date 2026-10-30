/* NTS Key Establishment records (RFC 8915 section 4): the one request this
 * client sends, the framing of a response as it arrives, and the check of
 * a whole response, record by record. The TLS session the records travel
 * in is the host's (nts_host_ops.key_exchange); what comes back through it
 * is checked here before any of it is used. Untrusted bytes are read with
 * length checks and every list has a cap. */
#include <string.h>

#include "nts_core.h"

enum {
	REC_EOM = 0,
	REC_NEXT_PROTOCOL = 1,
	REC_ERROR = 2,
	REC_WARNING = 3,
	REC_AEAD = 4,
	REC_COOKIE = 5,
	REC_SERVER = 6,
	REC_PORT = 7,
	REC_CRITICAL = 0x8000,
	AEAD_SIV_CMAC_256 = 15,
};

static uint16_t be16(const uint8_t *p) { return (uint16_t)((uint16_t)p[0] << 8 | p[1]); }

void nts_ke_request(uint8_t out[NTS_KE_REQUEST_LEN])
{
	static const uint8_t req[NTS_KE_REQUEST_LEN] = {
		0x80, REC_NEXT_PROTOCOL, 0, 2, 0, 0,
		0x80, REC_AEAD, 0, 2, 0, AEAD_SIV_CMAC_256,
		0x80, REC_EOM, 0, 0,
	};
	memcpy(out, req, sizeof req);
}

void nts_ke_exporter_context(bool s2c, uint8_t out[5])
{
	out[0] = 0;
	out[1] = 0;
	out[2] = 0;
	out[3] = AEAD_SIV_CMAC_256;
	out[4] = s2c ? 1 : 0;
}

struct rec {
	bool critical;
	uint16_t typ;
	const uint8_t *body;
	size_t n;
};

/* Reads the record at buf[at:]. *ok is false if the buffer ends inside
 * it; a body over the cap is an error. */
static int read_record(const uint8_t *buf, size_t len, size_t at, struct rec *r, size_t *next, bool *ok, int *detail)
{
	*ok = false;
	if (at + 4 > len)
		return NTS_OK;
	uint16_t t = be16(buf + at);
	r->critical = (t & REC_CRITICAL) != 0;
	r->typ = t & ~REC_CRITICAL;
	size_t n = be16(buf + at + 2);
	if (n > NTS_KE_MAX_BODY) {
		*detail = r->typ;
		return NTS_ERR_KE_RECORD_TOO_LONG;
	}
	if (at + 4 + n > len)
		return NTS_OK;
	r->body = buf + at + 4;
	r->n = n;
	*next = at + 4 + n;
	*ok = true;
	return NTS_OK;
}

int nts_ke_complete(const uint8_t *buf, size_t n, size_t *len, bool *done)
{
	size_t at = 0;
	int count = 0, detail = 0;
	*len = 0;
	*done = false;
	for (;;) {
		struct rec r;
		size_t next = 0;
		bool ok;
		int rc = read_record(buf, n, at, &r, &next, &ok, &detail);
		if (rc)
			return rc;
		if (!ok)
			return n >= NTS_KE_MAX_RESPONSE_LEN ? NTS_ERR_KE_TOO_LONG : NTS_OK;
		if (++count > NTS_KE_MAX_RECORDS)
			return NTS_ERR_KE_TOO_MANY_RECORDS;
		if (next > NTS_KE_MAX_RESPONSE_LEN)
			return NTS_ERR_KE_TOO_LONG;
		at = next;
		if (r.typ == REC_EOM) {
			*len = at;
			*done = true;
			return NTS_OK;
		}
	}
}

/* The rule of RFC 8915 section 4.1.7 as the Rust core read it: 1 to
 * NTS_MAX_SERVER_NAME octets of letters, digits, '.', '-' and ':'. That
 * covers dotted IPv4, IPv6 text without a zone ID, and A-labels of a
 * domain name. */
static bool server_name_ok(const uint8_t *b, size_t n)
{
	if (n < 1 || n > NTS_MAX_SERVER_NAME)
		return false;
	for (size_t i = 0; i < n; i++) {
		uint8_t c = b[i];
		bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '-' || c == ':';
		if (!ok)
			return false;
	}
	return true;
}

/* A bad body: the record type in the low 16 bits of the detail, the body
 * length above them. */
static int bad_body(const struct rec *r, int *detail)
{
	*detail = (int)r->typ | (int)(r->n << 16);
	return NTS_ERR_KE_BAD_RECORD_BODY;
}

/* Refused: an Error or Warning record, an unknown record with the
 * critical bit, a missing Next Protocol, AEAD or New Cookie record, a
 * protocol other than NTPv4, an AEAD other than AEAD_AES_SIV_CMAC_256, a
 * duplicate of a record that may occur once, a bad body, and anything
 * over the caps. Unknown records without the critical bit are skipped
 * (section 4). */
int nts_ke_parse(const uint8_t *buf, size_t n, nts_ke_response *r)
{
	bool protocol = false, aead = false, server = false, port = false;
	size_t at = 0;
	int count = 0;
	r->ncookies = 0;
	r->dropped = 0;
	r->server_len = 0;
	r->port = 0;
	r->detail = 0;
	if (n > NTS_KE_MAX_RESPONSE_LEN)
		return NTS_ERR_KE_TOO_LONG;
	for (;;) {
		struct rec rec;
		size_t next = 0;
		bool ok;
		int rc = read_record(buf, n, at, &rec, &next, &ok, &r->detail);
		if (rc)
			return rc;
		if (!ok)
			return NTS_ERR_KE_TRUNCATED;
		at = next;
		if (++count > NTS_KE_MAX_RECORDS)
			return NTS_ERR_KE_TOO_MANY_RECORDS;
		switch (rec.typ) {
		case REC_EOM:
			/* Section 4.1.1: critical bit set, empty body, final record. */
			if (!rec.critical || rec.n != 0)
				return NTS_ERR_KE_BAD_EOM;
			if (at != n) {
				r->detail = (int)(n - at);
				return NTS_ERR_KE_TRAILING_DATA;
			}
			if (!protocol) {
				r->detail = REC_NEXT_PROTOCOL;
				return NTS_ERR_KE_MISSING_RECORD;
			}
			if (!aead) {
				r->detail = REC_AEAD;
				return NTS_ERR_KE_MISSING_RECORD;
			}
			/* Section 4.1.6: servers MUST send at least one cookie. */
			if (r->ncookies == 0) {
				r->detail = REC_COOKIE;
				return NTS_ERR_KE_MISSING_RECORD;
			}
			return NTS_OK;
		case REC_NEXT_PROTOCOL:
			/* Section 4.1.2: exactly once, critical bit set, a list of
			 * 16-bit IDs that is a subset of what we offered (NTPv4). */
			if (!rec.critical) {
				r->detail = rec.typ;
				return NTS_ERR_KE_CRITICAL_BIT_MISSING;
			}
			if (protocol) {
				r->detail = rec.typ;
				return NTS_ERR_KE_DUPLICATE_RECORD;
			}
			protocol = true;
			if (rec.n % 2 != 0)
				return bad_body(&rec, &r->detail);
			if (rec.n == 0)
				return NTS_ERR_KE_NO_COMMON_PROTOCOL;
			for (size_t i = 0; i < rec.n; i += 2)
				if (be16(rec.body + i) != 0) {
					r->detail = be16(rec.body + i);
					return NTS_ERR_KE_WRONG_PROTOCOL;
				}
			break;
		case REC_ERROR:
			/* Section 4.1.3: a 2-octet code. The client discards the keys
			 * and does not go on. */
			if (rec.n != 2)
				return bad_body(&rec, &r->detail);
			r->detail = be16(rec.body);
			return NTS_ERR_KE_SERVER_ERROR;
		case REC_WARNING:
			/* Section 4.1.4: no codes are defined and unknown codes MUST be
			 * treated as errors, so every warning is one. */
			if (rec.n != 2)
				return bad_body(&rec, &r->detail);
			r->detail = be16(rec.body);
			return NTS_ERR_KE_SERVER_WARNING;
		case REC_AEAD:
			/* Section 4.1.5: exactly once when NTPv4 is negotiated, the
			 * critical bit MAY be set, at most one ID in a response, chosen
			 * from what we offered. */
			if (aead) {
				r->detail = rec.typ;
				return NTS_ERR_KE_DUPLICATE_RECORD;
			}
			aead = true;
			if (rec.n % 2 != 0 || rec.n > 2)
				return bad_body(&rec, &r->detail);
			if (rec.n == 0)
				return NTS_ERR_KE_NO_COMMON_AEAD;
			if (be16(rec.body) != AEAD_SIV_CMAC_256) {
				r->detail = be16(rec.body);
				return NTS_ERR_KE_WRONG_AEAD;
			}
			break;
		case REC_COOKIE:
			/* Section 4.1.6: opaque to the client; at least one. */
			if (rec.n < 1 || rec.n > NTS_MAX_COOKIE_LEN)
				return bad_body(&rec, &r->detail);
			if (r->ncookies < NTS_MAX_COOKIES) {
				memcpy(r->cookies[r->ncookies], rec.body, rec.n);
				r->cookie_len[r->ncookies] = rec.n;
				r->ncookies++;
			} else {
				r->dropped++;
			}
			break;
		case REC_SERVER:
			/* Section 4.1.7: at most one; an ASCII IPv4 or IPv6 address (no
			 * zone ID) or a domain name. */
			if (server) {
				r->detail = rec.typ;
				return NTS_ERR_KE_DUPLICATE_RECORD;
			}
			if (!server_name_ok(rec.body, rec.n))
				return bad_body(&rec, &r->detail);
			memcpy(r->server, rec.body, rec.n);
			r->server_len = rec.n;
			server = true;
			break;
		case REC_PORT:
			/* Section 4.1.8: a 16-bit port. The RFC sets no count; two
			 * ports are ambiguous, so a second one is refused. Port 0 is
			 * not a port a server listens on. */
			if (port) {
				r->detail = rec.typ;
				return NTS_ERR_KE_DUPLICATE_RECORD;
			}
			if (rec.n != 2 || be16(rec.body) == 0)
				return bad_body(&rec, &r->detail);
			r->port = be16(rec.body);
			port = true;
			break;
		default:
			/* Section 4: an unknown record is ignored without the critical
			 * bit and is an error with it. */
			if (rec.critical) {
				r->detail = rec.typ;
				return NTS_ERR_KE_UNKNOWN_CRITICAL;
			}
		}
	}
}
