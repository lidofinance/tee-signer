/* The NTPv4 client request and the check of the server response, with the
 * NTS extension fields (RFC 8915 section 5, RFC 7822, RFC 5905), check
 * for check in the order of the Go code this replaced. No socket, no
 * clock, no random numbers: the client (client.c) moves the bytes and
 * supplies every random value. */
#include <string.h>

#include "nts_core.h"

enum {
	HEADER_LEN = 48,
	VERSION = 4,
	MODE_CLIENT = 3,
	MODE_SERVER = 4,
	LEAP_UNSYNCHRONIZED = 3,
	MAX_STRATUM = 15,
	EXT_UNIQUE_ID = 0x0104,
	EXT_COOKIE = 0x0204,
	EXT_PLACEHOLDER = 0x0304,
	EXT_AUTH = 0x0404,
	FIELD_HEADER_LEN = 4,
	MIN_FIELD_LEN = 16,
	AUTH_LENGTHS_LEN = 4,
	REQUEST_AUTH_FIELD_LEN = FIELD_HEADER_LEN + AUTH_LENGTHS_LEN + NTS_NONCE_LEN + NTS_SIV_TAG_LEN,
};

static uint16_t be16(const uint8_t *p) { return (uint16_t)((uint16_t)p[0] << 8 | p[1]); }
static uint32_t be32(const uint8_t *p) { return (uint32_t)be16(p) << 16 | be16(p + 2); }
static uint64_t be64(const uint8_t *p) { return (uint64_t)be32(p) << 32 | be32(p + 4); }
static void put16(uint8_t *p, uint16_t v)
{
	p[0] = (uint8_t)(v >> 8);
	p[1] = (uint8_t)v;
}
static void put64(uint8_t *p, uint64_t v)
{
	for (int i = 7; i >= 0; i--) {
		p[i] = (uint8_t)v;
		v >>= 8;
	}
}

static size_t pad4(size_t n) { return (n + 3) & ~(size_t)3; }

/* The length of an extension field with a body of n octets: the header,
 * the body padded to 4 octets and to the 16-octet minimum of RFC 7822
 * section 7.5.1.4. */
size_t nts_field_len(size_t n)
{
	size_t p = pad4(n);
	if (p < MIN_FIELD_LEN - FIELD_HEADER_LEN)
		p = MIN_FIELD_LEN - FIELD_HEADER_LEN;
	return FIELD_HEADER_LEN + p;
}

size_t nts_request_len(size_t cookielen, int placeholders)
{
	return HEADER_LEN + nts_field_len(NTS_UID_LEN) + REQUEST_AUTH_FIELD_LEN + nts_field_len(cookielen) * ((size_t)placeholders + 1);
}

/* The most placeholders a request with a cookie of cookielen octets can
 * carry: at most NTS_MAX_PLACEHOLDERS, and few enough that the request
 * fits in NTS_MAX_REQUEST_LEN octets (RFC 8915 section 5.7). */
int nts_max_placeholders(size_t cookielen)
{
	for (int p = NTS_MAX_PLACEHOLDERS; p > 0; p--)
		if (nts_request_len(cookielen, p) <= NTS_MAX_REQUEST_LEN)
			return p;
	return 0;
}

/* Appends one field at *at, or fails if it would not fit. */
static bool append_field(uint8_t *out, size_t cap, size_t *at, uint16_t typ, const uint8_t *body, size_t n)
{
	size_t len = nts_field_len(n);
	if (*at + len > cap)
		return false;
	put16(out + *at, typ);
	put16(out + *at + 2, (uint16_t)len);
	memcpy(out + *at + FIELD_HEADER_LEN, body, n);
	memset(out + *at + FIELD_HEADER_LEN + n, 0, len - FIELD_HEADER_LEN - n);
	*at += len;
	return true;
}

int nts_build_request(const nts_siv_key *c2s, uint64_t transmit, const uint8_t uid[NTS_UID_LEN],
		      const uint8_t nonce[NTS_NONCE_LEN], const uint8_t *cookie, size_t cookielen, int placeholders,
		      uint8_t *out, size_t outcap, size_t *outlen, nts_pending *p)
{
	uint8_t placeholder[NTS_MAX_COOKIE_LEN], tag[NTS_SIV_TAG_LEN], body[AUTH_LENGTHS_LEN + NTS_NONCE_LEN + NTS_SIV_TAG_LEN];
	size_t at = 0;
	if (placeholders < 0 || placeholders > NTS_MAX_PLACEHOLDERS)
		return NTS_ERR_TOO_MANY_PLACEHOLDERS;
	if (cookielen < 1 || cookielen > NTS_MAX_COOKIE_LEN)
		return NTS_ERR_BAD_COOKIE;
	size_t n = nts_request_len(cookielen, placeholders);
	if (n > NTS_MAX_REQUEST_LEN || n > outcap)
		return NTS_ERR_REQUEST_TOO_LONG;
	memset(out, 0, HEADER_LEN);
	out[0] = VERSION << 3 | MODE_CLIENT;
	put64(out + 40, transmit);
	at = HEADER_LEN;
	if (!append_field(out, outcap, &at, EXT_UNIQUE_ID, uid, NTS_UID_LEN) || !append_field(out, outcap, &at, EXT_COOKIE, cookie, cookielen))
		return NTS_ERR_REQUEST_TOO_LONG;
	memset(placeholder, 0, cookielen);
	for (int i = 0; i < placeholders; i++)
		if (!append_field(out, outcap, &at, EXT_PLACEHOLDER, placeholder, cookielen))
			return NTS_ERR_REQUEST_TOO_LONG;
	/* Section 5.6: A is the packet so far, N our nonce, P empty; the
	 * ciphertext is the 16-octet tag. */
	const uint8_t *ads[2] = {out, nonce};
	size_t adlens[2] = {at, NTS_NONCE_LEN};
	nts_siv_seal(c2s, ads, adlens, 2, NULL, 0, tag);
	put16(body, NTS_NONCE_LEN);
	put16(body + 2, NTS_SIV_TAG_LEN);
	memcpy(body + 4, nonce, NTS_NONCE_LEN);
	memcpy(body + 4 + NTS_NONCE_LEN, tag, NTS_SIV_TAG_LEN);
	if (!append_field(out, outcap, &at, EXT_AUTH, body, sizeof body) || at != n)
		return NTS_ERR_REQUEST_TOO_LONG;
	*outlen = at;
	p->transmit = transmit;
	memcpy(p->uid, uid, NTS_UID_LEN);
	p->placeholders = placeholders;
	p->answered = false;
	return NTS_OK;
}

static bool all_zero(const uint8_t *b, size_t n)
{
	uint8_t acc = 0;
	for (size_t i = 0; i < n; i++)
		acc |= b[i];
	return acc == 0;
}

static bool ct_eq(const uint8_t *a, const uint8_t *b, size_t n)
{
	uint8_t acc = 0;
	for (size_t i = 0; i < n; i++)
		acc |= (uint8_t)(a[i] ^ b[i]);
	return acc == 0;
}

/* The NTS authenticator of a response, located in the packet. */
struct authenticator {
	size_t start; /* where the field starts: the associated data is everything before it */
	const uint8_t *nonce, *ct;
	size_t noncelen, ctlen;
};

/* RFC 8915 section 5.6: Nonce Length, Ciphertext Length, the nonce and the
 * ciphertext each zero-padded to 4 octets, then Additional Padding, all
 * zero: the padding is outside the AEAD input, so it is checked here. */
static int parse_authenticator(const uint8_t *body, size_t n, size_t start, struct authenticator *a)
{
	if (n < AUTH_LENGTHS_LEN)
		return NTS_ERR_BAD_AUTHENTICATOR;
	size_t nl = be16(body), cl = be16(body + 2);
	if (nl == 0 || cl < NTS_SIV_TAG_LEN)
		return NTS_ERR_BAD_AUTHENTICATOR;
	size_t nonce_end = AUTH_LENGTHS_LEN + nl, ct_start = AUTH_LENGTHS_LEN + pad4(nl);
	size_t ct_end = ct_start + cl, rest = ct_start + pad4(cl);
	if (rest > n)
		return NTS_ERR_BAD_AUTHENTICATOR;
	if (!all_zero(body + nonce_end, ct_start - nonce_end) || !all_zero(body + ct_end, rest - ct_end) || !all_zero(body + rest, n - rest))
		return NTS_ERR_BAD_AUTHENTICATOR;
	a->start = start;
	a->nonce = body + AUTH_LENGTHS_LEN;
	a->noncelen = nl;
	a->ct = body + ct_start;
	a->ctlen = cl;
	return NTS_OK;
}

/* Walks the extension fields after the header (RFC 7822 section 7.5),
 * stopping at the first authenticator: the fields after it are
 * unauthenticated and never read. Unknown fields before it are skipped. */
static int parse_fields(const uint8_t *packet, size_t len, const uint8_t **uid, size_t *uidlen, struct authenticator *auth, bool *have_auth)
{
	*uid = NULL;
	*uidlen = 0;
	*have_auth = false;
	for (size_t at = HEADER_LEN; at < len;) {
		if (at + FIELD_HEADER_LEN > len)
			return NTS_ERR_BAD_EXTENSION_FIELD;
		uint16_t typ = be16(packet + at);
		size_t n = be16(packet + at + 2);
		if (n % 4 != 0 || n < MIN_FIELD_LEN || at + n > len)
			return NTS_ERR_BAD_EXTENSION_FIELD;
		const uint8_t *body = packet + at + FIELD_HEADER_LEN;
		size_t bodylen = n - FIELD_HEADER_LEN;
		if (typ == EXT_UNIQUE_ID) {
			if (*uid)
				return NTS_ERR_DUPLICATE_UID;
			*uid = body;
			*uidlen = bodylen;
		} else if (typ == EXT_AUTH) {
			int rc = parse_authenticator(body, bodylen, at, auth);
			if (rc)
				return rc;
			*have_auth = true;
			return NTS_OK;
		}
		at += n;
	}
	return NTS_OK;
}

/* The cookies in the decrypted part (RFC 8915 section 5.6): fields in
 * RFC 7822 form, a multiple of 4 and at least the header; at most
 * placeholders + 1 cookies (section 5.7), each 1 to NTS_MAX_COOKIE_LEN. */
static int encrypted_cookies(const uint8_t *plain, size_t len, int max, nts_time_response *t)
{
	t->ncookies = 0;
	for (size_t at = 0; at < len;) {
		if (at + FIELD_HEADER_LEN > len)
			return NTS_ERR_BAD_ENCRYPTED_FIELD;
		uint16_t typ = be16(plain + at);
		size_t n = be16(plain + at + 2);
		if (n % 4 != 0 || n < FIELD_HEADER_LEN || at + n > len)
			return NTS_ERR_BAD_ENCRYPTED_FIELD;
		if (typ == EXT_COOKIE) {
			if (t->ncookies >= max)
				return NTS_ERR_TOO_MANY_COOKIES;
			size_t cl = n - FIELD_HEADER_LEN;
			if (cl < 1 || cl > NTS_MAX_COOKIE_LEN)
				return NTS_ERR_BAD_COOKIE;
			memcpy(t->cookies[t->ncookies], plain + at + FIELD_HEADER_LEN, cl);
			t->cookie_len[t->ncookies] = cl;
			t->ncookies++;
		}
		at += n;
	}
	return NTS_OK;
}

int nts_verify_response(nts_pending *p, const nts_siv_key *s2c, const uint8_t *packet, size_t len, nts_verdict *v)
{
	uint8_t plain[NTS_MAX_RESPONSE_LEN];
	const uint8_t *uid;
	size_t uidlen;
	struct authenticator auth;
	bool have_auth;
	uint8_t want[8];
	int rc;

	if (p->answered)
		return NTS_ERR_ALREADY_ANSWERED;
	if (len > NTS_MAX_RESPONSE_LEN)
		return NTS_ERR_TOO_LONG;
	if (len < HEADER_LEN)
		return NTS_ERR_TOO_SHORT;
	uint8_t leap = packet[0] >> 6, version = (packet[0] >> 3) & 7, mode = packet[0] & 7, stratum = packet[1];
	v->detail = 0;
	if (version != VERSION) {
		v->detail = version;
		return NTS_ERR_BAD_VERSION;
	}
	if (mode != MODE_SERVER) {
		v->detail = mode;
		return NTS_ERR_BAD_MODE;
	}
	/* RFC 5905 section 8: the origin timestamp is our transmit timestamp,
	 * random, so this is a 64-bit check against forged responses. */
	put64(want, p->transmit);
	if (!ct_eq(packet + 24, want, 8))
		return NTS_ERR_ORIGIN_MISMATCH;
	rc = parse_fields(packet, len, &uid, &uidlen, &auth, &have_auth);
	if (rc)
		return rc;
	if (!uid)
		return NTS_ERR_MISSING_UID;
	if (uidlen != NTS_UID_LEN || !ct_eq(uid, p->uid, NTS_UID_LEN))
		return NTS_ERR_UID_MISMATCH;
	if (stratum == 0) {
		/* A Kiss-o'-Death: no time in it, and it does not answer the
		 * request: anyone on the path can forge one. An authenticator, if
		 * there is one, is checked, and the verdict says whether it
		 * verified. */
		v->kind = NTS_KIND_KISS;
		for (int i = 0; i < 4; i++) {
			uint8_t c = packet[12 + i];
			v->kiss[i] = (char)(c < 0x20 || c > 0x7e ? '?' : c);
		}
		v->kiss_authentic = false;
		if (have_auth) {
			const uint8_t *ads[2] = {packet, auth.nonce};
			size_t adlens[2] = {auth.start, auth.noncelen};
			v->kiss_authentic = nts_siv_open(s2c, ads, adlens, 2, auth.ct, auth.ctlen, plain);
		}
		return NTS_OK;
	}
	if (!have_auth)
		return NTS_ERR_MISSING_AUTHENTICATOR;
	{
		const uint8_t *ads[2] = {packet, auth.nonce};
		size_t adlens[2] = {auth.start, auth.noncelen};
		if (!nts_siv_open(s2c, ads, adlens, 2, auth.ct, auth.ctlen, plain))
			return NTS_ERR_NOT_AUTHENTIC;
	}
	nts_time_response *t = &v->time;
	rc = encrypted_cookies(plain, auth.ctlen - NTS_SIV_TAG_LEN, p->placeholders + 1, t);
	if (rc)
		return rc;
	if (leap == LEAP_UNSYNCHRONIZED)
		return NTS_ERR_UNSYNCHRONIZED;
	if (stratum > MAX_STRATUM) {
		v->detail = stratum;
		return NTS_ERR_BAD_STRATUM;
	}
	if (t->ncookies == 0)
		return NTS_ERR_NO_COOKIES;
	p->answered = true;
	v->kind = NTS_KIND_TIME;
	t->leap = leap;
	t->stratum = stratum;
	t->precision = (int8_t)packet[3];
	t->root_delay = be32(packet + 4);
	t->root_dispersion = be32(packet + 8);
	t->reference = be64(packet + 16);
	t->origin = be64(packet + 24);
	t->receive = be64(packet + 32);
	t->transmit = be64(packet + 40);
	return NTS_OK;
}
