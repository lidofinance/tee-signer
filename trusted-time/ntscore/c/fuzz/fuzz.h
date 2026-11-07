/* Shared helpers of the NTS core's fuzz targets: each target defines
 * LLVMFuzzerTestOneInput and builds with clang's libFuzzer or with
 * devkit/cfuzz/driver.c (gcc), under ASan and UBSan (../Makefile, make
 * fuzz; fuzz.sh runs them). The Go targets (../../go/fuzz_test.go) hold
 * the oracles of the protocol; these run the C itself under the
 * sanitizers with coverage, which the Go engine cannot see into. */
#ifndef NTS_FUZZ_H
#define NTS_FUZZ_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "nts_core.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

/* An oracle failure: print it and abort, so the engine saves the input. */
#define FUZZ_CHECK(cond)                                                                 \
	do {                                                                                 \
		if (!(cond)) {                                                                   \
			fprintf(stderr, "==FUZZ ORACLE== %s:%d: %s\n", __FILE__, __LINE__, #cond); \
			abort();                                                                     \
		}                                                                                \
	} while (0)

/* Reads the input front to back. Past the end every read gives zeros,
 * which is the honest choice everywhere. */
typedef struct {
	const uint8_t *p;
	size_t n;
} fz_in;

static inline uint8_t fz_u8(fz_in *in)
{
	uint8_t v = 0;
	if (in->n) {
		v = *in->p++;
		in->n--;
	}
	return v;
}

static inline int fz_pick(fz_in *in, int n) { return fz_u8(in) % n; }

static inline uint64_t fz_u64(fz_in *in)
{
	uint64_t v = 0;
	for (int i = 0; i < 8; i++)
		v = v << 8 | fz_u8(in);
	return v;
}

/* Up to cap octets of the input into buf; returns how many. */
static inline size_t fz_bytes(fz_in *in, uint8_t *buf, size_t cap)
{
	size_t n = in->n < cap ? in->n : cap;
	memcpy(buf, in->p, n);
	in->p += n;
	in->n -= n;
	return n;
}

/* A fixed test key: 32 octets of a pattern from seed. */
static inline void fz_key(uint8_t key[NTS_KEY_LEN], uint8_t seed)
{
	for (int i = 0; i < NTS_KEY_LEN; i++)
		key[i] = (uint8_t)(seed * 37 + i * 11 + 5);
}

static inline void put16(uint8_t *p, uint16_t v)
{
	p[0] = (uint8_t)(v >> 8);
	p[1] = (uint8_t)v;
}

static inline void put64(uint8_t *p, uint64_t v)
{
	for (int i = 7; i >= 0; i--) {
		p[i] = (uint8_t)v;
		v >>= 8;
	}
}

/* ---- The server side, as the harnesses play it ---- */

/* An NTS-KE response: Next Protocol NTPv4, AEAD 15, ncookies cookies of
 * cookielen octets (a pattern from seed), the Server and Port records
 * if asked, End of Message. Returns the length, 0 if cap is too small. */
static inline size_t fz_ke_response(uint8_t *out, size_t cap, int ncookies, size_t cookielen, uint8_t seed, const char *server, uint16_t port)
{
	size_t at = 0, srvlen = server ? strlen(server) : 0;
	size_t need = 6 + 6 + (size_t)ncookies * (4 + cookielen) + (server ? 4 + srvlen : 0) + (port ? 6 : 0) + 4;
	if (need > cap)
		return 0;
	static const uint8_t head[12] = {0x80, 0x01, 0, 2, 0, 0, 0x80, 0x04, 0, 2, 0, 15};
	memcpy(out, head, 12);
	at = 12;
	for (int c = 0; c < ncookies; c++) {
		put16(out + at, 0x0005);
		put16(out + at + 2, (uint16_t)cookielen);
		for (size_t i = 0; i < cookielen; i++)
			out[at + 4 + i] = (uint8_t)(seed + c * 7 + i);
		at += 4 + cookielen;
	}
	if (server) {
		put16(out + at, 0x8006);
		put16(out + at + 2, (uint16_t)srvlen);
		memcpy(out + at + 4, server, srvlen);
		at += 4 + srvlen;
	}
	if (port) {
		put16(out + at, 0x8007);
		put16(out + at + 2, 2);
		put16(out + at + 4, port);
		at += 6;
	}
	put16(out + at, 0x8000);
	put16(out + at + 2, 0);
	return at + 4;
}

/* What a server reads from a client request: the transmit timestamp (the
 * origin of the answer) and the Unique Identifier, which the core puts
 * first after the header. The authenticator is not checked here: the
 * core's own request is well-formed, and a harness never forges requests. */
typedef struct {
	uint8_t origin[8];
	uint8_t uid[NTS_UID_LEN];
	int placeholders;
} fz_request;

static inline bool fz_read_request(const uint8_t *req, size_t n, fz_request *r)
{
	if (n < 48 + 4 + NTS_UID_LEN || req[48] != 0x01 || req[49] != 0x04)
		return false;
	memcpy(r->origin, req + 40, 8);
	memcpy(r->uid, req + 52, NTS_UID_LEN);
	r->placeholders = 0;
	for (size_t at = 48; at + 4 <= n;) {
		size_t l = (size_t)req[at + 2] << 8 | req[at + 3];
		if (l < 16 || at + l > n)
			break;
		if (req[at] == 0x03 && req[at + 1] == 0x04)
			r->placeholders++;
		at += l;
	}
	return true;
}

/* An authentic server answer to r: a time response (stratum 1 to 15,
 * receive and transmit as given, ncookies cookies of 100 octets in the
 * encrypted part) or, with stratum 0, a Kiss-o'-Death with the code, with
 * an authenticator if authentic. Returns the length, 0 if cap is too
 * small or the key is not usable. */
static inline size_t fz_server_answer(const nts_siv_key *s2c, const fz_request *r, uint8_t stratum, const char *code, bool authentic,
				     uint64_t receive, uint64_t transmit, int ncookies, uint8_t *out, size_t cap)
{
	uint8_t pt[NTS_MAX_COOKIES * 104] = {0}, ct[sizeof pt + NTS_SIV_TAG_LEN], nonce[NTS_NONCE_LEN];
	size_t ptlen = 0, at = 0;
	if (ncookies < 0 || ncookies > NTS_MAX_COOKIES || cap < 48 + 36 + 8 + sizeof nonce + sizeof ct)
		return 0;
	memset(out, 0, 48);
	out[0] = (uint8_t)((stratum == 0 ? 3 : 0) << 6 | 4 << 3 | 4);
	out[1] = stratum;
	out[2] = 6;
	out[3] = (uint8_t)-20;
	put16(out + 4, 0);
	put16(out + 6, 0x0100); /* root delay: 2^-8 s */
	put16(out + 8, 0);
	put16(out + 10, 0x0200);
	memcpy(out + 12, stratum == 0 && strlen(code) >= 4 ? code : "FUZZ", 4);
	put64(out + 16, receive - ((uint64_t)16 << 32));
	memcpy(out + 24, r->origin, 8);
	put64(out + 32, receive);
	put64(out + 40, transmit);
	at = 48;
	put16(out + at, 0x0104);
	put16(out + at + 2, 4 + NTS_UID_LEN);
	memcpy(out + at + 4, r->uid, NTS_UID_LEN);
	at += 4 + NTS_UID_LEN;
	if (stratum == 0 && !authentic)
		return at;
	for (int c = 0; c < ncookies && stratum != 0; c++) {
		put16(pt + ptlen, 0x0204);
		put16(pt + ptlen + 2, 104);
		for (int i = 0; i < 100; i++)
			pt[ptlen + 4 + i] = (uint8_t)(c * 13 + i);
		ptlen += 104;
	}
	for (int i = 0; i < NTS_NONCE_LEN; i++)
		nonce[i] = (uint8_t)(0x4e + i);
	const uint8_t *ads[2] = {out, nonce};
	size_t adlens[2] = {at, sizeof nonce};
	size_t ctlen = nts_siv_seal(s2c, ads, adlens, 2, pt, ptlen, ct);
	if (ctlen == 0 && ptlen != 0)
		return 0;
	put16(out + at, 0x0404);
	put16(out + at + 2, (uint16_t)(4 + 4 + sizeof nonce + ctlen));
	put16(out + at + 4, sizeof nonce);
	put16(out + at + 6, (uint16_t)ctlen);
	memcpy(out + at + 8, nonce, sizeof nonce);
	memcpy(out + at + 8 + sizeof nonce, ct, ctlen);
	return at + 8 + sizeof nonce + ctlen;
}

#endif
