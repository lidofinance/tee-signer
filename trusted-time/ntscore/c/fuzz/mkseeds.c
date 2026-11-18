/* Writes the seed corpora of the fuzz targets: a good NTS-KE response and
 * one with Server and Port records, the honest answer and two Kiss-o'-
 * Deaths to the fixed request of target_verify.c, an AES-SIV input, a
 * measurement, plain NTP answers and kisses to the fixed request of
 * target_plain.c, and decision streams for the client: honest, random,
 * and one for each thing a run may do beyond the untrusted operations
 * (plain NTP, cancels, the configuration calls, host operations that
 * return codes of the core's own) and for all of them.
 *
 *   mkseeds OUT_DIR
 *
 * Built against the plain core, without sanitizers. */
#include <errno.h>
#include <sys/stat.h>

#include "fuzz.h"

static const char *g_out;
static int g_written;

static void put(const char *target, const char *name, const uint8_t *d, size_t n)
{
	char path[4096];
	snprintf(path, sizeof path, "%s/%s", g_out, target);
	mkdir(path, 0755);
	snprintf(path, sizeof path, "%s/%s/%s", g_out, target, name);
	FILE *f = fopen(path, "wb");
	if (!f || fwrite(d, 1, n, f) != n || fclose(f)) {
		fprintf(stderr, "mkseeds: %s: %s\n", path, strerror(errno));
		exit(1);
	}
	g_written++;
}

int main(int argc, char **argv)
{
	static uint8_t buf[70000], req[NTS_MAX_REQUEST_LEN], key[NTS_KEY_LEN], cookie[100], uid[NTS_UID_LEN], nonce[NTS_NONCE_LEN];
	nts_siv_key c2s, s2c;
	nts_pending p;
	size_t n, reqlen = 0;
	if (argc != 2) {
		fprintf(stderr, "usage: mkseeds OUT_DIR\n");
		return 2;
	}
	g_out = argv[1];
	mkdir(g_out, 0755);
	nts_setup();

	n = fz_ke_response(buf, sizeof buf, 8, 100, 1, NULL, 0);
	put("ke", "eight-cookies", buf, n);
	n = fz_ke_response(buf, sizeof buf, 1, 1024, 2, "ntp.example.test", 4123);
	put("ke", "server-port", buf, n);
	n = fz_ke_response(buf, sizeof buf, 3, 7, 3, "2001:db8::1", 123);
	put("ke", "ipv6-short-cookies", buf, n);

	/* The fixed request of target_verify.c, and the answers to it. */
	fz_key(key, 1);
	nts_siv_init(&c2s, key, sizeof key);
	fz_key(key, 2);
	nts_siv_init(&s2c, key, sizeof key);
	for (int i = 0; i < 100; i++)
		cookie[i] = (uint8_t)i;
	for (int i = 0; i < NTS_UID_LEN; i++)
		uid[i] = (uint8_t)(0xa0 + i);
	for (int i = 0; i < NTS_NONCE_LEN; i++)
		nonce[i] = (uint8_t)(0x4e + i);
	if (nts_build_request(&c2s, 0x0102030405060708ULL, uid, nonce, cookie, sizeof cookie, 3, req, sizeof req, &reqlen, &p) != NTS_OK) {
		fprintf(stderr, "mkseeds: the request\n");
		return 1;
	}
	fz_request r;
	fz_read_request(req, reqlen, &r);
	uint64_t recv = nts_ntp_from_unix_nanos(1793491200LL * 1000000000LL);
	n = fz_server_answer(&s2c, &r, 2, "", false, recv, recv + 1000000, 4, buf, sizeof buf);
	put("verify", "time-four-cookies", buf, n);
	n = fz_server_answer(&s2c, &r, 1, "", false, recv, recv, 1, buf, sizeof buf);
	put("verify", "time-one-cookie", buf, n);
	n = fz_server_answer(&s2c, &r, 0, "RATE", true, recv, recv, 0, buf, sizeof buf);
	put("verify", "kod-rate-authentic", buf, n);
	n = fz_server_answer(&s2c, &r, 0, "NTSN", false, recv, recv, 0, buf, sizeof buf);
	put("verify", "kod-ntsn", buf, n);

	n = 0;
	fz_key(buf, 7);
	n += NTS_KEY_LEN;
	buf[n++] = 24; /* ad length */
	for (int i = 0; i < 24; i++)
		buf[n++] = (uint8_t)i;
	buf[n++] = 15; /* nonce length - 1 */
	for (int i = 0; i < 16; i++)
		buf[n++] = (uint8_t)(0x4e + i);
	buf[n++] = 3; /* the bit to flip */
	memcpy(buf + n, "this is some plaintext to encrypt using SIV-AES", 47);
	n += 47;
	put("siv", "rfc5297-like", buf, n);

	n = 0;
	buf[n++] = 0;  /* leap */
	buf[n++] = 2;  /* stratum */
	buf[n++] = (uint8_t)-20;
	for (int k = 0; k < 2; k++) {
		put64(buf + n, 0x0100);
		n += 8;
	}
	put64(buf + n, recv - ((uint64_t)16 << 32));
	n += 8;
	put64(buf + n, recv);
	n += 8;
	put64(buf + n, recv + 1000000);
	n += 8;
	put64(buf + n, 3600000000000ULL); /* t1 */
	n += 8;
	put64(buf + n, 3600000000000ULL + 20000000); /* t4 */
	n += 8;
	put64(buf + n, 1790812800ULL * 1000000000ULL); /* pivot */
	n += 8;
	put("measure", "honest", buf, n);

	/* target_plain.c: t1, t4, the pivot, then the datagram. */
	{
		static const uint8_t origin[8] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88};
		static const struct {
			const char *name, *code;
			uint8_t stratum;
			size_t tail;
		} plain[] = {{"time", "", 2, 0},	   {"time-stratum-15", "", 15, 0}, {"time-with-a-tail", "", 1, 20}, {"kod-rate", "RATE", 0, 0},
			     {"kod-deny", "DENY", 0, 0},   {"kod-nts-nak", "NTS\0", 0, 0}, {"kod-unprintable", "\x01\x02\x03\x04", 0, 12}};
		for (size_t k = 0; k < sizeof plain / sizeof plain[0]; k++) {
			n = 0;
			put64(buf + n, 3600000000000ULL); /* t1 */
			put64(buf + n + 8, 3600000000000ULL + 20000000); /* t4 */
			put64(buf + n + 16, 1790812800ULL * 1000000000ULL); /* pivot */
			n += 24;
			n += fz_plain_answer(origin, plain[k].stratum, plain[k].code, recv, recv + 1000000, buf + n);
			memset(buf + n, 0xff, plain[k].tail);
			put("plain", plain[k].name, buf, n + plain[k].tail);
		}
	}

	memset(buf, 0, 64);
	put("client", "honest", buf, 64);
	uint64_t x = 0x243f6a8885a308d3ULL;
	/* The first octet says what the run does beyond the untrusted
	 * operations (target_client.c: plain NTP, cancels, configuration
	 * calls, codes no host operation has); 0 is none of it. */
	static const uint8_t flags[] = {0, 0, 0, 0, 1, 2, 4, 5, 7, 7, 8, 8, 9, 12, 15, 15};
	for (int s = 0; s < (int)sizeof flags; s++) {
		size_t len = 300 + (size_t)(s % 4) * 200;
		for (size_t i = 0; i < len; i++) {
			x ^= x << 13;
			x ^= x >> 7;
			x ^= x << 17;
			buf[i] = (uint8_t)x;
		}
		buf[0] = flags[s];
		char name[32];
		snprintf(name, sizeof name, "random-%d-flags-%d", s, flags[s]);
		put("client", name, buf, len);
	}
	for (int f = 1; f < 16; f++) {
		memset(buf, 0, 64);
		buf[0] = (uint8_t)f;
		char name[32];
		snprintf(name, sizeof name, "honest-flags-%d", f);
		put("client", name, buf, 64);
	}
	printf("mkseeds: %d files\n", g_written);
	return 0;
}
