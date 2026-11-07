/* The hostile host, in C: the client core with its untrusted operations
 * fed from the input (key exchange responses honest, mutated, garbage or
 * refused; datagrams honest, with trailing octets, mutated, garbage, a
 * Kiss-o'-Death of any code with or without an authenticator, another
 * server's answer, nothing; sockets that fail; a counter that jumps) and
 * its trusted operations honest. The Go harness (../../go/hostile_test.go)
 * holds the protocol oracles; this one runs the whole client under the
 * sanitizers with coverage, and checks the little it can see: the jar
 * within its size, a quorum of three or more, a bound within the limit,
 * a time that never goes back, and no call refused as busy. The input is
 * read as decisions; exhausted, it reads as zero, the honest choice. */
#include "fuzz.h"

#define NSERV 3
#define NCONN 8
#define QLEN 4

static fz_in in;
static nts_core *core;
static nts_siv_key srv_s2c[NSERV];
static uint8_t keys_c2s[NSERV][NTS_KEY_LEN], keys_s2c[NSERV][NTS_KEY_LEN];
static int64_t now, true_off; /* true Unix ns = now + true_off */
static uint64_t rng_state;

struct conn {
	int peer;
	int nq, at;
	size_t qlen[QLEN];
	uint8_t q[QLEN][NTS_MAX_RESPONSE_LEN + 64];
};
static struct conn conns[NCONN];
static int nconns;

static uint64_t rnd(void)
{
	rng_state ^= rng_state << 13;
	rng_state ^= rng_state >> 7;
	rng_state ^= rng_state << 17;
	return rng_state;
}

static int h_random(void *ctx, uint8_t *buf, size_t n)
{
	(void)ctx;
	for (size_t i = 0; i < n; i++)
		buf[i] = (uint8_t)rnd();
	return NTS_OK;
}

static int64_t h_monotonic(void *ctx)
{
	(void)ctx;
	now += 1000;
	return now;
}

static void mutate(uint8_t *b, size_t n)
{
	int k = 1 + fz_pick(&in, 8);
	for (int i = 0; i < k && n; i++)
		b[fz_u64(&in) % n] ^= (uint8_t)(1 + fz_u8(&in));
}

static int h_key_exchange(void *ctx, size_t peer, const nts_server *srv, int64_t validity, int64_t timeout, const uint8_t *req, size_t reqlen,
			  uint8_t *resp, size_t respcap, size_t *resplen, uint8_t c2s[NTS_KEY_LEN], uint8_t s2c[NTS_KEY_LEN], int64_t *elapsed)
{
	(void)ctx;
	(void)srv;
	(void)timeout;
	FUZZ_CHECK(reqlen == NTS_KE_REQUEST_LEN && req[0] == 0x80 && validity > 0);
	size_t n = 0;
	switch (fz_pick(&in, 8)) {
	case 0:
	case 1:
	case 2:
		n = fz_ke_response(resp, respcap, 8, 100, (uint8_t)peer, NULL, 0);
		break;
	case 3:
		n = fz_ke_response(resp, respcap, 1 + fz_pick(&in, 8), 1 + fz_pick(&in, 1024), (uint8_t)peer, "ntp.test", 4123);
		break;
	case 4:
		n = fz_ke_response(resp, respcap, 8, 100, (uint8_t)peer, NULL, 0);
		mutate(resp, n);
		break;
	case 5:
		n = fz_bytes(&in, resp, respcap < 2000 ? respcap : 2000);
		break;
	case 6:
		/* Another server's keys with this response: its cookies will not
		 * verify there. */
		peer = (peer + 1) % NSERV;
		n = fz_ke_response(resp, respcap, 8, 100, (uint8_t)peer, NULL, 0);
		break;
	default:
		return NTS_ERR_HOST;
	}
	memcpy(c2s, keys_c2s[peer], NTS_KEY_LEN);
	memcpy(s2c, keys_s2c[peer], NTS_KEY_LEN);
	*resplen = n;
	*elapsed = 1000000;
	return NTS_OK;
}

static int h_udp_open(void *ctx, size_t peer, const char *addr, size_t addrlen, int64_t timeout, void **sock)
{
	(void)ctx;
	(void)timeout;
	FUZZ_CHECK(addrlen > 0 && addrlen <= NTS_MAX_ADDR_LEN && addr[addrlen - 1] != ':');
	if (fz_pick(&in, 16) == 15)
		return NTS_ERR_HOST;
	struct conn *c = &conns[nconns++ % NCONN];
	memset(c, 0, sizeof *c);
	c->peer = (int)peer;
	*sock = c;
	return NTS_OK;
}

static int h_udp_send(void *ctx, void *sock, const uint8_t *p, size_t n)
{
	(void)ctx;
	struct conn *c = sock;
	fz_request r;
	FUZZ_CHECK(fz_read_request(p, n, &r) && n <= NTS_MAX_REQUEST_LEN && r.placeholders <= NTS_MAX_PLACEHOLDERS);
	if (fz_pick(&in, 12) == 11)
		return NTS_ERR_HOST;
	uint64_t recv = nts_ntp_from_unix_nanos(now + true_off + 500000 + (int64_t)fz_pick(&in, 5) * 1000000);
	c->nq = 1 + fz_pick(&in, QLEN);
	for (int k = 0; k < c->nq; k++) {
		uint8_t *q = c->q[k];
		size_t cap = NTS_MAX_RESPONSE_LEN + 64, len = 0;
		const nts_siv_key *key = &srv_s2c[c->peer];
		int ncookies = r.placeholders + 1;
		switch (fz_pick(&in, 11)) {
		case 0:
		case 1:
		case 2:
			len = fz_server_answer(key, &r, 2, "", false, recv, recv + 1000000, ncookies, q, cap);
			break;
		case 3:
			len = fz_server_answer(key, &r, 2, "", false, recv, recv + 1000000, ncookies, q, cap);
			len += fz_bytes(&in, q + len, 40);
			break;
		case 4:
			len = fz_server_answer(key, &r, 2, "", false, recv, recv + 1000000, ncookies, q, cap);
			mutate(q, len);
			break;
		case 5:
			len = fz_bytes(&in, q, 1300);
			break;
		case 6:
			len = fz_server_answer(key, &r, 0, (const char *[]){"RATE", "DENY", "RSTR", "NTSN", "STEP"}[fz_pick(&in, 5)], fz_pick(&in, 2), recv, recv, 0, q, cap);
			break;
		case 7:
			len = 0; /* nothing comes */
			break;
		case 8:
			len = fz_server_answer(&srv_s2c[(c->peer + 1) % NSERV], &r, 2, "", false, recv, recv + 1000000, ncookies, q, cap);
			break;
		case 9:
			len = fz_server_answer(key, &r, (uint8_t)fz_pick(&in, 17), "", false, recv, recv + 1000000, fz_pick(&in, NTS_MAX_COOKIES + 1), q, cap);
			break;
		default:
			len = fz_server_answer(key, &r, 2, "", false, recv + ((uint64_t)fz_u8(&in) << 32), recv, ncookies, q, cap);
		}
		c->qlen[k] = len;
	}
	return NTS_OK;
}

static int h_udp_recv(void *ctx, void *sock, uint8_t *buf, size_t cap, size_t *n, int64_t wait)
{
	(void)ctx;
	struct conn *c = sock;
	now += 1000000 * (1 + fz_pick(&in, 40));
	if (fz_pick(&in, 12) == 11)
		now += wait + 1;
	if (c->at >= c->nq || c->qlen[c->at] == 0) {
		now += wait;
		return NTS_ERR_HOST_TIMEOUT;
	}
	size_t len = c->qlen[c->at];
	const uint8_t *p = c->q[c->at];
	c->at++;
	if (fz_pick(&in, 20) == 19)
		return NTS_ERR_HOST;
	*n = len < cap ? len : cap;
	memcpy(buf, p, *n);
	return NTS_OK;
}

static void h_udp_close(void *ctx, void *sock)
{
	(void)ctx;
	(void)sock;
}

static void setup(void)
{
	nts_setup();
	core = malloc(nts_core_size());
	FUZZ_CHECK(core != NULL);
}

static void start(void)
{
	static nts_config cfg;
	static const nts_host_ops ops = {NULL, h_random, h_monotonic, h_key_exchange, h_udp_open, h_udp_send, h_udp_recv, h_udp_close};
	memset(&cfg, 0, sizeof cfg);
	cfg.nservers = NSERV;
	for (int i = 0; i < NSERV; i++) {
		nts_server *s = &cfg.servers[i];
		s->op[0] = (char)('a' + i);
		s->op_len = 1;
		memcpy(s->host, "nts-x.test", 10);
		s->host[4] = (char)('a' + i);
		s->host_len = 10;
		s->roots[0] = 'x';
		s->roots_len = 1;
		fz_key(keys_c2s[i], (uint8_t)(1 + i));
		fz_key(keys_s2c[i], (uint8_t)(11 + i));
		FUZZ_CHECK(nts_siv_init(&srv_s2c[i], keys_s2c[i], NTS_KEY_LEN) == NTS_OK);
	}
	cfg.interval_ns = 2000000000LL;
	cfg.min_poll_ns = 1000000000LL;
	cfg.max_poll_ns = 64000000000LL;
	cfg.max_bound_ns = 100000000LL;
	cfg.max_age_ns = 5000000000LL;
	cfg.max_coarse_diff_ns = 30000000000LL;
	cfg.coarse_resolution_ns = 1000000000LL;
	cfg.exchange_timeout_ns = 1000000000LL;
	cfg.kiss_grace_ns = 100000000LL;
	cfg.drift_baseline_polls = 4;
	cfg.floor_unix_ns = 1790812800LL * 1000000000LL; /* 2026-10-01 */
	FUZZ_CHECK(nts_core_init(core, &ops, &cfg, nts_core_size()) == NTS_OK);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	static bool ready;
	static nts_status st;
	if (!ready) {
		setup();
		ready = true;
	}
	in.p = data;
	in.n = size;
	rng_state = 0x9e3779b97f4a7c15ULL ^ size;
	now = (int64_t)fz_pick(&in, 200) * 3600000000000LL;
	true_off = 1793491200LL * 1000000000LL + (int64_t)fz_pick(&in, 730) * 86400000000000LL - now; /* 2026-11-01 and up to two years on */
	nconns = 0;
	start();
	int64_t highest = INT64_MIN;
	for (int round = 0; round < 40 && in.n > 0; round++) {
		switch (fz_pick(&in, 16)) {
		case 15:
			now += 1000000000LL * (1 + fz_pick(&in, 60));
			break;
		case 14:
			now += 3600000000000LL * (1 + fz_pick(&in, 48));
			break;
		default:
			now += 1000000LL * (1 + fz_pick(&in, 200));
		}
		int64_t coarse_err = (int64_t)fz_pick(&in, 25) * 1000000000LL - 12000000000LL;
		if (fz_pick(&in, 8) == 7)
			coarse_err = ((int64_t)fz_u8(&in) - 128) * 3600000000000LL;
		int64_t coarse_local = now, coarse = now + true_off + coarse_err;
		uint32_t due = nts_due(core, now);
		for (size_t i = 0; i < NSERV; i++) {
			if (!(due & (1u << i)))
				continue;
			nts_poll(core, i, coarse, coarse_local);
			nts_peer_view v;
			FUZZ_CHECK(nts_peer_get(core, i, &v) == NTS_OK);
			FUZZ_CHECK(v.cookies >= 0 && v.cookies <= NTS_MAX_COOKIES);
		}
		int rc = nts_combine(core, coarse, coarse_local);
		FUZZ_CHECK(rc != NTS_ERR_BUSY);
		nts_status_get(core, &st);
		FUZZ_CHECK(!st.busy && st.npeers == NSERV);
		if (st.have_result) {
			int members = 0;
			for (int i = 0; i < NSERV; i++)
				members += (st.members >> i) & 1;
			FUZZ_CHECK(members >= NTS_QUORUM_MIN_SERVERS);
		}
		int64_t t, bound;
		if (nts_bounded(core, &t, &bound) == NTS_OK) {
			FUZZ_CHECK(t >= highest);
			FUZZ_CHECK(bound >= 0 && bound <= 100000000LL);
			highest = t;
		}
	}
	FUZZ_CHECK(nts_core_wipe(core) == NTS_OK);
	return 0;
}
