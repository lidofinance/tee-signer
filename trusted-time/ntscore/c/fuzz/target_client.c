/* The hostile host, in C: the client core with its untrusted operations
 * fed from the input (key exchange responses honest, mutated, garbage or
 * refused; datagrams honest, with trailing octets, mutated, garbage, a
 * Kiss-o'-Death of any code with or without an authenticator, another
 * server's answer, nothing; sockets that fail; a counter that jumps) and
 * its trusted operations honest. The Go harness (../../go/hostile_test.go)
 * holds the protocol oracles; this one runs the whole client under the
 * sanitizers with coverage, and checks the little it can see: the jar
 * within its size, a quorum of three or more, a bound within the limit,
 * a time that never goes back, no certificate dated before the era pivot,
 * and no call refused as busy between polls. The input is read as
 * decisions; exhausted, it reads as zero, the honest choice.
 *
 * The exclusion of nts_core.h is driven from inside, on every run: from a
 * poll's socket open every call that a poll excludes is made and must be
 * refused as busy (the combine, the wipe, both configuration calls, the
 * full status, a second poll of the same peer), and from the clock
 * reading of a combine, a configuration call or a full status a poll is
 * made and must be refused as busy. A refused call does nothing, so the
 * run goes on as if none had been made.
 *
 * The first octet says what the run does beyond that (zero: nothing):
 * the core on plain NTP, where the answers are the bare header and the
 * input forges them freely (no key exchange may run, no cookie may be
 * held); host operations that report a cancel by the caller; host
 * operations that return codes no host operation has (the core's own: a
 * wide answer, a Kiss-o'-Death, busy; and unknown ones), which must end
 * the poll as a failed host operation and count as nothing else; and the
 * configuration calls between rounds, with legal and illegal values:
 * nts_core_set_servers with sublists, other orders, renamed hosts, too
 * many servers and twins, nts_core_set_policy with either protocol and
 * good and bad bounds. A refused call must change nothing it can see, an
 * accepted one must leave a list of the size given and the protocol
 * given, and the time must not go back across either. */
#include "fuzz.h"

#define NSERV 5 /* the servers of the world; the core starts with the first three or all */
#define NCONN 8
#define QLEN 4

#define F_PLAIN 1
#define F_CANCEL 2
#define F_CONFIG 4
#define F_BADRC 8

static fz_in in;
static nts_core *core;
static nts_siv_key srv_s2c[NSERV];
static uint8_t keys_c2s[NSERV][NTS_KEY_LEN], keys_s2c[NSERV][NTS_KEY_LEN];
static int64_t now, true_off; /* true Unix ns = now + true_off */
static uint64_t rng_state;
static int flags;
static bool plain; /* the protocol the core is on */
static int64_t max_bound;
static size_t nlist; /* the servers of the core's list */
static nts_server list[NTS_MAX_SERVERS + 1];

struct conn {
	int server; /* which server of the world */
	int nq, at;
	size_t qlen[QLEN];
	uint8_t q[QLEN][NTS_MAX_RESPONSE_LEN + 64];
};
static struct conn conns[NCONN];
static int nconns;
static int excl; /* a call that excludes the polls is under way */
static int bad_at; /* the first operation of the poll under way that returned a code no host operation has: 1 key exchange, 2 open, 3 send, 4 receive */

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
	/* A poll that comes in while a combine, a configuration call or a full
	 * status is at work is refused, and reads no clock (so this ends). */
	if (excl)
		FUZZ_CHECK(nts_poll(core, 0, 0, 0) == NTS_ERR_BUSY);
	now += 1000;
	return now;
}

/* From inside a poll of peer: every call a poll excludes, and a second
 * poll of the same peer. The gate comes before the arguments are looked
 * at, so the empty list is refused as busy too. */
static void during_poll(size_t peer)
{
	static nts_status s;
	FUZZ_CHECK(nts_combine(core, 0, 0) == NTS_ERR_BUSY);
	FUZZ_CHECK(nts_core_wipe(core) == NTS_ERR_BUSY);
	FUZZ_CHECK(nts_core_set_servers(core, list, nlist, 0, 0) == NTS_ERR_BUSY);
	FUZZ_CHECK(nts_core_set_servers(core, list, 0, 0, 0) == NTS_ERR_BUSY);
	FUZZ_CHECK(nts_core_set_policy(core, plain ? NTS_PROTO_NTS : NTS_PROTO_NTP, max_bound, max_bound, 0, 0) == NTS_ERR_BUSY);
	nts_status_get(core, &s);
	FUZZ_CHECK(s.busy && s.npeers == nlist);
	FUZZ_CHECK(nts_poll(core, peer, 0, 0) == NTS_ERR_BUSY);
}

/* A code no host operation has, sometimes, for operation op of a poll. */
static int bad_rc(int op)
{
	static const int codes[] = {NTS_ERR_SAMPLE_WIDE, NTS_ERR_KISS, NTS_ERR_BUSY, NTS_ERR_NOT_DUE, NTS_ERR_NO_QUORUM, NTS_ERR_NO_COOKIE, 9999, -1};
	if (!(flags & F_BADRC) || fz_pick(&in, 16) != 14)
		return NTS_OK;
	if (!bad_at)
		bad_at = op;
	return codes[fz_pick(&in, 8)];
}

static void mutate(uint8_t *b, size_t n)
{
	int k = 1 + fz_pick(&in, 8);
	for (int i = 0; i < k && n; i++)
		b[fz_u64(&in) % n] ^= (uint8_t)(1 + fz_u8(&in));
}

static bool cancelled(void) { return (flags & F_CANCEL) && fz_pick(&in, 16) == 15; }

/* The server of the world behind position peer of the core's list: its
 * operator label says which. */
static int server_of(size_t peer)
{
	FUZZ_CHECK(peer < nlist && list[peer].op_len == 1 && list[peer].op[0] >= 'a' && list[peer].op[0] < 'a' + NSERV);
	return list[peer].op[0] - 'a';
}

static int h_key_exchange(void *ctx, size_t peer, const nts_server *srv, int64_t validity, int64_t timeout, const uint8_t *req, size_t reqlen,
			  uint8_t *resp, size_t respcap, size_t *resplen, uint8_t c2s[NTS_KEY_LEN], uint8_t s2c[NTS_KEY_LEN], int64_t *elapsed)
{
	(void)ctx;
	(void)timeout;
	static nts_status sum;
	FUZZ_CHECK(!plain);
	FUZZ_CHECK(reqlen == NTS_KE_REQUEST_LEN && req[0] == 0x80 && validity > 0);
	/* No certificate is dated before the era pivot, whatever the coarse
	 * reading was. */
	nts_summary_get(core, &sum);
	FUZZ_CHECK(validity >= sum.era_pivot && validity > 1790812800LL * 1000000000LL);
	int s = server_of(peer);
	FUZZ_CHECK(srv->op_len == 1 && srv->op[0] == 'a' + s && srv->host_len == list[peer].host_len &&
		   memcmp(srv->host, list[peer].host, srv->host_len) == 0);
	if (cancelled())
		return NTS_ERR_HOST_CANCELLED;
	int bad = bad_rc(1);
	if (bad != NTS_OK)
		return bad;
	size_t n = 0;
	switch (fz_pick(&in, 8)) {
	case 0:
	case 1:
	case 2:
		n = fz_ke_response(resp, respcap, 8, 100, (uint8_t)s, NULL, 0);
		break;
	case 3:
		n = fz_ke_response(resp, respcap, 1 + fz_pick(&in, 8), 1 + fz_pick(&in, 1024), (uint8_t)s, "ntp.test", 4123);
		break;
	case 4:
		n = fz_ke_response(resp, respcap, 8, 100, (uint8_t)s, NULL, 0);
		mutate(resp, n);
		break;
	case 5:
		n = fz_bytes(&in, resp, respcap < 2000 ? respcap : 2000);
		break;
	case 6:
		/* Another server's keys with this response: its cookies will not
		 * verify there. */
		s = (s + 1) % NSERV;
		n = fz_ke_response(resp, respcap, 8, 100, (uint8_t)s, NULL, 0);
		break;
	default:
		return NTS_ERR_HOST;
	}
	memcpy(c2s, keys_c2s[s], NTS_KEY_LEN);
	memcpy(s2c, keys_s2c[s], NTS_KEY_LEN);
	*resplen = n;
	*elapsed = 1000000;
	return NTS_OK;
}

static int h_udp_open(void *ctx, size_t peer, const char *addr, size_t addrlen, int64_t timeout, void **sock)
{
	(void)ctx;
	FUZZ_CHECK(timeout > 0);
	FUZZ_CHECK(addrlen > 0 && addrlen <= NTS_MAX_ADDR_LEN && addr[addrlen - 1] != ':');
	int s = server_of(peer);
	if (plain && list[peer].ntp_addr_len > 0)
		FUZZ_CHECK(addrlen == list[peer].ntp_addr_len && memcmp(addr, list[peer].ntp_addr, addrlen) == 0);
	during_poll(peer);
	if (cancelled())
		return NTS_ERR_HOST_CANCELLED;
	int bad = bad_rc(2);
	if (bad != NTS_OK)
		return bad;
	if (fz_pick(&in, 16) == 15)
		return NTS_ERR_HOST;
	struct conn *c = &conns[nconns++ % NCONN];
	memset(c, 0, sizeof *c);
	c->server = s;
	*sock = c;
	return NTS_OK;
}

/* The answers to a plain request: the world sees the transmit timestamp,
 * so it answers honestly or with any time, any kiss, anything. */
static int plain_send(struct conn *c, const uint8_t *p, size_t n)
{
	FUZZ_CHECK(n == NTS_PLAIN_REQUEST_LEN && p[0] == 0x23);
	for (int i = 1; i < 40; i++)
		FUZZ_CHECK(p[i] == 0);
	if (cancelled())
		return NTS_ERR_HOST_CANCELLED;
	int bad = bad_rc(3);
	if (bad != NTS_OK)
		return bad;
	if (fz_pick(&in, 12) == 11)
		return NTS_ERR_HOST;
	uint64_t recv = nts_ntp_from_unix_nanos(now + true_off + 500000 + (int64_t)fz_pick(&in, 5) * 1000000);
	c->nq = 1 + fz_pick(&in, QLEN);
	for (int k = 0; k < c->nq; k++) {
		uint8_t *q = c->q[k];
		size_t len = 0;
		switch (fz_pick(&in, 10)) {
		case 0:
		case 1:
		case 2:
			len = fz_plain_answer(p + 40, 2, "", recv, recv + 1000000, q);
			break;
		case 3:
			len = fz_plain_answer(p + 40, 2, "", recv, recv + 1000000, q);
			len += fz_bytes(&in, q + len, 40);
			break;
		case 4:
			len = fz_plain_answer(p + 40, 2, "", recv, recv + 1000000, q);
			mutate(q, len);
			break;
		case 5:
			len = fz_bytes(&in, q, 1300);
			break;
		case 6:
			len = fz_plain_answer(p + 40, 0, (const char *[]){"RATE", "DENY", "RSTR", "NTSN", "NTS\0", "STEP"}[fz_pick(&in, 6)], recv, recv, q);
			break;
		case 7:
			len = 0; /* nothing comes */
			break;
		case 8: {
			/* A forged time: seconds to years off, either way. */
			uint64_t off = (uint64_t)((int64_t)fz_u8(&in) - 128) << (32 + fz_pick(&in, 24));
			len = fz_plain_answer(p + 40, (uint8_t)(1 + fz_pick(&in, 16)), "", recv + off, recv + off + 1000000, q);
			break;
		}
		default:
			len = fz_plain_answer(p + 40, (uint8_t)fz_pick(&in, 17), "FUZZ", recv + ((uint64_t)fz_u8(&in) << 32), recv, q);
		}
		c->qlen[k] = len;
	}
	return NTS_OK;
}

static int h_udp_send(void *ctx, void *sock, const uint8_t *p, size_t n)
{
	(void)ctx;
	struct conn *c = sock;
	fz_request r;
	if (plain)
		return plain_send(c, p, n);
	FUZZ_CHECK(fz_read_request(p, n, &r) && n <= NTS_MAX_REQUEST_LEN && r.placeholders <= NTS_MAX_PLACEHOLDERS);
	if (cancelled())
		return NTS_ERR_HOST_CANCELLED;
	int bad = bad_rc(3);
	if (bad != NTS_OK)
		return bad;
	if (fz_pick(&in, 12) == 11)
		return NTS_ERR_HOST;
	uint64_t recv = nts_ntp_from_unix_nanos(now + true_off + 500000 + (int64_t)fz_pick(&in, 5) * 1000000);
	c->nq = 1 + fz_pick(&in, QLEN);
	for (int k = 0; k < c->nq; k++) {
		uint8_t *q = c->q[k];
		size_t cap = NTS_MAX_RESPONSE_LEN + 64, len = 0;
		const nts_siv_key *key = &srv_s2c[c->server];
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
			len = fz_server_answer(key, &r, 0, (const char *[]){"RATE", "DENY", "RSTR", "NTSN", "STEP", "NTS\0"}[fz_pick(&in, 6)], fz_pick(&in, 2), recv, recv,
					       0, q, cap);
			break;
		case 7:
			len = 0; /* nothing comes */
			break;
		case 8:
			len = fz_server_answer(&srv_s2c[(c->server + 1) % NSERV], &r, 2, "", false, recv, recv + 1000000, ncookies, q, cap);
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
	if (cancelled())
		return NTS_ERR_HOST_CANCELLED;
	int bad = bad_rc(4);
	if (bad != NTS_OK)
		return bad;
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
	core = malloc(nts_core_size_for(NSERV));
	FUZZ_CHECK(core != NULL);
	for (int i = 0; i < NSERV; i++) {
		fz_key(keys_c2s[i], (uint8_t)(1 + i));
		fz_key(keys_s2c[i], (uint8_t)(11 + i));
		FUZZ_CHECK(nts_siv_init(&srv_s2c[i], keys_s2c[i], NTS_KEY_LEN) == NTS_OK);
	}
}

/* Server s of the world as the core is given it; alt is another host
 * name for it (a changed server: a new peer to the core). */
static void server(nts_server *s, int i, int alt)
{
	memset(s, 0, sizeof *s);
	s->op[0] = (char)('a' + i);
	s->op_len = 1;
	memcpy(s->host, "nts-x0.test", 11);
	s->host[4] = (char)('a' + i);
	s->host[5] = (char)('0' + alt);
	s->host_len = 11;
	s->roots[0] = 'x';
	s->roots_len = 1;
	if (i % 2) {
		memcpy(s->ntp_addr, "192.0.2.0:123", 13);
		s->ntp_addr[8] = (char)('0' + i);
		s->ntp_addr_len = 13;
	}
}

static void start(void)
{
	static nts_config cfg;
	static const nts_host_ops ops = {NULL, h_random, h_monotonic, h_key_exchange, h_udp_open, h_udp_send, h_udp_recv, h_udp_close};
	memset(&cfg, 0, sizeof cfg);
	nlist = (flags & F_CONFIG) ? 3 + (size_t)fz_pick(&in, NSERV - 2) : 3;
	cfg.nservers = nlist;
	for (size_t i = 0; i < nlist; i++) {
		server(&list[i], (int)i, 0);
		cfg.servers[i] = list[i];
	}
	max_bound = 100000000LL;
	cfg.interval_ns = 2000000000LL;
	cfg.min_poll_ns = 1000000000LL;
	cfg.max_poll_ns = 64000000000LL;
	cfg.max_bound_ns = max_bound;
	cfg.max_age_ns = 5000000000LL;
	cfg.max_coarse_diff_ns = 30000000000LL;
	cfg.coarse_resolution_ns = 1000000000LL;
	cfg.exchange_timeout_ns = 1000000000LL;
	cfg.kiss_grace_ns = 100000000LL;
	cfg.drift_baseline_polls = 4;
	cfg.floor_unix_ns = 1790812800LL * 1000000000LL; /* 2026-10-01 */
	cfg.start_wait_ns = 10000000000LL;
	cfg.query_timeout_ns = fz_pick(&in, 4) == 3 ? 300000000LL : 0;
	plain = (flags & F_PLAIN) && nts_plain_supported();
	cfg.protocol = plain ? NTS_PROTO_NTP : NTS_PROTO_NTS;
	FUZZ_CHECK(nts_core_init(core, &ops, &cfg, nts_core_size_for(NSERV)) == NTS_OK);
}

static nts_status st, st2;

/* What a refused configuration call must leave as it was. */
static void unchanged(void)
{
	nts_status_get(core, &st2);
	FUZZ_CHECK(st2.npeers == st.npeers && st2.have_result == st.have_result && st2.members == st.members && st2.protocol == st.protocol);
	FUZZ_CHECK(st2.at == st.at && st2.offset == st.offset && st2.cold == st.cold && st2.era_pivot == st.era_pivot);
	for (size_t i = 0; i < st.npeers; i++)
		FUZZ_CHECK(st2.peers[i].cookies == st.peers[i].cookies && st2.peers[i].have_sample == st.peers[i].have_sample &&
			   st2.peers[i].next_poll == st.peers[i].next_poll);
}

static void set_servers(int64_t coarse, int64_t coarse_local)
{
	static nts_server next[NTS_MAX_SERVERS + 1];
	size_t n = 0;
	bool legal = true;
	nts_status_get(core, &st);
	int first = fz_pick(&in, NSERV);
	for (int k = 0; k < NSERV; k++) {
		int i = (first + k) % NSERV;
		if (fz_pick(&in, 4) == 3)
			continue;
		server(&next[n++], i, fz_pick(&in, 8) == 7 ? 1 + fz_pick(&in, 2) : 0);
	}
	switch (fz_pick(&in, 12)) {
	case 8: /* an operator named twice */
		if (n > 0 && n < NTS_MAX_SERVERS) {
			next[n] = next[0];
			next[n].host[5] = '9';
			n++;
			legal = false;
		}
		break;
	case 9: /* a host named twice */
		if (n > 1) {
			memcpy(next[1].host, next[0].host, next[0].host_len);
			legal = false;
		}
		break;
	case 10: /* more than the capacity */
		while (n <= NSERV) {
			server(&next[n], (int)n % NSERV, 0);
			next[n].op[0] = (char)('A' + n);
			next[n].host[4] = (char)('A' + n);
			n++;
		}
		legal = false;
		break;
	case 11: /* a length over its limit */
		if (n > 0) {
			next[n - 1].roots_len = NTS_MAX_ROOTS_LEN + 1;
			legal = false;
		}
		break;
	}
	excl++;
	int rc = nts_core_set_servers(core, next, n, coarse, coarse_local);
	excl--;
	if (!legal) {
		FUZZ_CHECK(rc == NTS_ERR_BAD_CONFIG);
		unchanged();
		return;
	}
	FUZZ_CHECK(rc == NTS_OK);
	memcpy(list, next, n * sizeof next[0]);
	nlist = n;
	nts_status_get(core, &st2);
	FUZZ_CHECK(st2.npeers == n && !st2.busy);
	FUZZ_CHECK(!st2.have_result || (n >= NTS_QUORUM_MIN_SERVERS && st2.members >> n == 0));
}

static void set_policy(int64_t coarse, int64_t coarse_local)
{
	static const int protos[] = {NTS_PROTO_NTS, NTS_PROTO_NTS, NTS_PROTO_NTP, 2, -1};
	static const int64_t bounds[] = {100000000LL, 50000000LL, 20000000LL, 0, -1};
	static const int64_t caps[] = {100000000LL, 100000000LL, 60000000LL, NTS_MAX_SAMPLE_BOUND_NS, NTS_MAX_SAMPLE_BOUND_NS + 1, 10000000LL};
	nts_status_get(core, &st);
	int proto = protos[fz_pick(&in, 5)];
	if (fz_pick(&in, 2))
		proto = st.protocol;
	int64_t bound = bounds[fz_pick(&in, 5)], cap = caps[fz_pick(&in, 6)];
	bool legal = (proto == NTS_PROTO_NTS || (proto == NTS_PROTO_NTP && nts_plain_supported())) && bound > 0 && cap >= bound &&
		     cap <= NTS_MAX_SAMPLE_BOUND_NS;
	excl++;
	int rc = nts_core_set_policy(core, proto, bound, cap, coarse, coarse_local);
	excl--;
	if (!legal) {
		FUZZ_CHECK(rc == NTS_ERR_BAD_CONFIG);
		unchanged();
		return;
	}
	FUZZ_CHECK(rc == NTS_OK);
	nts_status_get(core, &st2);
	FUZZ_CHECK(st2.protocol == proto && st2.npeers == st.npeers);
	if (proto != st.protocol) {
		FUZZ_CHECK(!st2.have_result && !st2.have_drift);
		for (size_t i = 0; i < st2.npeers; i++)
			FUZZ_CHECK(!st2.peers[i].have_sample && st2.peers[i].cookies == 0);
	}
	plain = proto == NTS_PROTO_NTP;
	max_bound = bound;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	static bool ready;
	if (!ready) {
		setup();
		ready = true;
	}
	in.p = data;
	in.n = size;
	rng_state = 0x9e3779b97f4a7c15ULL ^ size;
	flags = fz_u8(&in);
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
		switch (fz_pick(&in, 8)) {
		case 7:
			coarse_err = ((int64_t)fz_u8(&in) - 128) * 3600000000000LL;
			break;
		case 6:
			coarse_err += (int64_t)(fz_pick(&in, 2) * 2 - 1) * (4294967296LL * 1000000000LL); /* an NTP era off */
			break;
		}
		int64_t coarse_local = now, coarse = now + true_off + coarse_err;
		if (flags & F_CONFIG)
			switch (fz_pick(&in, 8)) {
			case 6:
				set_servers(coarse, coarse_local);
				break;
			case 7:
				set_policy(coarse, coarse_local);
				break;
			}
		uint32_t due = nts_due(core, now);
		FUZZ_CHECK(nlist == NTS_MAX_SERVERS || due >> nlist == 0);
		for (size_t i = 0; i < nlist; i++) {
			if (!(due & (1u << i)))
				continue;
			nts_peer_view was, v;
			FUZZ_CHECK(nts_peer_get(core, i, &was) == NTS_OK);
			bad_at = 0;
			int rc = nts_poll(core, i, coarse, coarse_local);
			FUZZ_CHECK(nts_peer_get(core, i, &v) == NTS_OK);
			FUZZ_CHECK(rc != NTS_ERR_BUSY);
			/* A code no host operation has is a failed host operation: from
			 * the socket's open or send that is the poll's outcome, from a
			 * receive too unless a Kiss-o'-Death read before it stands. */
			FUZZ_CHECK((bad_at != 2 && bad_at != 3) || rc == NTS_ERR_HOST);
			FUZZ_CHECK(bad_at != 4 || rc == NTS_ERR_HOST || rc == NTS_ERR_KISS);
			/* A wide answer and a kiss are the core's findings: counted
			 * when the poll ends with them, and only then. */
			FUZZ_CHECK(v.stats.wide - was.stats.wide == (rc == NTS_ERR_SAMPLE_WIDE));
			FUZZ_CHECK((v.stats.kiss_rate + v.stats.kiss_ntsn + v.stats.kiss_deny + v.stats.kiss_rstr + v.stats.kiss_other) -
					   (was.stats.kiss_rate + was.stats.kiss_ntsn + was.stats.kiss_deny + was.stats.kiss_rstr + was.stats.kiss_other) ==
				   (rc == NTS_ERR_KISS));
			FUZZ_CHECK(v.cookies >= 0 && v.cookies <= NTS_MAX_COOKIES);
			FUZZ_CHECK(!plain || (v.cookies == 0 && !v.need_ke));
			FUZZ_CHECK(rc != NTS_ERR_HOST_CANCELLED || (flags & F_CANCEL));
			FUZZ_CHECK(rc != NTS_OK || (v.have_sample && v.sample.bound <= NTS_MAX_SAMPLE_BOUND_NS));
		}
		FUZZ_CHECK(nts_poll(core, nlist, coarse, coarse_local) == NTS_ERR_BAD_CONFIG);
		excl++;
		int rc = nts_combine(core, coarse, coarse_local);
		FUZZ_CHECK(rc != NTS_ERR_BUSY);
		nts_status_get(core, &st);
		excl--;
		FUZZ_CHECK(!st.busy && st.npeers == nlist && st.protocol == (plain ? NTS_PROTO_NTP : NTS_PROTO_NTS));
		if (st.have_result) {
			int members = 0;
			for (size_t i = 0; i < nlist; i++)
				members += (st.members >> i) & 1;
			FUZZ_CHECK(members >= NTS_QUORUM_MIN_SERVERS && st.members >> nlist == 0);
			FUZZ_CHECK(st.max_wrong <= nts_quorum_wrong((size_t)members) && st.worst >= st.bound);
		}
		int64_t t, bound;
		if (nts_bounded(core, &t, &bound) == NTS_OK) {
			FUZZ_CHECK(t >= highest);
			FUZZ_CHECK(bound >= 0 && bound <= max_bound);
			FUZZ_CHECK(t >= 1790812800LL * 1000000000LL);
			highest = t;
		}
	}
	FUZZ_CHECK(nts_core_wipe(core) == NTS_OK);
	return 0;
}
