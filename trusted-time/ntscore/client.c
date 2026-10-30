/* The client: the associations (keys and cookies) of the servers, one
 * poll of a server (NTS-KE when needed, then one authenticated query with
 * the Kiss-o'-Death policy and the backoff), the quorum of the fresh
 * samples with the coarse and the drift checks, and the time served from
 * the quorum in force, aged by rho. Everything here was the Go clock's
 * (trusted-time/clock) and query's (trusted-time/nts) logic; it moved in
 * so that the wrapper hands the core nothing but bytes from the network.
 *
 *   - Each server is asked every interval_ns (at least min_poll_ns apart);
 *     a query gets exchange_timeout_ns or half the interval, whichever is
 *     shorter. An authenticated Kiss-o'-Death RATE doubles that server's
 *     interval up to max_poll_ns (RFC 5905 section 7.4); each good answer
 *     halves it back. An authenticated DENY or RSTR costs the server
 *     max_poll_ns of silence and a new NTS-KE, after which it is asked
 *     again (RFC 5905 section 7.4 says to stop; a forged one would
 *     otherwise take a server out until restart). An unauthenticated
 *     Kiss-o'-Death is only counted. NTSN keeps the cookies in hand and
 *     NTS-KE runs again when they run out (RFC 8915 section 5.7). NTS-KE
 *     failures back off from the interval to max_poll_ns.
 *   - The latest sample of each server, at most 4 intervals old, goes to
 *     the quorum (one server may be wrong). The result is an offset from
 *     the local monotonic clock and an error bound.
 *   - Between quorums the bound grows by NTS_RHO_PPM of the elapsed
 *     monotonic time. nts_bounded refuses once it is over max_bound_ns,
 *     so the signer refuses rather than signs on a time it cannot vouch
 *     for.
 *   - Aging by rho holds only if the local clock keeps within rho of real
 *     time. Each quorum is checked against the last one and against a
 *     baseline quorum about drift_baseline_polls intervals older; if the
 *     offset moved more than the two bounds and rho allow, the quorum is
 *     refused and the time with it until the next quorum agrees with it.
 *     The short pair catches jumps, the long pair a steady rate over rho
 *     that the bounds hide on a short pair.
 *   - The coarse time is checked on every quorum: an NTS time more than
 *     max_coarse_diff_ns from it, after its resolution, is refused. It
 *     also dates the certificates of NTS-KE before the first quorum. The
 *     NTP era comes from floor_unix_ns, never from it.
 *   - The time never goes back. */
#include <string.h>

#include "nts_core.h"

typedef __int128 i128;

struct peer {
	bool have_keys;
	nts_siv_key c2s, s2c;
	int ncookies; /* oldest first; each used once */
	size_t cookie_len[NTS_MAX_COOKIES];
	uint8_t cookies[NTS_MAX_COOKIES][NTS_MAX_COOKIE_LEN];
	char ntp_addr[NTS_MAX_ADDR_LEN];
	size_t ntp_addr_len;
	bool have_sample;
	nts_sample sample;
	int64_t poll_ns, next_poll, ke_wait_ns, next_ke;
	char disabled[4];
	bool is_disabled;
	int last_err, last_detail;
	char last_kiss[4];
	bool last_kiss_authentic;
	nts_peer_stats stats;
	/* Scratch of a poll, here so that a poll needs little stack. */
	uint8_t ke_resp[NTS_KE_MAX_RESPONSE_LEN];
	nts_ke_response ke;
	uint8_t request[NTS_MAX_REQUEST_LEN];
	uint8_t packet[NTS_MAX_RESPONSE_LEN + 1]; /* one over the cap, so an oversized answer is seen as such */
	nts_verdict verdict;
};

struct result {
	int64_t offset, bound, at, lo, hi;
	uint32_t members;
};

struct nts_core {
	nts_config cfg;
	nts_host_ops ops;
	struct peer peers[NTS_MAX_SERVERS];
	bool have_result;
	struct result result;
	/* The quorums of the drift check, oldest first: the last one (served
	 * or refused) at the end, the baseline at index 0. A refused quorum
	 * starts a new history. */
	struct result hist[NTS_MAX_HIST];
	size_t nhist;
	bool have_highest;
	int64_t highest;
	bool have_drift;
	int64_t drift_delta, drift_dt, drift_bounds;
	int64_t violations, refusals;
	bool have_coarse_diff;
	int64_t coarse_diff;
	int last_err, last_detail;
	size_t last_fresh;
	bool members_changed;
};

size_t nts_core_size(void) { return sizeof(nts_core); }

static int64_t imin(int64_t a, int64_t b) { return a < b ? a : b; }
static int64_t imax(int64_t a, int64_t b) { return a > b ? a : b; }
static int64_t sat(i128 v) { return v > INT64_MAX ? INT64_MAX : v < INT64_MIN ? INT64_MIN : (int64_t)v; }
static int64_t mono(const nts_core *c) { return c->ops.monotonic(c->ops.ctx); }

int nts_core_init(nts_core *c, const nts_host_ops *ops, const nts_config *cfg)
{
	if (!ops->random || !ops->monotonic || !ops->key_exchange || !ops->udp_open || !ops->udp_send || !ops->udp_recv || !ops->udp_close)
		return NTS_ERR_BAD_CONFIG;
	if (cfg->nservers > NTS_MAX_SERVERS || cfg->interval_ns <= 0 || cfg->min_poll_ns <= 0 || cfg->max_poll_ns <= 0 ||
	    cfg->max_bound_ns <= 0 || cfg->max_coarse_diff_ns < 0 || cfg->coarse_resolution_ns < 0 || cfg->exchange_timeout_ns <= 0 ||
	    cfg->kiss_grace_ns < 0 || cfg->drift_baseline_polls < 1)
		return NTS_ERR_BAD_CONFIG;
	for (size_t i = 0; i < cfg->nservers; i++) {
		const nts_server *s = &cfg->servers[i];
		if (s->op_len < 1 || s->op_len > NTS_MAX_OPERATOR_LEN || s->host_len < 1 || s->host_len > NTS_MAX_HOST_LEN ||
		    s->ke_addr_len > NTS_MAX_ADDR_LEN || s->roots_len > NTS_MAX_ROOTS_LEN)
			return NTS_ERR_BAD_CONFIG;
	}
	memset(c, 0, sizeof *c);
	c->cfg = *cfg;
	c->ops = *ops;
	for (size_t i = 0; i < cfg->nservers; i++)
		c->peers[i].poll_ns = imax(cfg->interval_ns, cfg->min_poll_ns);
	return NTS_OK;
}

/* Drops the keys and wipes the cookies of one peer. */
static void wipe_assoc(struct peer *p)
{
	memset(&p->c2s, 0, sizeof p->c2s);
	memset(&p->s2c, 0, sizeof p->s2c);
	memset(p->cookies, 0, sizeof p->cookies);
	memset(p->cookie_len, 0, sizeof p->cookie_len);
	p->ncookies = 0;
	p->have_keys = false;
}

void nts_core_wipe(nts_core *c)
{
	for (size_t i = 0; i < c->cfg.nservers; i++)
		wipe_assoc(&c->peers[i]);
}

uint32_t nts_due(const nts_core *c, int64_t now)
{
	uint32_t due = 0;
	for (size_t i = 0; i < c->cfg.nservers; i++)
		if (now >= c->peers[i].next_poll)
			due |= (uint32_t)1 << i;
	return due;
}

/* ---- The cookie jar (RFC 8915 section 5.7: each cookie goes out once) ---- */

/* Takes the oldest cookie out of the jar. */
static void jar_take(struct peer *p, uint8_t *cookie, size_t *len)
{
	*len = p->cookie_len[0];
	memcpy(cookie, p->cookies[0], *len);
	memmove(p->cookies[0], p->cookies[1], sizeof p->cookies[0] * (NTS_MAX_COOKIES - 1));
	memmove(&p->cookie_len[0], &p->cookie_len[1], sizeof p->cookie_len[0] * (NTS_MAX_COOKIES - 1));
	p->ncookies--;
	memset(p->cookies[p->ncookies], 0, sizeof p->cookies[0]);
	p->cookie_len[p->ncookies] = 0;
}

/* Puts a cookie that never left the process back at the front. */
static void jar_return(struct peer *p, const uint8_t *cookie, size_t len)
{
	if (p->ncookies >= NTS_MAX_COOKIES)
		return;
	memmove(p->cookies[1], p->cookies[0], sizeof p->cookies[0] * (NTS_MAX_COOKIES - 1));
	memmove(&p->cookie_len[1], &p->cookie_len[0], sizeof p->cookie_len[0] * (NTS_MAX_COOKIES - 1));
	memcpy(p->cookies[0], cookie, len);
	p->cookie_len[0] = len;
	p->ncookies++;
}

/* Adds the cookies of an authentic response, newest last, and drops the
 * oldest beyond NTS_MAX_COOKIES. */
static void jar_keep(struct peer *p, int n, const size_t *lens, const uint8_t cookies[][NTS_MAX_COOKIE_LEN])
{
	for (int i = 0; i < n; i++) {
		if (p->ncookies == NTS_MAX_COOKIES) {
			memmove(p->cookies[0], p->cookies[1], sizeof p->cookies[0] * (NTS_MAX_COOKIES - 1));
			memmove(&p->cookie_len[0], &p->cookie_len[1], sizeof p->cookie_len[0] * (NTS_MAX_COOKIES - 1));
			p->ncookies--;
		}
		memcpy(p->cookies[p->ncookies], cookies[i], lens[i]);
		p->cookie_len[p->ncookies] = lens[i];
		p->ncookies++;
	}
}

/* ---- The key exchange ---- */

/* host:port, an IPv6 literal in brackets (as Go's net.JoinHostPort). */
static void set_ntp_addr(struct peer *p, const char *host, size_t hostlen, uint16_t port)
{
	size_t at = 0;
	bool v6 = memchr(host, ':', hostlen) != NULL;
	char digits[6];
	int nd = 0;
	if (v6)
		p->ntp_addr[at++] = '[';
	memcpy(p->ntp_addr + at, host, hostlen);
	at += hostlen;
	if (v6)
		p->ntp_addr[at++] = ']';
	p->ntp_addr[at++] = ':';
	do {
		digits[nd++] = (char)('0' + port % 10);
		port /= 10;
	} while (port);
	while (nd)
		p->ntp_addr[at++] = digits[--nd];
	p->ntp_addr_len = at;
}

/* The core's own Unix time at the monotonic time now, or the coarse
 * reading moved forward before the first quorum. */
static int64_t unix_now(const nts_core *c, int64_t now, int64_t coarse_unix, int64_t coarse_local)
{
	if (c->have_result)
		return sat((i128)now + c->result.offset);
	return sat((i128)coarse_unix + ((i128)now - coarse_local));
}

static int key_exchange(nts_core *c, size_t i, int64_t now, int64_t coarse_unix, int64_t coarse_local)
{
	struct peer *p = &c->peers[i];
	const nts_server *srv = &c->cfg.servers[i];
	uint8_t req[NTS_KE_REQUEST_LEN], c2s[NTS_KEY_LEN], s2c[NTS_KEY_LEN];
	size_t resplen = 0;
	int64_t elapsed = 0;
	int detail = 0;
	nts_ke_request(req);
	int rc = c->ops.key_exchange(c->ops.ctx, i, srv, unix_now(c, now, coarse_unix, coarse_local), c->cfg.exchange_timeout_ns, req, sizeof req,
				     p->ke_resp, sizeof p->ke_resp, &resplen, c2s, s2c, &elapsed);
	if (rc == NTS_OK && resplen > sizeof p->ke_resp)
		rc = NTS_ERR_HOST;
	if (rc == NTS_OK) {
		rc = nts_ke_parse(p->ke_resp, resplen, &p->ke);
		detail = p->ke.detail;
	}
	if (rc == NTS_OK)
		rc = nts_siv_init(&p->c2s, c2s, sizeof c2s);
	if (rc == NTS_OK)
		rc = nts_siv_init(&p->s2c, s2c, sizeof s2c);
	memset(c2s, 0, sizeof c2s);
	memset(s2c, 0, sizeof s2c);
	if (rc == NTS_OK) {
		memcpy(p->cookies, p->ke.cookies, sizeof p->cookies);
		memcpy(p->cookie_len, p->ke.cookie_len, sizeof p->cookie_len);
		p->ncookies = p->ke.ncookies;
		p->have_keys = true;
		/* RFC 8915 sections 4.1.7, 4.1.8: the server named, else the KE
		 * host; the port named, else 123. */
		if (p->ke.server_len)
			set_ntp_addr(p, p->ke.server, p->ke.server_len, p->ke.port ? p->ke.port : 123);
		else
			set_ntp_addr(p, srv->host, srv->host_len, p->ke.port ? p->ke.port : 123);
	}
	memset(&p->ke, 0, sizeof p->ke);
	memset(p->ke_resp, 0, sizeof p->ke_resp);
	if (rc != NTS_OK) {
		wipe_assoc(p);
		p->stats.ke_fail++;
		p->last_err = rc;
		p->last_detail = detail;
		p->ke_wait_ns = imin(imax(2 * p->ke_wait_ns, c->cfg.interval_ns), c->cfg.max_poll_ns);
		p->next_ke = now + p->ke_wait_ns;
		return rc;
	}
	p->stats.ke_ok++;
	p->stats.last_ke_ns = elapsed;
	p->stats.cookies_after_ke = p->ncookies;
	p->ke_wait_ns = 0;
	return NTS_OK;
}

/* ---- One query ---- */

/* The outcome of a query. */
struct outcome {
	int rc, detail; /* NTS_OK with a sample; NTS_ERR_KISS; or what refused */
	char kiss[4];
	bool kiss_authentic;
};

/* Sends one request with the oldest cookie and reads until an answer is
 * ours and authentic, a Kiss-o'-Death with our Unique Identifier arrives
 * and nothing authentic follows it within kiss_grace_ns, or the time runs
 * out: a datagram that fails the check may be a forgery (one sent before
 * the real answer, say), so it is dropped and the real answer can still
 * come. T1 and T4 come from the monotonic clock; the pivot of the NTP era
 * is floor_unix_ns. The cookies of an authentic response are kept even if
 * the measurement is refused: they are good for the next one. */
static void query(nts_core *c, size_t i, struct outcome *o)
{
	struct peer *p = &c->peers[i];
	uint8_t rnd[NTS_REQUEST_RANDOM_LEN], cookie[NTS_MAX_COOKIE_LEN];
	size_t cookielen = 0, reqlen = 0;
	nts_pending pending;
	void *sock = NULL;
	int64_t timeout = imin(c->cfg.exchange_timeout_ns, c->cfg.interval_ns / 2);
	if (timeout <= 0)
		timeout = c->cfg.exchange_timeout_ns;
	memset(o, 0, sizeof *o);
	if (p->ncookies == 0) {
		o->rc = NTS_ERR_NO_COOKIE;
		return;
	}
	if (c->ops.random(c->ops.ctx, rnd, sizeof rnd) != NTS_OK) {
		o->rc = NTS_ERR_HOST_RANDOM;
		return;
	}
	jar_take(p, cookie, &cookielen);
	/* The jar holds this cookie no more, so the response should bring
	 * NTS_MAX_COOKIES - held new ones: one for the cookie, the rest for
	 * the placeholders, within the size limit. */
	int placeholders = NTS_MAX_COOKIES - 1 - p->ncookies;
	if (placeholders < 0)
		placeholders = 0;
	int most = nts_max_placeholders(cookielen);
	if (placeholders > most)
		placeholders = most;
	uint64_t transmit = 0;
	for (int k = 0; k < 8; k++)
		transmit = transmit << 8 | rnd[k];
	int rc = nts_build_request(&p->c2s, transmit, rnd + 8, rnd + 8 + NTS_UID_LEN, cookie, cookielen, placeholders, p->request, sizeof p->request,
				   &reqlen, &pending);
	memset(rnd, 0, sizeof rnd);
	if (rc != NTS_OK) {
		jar_return(p, cookie, cookielen);
		memset(cookie, 0, sizeof cookie);
		o->rc = rc;
		return;
	}
	rc = c->ops.udp_open(c->ops.ctx, i, p->ntp_addr, p->ntp_addr_len, timeout, &sock);
	if (rc != NTS_OK) {
		jar_return(p, cookie, cookielen);
		memset(cookie, 0, sizeof cookie);
		o->rc = rc;
		return;
	}
	int64_t t1 = mono(c);
	rc = c->ops.udp_send(c->ops.ctx, sock, p->request, reqlen);
	if (rc != NTS_OK) {
		jar_return(p, cookie, cookielen);
		memset(cookie, 0, sizeof cookie);
		c->ops.udp_close(c->ops.ctx, sock);
		o->rc = rc;
		return;
	}
	memset(cookie, 0, sizeof cookie);
	memset(p->request, 0, sizeof p->request);
	int64_t deadline = t1 + timeout;
	bool have_kiss = false;
	int last = NTS_OK;
	for (;;) {
		size_t n = 0;
		int64_t wait = deadline - mono(c);
		rc = wait > 0 ? c->ops.udp_recv(c->ops.ctx, sock, p->packet, sizeof p->packet, &n, wait) : NTS_ERR_HOST_TIMEOUT;
		int64_t t4 = mono(c);
		if (rc != NTS_OK || n > sizeof p->packet) {
			if (have_kiss) {
				/* Nothing authentic followed the Kiss-o'-Death: it stands. */
				o->rc = NTS_ERR_KISS;
				break;
			}
			o->rc = rc == NTS_OK ? NTS_ERR_HOST : rc;
			o->detail = last; /* the last refusal, named in the timeout */
			break;
		}
		rc = nts_verify_response(&pending, &p->s2c, p->packet, n, &p->verdict);
		if (rc != NTS_OK) {
			last = rc;
			continue;
		}
		if (p->verdict.kind == NTS_KIND_KISS) {
			/* A Kiss-o'-Death does not end the query: a forged one may come
			 * before the real answer. The query reads on for the grace, or
			 * to its deadline if that is sooner, and reports the KoD only
			 * if nothing authentic follows. */
			have_kiss = true;
			memcpy(o->kiss, p->verdict.kiss, 4);
			o->kiss_authentic = p->verdict.kiss_authentic;
			deadline = imin(deadline, t4 + c->cfg.kiss_grace_ns);
			continue;
		}
		jar_keep(p, p->verdict.time.ncookies, p->verdict.time.cookie_len, p->verdict.time.cookies);
		rc = nts_measure(&p->verdict.time, t1, t4, c->cfg.floor_unix_ns, &p->sample);
		if (rc != NTS_OK) {
			o->rc = rc;
			o->detail = p->sample.detail;
			break;
		}
		p->sample.cookies_held = p->ncookies;
		o->rc = NTS_OK;
		break;
	}
	memset(&p->verdict, 0, sizeof p->verdict);
	memset(p->packet, 0, sizeof p->packet);
	c->ops.udp_close(c->ops.ctx, sock);
}

int nts_poll(nts_core *c, size_t i, int64_t coarse_unix_ns, int64_t coarse_local)
{
	if (i >= c->cfg.nservers)
		return NTS_ERR_BAD_CONFIG;
	struct peer *p = &c->peers[i];
	int64_t now = mono(c);
	if (!p->have_keys || p->ncookies == 0) {
		wipe_assoc(p);
		if (now < p->next_ke)
			return NTS_ERR_NOT_DUE;
		int rc = key_exchange(c, i, now, coarse_unix_ns, coarse_local);
		if (rc != NTS_OK)
			return rc;
	}
	struct outcome o;
	query(c, i, &o);
	now = mono(c);
	p->stats.queries++;
	p->stats.cookies_held = p->ncookies;
	p->next_poll = now + p->poll_ns;
	p->last_err = o.rc;
	p->last_detail = o.detail;
	switch (o.rc) {
	case NTS_ERR_KISS:
		/* A Kiss-o'-Death may be forged: the fields it must match travel in
		 * the clear, so anyone on the path who saw the request can send
		 * one, and only a server that holds the cookie's keys can
		 * authenticate one (never an NTSN: it says the server has no keys
		 * for that cookie). An unauthenticated KoD changes nothing but the
		 * count: the next poll comes at its time with the next cookie, and
		 * NTS-KE runs when the cookies run out, as RFC 8915 section 5.7
		 * asks. An authenticated one is obeyed: RATE doubles the poll,
		 * DENY and RSTR cost this server max_poll_ns of silence and a new
		 * key exchange, never the rest of the process. A forger gains no
		 * more than dropping the answers would give. */
		memcpy(p->last_kiss, o.kiss, 4);
		p->last_kiss_authentic = o.kiss_authentic;
		if (memcmp(o.kiss, "RATE", 4) == 0)
			p->stats.kiss_rate++;
		else if (memcmp(o.kiss, "NTSN", 4) == 0)
			p->stats.kiss_ntsn++;
		else if (memcmp(o.kiss, "DENY", 4) == 0)
			p->stats.kiss_deny++;
		else if (memcmp(o.kiss, "RSTR", 4) == 0)
			p->stats.kiss_rstr++;
		else
			p->stats.kiss_other++;
		if (!o.kiss_authentic)
			break;
		if (memcmp(o.kiss, "RATE", 4) == 0) {
			p->poll_ns = imin(2 * p->poll_ns, c->cfg.max_poll_ns);
			p->next_poll = now + p->poll_ns;
		} else if (memcmp(o.kiss, "DENY", 4) == 0 || memcmp(o.kiss, "RSTR", 4) == 0) {
			memcpy(p->disabled, o.kiss, 4);
			p->is_disabled = true;
			p->have_sample = false;
			memset(&p->sample, 0, sizeof p->sample);
			p->poll_ns = c->cfg.max_poll_ns;
			p->next_poll = now + p->poll_ns;
			wipe_assoc(p);
		}
		break;
	case NTS_OK:
		p->stats.samples++;
		p->have_sample = true;
		p->is_disabled = false;
		memset(p->disabled, 0, sizeof p->disabled);
		p->poll_ns = imax(p->poll_ns / 2, imax(c->cfg.interval_ns, c->cfg.min_poll_ns));
		p->stats.last_delay_ns = p->sample.delay;
		p->stats.last_bound_ns = p->sample.bound;
		break;
	default:
		p->stats.errors++;
	}
	return o.rc;
}

/* ---- The quorum, the checks, the time ---- */

bool nts_coarse_refused(int64_t diff, int64_t limit, int64_t res)
{
	/* The coarse reading truncates real time to whole seconds, so real
	 * time at the coarse source was in [coarse, coarse + res). NTS is
	 * accepted if some point of that range lies within limit of it:
	 * -limit <= diff < limit + res. */
	return diff < -limit || diff >= nts_add_bound(limit, res);
}

int nts_combine(nts_core *c, int64_t coarse_unix_ns, int64_t coarse_local)
{
	nts_interval in[NTS_MAX_SERVERS];
	uint32_t members = 0;
	size_t n = 0;
	int64_t now = mono(c);
	i128 max_age = (i128)4 * c->cfg.interval_ns;
	c->members_changed = false;
	for (size_t i = 0; i < c->cfg.nservers; i++) {
		const struct peer *p = &c->peers[i];
		if (!p->have_sample || (i128)now - p->sample.t4 > max_age)
			continue;
		in[n].op = c->cfg.servers[i].op;
		in[n].oplen = c->cfg.servers[i].op_len;
		in[n].offset = p->sample.offset;
		in[n].bound = p->sample.bound;
		in[n].t4 = p->sample.t4;
		members |= (uint32_t)1 << i;
		n++;
	}
	c->last_fresh = n;
	nts_quorum_result q;
	int rc = nts_quorum(in, n, now, &q);
	if (rc != NTS_OK) {
		c->last_err = rc;
		c->last_detail = 0;
		return rc;
	}
	/* The coarse reading was taken before the polls: move it forward by
	 * the local time since then. */
	i128 t = (i128)now + q.offset;
	int64_t diff = sat(t - ((i128)coarse_unix_ns + ((i128)now - coarse_local)));
	c->coarse_diff = diff;
	c->have_coarse_diff = true;
	if (nts_coarse_refused(diff, c->cfg.max_coarse_diff_ns, c->cfg.coarse_resolution_ns)) {
		c->last_err = NTS_ERR_COARSE_CHECK;
		c->last_detail = 0;
		return NTS_ERR_COARSE_CHECK;
	}
	struct result cur = {.offset = q.offset, .bound = q.bound, .at = now, .lo = q.lo, .hi = q.hi, .members = members};
	/* The bound grows by rho only if the local clock keeps within rho of
	 * real time. Check that against the last quorum and the baseline: both
	 * intervals of a pair hold the real offset (one server at most wrong
	 * in each), and it can move by at most rho times the time between
	 * them. If a pair does not fit, the local clock broke rho (or more
	 * servers are wrong): this quorum is not served, a new history starts
	 * with it, and the next quorum must agree with it first. */
	const struct result *refs[2];
	size_t nrefs = 0;
	if (c->nhist > 0) {
		refs[nrefs++] = &c->hist[c->nhist - 1];
		if (c->nhist > 1)
			refs[nrefs++] = &c->hist[0];
	}
	for (size_t k = 0; k < nrefs; k++) {
		const struct result *ref = refs[k];
		if (now <= ref->at)
			continue;
		i128 dt = (i128)now - ref->at;
		i128 delta = (i128)cur.offset - ref->offset;
		int64_t allowed = nts_add_bound(nts_add_bound(ref->bound, nts_drift(sat(dt))), cur.bound);
		bool failed = (delta < 0 ? -delta : delta) > allowed;
		/* The status shows the longest pair, or the pair that failed. */
		if (k == nrefs - 1 || failed) {
			c->have_drift = true;
			c->drift_delta = sat(delta);
			c->drift_dt = sat(dt);
			c->drift_bounds = nts_add_bound(ref->bound, cur.bound);
		}
		if (failed) {
			c->hist[0] = cur;
			c->nhist = 1;
			c->have_result = false;
			c->violations++;
			c->last_err = NTS_ERR_DRIFT;
			c->last_detail = 0;
			return NTS_ERR_DRIFT;
		}
	}
	/* Keep the newest quorum at least the baseline old as hist[0], and
	 * drop the ones before it. */
	if (c->nhist == NTS_MAX_HIST) {
		memmove(&c->hist[1], &c->hist[2], sizeof c->hist[0] * (NTS_MAX_HIST - 2));
		c->nhist--;
	}
	c->hist[c->nhist++] = cur;
	i128 baseline = (i128)c->cfg.drift_baseline_polls * c->cfg.interval_ns;
	while (c->nhist > 2 && (i128)now - c->hist[1].at >= baseline) {
		memmove(&c->hist[0], &c->hist[1], sizeof c->hist[0] * (c->nhist - 1));
		c->nhist--;
	}
	c->members_changed = !c->have_result || c->result.members != members;
	c->result = cur;
	c->have_result = true;
	c->last_err = NTS_OK;
	c->last_detail = 0;
	return NTS_OK;
}

int nts_bounded(nts_core *c, int64_t *unix_ns, int64_t *bound_ns)
{
	*unix_ns = 0;
	*bound_ns = 0;
	if (!c->have_result)
		return NTS_ERR_NO_QUORUM;
	int64_t now = mono(c);
	/* nts_add_bound saturates, and a negative bound is refused as well: a
	 * bound that wrapped around once let a quorum months old serve time
	 * again (TIME-BOUND-01). */
	int64_t bound = nts_add_bound(c->result.bound, nts_drift(sat((i128)now - c->result.at)));
	*bound_ns = bound;
	if (bound < 0 || bound > c->cfg.max_bound_ns) {
		c->refusals++;
		return NTS_ERR_BOUND_OVER_LIMIT;
	}
	int64_t t = sat((i128)now + c->result.offset);
	if (c->have_highest && t < c->highest)
		t = c->highest;
	c->highest = t;
	c->have_highest = true;
	*unix_ns = t;
	return NTS_OK;
}

void nts_summary_get(const nts_core *c, nts_status *st)
{
	memset(st, 0, sizeof *st);
	st->have_result = c->have_result;
	st->offset = c->result.offset;
	st->bound = c->result.bound;
	st->at = c->result.at;
	st->lo = c->result.lo;
	st->hi = c->result.hi;
	st->members = c->result.members;
	st->have_drift = c->have_drift;
	st->drift_delta = c->drift_delta;
	st->drift_dt = c->drift_dt;
	st->drift_bounds = c->drift_bounds;
	st->violations = c->violations;
	st->refusals = c->refusals;
	st->have_coarse_diff = c->have_coarse_diff;
	st->coarse_diff = c->coarse_diff;
	st->last_err = c->last_err;
	st->last_detail = c->last_detail;
	st->last_fresh = c->last_fresh;
	st->members_changed = c->members_changed;
	st->npeers = c->cfg.nservers;
}

static void peer_view(const struct peer *p, nts_peer_view *v)
{
	v->have_sample = p->have_sample;
	v->sample = p->sample;
	v->poll_ns = p->poll_ns;
	memcpy(v->disabled, p->disabled, 4);
	v->is_disabled = p->is_disabled;
	v->last_err = p->last_err;
	v->last_detail = p->last_detail;
	memcpy(v->last_kiss, p->last_kiss, 4);
	v->last_kiss_authentic = p->last_kiss_authentic;
	memcpy(v->ntp_addr, p->ntp_addr, p->ntp_addr_len);
	v->ntp_addr_len = p->ntp_addr_len;
	v->cookies = p->ncookies;
	v->stats = p->stats;
}

int nts_peer_get(const nts_core *c, size_t i, nts_peer_view *v)
{
	if (i >= c->cfg.nservers)
		return NTS_ERR_BAD_CONFIG;
	memset(v, 0, sizeof *v);
	peer_view(&c->peers[i], v);
	return NTS_OK;
}

void nts_status_get(const nts_core *c, nts_status *st)
{
	nts_summary_get(c, st);
	for (size_t i = 0; i < c->cfg.nservers; i++)
		peer_view(&c->peers[i], &st->peers[i]);
}
