/* The client: the associations (keys and cookies) of the servers, one
 * poll of a server (NTS-KE when needed, then one authenticated query with
 * the Kiss-o'-Death policy and the backoff), the quorum of the fresh
 * samples with the coarse and the drift checks, and the time served from
 * the quorum in force, aged by rho. Everything here was the Go clock's
 * (trusted-time/clock) and query's (trusted-time/nts) logic; it moved in
 * so that the wrapper hands the core nothing but bytes from the network.
 *
 *   - Each server is asked every interval_ns (at least min_poll_ns apart);
 *     a query gets query_timeout_ns, or without it exchange_timeout_ns or
 *     half the interval, whichever is shorter. An authenticated Kiss-o'-Death RATE doubles that server's
 *     interval up to max_poll_ns (RFC 5905 section 7.4); each good answer
 *     halves it back. An authenticated DENY or RSTR costs the server
 *     max_poll_ns of silence and a new NTS-KE, after which it is asked
 *     again (RFC 5905 section 7.4 says to stop; a forged one would
 *     otherwise take a server out until restart). An unauthenticated
 *     Kiss-o'-Death is only counted. NTSN keeps the cookies in hand and
 *     NTS-KE runs again when they run out (RFC 8915 section 5.7), or after
 *     NTS_KE_AFTER_LOST queries in a row got no answer, once per such
 *     streak, the old cookies kept until it succeeds: a server that
 *     rotated its keys and drops the old cookies would otherwise cost all
 *     of them first. NTS-KE
 *     failures back off from the interval to max_poll_ns once a quorum has
 *     been served; until then NTS-KE is tried again after a random 3/4 to
 *     5/4 of the interval, so a relay that comes up late does not push the
 *     first quorum past the runner's start wait, and clients that failed
 *     together do not try again together. A configuration call that
 *     leaves no quorum brings that start state back for start_wait_ns at
 *     most.
 *   - With plain NTP (NTS_PROTO_NTP) there is no NTS-KE and there are no
 *     cookies; a query is the 48-octet header and the answer is checked
 *     by its header alone. No Kiss-o'-Death can be authenticated then, so
 *     RATE, DENY and RSTR are obeyed as they come (it costs availability
 *     only, and nothing of the protocol is authenticated). Everything
 *     below is the same, and holds only against a network that does not
 *     forge the answers (nts_core.h).
 *   - An answer whose bound is over the receipt bound is refused
 *     (NTS_ERR_SAMPLE_WIDE): the cap max_sample_bound_ns less the aging
 *     over the join age, so a sample taken stays under the cap, aged by
 *     rho, for as long as it may join. The earlier sample stays, the
 *     cookies of the answer are kept, and a loss streak ends: the server
 *     does answer.
 *   - The latest sample of each server, at most join_age_ns old, goes to
 *     the quorum: of n such samples nts_quorum_wrong(n) may be wrong (a
 *     majority must agree, and at least 3). The
 *     result is an offset from the local monotonic clock and an error
 *     bound. join_age_ns is under max_age_ns by the host's room for its
 *     next combine, so a quorum stays under max_age_ns until the next one
 *     can replace it, or the time would be refused in between.
 *   - Between quorums the bound grows by NTS_RHO_PPM of the elapsed
 *     monotonic time. nts_bounded refuses once it is over max_bound_ns,
 *     so the signer refuses rather than signs on a time it cannot vouch
 *     for.
 *   - nts_bounded also refuses once the oldest sample of the quorum in
 *     force is over max_age_ns old. The host sets the rate of the local
 *     clock: run fast while the servers are blocked, it moves the time
 *     ahead by less than its own count since the samples, so by less than
 *     max_age_ns. Run slow, it ages the samples slowly too, and the time
 *     can lag real time without limit (it never goes back). Neither this
 *     limit nor the coarse check (on the same local clock) catches that;
 *     the drift check does once new samples come.
 *   - Aging by rho holds only if the local clock keeps within rho of real
 *     time. Each quorum is checked against the last one and against a
 *     baseline quorum about drift_baseline_polls intervals older; if the
 *     offset moved more than the two bounds and rho allow, the quorum is
 *     refused and the time with it until a quorum of new samples agrees
 *     with it: the refused samples do not enter a quorum again.
 *     The short pair catches jumps, the long pair a steady rate over rho
 *     that the bounds hide on a short pair.
 *   - The coarse time is checked on every quorum: an NTS time more than
 *     max_coarse_diff_ns from it, after its resolution, is refused, and
 *     the time with it until a quorum passes, as after a drift refusal.
 *     It also dates the certificates of NTS-KE while no quorum in force
 *     would be served, but never before the era pivot: a time the core
 *     has served is not undone by a coarse reading.
 *   - The NTP era never comes from the coarse time. Timestamps are read
 *     around the era pivot: floor_unix_ns, or the highest time served or
 *     the time of a served quorum if later. A quorum time before
 *     floor_unix_ns or more than NTS_ERA_WINDOW_NS after the pivot is
 *     refused before the coarse and drift checks and does not enter the
 *     drift history, so it cannot start a history that later quorums must
 *     agree with. A coarse reading 2^32 s off therefore moves nothing: the
 *     answers are read in the right era and the coarse check refuses.
 *   - The server list, the protocol and the bounds change on a running
 *     core only by the two configuration calls (nts_core.h), which fail
 *     closed.
 *   - A poll and the calls that read or write more than one peer (the
 *     combine, the full status, the wipe, the configuration calls)
 *     exclude each other: one atomic word, taken by compare-and-swap,
 *     never waited for. Whoever comes second gets NTS_ERR_BUSY and has
 *     changed nothing. Two polls of one peer exclude each other the same
 *     way.
 *   - The time never goes back. */
#include <stdatomic.h>
#include <string.h>

#include "nts_core.h"

typedef __int128 i128;

struct peer {
	nts_server srv; /* this server's configuration, copied at init */
	bool have_keys;
	nts_siv_key c2s, s2c;
	int ncookies, head; /* a ring: the oldest at head; each used once */
	size_t cookie_len[NTS_MAX_COOKIES];
	uint8_t cookies[NTS_MAX_COOKIES][NTS_MAX_COOKIE_LEN];
	char ntp_addr[NTS_MAX_ADDR_LEN];
	size_t ntp_addr_len;
	bool have_sample;
	int sample_protocol; /* the protocol the sample was taken with: samples of two protocols never meet in a quorum */
	nts_sample sample;
	int64_t poll_ns, next_poll, ke_wait_ns, next_ke;
	char disabled[4]; /* the DENY or RSTR obeyed; empty when none */
	int last_err, last_detail;
	char last_kiss[4];
	bool last_kiss_authentic;
	/* Queries in a row that got no answer and no kiss; at NTS_KE_AFTER_LOST
	 * the next poll runs NTS-KE first, once per such streak (lost_ke),
	 * until an answer ends it. */
	int lost_in_row;
	bool lost_ke;
	/* A poll of this peer is under way: a second one is refused. Written
	 * under the shared hold of the core's gate, so never while a
	 * configuration call clears the slot. */
	atomic_bool polling;
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
	int64_t sampled; /* the oldest sample (T4) in the quorum */
	uint32_t members; /* by slot, so a swap of the list moves no bit */
	/* The largest error a wrong member may have caused. With exactly 3
	 * samples none may be wrong: the result is the overlap of all three,
	 * so one wrong operator can place a narrow interval anywhere inside
	 * the honest overlap, and the error is up to the width of the widest
	 * honest interval, twice its aged bound, while bound may be a few ms.
	 * With more samples a wrong one is outvoted and worst is bound. */
	int64_t worst;
	size_t max_wrong;
};

/* The configuration without its server array: the servers are in their
 * peers, so a core holds only as many as it has. */
struct params {
	size_t nservers;
	int64_t interval_ns, min_poll_ns, max_poll_ns, max_bound_ns, max_age_ns, join_age_ns, max_coarse_diff_ns, coarse_resolution_ns, exchange_timeout_ns,
		kiss_grace_ns;
	int drift_baseline_polls;
	int64_t floor_unix_ns;
	int protocol;
	int64_t max_sample_bound_ns; /* resolved: never 0 */
	int64_t query_timeout_ns, start_wait_ns;
};

struct nts_core {
	struct params cfg;
	nts_host_ops ops;
	bool have_result;
	struct result result;
	/* A quorum has been served: NTS-KE failures back off from then on. A
	 * configuration call that leaves no quorum clears it and sets
	 * cold_until, the end of that start state (0: none, as before the
	 * first quorum, which has no end here: the host gives up on its own). */
	bool served;
	int64_t cold_until;
	/* The Unix time NTP timestamps are read around: floor_unix_ns, raised
	 * to the highest time served and the time of each served quorum. Only
	 * a combine and the configuration calls write it, never a poll. */
	int64_t era_pivot;
	/* The quorums of the drift check, oldest first: the last one (served
	 * or refused) at the end, the baseline at index 0. A refused quorum
	 * starts a new history. */
	struct result hist[NTS_MAX_HIST];
	size_t nhist;
	/* The newest sample (T4) of the last quorum the drift check refused.
	 * Samples up to it do not enter a quorum again. */
	bool have_refused_t4;
	int64_t refused_t4;
	int64_t highest; /* INT64_MIN before the first time served */
	bool have_drift;
	int64_t drift_delta, drift_dt, drift_bounds;
	int64_t violations, refusals;
	bool have_coarse_diff;
	int64_t coarse_diff;
	int last_err, last_detail;
	size_t last_fresh;
	bool members_changed;
	/* The gate between the polls and the calls that touch more than one
	 * peer (combine, the full status, the wipe, the configuration calls):
	 * above 0 the polls under way, -1 one such call, 0 nobody. Both sides
	 * enter by compare-and-swap only and never wait: a poll does not start
	 * while the word is -1, an exclusive call does not start unless it is
	 * 0, and the one refused gets NTS_ERR_BUSY. So no poll runs on a peer
	 * that is being wiped or given to another server, and no quorum is
	 * read from a sample that is being written. */
	atomic_int polling;
	/* The peers live in slots; order[i] is the slot of server i of the
	 * current list. A swap of the list moves no peer (each is tens of
	 * kilobytes) and needs no scratch memory: a kept server keeps its
	 * slot, a new one takes a free slot. */
	size_t capacity;
	uint8_t order[NTS_MAX_SERVERS];
	struct peer peers[]; /* capacity of them: what the host allocated */
};

/* The exclusive side of the gate: taken only from 0. */
static bool excl_enter(nts_core *c)
{
	int none = 0;
	return atomic_compare_exchange_strong_explicit(&c->polling, &none, -1, memory_order_acq_rel, memory_order_acquire);
}

static void excl_leave(nts_core *c) { atomic_store_explicit(&c->polling, 0, memory_order_release); }

/* The shared side, a poll's: one more poll, unless an exclusive call holds
 * the gate. */
static bool poll_enter(nts_core *c)
{
	int n = atomic_load_explicit(&c->polling, memory_order_acquire);
	do {
		if (n < 0)
			return false;
	} while (!atomic_compare_exchange_weak_explicit(&c->polling, &n, n + 1, memory_order_acq_rel, memory_order_acquire));
	return true;
}

static void poll_leave(nts_core *c) { atomic_fetch_sub_explicit(&c->polling, 1, memory_order_acq_rel); }

size_t nts_core_size_for(size_t nservers)
{
	if (nservers > NTS_MAX_SERVERS)
		nservers = NTS_MAX_SERVERS;
	return sizeof(nts_core) + nservers * sizeof(struct peer);
}

size_t nts_core_size(void) { return nts_core_size_for(NTS_MAX_SERVERS); }

static int64_t imin(int64_t a, int64_t b) { return a < b ? a : b; }
static int64_t imax(int64_t a, int64_t b) { return a > b ? a : b; }
static int64_t sat(i128 v) { return v > INT64_MAX ? INT64_MAX : v < INT64_MIN ? INT64_MIN : (int64_t)v; }
static int64_t mono(const nts_core *c) { return c->ops.monotonic(c->ops.ctx); }

/* What a host operation returned, as the core takes it: NTS_OK or one of
 * the three host errors. The socket operations are untrusted, and any
 * other code of this header would be read below as the core's own finding
 * (an answer that was too wide, a Kiss-o'-Death): it becomes NTS_ERR_HOST. */
static int host_rc(int rc)
{
	return rc == NTS_OK || rc == NTS_ERR_HOST || rc == NTS_ERR_HOST_TIMEOUT || rc == NTS_ERR_HOST_CANCELLED ? rc : NTS_ERR_HOST;
}
static int check(const nts_core *c, int64_t now, int64_t *bound, int64_t *age);
static struct peer *peer_at(nts_core *c, size_t i) { return &c->peers[c->order[i]]; }
static const struct peer *cpeer_at(const nts_core *c, size_t i) { return &c->peers[c->order[i]]; }

bool nts_plain_supported(void)
{
#if defined(NTS_NO_PLAIN_NTP)
	return false;
#else
	return true;
#endif
}

static bool is_plain(const nts_core *c) { return nts_plain_supported() && c->cfg.protocol == NTS_PROTO_NTP; }

static bool protocol_ok(int protocol) { return protocol == NTS_PROTO_NTS || (protocol == NTS_PROTO_NTP && nts_plain_supported()); }

static bool same(const char *a, size_t alen, const char *b, size_t blen) { return alen == blen && memcmp(a, b, alen) == 0; }

/* Whether a and b are the same server, so that the peer of a can serve b
 * with its keys, cookies and sample. */
static bool same_server(const nts_server *a, const nts_server *b)
{
	return same(a->op, a->op_len, b->op, b->op_len) && same(a->host, a->host_len, b->host, b->host_len) &&
	       same(a->ke_addr, a->ke_addr_len, b->ke_addr, b->ke_addr_len) && same(a->ntp_addr, a->ntp_addr_len, b->ntp_addr, b->ntp_addr_len) &&
	       same((const char *)a->roots, a->roots_len, (const char *)b->roots, b->roots_len);
}

/* A server list the core takes: every length within its limit and no
 * operator named twice (the quorum would refuse it every time). With
 * distinct, also no host and no set NTP address named twice: one server
 * would get two votes. */
static bool servers_ok(const nts_server *servers, size_t n, bool distinct)
{
	for (size_t i = 0; i < n; i++) {
		const nts_server *s = &servers[i];
		if (s->op_len < 1 || s->op_len > NTS_MAX_OPERATOR_LEN || s->host_len < 1 || s->host_len > NTS_MAX_HOST_LEN ||
		    s->ke_addr_len > NTS_MAX_ADDR_LEN || s->ntp_addr_len > NTS_MAX_ADDR_LEN || s->roots_len > NTS_MAX_ROOTS_LEN)
			return false;
		for (size_t j = 0; j < i; j++) {
			const nts_server *o = &servers[j];
			if (same(o->op, o->op_len, s->op, s->op_len))
				return false;
			if (!distinct)
				continue;
			if (same(o->host, o->host_len, s->host, s->host_len))
				return false;
			if (s->ntp_addr_len > 0 && same(o->ntp_addr, o->ntp_addr_len, s->ntp_addr, s->ntp_addr_len))
				return false;
		}
	}
	return true;
}

static void new_peer(const nts_core *c, struct peer *p, const nts_server *srv)
{
	p->srv = *srv;
	p->poll_ns = imax(c->cfg.interval_ns, c->cfg.min_poll_ns);
}

int nts_core_init(nts_core *c, const nts_host_ops *ops, const nts_config *cfg, size_t size)
{
	if (!ops->random || !ops->monotonic || !ops->key_exchange || !ops->udp_open || !ops->udp_send || !ops->udp_recv || !ops->udp_close)
		return NTS_ERR_BAD_CONFIG;
	if (cfg->nservers > NTS_MAX_SERVERS || cfg->interval_ns <= 0 || cfg->min_poll_ns <= 0 || cfg->max_poll_ns <= 0 ||
	    cfg->max_bound_ns <= 0 || cfg->max_age_ns <= 0 || cfg->join_age_ns < 0 || cfg->join_age_ns > cfg->max_age_ns || cfg->max_coarse_diff_ns < 0 ||
	    cfg->coarse_resolution_ns < 0 || cfg->exchange_timeout_ns <= 0 || cfg->kiss_grace_ns < 0 || cfg->drift_baseline_polls < 1 ||
	    cfg->query_timeout_ns < 0 || cfg->start_wait_ns < 0 || !protocol_ok(cfg->protocol))
		return NTS_ERR_BAD_CONFIG;
	if (cfg->max_sample_bound_ns != 0 && (cfg->max_sample_bound_ns < cfg->max_bound_ns || cfg->max_sample_bound_ns > NTS_MAX_SAMPLE_BOUND_NS))
		return NTS_ERR_BAD_CONFIG;
	if (!servers_ok(cfg->servers, cfg->nservers, false))
		return NTS_ERR_BAD_CONFIG;
	if (size < nts_core_size_for(cfg->nservers))
		return NTS_ERR_BAD_CONFIG;
	/* What the host allocated is the capacity: the peers that fit. */
	size_t capacity = (size - sizeof(nts_core)) / sizeof(struct peer);
	if (capacity > NTS_MAX_SERVERS)
		capacity = NTS_MAX_SERVERS;
	memset(c, 0, nts_core_size_for(capacity));
	c->capacity = capacity;
	c->highest = INT64_MIN;
	c->era_pivot = cfg->floor_unix_ns;
	c->cfg.nservers = cfg->nservers;
	c->cfg.interval_ns = cfg->interval_ns;
	c->cfg.min_poll_ns = cfg->min_poll_ns;
	c->cfg.max_poll_ns = cfg->max_poll_ns;
	c->cfg.max_bound_ns = cfg->max_bound_ns;
	c->cfg.max_age_ns = cfg->max_age_ns;
	c->cfg.join_age_ns = cfg->join_age_ns > 0 ? cfg->join_age_ns : cfg->max_age_ns;
	c->cfg.max_coarse_diff_ns = cfg->max_coarse_diff_ns;
	c->cfg.coarse_resolution_ns = cfg->coarse_resolution_ns;
	c->cfg.exchange_timeout_ns = cfg->exchange_timeout_ns;
	c->cfg.kiss_grace_ns = cfg->kiss_grace_ns;
	c->cfg.drift_baseline_polls = cfg->drift_baseline_polls;
	c->cfg.floor_unix_ns = cfg->floor_unix_ns;
	c->cfg.protocol = cfg->protocol;
	c->cfg.max_sample_bound_ns = cfg->max_sample_bound_ns > 0 ? cfg->max_sample_bound_ns : cfg->max_bound_ns;
	c->cfg.query_timeout_ns = cfg->query_timeout_ns;
	c->cfg.start_wait_ns = cfg->start_wait_ns;
	c->ops = *ops;
	for (size_t i = 0; i < cfg->nservers; i++) {
		c->order[i] = (uint8_t)i;
		new_peer(c, &c->peers[i], &cfg->servers[i]);
	}
	return NTS_OK;
}

/* Drops the keys and wipes the cookies of one peer. */
static void wipe_assoc(struct peer *p)
{
	nts_wipe(&p->c2s, sizeof p->c2s);
	nts_wipe(&p->s2c, sizeof p->s2c);
	nts_wipe(p->cookies, sizeof p->cookies);
	nts_wipe(p->cookie_len, sizeof p->cookie_len);
	p->ncookies = 0;
	p->head = 0;
	p->have_keys = false;
}

int nts_core_wipe(nts_core *c)
{
	if (!excl_enter(c))
		return NTS_ERR_BUSY;
	for (size_t i = 0; i < c->cfg.nservers; i++)
		wipe_assoc(peer_at(c, i));
	excl_leave(c);
	return NTS_OK;
}

uint32_t nts_due(const nts_core *c, int64_t now)
{
	uint32_t due = 0;
	for (size_t i = 0; i < c->cfg.nservers; i++)
		if (now >= cpeer_at(c, i)->next_poll)
			due |= (uint32_t)1 << i;
	return due;
}

/* ---- The cookie jar (RFC 8915 section 5.7: each cookie goes out once) ---- */

/* The slot k cookies after the oldest. */
static int jar_slot(const struct peer *p, int k) { return (p->head + k) % NTS_MAX_COOKIES; }

/* Drops the oldest cookie: sent, or crowded out by new ones. */
static void jar_drop(struct peer *p)
{
	nts_wipe(p->cookies[p->head], sizeof p->cookies[0]);
	p->cookie_len[p->head] = 0;
	p->head = jar_slot(p, 1);
	p->ncookies--;
}

/* Adds the cookies of an authentic response, newest last, and drops the
 * oldest beyond NTS_MAX_COOKIES. A slot a cookie left is wiped, so a new
 * cookie lands in zeros. */
static void jar_keep(struct peer *p, int n, const size_t *lens, const uint8_t cookies[][NTS_MAX_COOKIE_LEN])
{
	for (int i = 0; i < n; i++) {
		if (p->ncookies == NTS_MAX_COOKIES)
			jar_drop(p);
		int k = jar_slot(p, p->ncookies);
		memcpy(p->cookies[k], cookies[i], lens[i]);
		p->cookie_len[k] = lens[i];
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

/* The core's own Unix time at the monotonic time now, while the quorum in
 * force would be served (the rules of nts_bounded: its bound and its age);
 * otherwise the coarse reading moved forward by the local time since it
 * was taken: before the first quorum, after the drift check refused one,
 * and once the quorum in force has aged past its limits. The time that
 * dates a certificate thus follows the same rules as the time served. */
static int64_t unix_now(const nts_core *c, int64_t now, int64_t coarse_unix, int64_t coarse_local)
{
	int64_t bound, age;
	if (check(c, now, &bound, &age) == NTS_OK)
		return sat((i128)now + c->result.offset);
	return sat((i128)coarse_unix + ((i128)now - coarse_local));
}

/* The wait before NTS-KE is tried again after a failure. Once a quorum has
 * been served it doubles from the interval up to max_poll_ns; before that
 * it is a random 3/4 to 5/4 of the interval: no backoff, so a relay that
 * comes up late does not push the first quorum past the host's start
 * wait, and random, so clients that failed together (a release, a region
 * outage) do not try again together. The random is the host's CSPRNG; if
 * that fails, the interval itself. */
static int64_t ke_retry_wait(nts_core *c, const struct peer *p, int64_t now)
{
	uint8_t rnd[8];
	/* The start state a configuration call began ends at cold_until even
	 * if no combine has run since to note it (a poll writes only its
	 * peer): without the limit a host that drops the answers after a swap
	 * would keep the client on the start retries, with no backoff, for as
	 * long as it liked. */
	if (c->served || (c->cold_until != 0 && now >= c->cold_until))
		return imin(imax(2 * p->ke_wait_ns, c->cfg.interval_ns), c->cfg.max_poll_ns);
	int64_t spread = c->cfg.interval_ns / 2;
	if (spread <= 0 || c->ops.random(c->ops.ctx, rnd, sizeof rnd) != NTS_OK)
		return c->cfg.interval_ns;
	uint64_t r = 0;
	for (int k = 0; k < 8; k++)
		r = r << 8 | rnd[k];
	return c->cfg.interval_ns - spread / 2 + (int64_t)(r % (uint64_t)spread);
}

/* One NTS-KE session. The keys and the cookies it gives replace the
 * peer's only once the whole of it succeeded (the keys are expanded apart
 * and copied then): a failed one leaves the peer as it was, so the key
 * exchange of a loss streak costs nothing when it fails. */
static int key_exchange(nts_core *c, size_t i, int64_t now, int64_t coarse_unix, int64_t coarse_local)
{
	struct peer *p = peer_at(c, i);
	const nts_server *srv = &p->srv;
	uint8_t req[NTS_KE_REQUEST_LEN], c2s[NTS_KEY_LEN], s2c[NTS_KEY_LEN];
	nts_siv_key nc2s, ns2c;
	size_t resplen = 0;
	int64_t elapsed = 0;
	int detail = 0;
	nts_ke_request(req);
	/* A certificate time not after the floor is no time at all (the host
	 * had no coarse reading, say): check no certificate at it, and do not
	 * hand it to the host, whose TLS stack may read a zero time as its
	 * own clock. */
	int64_t validity = unix_now(c, now, coarse_unix, coarse_local);
	int rc = validity <= c->cfg.floor_unix_ns ? NTS_ERR_NO_TRUSTED_TIME : NTS_OK;
	/* Never before the era pivot: that is a time the core served (the
	 * highest, or a quorum's), so real time is not before it by more than
	 * that quorum's bound. A coarse reading below it, when no quorum is in
	 * force (after a configuration call, a refusal, samples aged out),
	 * would otherwise date a certificate back to where it had not yet
	 * expired. The pivot is written by the exclusive calls only, never
	 * during a poll. */
	validity = imax(validity, c->era_pivot);
	if (rc == NTS_OK)
		rc = host_rc(c->ops.key_exchange(c->ops.ctx, i, srv, validity, c->cfg.exchange_timeout_ns, req, sizeof req, p->ke_resp,
						 sizeof p->ke_resp, &resplen, c2s, s2c, &elapsed));
	if (rc == NTS_OK && resplen > sizeof p->ke_resp)
		rc = NTS_ERR_HOST;
	if (rc == NTS_OK) {
		rc = nts_ke_parse(p->ke_resp, resplen, &p->ke);
		detail = p->ke.detail;
	}
	if (rc == NTS_OK)
		rc = nts_siv_init(&nc2s, c2s, sizeof c2s);
	if (rc == NTS_OK)
		rc = nts_siv_init(&ns2c, s2c, sizeof s2c);
	nts_wipe(c2s, sizeof c2s);
	nts_wipe(s2c, sizeof s2c);
	if (rc == NTS_OK) {
		wipe_assoc(p);
		p->c2s = nc2s;
		p->s2c = ns2c;
		memcpy(p->cookies, p->ke.cookies, sizeof p->cookies);
		memcpy(p->cookie_len, p->ke.cookie_len, sizeof p->cookie_len);
		p->ncookies = p->ke.ncookies;
		p->head = 0;
		p->have_keys = true;
		/* RFC 8915 sections 4.1.7, 4.1.8: the server named, else the KE
		 * host; the port named, else 123. */
		const char *host = p->ke.server_len ? p->ke.server : srv->host;
		size_t hostlen = p->ke.server_len ? p->ke.server_len : srv->host_len;
		set_ntp_addr(p, host, hostlen, p->ke.port ? p->ke.port : 123);
	}
	nts_wipe(&nc2s, sizeof nc2s);
	nts_wipe(&ns2c, sizeof ns2c);
	nts_wipe(&p->ke, sizeof p->ke);
	nts_wipe(p->ke_resp, sizeof p->ke_resp);
	if (rc == NTS_ERR_HOST_CANCELLED) {
		/* The host's caller ended it, not the server: no failure counted,
		 * no backoff. */
		p->last_err = rc;
		p->last_detail = 0;
		return rc;
	}
	if (rc != NTS_OK) {
		p->stats.ke_fail++;
		p->last_err = rc;
		p->last_detail = detail;
		p->ke_wait_ns = ke_retry_wait(c, p, now);
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
	bool measured; /* sample holds a measurement: with NTS_OK, and with NTS_ERR_SAMPLE_WIDE */
	nts_sample sample;
};

/* The widest bound a sample may have at receipt: the cap less the aging
 * over the join age. A sample under it stays under the cap, aged by rho,
 * for as long as it may join, so it never leaves a quorum early, and the
 * error wrong servers reach stays twice the cap. For a small cap it does
 * not go below half the cap. */
static int64_t receipt_bound_of(const nts_core *c, int64_t cap) { return imax(cap - nts_drift(c->cfg.join_age_ns), cap / 2); }
static int64_t receipt_bound(const nts_core *c) { return receipt_bound_of(c, c->cfg.max_sample_bound_ns); }

/* Sends one request and reads until an answer is ours and passes the
 * check, or the time runs out: a datagram that fails the check may be a
 * forgery (one sent before the real answer, say), so it is dropped and
 * the real answer can still come. T1 and T4 come from the monotonic
 * clock; the pivot of the NTP era is the core's era pivot.
 *
 * With NTS the request carries the oldest cookie and the answer must be
 * authentic. A Kiss-o'-Death with our Unique Identifier does not end the
 * query: it stands only if nothing authentic follows it within
 * kiss_grace_ns. The cookies of an authentic response are kept even if
 * the measurement is refused: they are good for the next one.
 *
 * With plain NTP the request is the header with a random transmit
 * timestamp, the only thing that ties an answer to it. A Kiss-o'-Death
 * that echoes it ends the query: the check closed the request (whoever
 * could forge that kiss could forge the answer as well). */
static void query(nts_core *c, size_t i, struct outcome *o)
{
	struct peer *p = peer_at(c, i);
	const bool plain = is_plain(c);
	uint8_t rnd[NTS_REQUEST_RANDOM_LEN];
	size_t reqlen = 0;
	nts_pending pending;
	nts_plain_pending plain_pending;
	void *sock = NULL;
	int64_t timeout = c->cfg.query_timeout_ns > 0 ? c->cfg.query_timeout_ns : imin(c->cfg.exchange_timeout_ns, c->cfg.interval_ns / 2);
	if (timeout <= 0)
		timeout = c->cfg.exchange_timeout_ns;
	memset(o, 0, sizeof *o);
	if (!plain && p->ncookies == 0) {
		o->rc = NTS_ERR_NO_COOKIE;
		return;
	}
	if (c->ops.random(c->ops.ctx, rnd, plain ? 8 : sizeof rnd) != NTS_OK) {
		o->rc = NTS_ERR_HOST_RANDOM;
		return;
	}
	uint64_t transmit = 0;
	for (int k = 0; k < 8; k++)
		transmit = transmit << 8 | rnd[k];
	int rc = NTS_OK;
	if (plain) {
		nts_plain_request(transmit, p->request, &plain_pending);
		reqlen = NTS_PLAIN_REQUEST_LEN;
	} else {
		/* The request carries the oldest cookie, built from the jar in
		 * place; the cookie leaves the jar once the socket is open, just
		 * before the send. The response should bring NTS_MAX_COOKIES - held
		 * new ones: one for the cookie, the rest for the placeholders,
		 * within the size limit. */
		const uint8_t *cookie = p->cookies[p->head];
		size_t cookielen = p->cookie_len[p->head];
		int placeholders = NTS_MAX_COOKIES - p->ncookies;
		int most = nts_max_placeholders(cookielen);
		if (placeholders > most)
			placeholders = most;
		rc = nts_build_request(&p->c2s, transmit, rnd + 8, rnd + 8 + NTS_UID_LEN, cookie, cookielen, placeholders, p->request,
				       sizeof p->request, &reqlen, &pending);
	}
	nts_wipe(rnd, sizeof rnd);
	if (rc != NTS_OK) {
		nts_wipe(p->request, sizeof p->request);
		o->rc = rc;
		return;
	}
	rc = host_rc(c->ops.udp_open(c->ops.ctx, i, p->ntp_addr, p->ntp_addr_len, timeout, &sock));
	if (rc != NTS_OK) {
		nts_wipe(p->request, sizeof p->request);
		o->rc = rc;
		return;
	}
	/* The cookie leaves the jar before the send: the host may send the
	 * request and report a failure, and each cookie goes out once (RFC
	 * 8915 section 5.7). */
	if (!plain)
		jar_drop(p);
	int64_t t1 = mono(c);
	rc = host_rc(c->ops.udp_send(c->ops.ctx, sock, p->request, reqlen));
	nts_wipe(p->request, sizeof p->request);
	if (rc != NTS_OK) {
		c->ops.udp_close(c->ops.ctx, sock);
		o->rc = rc;
		return;
	}
	int64_t deadline = t1 + timeout;
	bool have_kiss = false;
	int last = NTS_OK;
	for (;;) {
		size_t n = 0;
		int64_t wait = deadline - mono(c);
		rc = wait > 0 ? host_rc(c->ops.udp_recv(c->ops.ctx, sock, p->packet, sizeof p->packet, &n, wait)) : NTS_ERR_HOST_TIMEOUT;
		int64_t t4 = mono(c);
		if (rc != NTS_OK || n > sizeof p->packet) {
			if (have_kiss && rc != NTS_ERR_HOST_CANCELLED) {
				/* Nothing authentic followed the Kiss-o'-Death: it stands. */
				o->rc = NTS_ERR_KISS;
				break;
			}
			o->rc = rc == NTS_OK ? NTS_ERR_HOST : rc;
			o->detail = rc == NTS_ERR_HOST_CANCELLED ? 0 : last; /* the last refusal, named in the timeout */
			break;
		}
		rc = plain ? nts_plain_verify(&plain_pending, p->packet, n, &p->verdict) : nts_verify_response(&pending, &p->s2c, p->packet, n, &p->verdict);
		if (rc != NTS_OK) {
			last = rc;
			continue;
		}
		if (p->verdict.kind == NTS_KIND_KISS) {
			memcpy(o->kiss, p->verdict.kiss, 4);
			o->kiss_authentic = p->verdict.kiss_authentic;
			if (plain) {
				o->rc = NTS_ERR_KISS;
				break;
			}
			/* A Kiss-o'-Death does not end the query: a forged one may come
			 * before the real answer. The query reads on for the grace, or
			 * to its deadline if that is sooner, and reports the KoD only
			 * if nothing authentic follows. */
			have_kiss = true;
			deadline = imin(deadline, t4 + c->cfg.kiss_grace_ns);
			continue;
		}
		if (!plain)
			jar_keep(p, p->verdict.time.ncookies, p->verdict.time.cookie_len, p->verdict.time.cookies);
		rc = nts_measure(&p->verdict.time, t1, t4, c->era_pivot, &o->sample);
		if (rc != NTS_OK) {
			o->rc = rc;
			o->detail = o->sample.detail;
			break;
		}
		o->sample.cookies_held = p->ncookies;
		o->measured = true;
		o->rc = o->sample.bound > receipt_bound(c) ? NTS_ERR_SAMPLE_WIDE : NTS_OK;
		break;
	}
	nts_wipe(&p->verdict, sizeof p->verdict);
	nts_wipe(p->packet, sizeof p->packet);
	c->ops.udp_close(c->ops.ctx, sock);
}

static int poll_peer(nts_core *c, size_t i, int64_t coarse_unix_ns, int64_t coarse_local)
{
	struct peer *p = peer_at(c, i);
	const bool plain = is_plain(c);
	int64_t now = mono(c);
	if (plain) {
		/* The server's plain NTP address, or its host on port 123. */
		if (p->srv.ntp_addr_len > 0) {
			memcpy(p->ntp_addr, p->srv.ntp_addr, p->srv.ntp_addr_len);
			p->ntp_addr_len = p->srv.ntp_addr_len;
		} else {
			set_ntp_addr(p, p->srv.host, p->srv.host_len, 123);
		}
	} else {
		/* NTS-KE when the peer cannot ask (no keys or no cookies), and once
		 * per streak of NTS_KE_AFTER_LOST lost queries: a server that
		 * rotated its keys should answer an old cookie with NTSN, but one
		 * that drops it would otherwise cost all the cookies first. That
		 * second kind keeps the old cookies until NTS-KE succeeds, so a
		 * failed or backed-off one costs nothing; on a path that drops NTP
		 * but not NTS-KE a server gets one more NTS-KE per streak, not one
		 * per NTS_KE_AFTER_LOST queries. */
		bool usable = p->have_keys && p->ncookies > 0;
		bool stale = usable && p->lost_in_row >= NTS_KE_AFTER_LOST && !p->lost_ke;
		if (!usable) {
			wipe_assoc(p);
			if (now < p->next_ke)
				return NTS_ERR_NOT_DUE;
		}
		if (!usable || (stale && now >= p->next_ke)) {
			if (stale)
				p->lost_ke = true;
			int rc = key_exchange(c, i, now, coarse_unix_ns, coarse_local);
			if (rc == NTS_ERR_HOST_CANCELLED) {
				/* The key exchange of the streak is not used up. */
				if (stale)
					p->lost_ke = false;
				return rc;
			}
			if (rc != NTS_OK && !usable)
				return rc;
		}
	}
	struct outcome o;
	query(c, i, &o);
	now = mono(c);
	p->stats.queries++;
	if (o.rc == NTS_ERR_HOST_CANCELLED) {
		/* The host's caller cut the query, not the server or its own
		 * timeout: no loss, no streak, no error counted for a server that
		 * may be fine, and the peer stays due. The request may have gone
		 * out, so its cookie is spent. */
		p->last_err = o.rc;
		p->last_detail = 0;
		return o.rc;
	}
	p->next_poll = now + p->poll_ns;
	p->last_err = o.rc;
	p->last_detail = o.detail;
	if (o.measured) {
		p->stats.last_delay = o.sample.delay;
		p->stats.last_bound = o.sample.bound;
	}
	/* A wide answer is one that was measured: the code alone, without a
	 * measurement, is an error like any other. */
	if (o.rc == NTS_ERR_SAMPLE_WIDE && !o.measured)
		o.rc = p->last_err = NTS_ERR_HOST;
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
		 * more than dropping the answers would give. The price: a real
		 * NTSN (the server lost the keys of the cookie, never
		 * authenticated) costs its operator up to NTS_MAX_COOKIES polls,
		 * one cookie each, before NTS-KE runs again (or NTS_KE_AFTER_LOST
		 * lost ones), rather than a key exchange at once, which a forged
		 * NTSN per poll could then force (a TLS session every poll).
		 *
		 * With plain NTP no kiss can be authenticated, and none is asked
		 * to be: RATE, DENY and RSTR are obeyed as they come. Whoever can
		 * forge one can forge the time answer too; obeying costs
		 * availability only, and a public server's RATE is kept. */
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
		if (!o.kiss_authentic && !plain)
			break;
		if (memcmp(o.kiss, "RATE", 4) == 0) {
			p->poll_ns = imin(2 * p->poll_ns, c->cfg.max_poll_ns);
			p->next_poll = now + p->poll_ns;
		} else if (memcmp(o.kiss, "DENY", 4) == 0 || memcmp(o.kiss, "RSTR", 4) == 0) {
			memcpy(p->disabled, o.kiss, 4);
			p->have_sample = false;
			memset(&p->sample, 0, sizeof p->sample);
			p->poll_ns = c->cfg.max_poll_ns;
			p->next_poll = now + p->poll_ns;
			wipe_assoc(p);
		}
		break;
	case NTS_OK:
		p->stats.samples++;
		p->sample = o.sample;
		p->sample_protocol = c->cfg.protocol;
		p->have_sample = true;
		p->lost_in_row = 0;
		p->lost_ke = false;
		memset(p->disabled, 0, sizeof p->disabled);
		p->poll_ns = imax(p->poll_ns / 2, imax(c->cfg.interval_ns, c->cfg.min_poll_ns));
		break;
	case NTS_ERR_SAMPLE_WIDE:
		/* An answer, but too wide to join a quorum: the earlier sample
		 * stays until it ages out. The server does answer (with NTS, the
		 * cookies work), so a loss streak ends, and the next lost query
		 * does not run NTS-KE early. */
		p->stats.wide++;
		p->lost_in_row = 0;
		p->lost_ke = false;
		memset(p->disabled, 0, sizeof p->disabled);
		break;
	default:
		p->stats.errors++;
		if (p->lost_in_row < INT32_MAX)
			p->lost_in_row++;
	}
	return o.rc;
}

int nts_poll(nts_core *c, size_t i, int64_t coarse_unix_ns, int64_t coarse_local)
{
	/* The gate first: the list (its length, which slot is peer i) is read
	 * only once no configuration call can change it. */
	if (!poll_enter(c))
		return NTS_ERR_BUSY;
	int rc = NTS_ERR_BAD_CONFIG;
	if (i < c->cfg.nservers) {
		struct peer *p = peer_at(c, i);
		rc = NTS_ERR_BUSY;
		if (!atomic_exchange_explicit(&p->polling, true, memory_order_acq_rel)) {
			rc = poll_peer(c, i, coarse_unix_ns, coarse_local);
			atomic_store_explicit(&p->polling, false, memory_order_release);
		}
	}
	poll_leave(c);
	return rc;
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

/* Raises the era pivot to the highest time served and to the time of the
 * quorum in force at its forming. It never goes back and never comes from
 * the coarse time. */
static void raise_pivot(nts_core *c)
{
	c->era_pivot = imax(c->era_pivot, c->highest);
	if (c->have_result)
		c->era_pivot = imax(c->era_pivot, sat((i128)c->result.at + c->result.offset));
}

/* Whether p's sample may join a quorum at the monotonic time now: of the
 * protocol in force, at most join_age_ns old, newer than a quorum the
 * drift check refused, and within the receipt bound (a poll refuses wider
 * ones; this keeps that true after the bounds changed). Its bound, aged
 * by rho as the quorum ages it, then stays within the cap for the whole
 * join age. */
static bool joins(const nts_core *c, const struct peer *p, int64_t now)
{
	return p->have_sample && p->sample_protocol == c->cfg.protocol && (i128)now - p->sample.t4 <= c->cfg.join_age_ns &&
	       !(c->have_refused_t4 && p->sample.t4 <= c->refused_t4) && p->sample.bound <= receipt_bound(c);
}

static int combine(nts_core *c, int64_t coarse_unix_ns, int64_t coarse_local)
{
	nts_interval in[NTS_MAX_SERVERS];
	uint32_t members = 0;
	size_t n = 0;
	int64_t now = mono(c);
	/* The start state a configuration call began is over once its time
	 * is: NTS-KE failures back off again, with or without a quorum. */
	if (c->cold_until != 0 && now >= c->cold_until) {
		c->cold_until = 0;
		c->served = true;
	}
	raise_pivot(c);
	c->members_changed = false;
	c->last_detail = 0;
	for (size_t i = 0; i < c->cfg.nservers; i++) {
		const struct peer *p = cpeer_at(c, i);
		if (!joins(c, p, now))
			continue;
		in[n].op = p->srv.op;
		in[n].oplen = p->srv.op_len;
		in[n].offset = p->sample.offset;
		in[n].bound = p->sample.bound;
		in[n].t4 = p->sample.t4;
		members |= (uint32_t)1 << c->order[i];
		n++;
	}
	c->last_fresh = n;
	nts_quorum_result q;
	/* How many may be wrong is the core's rule, from the count of the
	 * fresh samples alone: never an argument of the host. */
	size_t max_wrong = nts_quorum_wrong(n);
	int rc = nts_quorum(in, n, max_wrong, now, &q);
	if (rc != NTS_OK) {
		c->last_err = rc;
		return rc;
	}
	i128 t = (i128)now + q.offset;
	/* The sanity window comes before the coarse and drift checks: a quorum
	 * outside it is not served and does not enter the drift history, so it
	 * cannot start a new history that later quorums must agree with. */
	if (t < c->cfg.floor_unix_ns || t - c->era_pivot > NTS_ERA_WINDOW_NS) {
		c->have_result = false;
		c->last_err = NTS_ERR_ERA_WINDOW;
		c->last_detail = t < c->cfg.floor_unix_ns ? 0 : 1;
		return NTS_ERR_ERA_WINDOW;
	}
	/* The coarse reading was taken before the polls: move it forward by
	 * the local time since then. */
	int64_t diff = sat(t - ((i128)coarse_unix_ns + ((i128)now - coarse_local)));
	c->coarse_diff = diff;
	c->have_coarse_diff = true;
	if (nts_coarse_refused(diff, c->cfg.max_coarse_diff_ns, c->cfg.coarse_resolution_ns)) {
		/* The quorum in force is not served on: the time is refused until
		 * a quorum passes this check, as after a drift refusal. */
		c->have_result = false;
		c->last_err = NTS_ERR_COARSE_CHECK;
		return NTS_ERR_COARSE_CHECK;
	}
	int64_t sampled = now, newest = INT64_MIN;
	for (size_t k = 0; k < n; k++) {
		sampled = imin(sampled, in[k].t4);
		newest = imax(newest, in[k].t4);
	}
	int64_t worst = q.bound;
	if (max_wrong == 0)
		for (size_t k = 0; k < n; k++) {
			int64_t aged = nts_add_bound(in[k].bound, nts_drift(sat((i128)now - in[k].t4)));
			worst = imax(worst, nts_add_bound(aged, aged));
		}
	struct result cur = {.offset = q.offset, .bound = q.bound, .at = now, .lo = q.lo, .hi = q.hi, .sampled = sampled, .members = members,
			     .worst = worst, .max_wrong = max_wrong};
	/* The bound grows by rho only if the local clock keeps within rho of
	 * real time. Check that against the last quorum and the baseline: both
	 * intervals of a pair hold the real offset (at most a minority of the
	 * servers wrong in each), and it can move by at most rho times the time between
	 * them. If a pair does not fit, the local clock broke rho (or more
	 * servers are wrong): this quorum is not served, a new history starts
	 * with it, and the next quorum, of new samples only, must agree with
	 * it first. */
	const struct result *refs[2];
	size_t nrefs = 0;
	if (c->nhist > 0) {
		refs[nrefs++] = &c->hist[c->nhist - 1];
		if (c->nhist > 1)
			refs[nrefs++] = &c->hist[0];
	}
	for (size_t k = 0; k < nrefs; k++) {
		const struct result *ref = refs[k];
		i128 dt = (i128)now - ref->at;
		i128 delta = (i128)cur.offset - ref->offset;
		int64_t allowed = nts_add_bound(nts_add_bound(ref->bound, nts_drift(sat(dt))), cur.bound);
		/* A counter that went back since the reference broke rho as well. */
		bool failed = dt < 0 || (delta < 0 ? -delta : delta) > allowed;
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
			if (!c->have_refused_t4 || newest > c->refused_t4)
				c->refused_t4 = newest;
			c->have_refused_t4 = true;
			c->violations++;
			c->last_err = NTS_ERR_DRIFT;
			return NTS_ERR_DRIFT;
		}
	}
	/* Keep the newest quorum at least the baseline old as hist[0], and
	 * drop the ones before it. The wrapper decides how often combine
	 * runs (clock.NTS: four times an interval), so the history must not
	 * depend on it: the entries before the last are kept at least
	 * baseline / (NTS_MAX_HIST - 4) apart. The last one, the newest, stays
	 * as a candidate for the baseline only if it is that far from the one
	 * before it; otherwise the new quorum replaces it. The window of one baseline then holds fewer entries than
	 * the array, and hist[0] is at most baseline + that spacing old. A
	 * history that fills anyway (a jump of the local clock) drops its
	 * newest entry, never an older one: dropping hist[1] each time kept
	 * hist[1] younger than the baseline for good, and the baseline stayed
	 * the first quorum, its pair ever longer and slower to catch a rate
	 * over rho. */
	i128 baseline = (i128)c->cfg.drift_baseline_polls * c->cfg.interval_ns;
	/* An int64 division: a 128-bit one is a call into the compiler's
	 * runtime (__divti3), which a freestanding build does not have. */
	int64_t spacing = sat(baseline) / (NTS_MAX_HIST - 4);
	if (c->nhist >= 2 && (i128)c->hist[c->nhist - 1].at - c->hist[c->nhist - 2].at < spacing) {
		c->hist[c->nhist - 1] = cur;
	} else {
		if (c->nhist == NTS_MAX_HIST)
			c->nhist--;
		c->hist[c->nhist++] = cur;
	}
	while (c->nhist > 2 && (i128)now - c->hist[1].at >= baseline) {
		memmove(&c->hist[0], &c->hist[1], sizeof c->hist[0] * (c->nhist - 1));
		c->nhist--;
	}
	c->members_changed = !c->have_result || c->result.members != members;
	c->result = cur;
	c->have_result = true;
	c->served = true;
	c->cold_until = 0;
	raise_pivot(c);
	c->last_err = NTS_OK;
	return NTS_OK;
}

int nts_combine(nts_core *c, int64_t coarse_unix_ns, int64_t coarse_local)
{
	/* Refused before anything is written: a poll under way reads the core
	 * (the era pivot, the configuration), and another exclusive call owns
	 * the status fields. */
	if (!excl_enter(c))
		return NTS_ERR_BUSY;
	int rc = combine(c, coarse_unix_ns, coarse_local);
	excl_leave(c);
	return rc;
}

/* ---- The configuration calls ---- */

/* The quorum in force lost a member (slots in gone): it stops serving at
 * once and forms again from the samples left, checked as every quorum.
 * If none forms, no time is served until a combine forms one, and the
 * start state begins: the retries of a start apply again, for
 * start_wait_ns at most. */
static void without(nts_core *c, uint32_t gone, int64_t coarse_unix_ns, int64_t coarse_local)
{
	if (!c->have_result || (c->result.members & gone) == 0)
		return;
	/* The time of the quorum that goes is kept in the pivot. */
	raise_pivot(c);
	c->have_result = false;
	if (combine(c, coarse_unix_ns, coarse_local) == NTS_OK)
		return;
	if (c->cfg.start_wait_ns > 0) {
		c->served = false;
		c->cold_until = sat((i128)mono(c) + c->cfg.start_wait_ns);
	}
}

int nts_core_set_servers(nts_core *c, const nts_server *servers, size_t n, int64_t coarse_unix_ns, int64_t coarse_local)
{
	uint8_t order[NTS_MAX_SERVERS];
	bool used[NTS_MAX_SERVERS] = {false}, kept[NTS_MAX_SERVERS] = {false};
	if (!excl_enter(c))
		return NTS_ERR_BUSY;
	if (n > c->capacity || !servers_ok(servers, n, true)) {
		excl_leave(c);
		return NTS_ERR_BAD_CONFIG;
	}
	/* A server that is as before keeps its slot and so all of its state. */
	for (size_t i = 0; i < n; i++)
		for (size_t j = 0; j < c->cfg.nservers; j++)
			if (same_server(&cpeer_at(c, j)->srv, &servers[i])) {
				order[i] = c->order[j];
				kept[i] = true;
				used[order[i]] = true;
				break;
			}
	/* What a removed or changed server held is wiped, and its slot is free. */
	uint32_t gone = 0;
	for (size_t j = 0; j < c->cfg.nservers; j++) {
		size_t slot = c->order[j];
		if (used[slot])
			continue;
		wipe_assoc(&c->peers[slot]);
		memset(&c->peers[slot], 0, sizeof c->peers[slot]);
		gone |= (uint32_t)1 << slot;
	}
	/* Every other server gets a new peer in a free slot: there is one, as
	 * n is within the capacity. */
	size_t slot = 0;
	for (size_t i = 0; i < n; i++) {
		if (kept[i])
			continue;
		while (used[slot])
			slot++;
		used[slot] = true;
		order[i] = (uint8_t)slot;
		memset(&c->peers[slot], 0, sizeof c->peers[slot]);
		new_peer(c, &c->peers[slot], &servers[i]);
	}
	memcpy(c->order, order, n);
	c->cfg.nservers = n;
	without(c, gone, coarse_unix_ns, coarse_local);
	excl_leave(c);
	return NTS_OK;
}

int nts_core_set_policy(nts_core *c, int protocol, int64_t max_bound_ns, int64_t max_sample_bound_ns, int64_t coarse_unix_ns,
			int64_t coarse_local)
{
	if (!excl_enter(c))
		return NTS_ERR_BUSY;
	if (!protocol_ok(protocol) || max_bound_ns <= 0 || max_sample_bound_ns < max_bound_ns || max_sample_bound_ns > NTS_MAX_SAMPLE_BOUND_NS) {
		excl_leave(c);
		return NTS_ERR_BAD_CONFIG;
	}
	bool restart = protocol != c->cfg.protocol;
	c->cfg.protocol = protocol;
	c->cfg.max_bound_ns = max_bound_ns;
	c->cfg.max_sample_bound_ns = max_sample_bound_ns;
	if (restart) {
		/* The other protocol's answers made every sample, the quorum in
		 * force and the drift history: all of it goes, and no time is
		 * served until a quorum forms on the new protocol. What limits
		 * the contacts stays (the poll intervals, the next polls, the
		 * stops), and so do the era pivot and the highest time served:
		 * the time still never goes back. */
		raise_pivot(c);
		for (size_t i = 0; i < c->cfg.nservers; i++) {
			struct peer *p = peer_at(c, i);
			wipe_assoc(p);
			p->have_sample = false;
			memset(&p->sample, 0, sizeof p->sample);
			p->ntp_addr_len = 0;
			p->next_ke = 0;
			p->ke_wait_ns = 0;
			p->lost_in_row = 0;
			p->lost_ke = false;
		}
		c->have_result = false;
		c->nhist = 0;
		c->have_drift = false;
		c->drift_delta = c->drift_dt = c->drift_bounds = 0;
		c->last_err = NTS_ERR_NO_QUORUM;
		c->last_detail = 0;
		if (c->cfg.start_wait_ns > 0) {
			c->served = false;
			c->cold_until = sat((i128)mono(c) + c->cfg.start_wait_ns);
		}
		excl_leave(c);
		return NTS_OK;
	}
	/* The bounds apply at once: nts_bounded checks the quorum in force
	 * against the new max_bound_ns at its next call, and each sample over
	 * the new receipt bound is dropped. */
	uint32_t gone = 0;
	for (size_t i = 0; i < c->cfg.nservers; i++) {
		struct peer *p = peer_at(c, i);
		if (!p->have_sample || p->sample.bound <= receipt_bound(c))
			continue;
		p->have_sample = false;
		memset(&p->sample, 0, sizeof p->sample);
		gone |= (uint32_t)1 << c->order[i];
	}
	without(c, gone, coarse_unix_ns, coarse_local);
	excl_leave(c);
	return NTS_OK;
}

/* Whether the quorum in force gives a time at the monotonic time now: its
 * bound then and the age of its oldest sample, and NTS_OK or the refusal. */
static int check(const nts_core *c, int64_t now, int64_t *bound, int64_t *age)
{
	*bound = 0;
	*age = 0;
	if (!c->have_result)
		return NTS_ERR_NO_QUORUM;
	/* nts_add_bound saturates, and a negative bound is refused as well: a
	 * bound that wrapped around once let a quorum months old serve time
	 * again (TIME-BOUND-01). */
	*bound = nts_add_bound(c->result.bound, nts_drift(sat((i128)now - c->result.at)));
	*age = sat((i128)now - c->result.sampled);
	if (*bound < 0 || *bound > c->cfg.max_bound_ns)
		return NTS_ERR_BOUND_OVER_LIMIT;
	if (*age > c->cfg.max_age_ns)
		return NTS_ERR_SAMPLES_TOO_OLD;
	return NTS_OK;
}

int nts_bounded(nts_core *c, int64_t *unix_ns, int64_t *bound_ns)
{
	int64_t now, age;
	*unix_ns = 0;
	if (!c->have_result) {
		*bound_ns = 0;
		return NTS_ERR_NO_QUORUM;
	}
	now = mono(c);
	int rc = check(c, now, bound_ns, &age);
	if (rc != NTS_OK) {
		c->refusals++;
		return rc;
	}
	int64_t t = sat((i128)now + c->result.offset);
	if (t < c->highest)
		t = c->highest;
	c->highest = t;
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
	st->sampled = c->result.sampled;
	/* The members of the result in force only: the slots of an earlier one
	 * may hold other servers by now. */
	for (size_t i = 0; c->have_result && i < c->cfg.nservers; i++)
		if (c->result.members & (uint32_t)1 << c->order[i])
			st->members |= (uint32_t)1 << i;
	st->worst = c->result.worst;
	st->max_wrong = c->result.max_wrong;
	st->protocol = c->cfg.protocol;
	st->era_pivot = c->era_pivot;
	st->now = mono(c);
	st->cold = !c->served && c->cold_until != 0 && st->now < c->cold_until;
	st->refusal = check(c, st->now, &st->bound_now, &st->sample_age);
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

static void peer_view(const nts_core *c, const struct peer *p, nts_peer_view *v)
{
	v->have_sample = p->have_sample;
	v->sample = p->sample;
	v->poll_ns = p->poll_ns;
	memcpy(v->disabled, p->disabled, 4);
	v->is_disabled = p->disabled[0] != 0;
	v->last_err = p->last_err;
	v->last_detail = p->last_detail;
	memcpy(v->last_kiss, p->last_kiss, 4);
	v->last_kiss_authentic = p->last_kiss_authentic;
	memcpy(v->ntp_addr, p->ntp_addr, p->ntp_addr_len);
	v->ntp_addr_len = p->ntp_addr_len;
	v->cookies = p->ncookies;
	v->stats = p->stats;
	v->next_poll = p->next_poll;
	v->next_ke = p->next_ke;
	v->lost_in_row = p->lost_in_row;
	v->need_ke = !is_plain(c) && (!p->have_keys || p->ncookies == 0);
}

int nts_peer_get(const nts_core *c, size_t i, nts_peer_view *v)
{
	if (i >= c->cfg.nservers)
		return NTS_ERR_BAD_CONFIG;
	memset(v, 0, sizeof *v);
	peer_view(c, cpeer_at(c, i), v);
	return NTS_OK;
}

void nts_status_get(const nts_core *c, nts_status *st)
{
	/* The peers are read under the gate, so no poll writes one meanwhile;
	 * the gate is the one thing this call writes in the core. */
	nts_core *g = (nts_core *)c;
	bool held = excl_enter(g);
	nts_summary_get(c, st);
	st->busy = !held;
	if (!held)
		return;
	for (size_t i = 0; i < c->cfg.nservers; i++)
		peer_view(c, cpeer_at(c, i), &st->peers[i]);
	excl_leave(g);
}
