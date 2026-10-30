/* The NTS client core of trusted-time in C: everything whose integrity the
 * signer's time rests on, written so that it can run inside a trusted
 * application where the Go wrapper cannot follow.
 *
 * The boundary. The wrapper is the network, nothing more: whatever it hands
 * the core is something an attacker on the wire could hand it too, that is
 * ciphertext and datagrams. The core holds the keys, the cookies, every
 * random value, every timestamp, the samples, the quorum and the time it
 * answers with. It gets them through the host operations of nts_host_ops,
 * which fall in two kinds:
 *
 *   trusted: random bytes, the monotonic clock, the TLS 1.3 session of
 *   NTS-KE with its exporter and its check of the certificate against the
 *   pinned roots. On the cloud runners the whole process is inside the TEE
 *   and Go implements them; in an OP-TEE trusted application they must be
 *   implemented inside it (TEE_GenerateRandom, the secure counter, mbedTLS).
 *
 *   untrusted: the TCP connection NTS-KE runs over and the UDP socket of
 *   the NTP exchange. They move bytes. If they lie, delay or drop, the
 *   client gets no time, never a wrong one: NTS authenticates every answer,
 *   the unique identifier refuses replays, delay widens the bound, and a
 *   bound past the limit refuses the time.
 *
 * What stays outside and why it is harmless there: when to poll (if the
 * wrapper stops polling, the bound ages past the limit and the core refuses
 * the time), logging, status for humans. The server list and the pinned
 * roots are configuration of the core and must reach it by a trusted path
 * (the sealed setup, the image), never from the wrapper at run time.
 *
 * Two inputs of the wrapper are trusted a little, and only until the first
 * quorum: the coarse time (the HTTPS-date quorum on the runners), which
 * dates the certificates of the first key exchanges and is a gross check
 * on every quorum after; the era of NTP timestamps is fixed by floor_unix_ns
 * of the configuration, not by it. After the first quorum the core dates
 * certificates with its own time.
 *
 * Freestanding C11, no allocation, no floating point; the only outside
 * symbols are memcpy, memmove, memchr, memset and memcmp (the Makefile
 * checks). 128-bit
 * arithmetic where the Go package used big.Int, with its own division.
 * The checks and their order follow the Go package this replaced, error
 * code for error value; the Go tests of trusted-time drive this code
 * through the cgo binding, and so do its fuzz targets. */
#ifndef NTS_CORE_H
#define NTS_CORE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* ---- Limits of the protocol ---- */

#define NTS_KEY_LEN 32
#define NTS_UID_LEN 32
#define NTS_NONCE_LEN 16
#define NTS_SIV_TAG_LEN 16
#define NTS_MAX_PLACEHOLDERS 7
#define NTS_MAX_REQUEST_LEN 1280
#define NTS_MAX_RESPONSE_LEN 2048
#define NTS_REQUEST_RANDOM_LEN (8 + NTS_UID_LEN + NTS_NONCE_LEN)
#define NTS_MAX_COOKIES 8
#define NTS_MAX_COOKIE_LEN 1024
#define NTS_KE_PORT 4460
#define NTS_KE_REQUEST_LEN 16
#define NTS_KE_MAX_RESPONSE_LEN 65536
#define NTS_KE_MAX_RECORDS 64
#define NTS_KE_MAX_BODY 1024
#define NTS_MAX_SERVER_NAME 255
#define NTS_RHO_PPM 500
#define NTS_MAX_SAMPLE_BOUND_NS 1000000000LL
#define NTS_QUORUM_F 1
#define NTS_QUORUM_MIN_SERVERS (2 * NTS_QUORUM_F + 1)
#define NTS_QUORUM_MAX_SERVERS 16
#define NTS_MAX_OPERATOR_LEN 32

/* ---- Limits of the client ---- */

#define NTS_MAX_SERVERS NTS_QUORUM_MAX_SERVERS
#define NTS_MAX_HOST_LEN NTS_MAX_SERVER_NAME
#define NTS_MAX_ADDR_LEN 320 /* host:port, an IPv6 literal in brackets */
#define NTS_MAX_ROOTS_LEN 16384 /* the pinned roots of one operator, PEM */
#define NTS_MAX_HIST 64 /* quorums kept for the drift check; 34 at the defaults */

/* Why a call refused. The ranges give the Go wrapper its error codes:
 * 10 to 39 the NTP exchange, 40 to 59 the measurement, 60 to 69 the quorum,
 * 70 to 89 NTS-KE, 90 to 99 a host operation, 100 and up the client. */
enum nts_err {
	NTS_OK = 0,
	NTS_ERR_KEY_LEN = 1,
	/* the request */
	NTS_ERR_TOO_MANY_PLACEHOLDERS = 10,
	NTS_ERR_REQUEST_TOO_LONG,
	NTS_ERR_BAD_COOKIE,
	/* the response; detail: the version, mode or stratum */
	NTS_ERR_ALREADY_ANSWERED = 20,
	NTS_ERR_TOO_SHORT,
	NTS_ERR_TOO_LONG,
	NTS_ERR_BAD_VERSION,
	NTS_ERR_BAD_MODE,
	NTS_ERR_ORIGIN_MISMATCH,
	NTS_ERR_BAD_EXTENSION_FIELD,
	NTS_ERR_DUPLICATE_UID,
	NTS_ERR_MISSING_UID,
	NTS_ERR_UID_MISMATCH,
	NTS_ERR_MISSING_AUTHENTICATOR,
	NTS_ERR_BAD_AUTHENTICATOR,
	NTS_ERR_NOT_AUTHENTIC,
	NTS_ERR_BAD_ENCRYPTED_FIELD,
	NTS_ERR_TOO_MANY_COOKIES,
	NTS_ERR_NO_COOKIES,
	NTS_ERR_UNSYNCHRONIZED,
	NTS_ERR_BAD_STRATUM,
	/* the measurement; detail: the stratum */
	NTS_ERR_LOCAL_TIMES_REVERSED = 40,
	NTS_ERR_SERVER_TIMES_REVERSED,
	NTS_ERR_NEGATIVE_DELAY,
	NTS_ERR_SAMPLE_STRATUM,
	NTS_ERR_NEVER_SYNCHRONIZED,
	NTS_ERR_ZERO_TIMESTAMP,
	NTS_ERR_REFERENCE_AFTER_TRANSMIT,
	NTS_ERR_TIMESTAMP_OUT_OF_RANGE,
	NTS_ERR_BOUND_TOO_LARGE,
	/* the quorum */
	NTS_ERR_TOO_FEW = 60,
	NTS_ERR_TOO_MANY,
	NTS_ERR_BAD_OPERATOR,
	NTS_ERR_DUPLICATE_OPERATOR,
	NTS_ERR_BAD_BOUND,
	NTS_ERR_FROM_THE_FUTURE,
	NTS_ERR_NO_AGREEMENT,
	NTS_ERR_OUT_OF_RANGE,
	/* NTS-KE; detail: the record type, the error or warning code, the
	 * protocol or AEAD ID, the octets after End of Message */
	NTS_ERR_KE_TRUNCATED = 70,
	NTS_ERR_KE_TOO_LONG,
	NTS_ERR_KE_TOO_MANY_RECORDS,
	NTS_ERR_KE_RECORD_TOO_LONG,
	NTS_ERR_KE_TRAILING_DATA,
	NTS_ERR_KE_BAD_EOM,
	NTS_ERR_KE_BAD_RECORD_BODY,
	NTS_ERR_KE_CRITICAL_BIT_MISSING,
	NTS_ERR_KE_UNKNOWN_CRITICAL,
	NTS_ERR_KE_DUPLICATE_RECORD,
	NTS_ERR_KE_MISSING_RECORD,
	NTS_ERR_KE_SERVER_ERROR,
	NTS_ERR_KE_SERVER_WARNING,
	NTS_ERR_KE_NO_COMMON_PROTOCOL,
	NTS_ERR_KE_WRONG_PROTOCOL,
	NTS_ERR_KE_NO_COMMON_AEAD,
	NTS_ERR_KE_WRONG_AEAD,
	/* a host operation failed; the host keeps the details */
	NTS_ERR_HOST = 90,
	NTS_ERR_HOST_TIMEOUT, /* the exchange timed out; detail: the last refusal, an nts_err */
	NTS_ERR_HOST_RANDOM,
	/* the client */
	NTS_ERR_NO_COOKIE = 100, /* no cookie left for a request; NTS-KE is due */
	NTS_ERR_BAD_CONFIG,
	NTS_ERR_NOT_DUE, /* nothing done: the peer waits for its next NTS-KE */
	NTS_ERR_KISS, /* the query ended with a Kiss-o'-Death: nts_peer_view.last_kiss */
	NTS_ERR_NO_QUORUM, /* no quorum in force; detail: what refused the last one */
	NTS_ERR_BOUND_OVER_LIMIT,
	NTS_ERR_COARSE_CHECK,
	NTS_ERR_DRIFT,
};

/* ---- AES-SIV-CMAC-256 (RFC 5297), siv.c ---- */

/* One expanded key: AES-128 round keys for S2V (the first 16 octets of
 * the key) and for CTR (the last 16). */
typedef struct {
	uint8_t mac[176];
	uint8_t ctr[176];
} nts_siv_key;

/* Computes the AES tables. Call once, before any other function and before
 * any thread runs. */
void nts_setup(void);

/* Expands a key of exactly NTS_KEY_LEN octets. */
int nts_siv_init(nts_siv_key *k, const uint8_t *key, size_t len);

/* V || C over the associated data strings ads[0..nads) and the plaintext;
 * out gets NTS_SIV_TAG_LEN + ptlen octets. Returns that length. */
size_t nts_siv_seal(const nts_siv_key *k, const uint8_t *const *ads, const size_t *adlens, size_t nads,
		    const uint8_t *pt, size_t ptlen, uint8_t *out);

/* Checks and decrypts V || C; pt gets ctlen - NTS_SIV_TAG_LEN octets. */
bool nts_siv_open(const nts_siv_key *k, const uint8_t *const *ads, const size_t *adlens, size_t nads,
		  const uint8_t *ct, size_t ctlen, uint8_t *pt);

/* ---- NTP time formats (RFC 5905 section 6), sample.c ---- */

/* The NTP timestamp of nanoseconds since the Unix epoch: the era dropped,
 * the fraction rounded up. */
uint64_t nts_ntp_from_unix_nanos(int64_t n);

/* Nanoseconds since the Unix epoch of an NTP timestamp, rounded down, in
 * the era nearest the pivot; false if that does not fit an int64. */
bool nts_unix_nanos(uint64_t t, int64_t pivot, int64_t *out);

/* t - earlier in 2^-32 s units, modulo 2^64, read as signed. */
int64_t nts_ntp_sub(uint64_t t, uint64_t earlier);

/* Nanoseconds of a signed difference in 2^-32 s units, rounded toward
 * minus infinity. */
int64_t nts_duration_nanos(int64_t d);

/* The NTP short format in nanoseconds, rounded down. */
int64_t nts_short_nanos(uint32_t s);

/* 2^precision seconds in nanoseconds, rounded up, for every int8; at most
 * 2^7 s. */
int64_t nts_precision_ns(int8_t precision);

/* ---- The NTPv4 request and response (RFC 8915 section 5), ntp.c ---- */

/* The length of an extension field with a body of n octets, of a request
 * with a cookie of cookielen octets and placeholders placeholders, and the
 * most placeholders such a request can carry within NTS_MAX_REQUEST_LEN. */
size_t nts_field_len(size_t n);
size_t nts_request_len(size_t cookielen, int placeholders);
int nts_max_placeholders(size_t cookielen);

/* A request waiting for its response. */
typedef struct {
	uint64_t transmit;
	uint8_t uid[NTS_UID_LEN];
	int placeholders;
	bool answered;
} nts_pending;

/* Builds the request into out (outcap octets) and the pending state. The
 * transmit timestamp, the unique identifier and the nonce are the caller's
 * random values (NTS_REQUEST_RANDOM_LEN octets in that order). */
int nts_build_request(const nts_siv_key *c2s, uint64_t transmit, const uint8_t uid[NTS_UID_LEN],
		      const uint8_t nonce[NTS_NONCE_LEN], const uint8_t *cookie, size_t cookielen, int placeholders,
		      uint8_t *out, size_t outcap, size_t *outlen, nts_pending *p);

/* The fields of an authentic response, as on the wire. */
typedef struct {
	uint8_t leap, stratum;
	int8_t precision;
	uint32_t root_delay, root_dispersion;
	uint64_t reference, origin, receive, transmit;
	int ncookies;
	size_t cookie_len[NTS_MAX_COOKIES];
	uint8_t cookies[NTS_MAX_COOKIES][NTS_MAX_COOKIE_LEN];
} nts_time_response;

enum nts_kind { NTS_KIND_TIME = 1, NTS_KIND_KISS = 2 };

/* What a valid response gives, or the detail of a refusal. */
typedef struct {
	int kind;
	char kiss[4]; /* the reference ID, non-printable octets as '?' */
	bool kiss_authentic;
	int detail;
	nts_time_response time;
} nts_verdict;

/* Checks a response to p with the S2C key. A refused response leaves p
 * open; an accepted time response closes it; a Kiss-o'-Death does not. */
int nts_verify_response(nts_pending *p, const nts_siv_key *s2c, const uint8_t *packet, size_t len, nts_verdict *v);

/* ---- The measurement (RFC 5905 section 8), sample.c ---- */

typedef struct {
	int64_t offset, delay, bound, t4, root_delay, root_dispersion;
	int stratum, precision, leap, cookies_received, cookies_held;
	int detail;
} nts_sample;

/* Offset, delay and error bound of an authentic response: t1 and t4 from
 * the monotonic clock around the exchange, the pivot any Unix time within
 * 68 years of now. */
int nts_measure(const nts_time_response *t, int64_t t1, int64_t t4, int64_t pivot, nts_sample *s);

/* How far a bound grows over d nanoseconds: NTS_RHO_PPM of d, rounded up,
 * saturated; 0 for d <= 0. */
int64_t nts_drift(int64_t d);

/* a + b for two bounds of zero or more, saturated at INT64_MAX; INT64_MAX
 * if either is negative. */
int64_t nts_add_bound(int64_t a, int64_t b);

/* ---- The quorum (RFC 5905 section 11.2.1), quorum.c ---- */

typedef struct {
	const char *op;
	size_t oplen;
	int64_t offset, bound, t4;
} nts_interval;

typedef struct {
	int64_t offset, bound, lo, hi;
} nts_quorum_result;

/* The time from n intervals of distinct operators, NTS_QUORUM_F of which
 * may be wrong, at the monotonic time now. */
int nts_quorum(const nts_interval *in, size_t n, int64_t now, nts_quorum_result *r);

/* ---- NTS-KE records (RFC 8915 section 4), ke.c ---- */

/* The request this client sends: Next Protocol NTPv4, AEAD 15, End of
 * Message, all critical. */
void nts_ke_request(uint8_t out[NTS_KE_REQUEST_LEN]);

/* The exporter context of the C2S (false) or S2C (true) key, 5 octets. */
void nts_ke_exporter_context(bool s2c, uint8_t out[5]);

/* Walks the records read so far: *len is the length of the response once
 * End of Message arrived and *done is true, or *done is false while it
 * has not. A refusal of the framing or the caps is an error. */
int nts_ke_complete(const uint8_t *buf, size_t n, size_t *len, bool *done);

typedef struct {
	int ncookies; /* the first NTS_MAX_COOKIES, in the server's order; at least one */
	size_t cookie_len[NTS_MAX_COOKIES];
	uint8_t cookies[NTS_MAX_COOKIES][NTS_MAX_COOKIE_LEN];
	int dropped; /* further valid cookies, not kept */
	char server[NTS_MAX_SERVER_NAME]; /* the NTP server named, or none */
	size_t server_len;
	uint16_t port; /* the NTP port named, 0 for none */
	int detail;
} nts_ke_response;

/* Checks a whole response. */
int nts_ke_parse(const uint8_t *buf, size_t n, nts_ke_response *r);

/* ---- The client, client.c ---- */

/* One NTS server: what the host needs to reach it and to check it. The
 * roots are the operator's pinned CA certificates, PEM, opaque to the
 * core, handed to the key exchange operation. */
typedef struct {
	char op[NTS_MAX_OPERATOR_LEN];
	size_t op_len;
	char host[NTS_MAX_HOST_LEN]; /* the TLS server name; the address too, unless ke_addr is set */
	size_t host_len;
	char ke_addr[NTS_MAX_ADDR_LEN]; /* host:port of NTS-KE; empty means host:4460 */
	size_t ke_addr_len;
	uint8_t roots[NTS_MAX_ROOTS_LEN];
	size_t roots_len;
} nts_server;

typedef struct {
	size_t nservers;
	nts_server servers[NTS_MAX_SERVERS];
	int64_t interval_ns; /* between two queries to one server */
	int64_t min_poll_ns; /* the shortest poll interval */
	int64_t max_poll_ns; /* the longest, after Kiss-o'-Death backoff */
	int64_t max_bound_ns; /* nts_bounded refuses over it */
	int64_t max_coarse_diff_ns; /* a quorum further from the coarse time is refused */
	int64_t coarse_resolution_ns; /* the coarse time names the second it was in */
	int64_t exchange_timeout_ns; /* one NTS-KE session or one query */
	int64_t kiss_grace_ns; /* how long a query reads on after a Kiss-o'-Death */
	int drift_baseline_polls; /* times interval_ns: the baseline of the drift check */
	int64_t floor_unix_ns; /* a Unix time known at build to be in the past: the NTP era pivot */
} nts_config;

/* The host operations. ctx is the host's. Every operation returns NTS_OK
 * or NTS_ERR_HOST (NTS_ERR_HOST_TIMEOUT for a receive that waited its
 * time out); the host keeps the details of its failures. */
typedef struct {
	void *ctx;
	/* Trusted: n octets from a CSPRNG. */
	int (*random)(void *ctx, uint8_t *buf, size_t n);
	/* Trusted: nanoseconds of a monotonic clock that runs within
	 * NTS_RHO_PPM of real time. */
	int64_t (*monotonic)(void *ctx);
	/* Trusted: one NTS-KE session with srv. Connect to ke_addr (or host
	 * and NTS_KE_PORT) over TCP, TLS 1.3 with ALPN "ntske/1" refusing any
	 * other, the chain checked to srv->roots with the certificate validity
	 * at validity_unix_ns, write req, read into resp until nts_ke_complete
	 * says done (or the cap, or the server closes), export the two keys
	 * with "EXPORTER-network-time-security" and nts_ke_exporter_context.
	 * timeout_ns bounds it all; *elapsed_ns is how long it took. The TCP
	 * connection is untrusted; the TLS session is not. */
	int (*key_exchange)(void *ctx, size_t peer, const nts_server *srv, int64_t validity_unix_ns, int64_t timeout_ns,
			    const uint8_t *req, size_t reqlen, uint8_t *resp, size_t respcap, size_t *resplen,
			    uint8_t c2s[NTS_KEY_LEN], uint8_t s2c[NTS_KEY_LEN], int64_t *elapsed_ns);
	/* Untrusted: a connected UDP socket to addr (host:port), closed by
	 * udp_close; timeout_ns bounds the whole exchange. */
	int (*udp_open)(void *ctx, size_t peer, const char *addr, size_t addrlen, int64_t timeout_ns, void **sock);
	int (*udp_send)(void *ctx, void *sock, const uint8_t *p, size_t n);
	/* Untrusted: one datagram, waiting at most wait_ns for it. */
	int (*udp_recv)(void *ctx, void *sock, uint8_t *buf, size_t cap, size_t *n, int64_t wait_ns);
	void (*udp_close)(void *ctx, void *sock);
} nts_host_ops;

typedef struct {
	int64_t ke_ok, ke_fail, queries, samples, errors;
	int64_t kiss_rate, kiss_ntsn, kiss_deny, kiss_rstr, kiss_other;
	int64_t last_ke_ns;
	int cookies_after_ke, cookies_held;
	int64_t last_delay_ns, last_bound_ns;
} nts_peer_stats;

/* What the host may read of one peer. */
typedef struct {
	bool have_sample;
	nts_sample sample;
	int64_t poll_ns;
	char disabled[4]; /* the DENY or RSTR obeyed, until the next good answer */
	bool is_disabled;
	int last_err, last_detail; /* the last poll's refusal, NTS_OK after a sample */
	char last_kiss[4];
	bool last_kiss_authentic;
	char ntp_addr[NTS_MAX_ADDR_LEN];
	size_t ntp_addr_len;
	int cookies;
	nts_peer_stats stats;
} nts_peer_view;

/* A snapshot of the client: the result in force, the drift reading
 * (ppm = delta / dt, the error from the bounds bounds / dt), the counters
 * and every peer. */
typedef struct {
	bool have_result;
	int64_t offset, bound, at, lo, hi; /* offset: real Unix ns minus monotonic ns, at the monotonic time at */
	uint32_t members; /* bit i: server i is in the quorum */
	bool have_drift;
	int64_t drift_delta, drift_dt, drift_bounds;
	int64_t violations, refusals;
	bool have_coarse_diff;
	int64_t coarse_diff;
	int last_err, last_detail; /* what refused the last combine, NTS_OK after a served quorum */
	size_t last_fresh; /* samples fresh enough for the last combine */
	bool members_changed; /* by the last combine */
	size_t npeers;
	nts_peer_view peers[NTS_MAX_SERVERS];
} nts_status;

/* The client state: opaque to the host, nts_core_size octets, aligned as
 * an int64_t. The host allocates and zeroes it. */
typedef struct nts_core nts_core;

size_t nts_core_size(void);

/* Takes the configuration (copied) and the host operations. */
int nts_core_init(nts_core *c, const nts_host_ops *ops, const nts_config *cfg);

/* Wipes the keys and the cookies. */
void nts_core_wipe(nts_core *c);

/* The peers due for a poll at the monotonic time now, as a bit mask. */
uint32_t nts_due(const nts_core *c, int64_t now);

/* One poll of peer i: NTS-KE if the peer holds no keys or no cookies, then
 * one query, with the Kiss-o'-Death policy and the backoff of the clock.
 * coarse_unix_ns is the host's coarse reading taken at the monotonic time
 * coarse_local: it dates the certificate before the first quorum. Returns
 * NTS_OK with a new sample, or what refused (NTS_ERR_NOT_DUE: nothing was
 * done).
 *
 * Concurrency: a poll writes only peer i, and reads the configuration and
 * the result in force. Polls of different peers may run at the same time;
 * nts_core_init, nts_core_wipe, nts_combine and nts_status may not run
 * while a poll does. nts_bounded and nts_summary may. */
int nts_poll(nts_core *c, size_t i, int64_t coarse_unix_ns, int64_t coarse_local);

/* The quorum of the fresh samples (at most 4 intervals old), checked
 * against the coarse time and against the earlier quorums (the drift
 * check), then served. */
int nts_combine(nts_core *c, int64_t coarse_unix_ns, int64_t coarse_local);

/* The time now, Unix nanoseconds, and its bound, or a refusal: no quorum,
 * or the bound aged over the limit. Never goes back. */
int nts_bounded(nts_core *c, int64_t *unix_ns, int64_t *bound_ns);

/* A full snapshot (not during a poll), and the part of it that is safe
 * during polls: everything but the peers. */
void nts_status_get(const nts_core *c, nts_status *st);
void nts_summary_get(const nts_core *c, nts_status *st);

/* One peer, as the poll of that peer left it. */
int nts_peer_get(const nts_core *c, size_t i, nts_peer_view *v);

/* The coarse check: diff is the NTS time minus the coarse time, both at
 * the same local instant. */
bool nts_coarse_refused(int64_t diff, int64_t limit, int64_t res);

#endif
