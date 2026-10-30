/* The NTP time formats with era-safe conversion (RFC 5905 section 6), and
 * the offset, delay and error bound of one server response (section 8)
 * with the checks that need no earlier state. The Go code this replaced
 * ran the arithmetic in big.Int; here it is 128-bit, with the same
 * rounding directions. */
#include "nts_core.h"

typedef __int128 i128;

#define NANOS ((i128)1000000000)
#define UNITS ((i128)1 << 32) /* fraction units per second: 2^-32 s */
#define EPOCH_NANOS ((i128)2208988800LL * NANOS)
#define ROUNDING_NS 3
#define PPM ((i128)1000000)

typedef unsigned __int128 u128;

/* n / d truncated toward zero, and n % d with the sign of n, for d > 0:
 * shift and subtract, so that the core needs no 128-bit division routine
 * of the compiler runtime (libgcc's __divti3 and friends) and stays at
 * memcpy, memset and memcmp. Fifteen or so calls per sample. */
static i128 divmod(i128 n, i128 d, i128 *rem)
{
	u128 un = n < 0 ? (u128)0 - (u128)n : (u128)n, ud = (u128)d, q = 0, r = 0;
	for (int i = 127; i >= 0; i--) {
		r = (r << 1) | ((un >> i) & 1);
		if (r >= ud) {
			r -= ud;
			q |= (u128)1 << i;
		}
	}
	*rem = n < 0 ? (i128)((u128)0 - r) : (i128)r;
	return n < 0 ? (i128)((u128)0 - q) : (i128)q;
}

/* n / d rounded toward plus infinity, d > 0. */
static i128 ceil_div(i128 n, i128 d)
{
	i128 r, q = divmod(n, d, &r);
	return r > 0 ? q + 1 : q;
}

/* n / d rounded toward minus infinity, d > 0: Go's big.Int Div. */
static i128 floor_div(i128 n, i128 d)
{
	i128 r, q = divmod(n, d, &r);
	return r < 0 ? q - 1 : q;
}

static bool fits(i128 v) { return v >= INT64_MIN && v <= INT64_MAX; }

uint64_t nts_ntp_from_unix_nanos(int64_t n)
{
	i128 x = ((i128)n + EPOCH_NANOS) << 32;
	return (uint64_t)ceil_div(x, NANOS); /* the low 64 bits, two's complement */
}

/* An NTP timestamp on the wire holds 32 bits of seconds and 32 bits of
 * fraction. The seconds wrap every 2^32 seconds (about 136 years), so the
 * wire value does not say which era it is in; era 0 ends on 2036-02-07
 * 06:28:16 UTC. RFC 5905 section 6: the era is found from a nearby time the
 * receiver already knows, and the difference of two timestamps is right as
 * long as they are less than about 68 years apart. */
bool nts_unix_nanos(uint64_t t, int64_t pivot, int64_t *out)
{
	i128 p = ((i128)pivot + EPOCH_NANOS) << 32;
	i128 pu = floor_div(p, NANOS);
	int64_t delta = (int64_t)(t - (uint64_t)pu);
	i128 units = pu + delta;
	i128 n = floor_div(units * NANOS, UNITS) - EPOCH_NANOS;
	if (!fits(n))
		return false;
	*out = (int64_t)n;
	return true;
}

int64_t nts_ntp_sub(uint64_t t, uint64_t earlier) { return (int64_t)(t - earlier); }

int64_t nts_duration_nanos(int64_t d) { return (int64_t)floor_div((i128)d * NANOS, UNITS); }

int64_t nts_short_nanos(uint32_t s) { return (int64_t)(((uint64_t)s * 1000000000ULL) >> 16); }

/* 2^precision seconds in nanoseconds, rounded up, for every int8 (RFC
 * 5905 section 7.3: precision is a signed log2 of seconds). Capped at 2^7
 * s, which is far over the sample bound anyway; 2^-64 s and below round
 * up to 1 ns. -128 gives 1 ns, not a shift by 128. */
static i128 precision_ns(int8_t precision)
{
	int p = precision;
	if (p >= 0)
		return NANOS << (p < 7 ? p : 7);
	int shift = -p < 64 ? -p : 64;
	return ceil_div(NANOS, (i128)1 << shift);
}

int64_t nts_drift(int64_t d)
{
	if (d <= 0)
		return 0;
	i128 q = ceil_div((i128)d * NTS_RHO_PPM, PPM);
	return q > INT64_MAX ? INT64_MAX : (int64_t)q;
}

int64_t nts_add_bound(int64_t a, int64_t b)
{
	if (a < 0 || b < 0 || a > INT64_MAX - b)
		return INT64_MAX;
	return a + b;
}

int nts_measure(const nts_time_response *s, int64_t t1, int64_t t4, int64_t pivot, nts_sample *out)
{
	int64_t t2, t3;
	out->detail = 0;
	if (s->stratum < 1 || s->stratum > 15) {
		out->detail = s->stratum;
		return NTS_ERR_SAMPLE_STRATUM;
	}
	if (s->reference == 0)
		return NTS_ERR_NEVER_SYNCHRONIZED;
	if (s->receive == 0 || s->transmit == 0)
		return NTS_ERR_ZERO_TIMESTAMP;
	if (nts_ntp_sub(s->transmit, s->reference) < 0)
		return NTS_ERR_REFERENCE_AFTER_TRANSMIT;
	if (t4 < t1)
		return NTS_ERR_LOCAL_TIMES_REVERSED;
	int64_t server_ns = nts_duration_nanos(nts_ntp_sub(s->transmit, s->receive));
	if (server_ns < 0)
		return NTS_ERR_SERVER_TIMES_REVERSED;
	if (!nts_unix_nanos(s->receive, pivot, &t2) || !nts_unix_nanos(s->transmit, pivot, &t3))
		return NTS_ERR_TIMESTAMP_OUT_OF_RANGE;
	i128 round_trip = (i128)t4 - t1;
	i128 delay = round_trip - server_ns;
	if (delay < 0)
		return NTS_ERR_NEGATIVE_DELAY;
	i128 offset = floor_div(((i128)t2 - t1) + ((i128)t3 - t4), 2);
	i128 bound = ceil_div(delay, 2) + ceil_div(nts_short_nanos(s->root_delay), 2) + nts_short_nanos(s->root_dispersion) + 2 +
		     precision_ns(s->precision) + ceil_div(round_trip * NTS_RHO_PPM, PPM) + ROUNDING_NS;
	if (bound > NTS_MAX_SAMPLE_BOUND_NS)
		return NTS_ERR_BOUND_TOO_LARGE;
	if (!fits(offset) || !fits(delay) || !fits(bound))
		return NTS_ERR_TIMESTAMP_OUT_OF_RANGE;
	out->offset = (int64_t)offset;
	out->delay = (int64_t)delay;
	out->bound = (int64_t)bound;
	out->t4 = t4;
	out->root_delay = nts_short_nanos(s->root_delay);
	out->root_dispersion = nts_short_nanos(s->root_dispersion);
	out->stratum = s->stratum;
	out->precision = s->precision;
	out->leap = s->leap;
	out->cookies_received = s->ncookies;
	out->cookies_held = 0;
	return NTS_OK;
}

int64_t nts_precision_ns(int8_t precision) { return (int64_t)precision_ns(precision); }
