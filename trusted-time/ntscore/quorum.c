/* The time from several servers that one of them may get wrong.
 *
 * Each measurement gives an interval [offset - bound, offset + bound] that
 * holds the real offset if the server is honest. With at most F servers
 * wrong, at least n - F intervals hold the real offset, so the real offset
 * is a point that at least n - F intervals cover. The result is [lo, hi],
 * the smallest and the largest such point, or no answer if there is none:
 * the intersection of RFC 5905 section 11.2.1 (Marzullo) with a fixed F
 * and without the clustering that follows it. */
#include <string.h>

#include "nts_core.h"

typedef __int128 i128;

struct end {
	i128 x;
	bool start;
};

static bool less(const struct end *a, const struct end *b)
{
	if (a->x != b->x)
		return a->x < b->x;
	return a->start && !b->start; /* at equal positions a start comes first: closed intervals touch */
}

static i128 floor_half(i128 n)
{
	i128 q = n / 2, r = n % 2; /* a constant divisor: no runtime routine */
	return r < 0 ? q - 1 : q;
}

static bool fits(i128 v) { return v >= INT64_MIN && v <= INT64_MAX; }

int nts_quorum(const nts_interval *in, size_t n, int64_t now, nts_quorum_result *r)
{
	struct end ends[2 * NTS_QUORUM_MAX_SERVERS];
	if (n < NTS_QUORUM_MIN_SERVERS)
		return NTS_ERR_TOO_FEW;
	if (n > NTS_QUORUM_MAX_SERVERS)
		return NTS_ERR_TOO_MANY;
	for (size_t i = 0; i < n; i++) {
		const nts_interval *s = &in[i];
		if (s->oplen == 0 || s->oplen > NTS_MAX_OPERATOR_LEN)
			return NTS_ERR_BAD_OPERATOR;
		for (size_t j = 0; j < i; j++)
			if (in[j].oplen == s->oplen && memcmp(in[j].op, s->op, s->oplen) == 0)
				return NTS_ERR_DUPLICATE_OPERATOR;
		if (s->bound < 0)
			return NTS_ERR_BAD_BOUND;
		if (s->t4 > now)
			return NTS_ERR_FROM_THE_FUTURE;
		i128 age = (i128)now - s->t4;
		if (!fits(age))
			return NTS_ERR_OUT_OF_RANGE;
		i128 bound = (i128)s->bound + nts_drift((int64_t)age);
		ends[2 * i].x = (i128)s->offset - bound;
		ends[2 * i].start = true;
		ends[2 * i + 1].x = (i128)s->offset + bound;
		ends[2 * i + 1].start = false;
	}
	/* Insertion sort: at most 32 ends. */
	for (size_t i = 1; i < 2 * n; i++)
		for (size_t j = i; j > 0 && less(&ends[j], &ends[j - 1]); j--) {
			struct end t = ends[j];
			ends[j] = ends[j - 1];
			ends[j - 1] = t;
		}
	size_t need = n - NTS_QUORUM_F;
	size_t count = 0;
	bool have_lo = false, have_hi = false;
	i128 lo = 0, hi = 0;
	for (size_t i = 0; i < 2 * n; i++) {
		if (ends[i].start) {
			count++;
			if (count >= need && !have_lo) {
				lo = ends[i].x;
				have_lo = true;
			}
		} else {
			if (count >= need) {
				hi = ends[i].x;
				have_hi = true;
			}
			if (count > 0)
				count--;
		}
	}
	if (!have_lo || !have_hi)
		return NTS_ERR_NO_AGREEMENT;
	i128 mid = floor_half(lo + hi);
	i128 half = floor_half(hi - lo + 1);
	if (!fits(mid) || !fits(half) || !fits(lo) || !fits(hi))
		return NTS_ERR_OUT_OF_RANGE;
	r->offset = (int64_t)mid;
	r->bound = (int64_t)half;
	r->lo = (int64_t)lo;
	r->hi = (int64_t)hi;
	return NTS_OK;
}
