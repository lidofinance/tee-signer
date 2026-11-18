/* The plain NTP response check on arbitrary bytes, against a fixed
 * request, then the measurement of what it accepts. The input is the
 * local times and the pivot (24 octets), then the datagram. Nothing
 * authenticates a plain response, so there is no oracle on the time it
 * names; what must hold: a refused response leaves the request open; a
 * Kiss-o'-Death closes it, is never authentic and has a printable code; a
 * time response closes it, has no cookies, a leap indicator under 3 and
 * a stratum of 1 to 15; nothing is accepted twice; and a sample measured
 * from it has a bound within the limits. */
#include "fuzz.h"

#define PLAIN_TRANSMIT 0x1122334455667788ULL

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	static nts_verdict v;
	fz_in in = {data, size};
	uint8_t req[NTS_PLAIN_REQUEST_LEN];
	nts_plain_pending p;
	nts_sample s;
	int64_t t1 = (int64_t)fz_u64(&in), t4 = (int64_t)fz_u64(&in), pivot = (int64_t)fz_u64(&in);

	nts_plain_request(PLAIN_TRANSMIT, req, &p);
	FUZZ_CHECK(req[0] == 0x23 && !p.answered && p.transmit == PLAIN_TRANSMIT);
	for (int i = 1; i < 40; i++)
		FUZZ_CHECK(req[i] == 0);
	memset(&v, 0x5a, sizeof v);
	int rc = nts_plain_verify(&p, in.p, in.n, &v);
	if (rc != NTS_OK) {
		FUZZ_CHECK(!p.answered);
		return 0;
	}
	FUZZ_CHECK(p.answered && in.n >= 48 && in.n <= NTS_MAX_RESPONSE_LEN);
	FUZZ_CHECK(nts_plain_verify(&p, in.p, in.n, &v) == NTS_ERR_ALREADY_ANSWERED);
	if (v.kind == NTS_KIND_KISS) {
		FUZZ_CHECK(!v.kiss_authentic && in.p[1] == 0);
		for (int i = 0; i < 4; i++)
			FUZZ_CHECK(v.kiss[i] >= 0x20 && v.kiss[i] <= 0x7e);
		return 0;
	}
	FUZZ_CHECK(v.kind == NTS_KIND_TIME && v.time.ncookies == 0 && v.time.leap < 3 && v.time.stratum >= 1 && v.time.stratum <= 15);
	FUZZ_CHECK(v.time.origin == PLAIN_TRANSMIT);
	if (nts_measure(&v.time, t1, t4, pivot, &s) == NTS_OK) {
		FUZZ_CHECK(s.bound >= 0 && s.bound <= NTS_MAX_SAMPLE_BOUND_NS);
		FUZZ_CHECK(s.delay >= 0 && s.t4 == t4 && s.cookies_received == 0 && s.cookies_held == 0);
	}
	return 0;
}
