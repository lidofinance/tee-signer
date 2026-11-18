/* The measurement on arbitrary server fields and local times: never a
 * crash, and a sample it takes has a bound and a delay of zero or more. */
#include "fuzz.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	fz_in in = {data, size};
	nts_time_response r;
	nts_sample s;
	memset(&r, 0, sizeof r);
	r.leap = fz_pick(&in, 4);
	r.stratum = fz_u8(&in);
	r.precision = (int8_t)fz_u8(&in);
	r.root_delay = (uint32_t)fz_u64(&in);
	r.root_dispersion = (uint32_t)fz_u64(&in);
	r.reference = fz_u64(&in);
	r.receive = fz_u64(&in);
	r.transmit = fz_u64(&in);
	int64_t t1 = (int64_t)fz_u64(&in), t4 = (int64_t)fz_u64(&in), pivot = (int64_t)fz_u64(&in);
	if (nts_measure(&r, t1, t4, pivot, &s) == NTS_OK) {
		FUZZ_CHECK(s.bound >= 0 && s.bound <= NTS_MAX_SAMPLE_BOUND_NS);
		FUZZ_CHECK(s.delay >= 0 && s.t4 == t4);
	}
	return 0;
}
