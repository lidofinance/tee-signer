/* The NTS-KE parsers on arbitrary bytes: the framing walk as the reader
 * uses it, then the whole check. */
#include "fuzz.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	static bool ready;
	static nts_ke_response r;
	size_t len = 0;
	bool done = false;
	if (!ready) {
		nts_setup();
		ready = true;
	}
	int rc = nts_ke_complete(data, size, &len, &done);
	if (rc == NTS_OK && done) {
		FUZZ_CHECK(len <= size && len <= NTS_KE_MAX_RESPONSE_LEN);
		if (nts_ke_parse(data, len, &r) == NTS_OK) {
			FUZZ_CHECK(r.ncookies >= 1 && r.ncookies <= NTS_MAX_COOKIES);
			for (int i = 0; i < r.ncookies; i++)
				FUZZ_CHECK(r.cookie_len[i] >= 1 && r.cookie_len[i] <= NTS_MAX_COOKIE_LEN);
			FUZZ_CHECK(r.server_len <= NTS_MAX_SERVER_NAME);
		}
	}
	nts_ke_parse(data, size, &r);
	return 0;
}
