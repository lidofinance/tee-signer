/* The response check on arbitrary bytes, against a fixed request: the
 * fields, the Unique Identifier, the authenticator with the S2C key, the
 * decrypted part. A refused response leaves the request open. */
#include "fuzz.h"

static nts_siv_key c2s, s2c;
static nts_pending pending;
static bool ready;

static void setup(void)
{
	uint8_t key[NTS_KEY_LEN], req[NTS_MAX_REQUEST_LEN], cookie[100], uid[NTS_UID_LEN], nonce[NTS_NONCE_LEN];
	size_t reqlen = 0;
	nts_setup();
	fz_key(key, 1);
	FUZZ_CHECK(nts_siv_init(&c2s, key, sizeof key) == NTS_OK);
	fz_key(key, 2);
	FUZZ_CHECK(nts_siv_init(&s2c, key, sizeof key) == NTS_OK);
	for (int i = 0; i < 100; i++)
		cookie[i] = (uint8_t)i;
	for (int i = 0; i < NTS_UID_LEN; i++)
		uid[i] = (uint8_t)(0xa0 + i);
	for (int i = 0; i < NTS_NONCE_LEN; i++)
		nonce[i] = (uint8_t)(0x4e + i);
	FUZZ_CHECK(nts_build_request(&c2s, 0x0102030405060708ULL, uid, nonce, cookie, sizeof cookie, 3, req, sizeof req, &reqlen, &pending) == NTS_OK);
	ready = true;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	static nts_verdict v;
	if (!ready)
		setup();
	nts_pending p = pending;
	int rc = nts_verify_response(&p, &s2c, data, size, &v);
	if (rc != NTS_OK) {
		FUZZ_CHECK(!p.answered);
	} else if (v.kind == NTS_KIND_TIME) {
		FUZZ_CHECK(p.answered && v.time.ncookies >= 1 && v.time.ncookies <= 4);
	} else {
		FUZZ_CHECK(v.kind == NTS_KIND_KISS && !p.answered);
	}
	return 0;
}
