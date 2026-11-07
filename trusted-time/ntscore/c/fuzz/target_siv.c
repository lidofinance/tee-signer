/* AES-SIV on arbitrary keys and messages: a sealed message opens, one with
 * a changed bit does not, and both AES paths agree where the CPU has the
 * instructions. */
#include "fuzz.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	static bool ready;
	static uint8_t ct[4096 + NTS_SIV_TAG_LEN], ct2[sizeof ct], pt[4096];
	fz_in in = {data, size};
	uint8_t key[NTS_KEY_LEN], ad[64], nonce[16], msg[4096];
	nts_siv_key k;
	if (!ready) {
		nts_setup();
		ready = true;
	}
	fz_bytes(&in, key, sizeof key);
	size_t adlen = fz_bytes(&in, ad, fz_pick(&in, sizeof ad + 1));
	size_t noncelen = fz_bytes(&in, nonce, 1 + fz_pick(&in, sizeof nonce));
	uint8_t flip = fz_u8(&in);
	size_t msglen = fz_bytes(&in, msg, sizeof msg);
	FUZZ_CHECK(nts_siv_init(&k, key, sizeof key) == NTS_OK);
	const uint8_t *ads[2] = {ad, nonce};
	size_t adlens[2] = {adlen, noncelen};
	size_t ctlen = nts_siv_seal(&k, ads, adlens, 2, msg, msglen, ct);
	FUZZ_CHECK(ctlen == msglen + NTS_SIV_TAG_LEN);
	FUZZ_CHECK(nts_siv_open(&k, ads, adlens, 2, ct, ctlen, pt));
	FUZZ_CHECK(memcmp(pt, msg, msglen) == 0);
	size_t bit = (size_t)flip * 7919 % (ctlen * 8);
	ct[bit / 8] ^= (uint8_t)(1 << (bit % 8));
	FUZZ_CHECK(!nts_siv_open(&k, ads, adlens, 2, ct, ctlen, pt));
	ct[bit / 8] ^= (uint8_t)(1 << (bit % 8));
	if (nts_aes_hardware()) {
		nts_aes_use_hardware(false);
		size_t n2 = nts_siv_seal(&k, ads, adlens, 2, msg, msglen, ct2);
		nts_aes_use_hardware(true);
		FUZZ_CHECK(n2 == ctlen && memcmp(ct, ct2, ctlen) == 0);
	}
	return 0;
}
