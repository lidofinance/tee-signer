/* AES-SIV-CMAC-256 (RFC 5297) as NTS uses it (RFC 8915 section 5.6), on
 * an AES-128 forward cipher of its own: CMAC and CTR need encryption
 * only. S2V takes the associated data strings, the nonce among them, and
 * the plaintext last. dbl is branch-free and the tag compare is constant
 * time.
 *
 * The AES runs on the CPU's instructions (AES-NI on x86-64, the ARMv8
 * Cryptography Extension on aarch64), found by nts_setup, and otherwise
 * on software that is constant time: no table, the S-box of each byte
 * computed as the field inverse (a fixed chain of multiplications) and
 * the affine map, so no memory access and no branch depends on a key or
 * state byte. The host shares the cache with the enclave and sees every
 * request and tag, so a table AES would leak the keys to it, and with the
 * S2C key it could forge the time. Both paths take the same expanded key
 * and must give the same output (siv_test.go runs the vectors and the
 * fuzzer on both). The only constants are the polynomial 0x1b, the affine
 * constant 0x63 and the round-constant start.
 *
 * NTS_AES_HW=1 or 0 at compile time forces a path (a trusted application
 * that cannot read the feature register); unset, the CPU is asked. */
#include <string.h>

#include "nts_core.h"

#if !defined(NTS_AES_HW) || NTS_AES_HW
#if defined(__x86_64__)
#include <cpuid.h>
#include <wmmintrin.h>
#define AES_HW_CODE 1
#elif defined(__aarch64__)
#include <arm_neon.h>
#define AES_HW_CODE 1
#endif
#endif

void nts_wipe(void *p, size_t n)
{
	volatile uint8_t *v = p;
	while (n--)
		*v++ = 0;
}

/* ---- AES-128, encryption ---- */

static bool setup_done, aes_hw_available, aes_hw;

static uint8_t xtime(uint8_t b) { return (uint8_t)((b << 1) ^ (uint8_t)(-(b >> 7) & 0x1b)); }
static uint8_t rotl8(uint8_t b, unsigned n) { return (uint8_t)((b << n) | (b >> (8 - n))); }

/* a * b in GF(2^8): eight steps, always all eight, the bits of b read by
 * index into masks. b is never shifted or compared, so a compiler has no
 * early exit to find: the run time cannot depend on the operands (gcc and
 * clang compile this to a counted loop or straight line; the disassembly
 * is worth a look after a compiler change). */
static uint8_t gf_mul(uint8_t a, uint8_t b)
{
	uint8_t p = 0;
	for (int i = 0; i < 8; i++) {
		p ^= (uint8_t)(-((b >> i) & 1) & a);
		a = xtime(a);
	}
	return p;
}

/* The S-box of x: the inverse as x^254 = x^2 x^4 ... x^128 (0 maps to 0),
 * then the affine map. */
static uint8_t sbox(uint8_t x)
{
	uint8_t x2 = gf_mul(x, x), x4 = gf_mul(x2, x2), x8 = gf_mul(x4, x4), x16 = gf_mul(x8, x8);
	uint8_t x32 = gf_mul(x16, x16), x64 = gf_mul(x32, x32), x128 = gf_mul(x64, x64);
	uint8_t inv = gf_mul(gf_mul(gf_mul(x2, x4), gf_mul(x8, x16)), gf_mul(gf_mul(x32, x64), x128));
	return (uint8_t)(inv ^ rotl8(inv, 1) ^ rotl8(inv, 2) ^ rotl8(inv, 3) ^ rotl8(inv, 4) ^ 0x63);
}

/* 11 round keys of 16 octets from a 16-octet key. */
static void aes_expand(uint8_t rk[176], const uint8_t key[16])
{
	uint8_t rcon = 1;
	memcpy(rk, key, 16);
	for (int i = 16; i < 176; i += 4) {
		uint8_t t0 = rk[i - 4], t1 = rk[i - 3], t2 = rk[i - 2], t3 = rk[i - 1];
		if (i % 16 == 0) {
			uint8_t u0 = (uint8_t)(sbox(t1) ^ rcon), u1 = sbox(t2), u2 = sbox(t3), u3 = sbox(t0);
			t0 = u0;
			t1 = u1;
			t2 = u2;
			t3 = u3;
			rcon = xtime(rcon);
		}
		rk[i] = (uint8_t)(rk[i - 16] ^ t0);
		rk[i + 1] = (uint8_t)(rk[i - 15] ^ t1);
		rk[i + 2] = (uint8_t)(rk[i - 14] ^ t2);
		rk[i + 3] = (uint8_t)(rk[i - 13] ^ t3);
	}
}

/* The plain form of FIPS 197 with the computed S-box: constant time. */
static void aes_encrypt_sw(const uint8_t rk[176], const uint8_t in[16], uint8_t out[16])
{
	uint8_t s[16], t[16];
	for (int i = 0; i < 16; i++)
		s[i] = (uint8_t)(in[i] ^ rk[i]);
	for (int r = 1; r <= 10; r++) {
		/* SubBytes and ShiftRows: the state is column-major, s[row + 4 col];
		 * row r moves left by r columns. */
		for (int c = 0; c < 4; c++)
			for (int row = 0; row < 4; row++)
				t[row + 4 * c] = sbox(s[row + 4 * ((c + row) % 4)]);
		if (r < 10) {
			for (int c = 0; c < 4; c++) {
				uint8_t a0 = t[4 * c], a1 = t[4 * c + 1], a2 = t[4 * c + 2], a3 = t[4 * c + 3];
				t[4 * c] = (uint8_t)(xtime(a0) ^ (xtime(a1) ^ a1) ^ a2 ^ a3);
				t[4 * c + 1] = (uint8_t)(a0 ^ xtime(a1) ^ (xtime(a2) ^ a2) ^ a3);
				t[4 * c + 2] = (uint8_t)(a0 ^ a1 ^ xtime(a2) ^ (xtime(a3) ^ a3));
				t[4 * c + 3] = (uint8_t)((xtime(a0) ^ a0) ^ a1 ^ a2 ^ xtime(a3));
			}
		}
		for (int i = 0; i < 16; i++)
			s[i] = (uint8_t)(t[i] ^ rk[16 * r + i]);
	}
	memcpy(out, s, 16);
	nts_wipe(s, sizeof s);
	nts_wipe(t, sizeof t);
}

#if defined(AES_HW_CODE) && defined(__x86_64__)
static bool aes_hw_probe(void)
{
	unsigned a, b, c, d;
	if (!__get_cpuid(1, &a, &b, &c, &d))
		return false;
	return (c >> 25) & 1; /* CPUID.1:ECX.AES */
}

__attribute__((target("aes,sse2"))) static void aes_encrypt_hw(const uint8_t rk[176], const uint8_t in[16], uint8_t out[16])
{
	__m128i s = _mm_xor_si128(_mm_loadu_si128((const __m128i *)in), _mm_loadu_si128((const __m128i *)rk));
	for (int r = 1; r < 10; r++)
		s = _mm_aesenc_si128(s, _mm_loadu_si128((const __m128i *)(rk + 16 * r)));
	s = _mm_aesenclast_si128(s, _mm_loadu_si128((const __m128i *)(rk + 160)));
	_mm_storeu_si128((__m128i *)out, s);
}
#elif defined(AES_HW_CODE) && defined(__aarch64__)
static bool aes_hw_probe(void)
{
#if defined(__APPLE__)
	return true; /* every Apple silicon CPU; the register is not readable there */
#else
	uint64_t isar0;
	/* Linux traps and emulates the read for user space (since 4.11). */
	__asm__("mrs %0, ID_AA64ISAR0_EL1" : "=r"(isar0));
	return ((isar0 >> 4) & 0xf) >= 1; /* ID_AA64ISAR0_EL1.AES */
#endif
}

/* AESE is AddRoundKey, SubBytes and ShiftRows; AESMC is MixColumns. */
__attribute__((target("+crypto"))) static void aes_encrypt_hw(const uint8_t rk[176], const uint8_t in[16], uint8_t out[16])
{
	uint8x16_t s = vld1q_u8(in);
	for (int r = 0; r < 9; r++)
		s = vaesmcq_u8(vaeseq_u8(s, vld1q_u8(rk + 16 * r)));
	s = vaeseq_u8(s, vld1q_u8(rk + 144));
	s = veorq_u8(s, vld1q_u8(rk + 160));
	vst1q_u8(out, s);
}
#endif

static void aes_encrypt(const uint8_t rk[176], const uint8_t in[16], uint8_t out[16])
{
#if defined(AES_HW_CODE)
	if (aes_hw) {
		aes_encrypt_hw(rk, in, out);
		return;
	}
#endif
	aes_encrypt_sw(rk, in, out);
}

void nts_setup(void)
{
#if defined(NTS_AES_HW) && NTS_AES_HW
	aes_hw_available = true;
#elif defined(AES_HW_CODE)
	aes_hw_available = aes_hw_probe();
#else
	aes_hw_available = false;
#endif
	aes_hw = aes_hw_available;
	setup_done = true;
}

bool nts_aes_hardware(void) { return aes_hw; }

#if !defined(NTS_NO_TEST_HOOKS)
bool nts_aes_use_hardware(bool use)
{
	aes_hw = use && aes_hw_available;
	return aes_hw;
}
#endif

/* ---- CMAC (RFC 4493) and S2V (RFC 5297 section 2.4) ---- */

/* dbl is multiplication by x in GF(2^128) (RFC 5297 section 2.3), without
 * a branch on the carried bit. */
static void dbl(const uint8_t in[16], uint8_t out[16])
{
	uint8_t mask = (uint8_t)(-(in[0] >> 7) & 0x87);
	for (int i = 0; i < 15; i++)
		out[i] = (uint8_t)((in[i] << 1) | (in[i + 1] >> 7));
	out[15] = (uint8_t)((in[15] << 1) ^ mask);
}

/* The subkeys of CMAC (RFC 4493 section 2.3) and S2V's first block, the
 * CMAC of a zero block (RFC 5297 section 2.4), fixed per key: computed at
 * nts_siv_init, not per call. */
static void siv_subkeys(nts_siv_key *k)
{
	uint8_t l[16] = {0};
	aes_encrypt(k->mac, l, l);
	dbl(l, k->k1);
	dbl(k->k1, k->k2);
	nts_wipe(l, sizeof l);
}

/* CMAC of msg. With xorend, the last 16 octets of msg are xored with it
 * first (S2V's xorend, RFC 5297 section 2.4), without copying msg: the
 * xor is applied as the blocks are built. msg has 16 octets or more then. */
static void cmac(const nts_siv_key *k, const uint8_t *msg, size_t len, const uint8_t *xorend, uint8_t out[16])
{
	const uint8_t *rk = k->mac, *k1 = k->k1, *k2 = k->k2;
	uint8_t x[16] = {0}, blk[16];
	size_t n = (len + 15) / 16;
	bool complete = n > 0 && len % 16 == 0;
	if (n == 0)
		n = 1;
	for (size_t b = 0; b < n; b++) {
		size_t at = b * 16, take = len - at < 16 ? len - at : 16;
		memset(blk, 0, 16);
		for (size_t i = 0; i < take; i++) {
			uint8_t c = msg[at + i];
			if (xorend && at + i >= len - 16)
				c ^= xorend[at + i - (len - 16)];
			blk[i] = c;
		}
		if (b == n - 1) {
			if (complete) {
				for (int i = 0; i < 16; i++)
					blk[i] ^= k1[i];
			} else {
				blk[take] = 0x80;
				for (int i = 0; i < 16; i++)
					blk[i] ^= k2[i];
			}
		}
		for (int i = 0; i < 16; i++)
			x[i] ^= blk[i];
		aes_encrypt(rk, x, x);
	}
	memcpy(out, x, 16);
	nts_wipe(x, sizeof x);
	nts_wipe(blk, sizeof blk);
}

/* S2V over the strings, the last one being the plaintext. */
static void s2v(const nts_siv_key *k, const uint8_t *const *strs, const size_t *lens, size_t n, uint8_t out[16])
{
	uint8_t d[16], m[16], t[16];
	memcpy(d, k->d0, 16);
	for (size_t i = 0; i + 1 < n; i++) {
		cmac(k, strs[i], lens[i], NULL, m);
		dbl(d, t);
		for (int j = 0; j < 16; j++)
			d[j] = (uint8_t)(t[j] ^ m[j]);
	}
	const uint8_t *sn = strs[n - 1];
	size_t ln = lens[n - 1];
	if (ln >= 16) {
		cmac(k, sn, ln, d, out);
	} else {
		uint8_t p[16] = {0};
		dbl(d, t);
		if (ln)
			memcpy(p, sn, ln); /* sn may be NULL when ln is 0 */
		p[ln] = 0x80;
		for (int j = 0; j < 16; j++)
			p[j] ^= t[j];
		cmac(k, p, 16, NULL, out);
		nts_wipe(p, sizeof p);
	}
	nts_wipe(d, sizeof d);
	nts_wipe(m, sizeof m);
	nts_wipe(t, sizeof t);
}

/* AES-CTR under the CTR key with the IV of RFC 5297 section 2.6: V with
 * bits 31 and 63 (from the right) cleared; the counter is the whole 16
 * octets, big-endian, as Go's cipher.NewCTR counts it. */
static void siv_ctr(const uint8_t rk[176], const uint8_t v[16], const uint8_t *in, size_t len, uint8_t *out)
{
	uint8_t ctr[16], ks[16];
	memcpy(ctr, v, 16);
	ctr[8] &= 0x7f;
	ctr[12] &= 0x7f;
	for (size_t at = 0; at < len; at += 16) {
		aes_encrypt(rk, ctr, ks);
		size_t take = len - at < 16 ? len - at : 16;
		for (size_t i = 0; i < take; i++)
			out[at + i] = (uint8_t)(in[at + i] ^ ks[i]);
		for (int i = 15; i >= 0; i--)
			if (++ctr[i] != 0)
				break;
	}
	nts_wipe(ctr, sizeof ctr);
	nts_wipe(ks, sizeof ks);
}

int nts_siv_init(nts_siv_key *k, const uint8_t *key, size_t len)
{
	if (len != NTS_KEY_LEN)
		return NTS_ERR_KEY_LEN;
	/* Without nts_setup the AES path is not chosen: refuse rather than
	 * run on a guess. */
	if (!setup_done)
		return NTS_ERR_BAD_CONFIG;
	aes_expand(k->mac, key);
	aes_expand(k->ctr, key + 16);
	siv_subkeys(k);
	static const uint8_t zero[16];
	cmac(k, zero, 16, NULL, k->d0);
	return NTS_OK;
}

/* The strings of S2V: the associated data, then the plaintext. */
#define MAX_STRS (NTS_SIV_MAX_AD + 1)

size_t nts_siv_seal(const nts_siv_key *k, const uint8_t *const *ads, const size_t *adlens, size_t nads,
		    const uint8_t *pt, size_t ptlen, uint8_t *out)
{
	const uint8_t *strs[MAX_STRS];
	size_t lens[MAX_STRS];
	if (nads + 1 > MAX_STRS)
		return 0;
	for (size_t i = 0; i < nads; i++) {
		strs[i] = ads[i];
		lens[i] = adlens[i];
	}
	strs[nads] = pt;
	lens[nads] = ptlen;
	s2v(k, strs, lens, nads + 1, out);
	siv_ctr(k->ctr, out, pt, ptlen, out + NTS_SIV_TAG_LEN);
	return NTS_SIV_TAG_LEN + ptlen;
}

static bool ct_eq(const uint8_t *a, const uint8_t *b, size_t n)
{
	uint8_t acc = 0;
	for (size_t i = 0; i < n; i++)
		acc |= (uint8_t)(a[i] ^ b[i]);
	return acc == 0;
}

bool nts_siv_open(const nts_siv_key *k, const uint8_t *const *ads, const size_t *adlens, size_t nads,
		  const uint8_t *ct, size_t ctlen, uint8_t *pt)
{
	const uint8_t *strs[MAX_STRS];
	size_t lens[MAX_STRS];
	uint8_t t[16];
	if (ctlen < NTS_SIV_TAG_LEN || nads + 1 > MAX_STRS)
		return false;
	siv_ctr(k->ctr, ct, ct + NTS_SIV_TAG_LEN, ctlen - NTS_SIV_TAG_LEN, pt);
	for (size_t i = 0; i < nads; i++) {
		strs[i] = ads[i];
		lens[i] = adlens[i];
	}
	strs[nads] = pt;
	lens[nads] = ctlen - NTS_SIV_TAG_LEN;
	s2v(k, strs, lens, nads + 1, t);
	bool ok = ct_eq(t, ct, 16);
	nts_wipe(t, sizeof t);
	return ok;
}
