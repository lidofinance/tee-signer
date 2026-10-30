/* AES-SIV-CMAC-256 (RFC 5297) as NTS uses it (RFC 8915 section 5.6), on
 * an AES-128 forward cipher of its own: CMAC and CTR need encryption
 * only. S2V takes the associated data
 * strings, the nonce among them, and the plaintext last. dbl is
 * branch-free and the tag compare is constant time. The AES below is the
 * plain form of FIPS 197, with its S-box computed from the field inverse
 * and the affine map, so the only constants here are the polynomial 0x1b,
 * the affine constant 0x63 and the round-constant start. Its table lookup
 * is by secret-dependent index, as in any table AES; a board port would
 * use the core's AES instructions or a bitsliced form. */
#include <string.h>

#include "nts_core.h"

/* ---- AES-128, encryption ---- */

static uint8_t sbox[256];

static uint8_t xtime(uint8_t b) { return (uint8_t)((b << 1) ^ (uint8_t)(-(b >> 7) & 0x1b)); }
static uint8_t rotl8(uint8_t b, unsigned n) { return (uint8_t)((b << n) | (b >> (8 - n))); }

static void sbox_init(void)
{
	uint8_t exp[256], lg[256];
	uint8_t x = 1;
	memset(lg, 0, sizeof lg);
	for (int i = 0; i < 255; i++) {
		exp[i] = x;
		lg[x] = (uint8_t)i;
		x ^= xtime(x); /* x = x * 3: 3 generates the multiplicative group */
	}
	exp[255] = exp[0];
	for (int i = 0; i < 256; i++) {
		uint8_t inv = 0;
		if (i != 0)
			inv = exp[(255 - lg[i]) % 255];
		sbox[i] = (uint8_t)(inv ^ rotl8(inv, 1) ^ rotl8(inv, 2) ^ rotl8(inv, 3) ^ rotl8(inv, 4) ^ 0x63);
	}
}

void nts_setup(void) { sbox_init(); }

/* 11 round keys of 16 octets from a 16-octet key. */
static void aes_expand(uint8_t rk[176], const uint8_t key[16])
{
	uint8_t rcon = 1;
	memcpy(rk, key, 16);
	for (int i = 16; i < 176; i += 4) {
		uint8_t t0 = rk[i - 4], t1 = rk[i - 3], t2 = rk[i - 2], t3 = rk[i - 1];
		if (i % 16 == 0) {
			uint8_t u0 = (uint8_t)(sbox[t1] ^ rcon), u1 = sbox[t2], u2 = sbox[t3], u3 = sbox[t0];
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

static void aes_encrypt(const uint8_t rk[176], const uint8_t in[16], uint8_t out[16])
{
	uint8_t s[16], t[16];
	for (int i = 0; i < 16; i++)
		s[i] = (uint8_t)(in[i] ^ rk[i]);
	for (int r = 1; r <= 10; r++) {
		/* SubBytes and ShiftRows: the state is column-major, s[row + 4 col];
		 * row r moves left by r columns. */
		for (int c = 0; c < 4; c++)
			for (int row = 0; row < 4; row++)
				t[row + 4 * c] = sbox[s[row + 4 * ((c + row) % 4)]];
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
}

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

/* CMAC of msg. With xorend, the last 16 octets of msg are xored with it
 * first (S2V's xorend, RFC 5297 section 2.4), without copying msg: the
 * xor is applied as the blocks are built. msg has 16 octets or more then. */
static void cmac(const uint8_t rk[176], const uint8_t *msg, size_t len, const uint8_t *xorend, uint8_t out[16])
{
	uint8_t l[16] = {0}, k1[16], k2[16], x[16] = {0}, blk[16];
	aes_encrypt(rk, l, l);
	dbl(l, k1);
	dbl(k1, k2);
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
}

/* S2V over the strings, the last one being the plaintext. */
static void s2v(const uint8_t rk[176], const uint8_t *const *strs, const size_t *lens, size_t n, uint8_t out[16])
{
	uint8_t zero[16] = {0}, d[16], m[16], t[16];
	cmac(rk, zero, 16, NULL, d);
	for (size_t i = 0; i + 1 < n; i++) {
		cmac(rk, strs[i], lens[i], NULL, m);
		dbl(d, t);
		for (int j = 0; j < 16; j++)
			d[j] = (uint8_t)(t[j] ^ m[j]);
	}
	const uint8_t *sn = strs[n - 1];
	size_t ln = lens[n - 1];
	if (ln >= 16) {
		cmac(rk, sn, ln, d, out);
	} else {
		uint8_t p[16] = {0};
		dbl(d, t);
		memcpy(p, sn, ln);
		p[ln] = 0x80;
		for (int j = 0; j < 16; j++)
			p[j] ^= t[j];
		cmac(rk, p, 16, NULL, out);
	}
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
}

int nts_siv_init(nts_siv_key *k, const uint8_t *key, size_t len)
{
	if (len != NTS_KEY_LEN)
		return NTS_ERR_KEY_LEN;
	aes_expand(k->mac, key);
	aes_expand(k->ctr, key + 16);
	return NTS_OK;
}

/* The strings of S2V: the associated data, then the plaintext. */
#define MAX_STRS 8

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
	s2v(k->mac, strs, lens, nads + 1, out);
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
	s2v(k->mac, strs, lens, nads + 1, t);
	return ct_eq(t, ct, 16);
}
