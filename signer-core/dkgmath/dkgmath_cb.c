/*
 * Scalar and G1 helpers for key generation (dkgmath.go). Secrets are
 * 32-byte big-endian scalars; every function wipes its stack copies.
 */
#include <stdint.h>
#include <string.h>

#include "blst.h"

static void wipe(void *p, size_t n)
{
    volatile uint8_t *v = p;
    while (n--)
        *v++ = 0;
}

/*
 * IETF KeyGen over ikm (at least 32 bytes). Writes a scalar in [1, r).
 * Returns 0, or 1 if the result is not a valid secret.
 */
int dkg_keygen(const uint8_t *ikm, size_t ikm_len, uint8_t out_be[32])
{
    blst_scalar s;
    blst_keygen(&s, ikm, ikm_len, NULL, 0);
    int ok = blst_sk_check(&s);
    blst_bendian_from_scalar(out_be, &s);
    wipe(&s, sizeof s);
    return ok ? 0 : 1;
}

/*
 * f(x) = sum coeffs[k] * x^k mod r by Horner's rule, for t coefficients of
 * 32 bytes each (big endian, each in [1, r)). Returns 0, or 1 if a
 * coefficient is out of range or the value is zero.
 */
int dkg_poly_eval(const uint8_t *coeffs_be, size_t t, uint64_t x, uint8_t out_be[32])
{
    blst_scalar acc, c, xs;
    uint64_t xl[4] = {x, 0, 0, 0};
    int rc = 1;

    if (t == 0 || x == 0)
        return 1;
    blst_scalar_from_uint64(&xs, xl);
    blst_scalar_from_bendian(&acc, coeffs_be + 32 * (t - 1));
    if (!blst_sk_check(&acc))
        goto out;
    for (size_t k = t - 1; k-- > 0;) {
        blst_scalar_from_bendian(&c, coeffs_be + 32 * k);
        if (!blst_sk_check(&c))
            goto out;
        if (!blst_sk_mul_n_check(&acc, &acc, &xs))
            goto out;
        if (!blst_sk_add_n_check(&acc, &acc, &c))
            goto out;
    }
    blst_bendian_from_scalar(out_be, &acc);
    rc = 0;
out:
    wipe(&acc, sizeof acc);
    wipe(&c, sizeof c);
    return rc;
}

/* out = a + b mod r. Returns 0, or 1 if an input is out of range or the sum is zero. */
int dkg_scalar_add(const uint8_t a_be[32], const uint8_t b_be[32], uint8_t out_be[32])
{
    blst_scalar a, b;
    int rc = 1;
    blst_scalar_from_bendian(&a, a_be);
    blst_scalar_from_bendian(&b, b_be);
    if (blst_sk_check(&a) && blst_sk_check(&b) && blst_sk_add_n_check(&a, &a, &b)) {
        blst_bendian_from_scalar(out_be, &a);
        rc = 0;
    }
    wipe(&a, sizeof a);
    wipe(&b, sizeof b);
    return rc;
}

/* 1 if p is a compressed G1 point in the subgroup and not the identity. */
int dkg_g1_check(const uint8_t p[48])
{
    blst_p1_affine a;
    if (blst_p1_uncompress(&a, p) != BLST_SUCCESS)
        return 0;
    return blst_p1_affine_in_g1(&a) && !blst_p1_affine_is_inf(&a);
}

/*
 * sum(scalars[i] * points[i]) in G1. points: n compressed keys of 48 bytes,
 * scalars: n little-endian 32-byte scalars. Returns 0, or 1 if a point does
 * not decode or is not in the group.
 */
int dkg_p1_lincomb(const uint8_t *points, const uint8_t *scalars, size_t n, uint8_t out[48])
{
    blst_p1 acc, p, term;
    blst_p1_affine a;
    memset(&acc, 0, sizeof acc);
    for (size_t i = 0; i < n; i++) {
        if (blst_p1_uncompress(&a, points + 48 * i) != BLST_SUCCESS ||
            !blst_p1_affine_in_g1(&a))
            return 1;
        blst_p1_from_affine(&p, &a);
        blst_p1_mult(&term, &p, scalars + 32 * i, 255);
        if (i == 0)
            acc = term;
        else
            blst_p1_add_or_double(&acc, &acc, &term);
    }
    blst_p1_compress(out, &acc);
    return 0;
}

/*
 * BLS signature (G2, Ethereum proof-of-possession ciphersuite) of msg with
 * the secret sk (big endian). Returns 0, or 1 if sk is not a valid secret.
 */
int dkg_sign(const uint8_t sk_be[32], const uint8_t *msg, size_t len, uint8_t sig[96])
{
    static const char dst[] = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
    blst_scalar sk;
    blst_p2 h, s;
    int rc = 1;
    blst_scalar_from_bendian(&sk, sk_be);
    if (blst_sk_check(&sk)) {
        blst_hash_to_g2(&h, msg, len, (const byte *)dst, sizeof dst - 1, NULL, 0);
        blst_sign_pk_in_g1(&s, &h, &sk);
        blst_p2_compress(sig, &s);
        rc = 0;
    }
    wipe(&sk, sizeof sk);
    return rc;
}

/*
 * Sum of n compressed G2 points (96 bytes each), each checked to be in the
 * group: a BLS aggregate signature. Returns 0, or 1 on a bad point.
 */
int dkg_p2_sum(const uint8_t *points, size_t n, uint8_t out[96])
{
    blst_p2 acc, p;
    blst_p2_affine a;
    memset(&acc, 0, sizeof acc);
    for (size_t i = 0; i < n; i++) {
        if (blst_p2_uncompress(&a, points + 96 * i) != BLST_SUCCESS || !blst_p2_affine_in_g2(&a))
            return 1;
        blst_p2_from_affine(&p, &a);
        if (i == 0)
            acc = p;
        else
            blst_p2_add_or_double(&acc, &acc, &p);
    }
    blst_p2_compress(out, &acc);
    return 0;
}
