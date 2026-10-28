/* BLS12-381 signing with blst, min-pubkey-size variant (G1 pubkeys, G2
 * signatures), proof-of-possession ciphersuite as used by Ethereum. */
#include "sc_internal.h"

static const uint8_t DST[] = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
#define DST_LEN (sizeof(DST) - 1)

int sc_bls_load_secret(blst_scalar *sk, const uint8_t secret[SC_SECRET_LEN])
{
    if (!sk || !secret)
        return SC_ERR_ARG;
    blst_scalar_from_bendian(sk, secret);
    if (!blst_sk_check(sk)) {
        sc_wipe(sk, sizeof *sk);
        return SC_ERR_BAD_KEY;
    }
    return SC_OK;
}

void sc_bls_hash_to_g2(blst_p2 *out, const uint8_t *msg, size_t msg_len)
{
    blst_hash_to_g2(out, msg, msg_len, DST, DST_LEN, NULL, 0);
}

void sc_bls_sign_hashed(const blst_scalar *sk, const blst_p2 *hashed,
                        uint8_t signature[SC_SIGNATURE_LEN])
{
    blst_p2 sig;
    blst_sign_pk_in_g1(&sig, hashed, sk);
    blst_p2_compress(signature, &sig);
}

int sc_bls_check_secret(const uint8_t secret[SC_SECRET_LEN])
{
    blst_scalar sk;
    int rc = sc_bls_load_secret(&sk, secret);
    sc_wipe(&sk, sizeof sk);
    return rc;
}

int sc_bls_pubkey(const uint8_t secret[SC_SECRET_LEN], uint8_t pubkey[SC_PUBKEY_LEN])
{
    blst_scalar sk;
    blst_p1 pk;
    int rc;
    if (!pubkey)
        return SC_ERR_ARG;
    rc = sc_bls_load_secret(&sk, secret);
    if (rc != SC_OK)
        return rc;
    blst_sk_to_pk_in_g1(&pk, &sk);
    blst_p1_compress(pubkey, &pk);
    sc_wipe(&sk, sizeof sk);
    return SC_OK;
}

int sc_bls_sign(const uint8_t secret[SC_SECRET_LEN], const uint8_t *msg, size_t msg_len,
                uint8_t signature[SC_SIGNATURE_LEN])
{
    blst_scalar sk;
    blst_p2 h;
    int rc;
    if (!signature || (!msg && msg_len))
        return SC_ERR_ARG;
    rc = sc_bls_load_secret(&sk, secret);
    if (rc != SC_OK)
        return rc;
    sc_bls_hash_to_g2(&h, msg, msg_len);
    sc_bls_sign_hashed(&sk, &h, signature);
    sc_wipe(&sk, sizeof sk);
    return SC_OK;
}

int sc_bls_verify(const uint8_t pubkey[SC_PUBKEY_LEN], const uint8_t *msg, size_t msg_len,
                  const uint8_t signature[SC_SIGNATURE_LEN])
{
    blst_p1_affine pk;
    blst_p2_affine sig;
    if (!pubkey || !signature || (!msg && msg_len))
        return SC_ERR_ARG;
    if (blst_p1_uncompress(&pk, pubkey) != BLST_SUCCESS || blst_p1_affine_is_inf(&pk) ||
        !blst_p1_affine_in_g1(&pk))
        return SC_ERR_ARG;
    if (blst_p2_uncompress(&sig, signature) != BLST_SUCCESS || !blst_p2_affine_in_g2(&sig))
        return SC_ERR_ARG;
    if (blst_core_verify_pk_in_g1(&pk, &sig, 1, msg, msg_len, DST, DST_LEN, NULL, 0) !=
        BLST_SUCCESS)
        return SC_ERR_ARG;
    return SC_OK;
}

/* ---- hash_to_G2 cache --------------------------------------------------- */

void sc_h2g2_cache_init(sc_h2g2_cache *c, sc_h2g2_entry *entries, uint32_t count)
{
    c->entries = entries;
    c->count = entries ? count : 0;
    c->clock = 0;
    c->hits = 0;
    c->misses = 0;
    if (c->count)
        memset(entries, 0, (size_t)count * sizeof *entries);
}

const blst_p2 *sc_h2g2_cache_get(sc_h2g2_cache *c, const uint8_t msg[SC_ROOT_LEN],
                                 blst_p2 *scratch)
{
    sc_h2g2_entry *victim = NULL;
    uint32_t i;

    c->clock++;
    for (i = 0; i < c->count; i++) {
        sc_h2g2_entry *e = &c->entries[i];
        if (e->stamp && memcmp(e->msg, msg, SC_ROOT_LEN) == 0) {
            e->stamp = c->clock;
            c->hits++;
            return &e->point;
        }
        if (!victim || e->stamp < victim->stamp)
            victim = e;
    }
    c->misses++;
    if (!victim) {
        sc_bls_hash_to_g2(scratch, msg, SC_ROOT_LEN);
        return scratch;
    }
    sc_bls_hash_to_g2(&victim->point, msg, SC_ROOT_LEN);
    memcpy(victim->msg, msg, SC_ROOT_LEN);
    victim->stamp = c->clock;
    return &victim->point;
}

void sc_h2g2_cache_wipe(sc_h2g2_cache *c)
{
    if (c->count)
        sc_wipe(c->entries, (size_t)c->count * sizeof *c->entries);
    c->clock = 0;
}
