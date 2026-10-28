/*
 * Fast stand-ins for the BLS math, linked with -Wl,--wrap so the signer-core
 * objects stay byte for byte the ones the tests build. Signing roots, SSZ
 * hashing (blst_sha256), slashing protection, storage and clock calls are
 * all real; only the curve operations are replaced by copies, which makes a
 * "signature" 1,000 times cheaper. build/sim-real links the real blst.
 */
#include <string.h>

#include "blst.h"

void __wrap_blst_hash_to_g2(blst_p2 *out, const byte *msg, size_t msg_len, const byte *DST,
                            size_t DST_len, const byte *aug, size_t aug_len);
void __wrap_blst_sign_pk_in_g1(blst_p2 *out_sig, const blst_p2 *hash, const blst_scalar *SK);
void __wrap_blst_p2_compress(byte out[96], const blst_p2 *in);
void __wrap_blst_sk_to_pk_in_g1(blst_p1 *out_pk, const blst_scalar *SK);
void __wrap_blst_p1_compress(byte out[48], const blst_p1 *in);

void __wrap_blst_hash_to_g2(blst_p2 *out, const byte *msg, size_t msg_len, const byte *DST,
                            size_t DST_len, const byte *aug, size_t aug_len)
{
    (void)DST, (void)DST_len, (void)aug, (void)aug_len;
    memset(out, 0, sizeof *out);
    memcpy(out, msg, msg_len < sizeof *out ? msg_len : sizeof *out);
}

void __wrap_blst_sign_pk_in_g1(blst_p2 *out_sig, const blst_p2 *hash, const blst_scalar *SK)
{
    unsigned char *o = (unsigned char *)out_sig;
    const unsigned char *k = (const unsigned char *)SK;
    *out_sig = *hash;
    for (size_t i = 0; i < sizeof *SK && i + 32 < sizeof *out_sig; i++)
        o[32 + i] = k[i];
}

void __wrap_blst_p2_compress(byte out[96], const blst_p2 *in) { memcpy(out, in, 96); }

void __wrap_blst_sk_to_pk_in_g1(blst_p1 *out_pk, const blst_scalar *SK)
{
    memset(out_pk, 0, sizeof *out_pk);
    memcpy(out_pk, SK, sizeof *SK);
}

void __wrap_blst_p1_compress(byte out[48], const blst_p1 *in) { memcpy(out, in, 48); }
