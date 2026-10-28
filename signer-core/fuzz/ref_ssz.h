/*
 * Reference SSZ merkleization for the fuzz oracles, written apart from
 * src/ on purpose: recursive, with a table of zero subtree roots, where the
 * core works in place. Only sha256 is shared (sc_compute_signing_root is
 * sha256 of its two 32-byte inputs).
 */
#ifndef SC_FUZZ_REF_SSZ_H
#define SC_FUZZ_REF_SSZ_H

#include "fuzz.h"

static inline void ref_hash(const uint8_t a[32], const uint8_t b[32], uint8_t out[32])
{
    uint8_t x[32], y[32];
    memcpy(x, a, 32);
    memcpy(y, b, 32);
    sc_compute_signing_root(x, y, out);
}

/* Root of an all-zero tree of the given depth (0..63). */
static inline const uint8_t *ref_zero(int depth)
{
    static uint8_t z[64][32];
    static int ready;
    if (!ready) {
        memset(z[0], 0, 32);
        for (int i = 1; i < 64; i++)
            ref_hash(z[i - 1], z[i - 1], z[i]);
        ready = 1;
    }
    return z[depth];
}

/* Root of a tree of the given depth whose first n leaves are chunks and
 * the rest zero. */
static inline void ref_merkle(const uint8_t *chunks, size_t n, int depth, uint8_t out[32])
{
    uint8_t l[32], r[32];
    size_t half;
    if (n == 0) {
        memcpy(out, ref_zero(depth), 32);
        return;
    }
    if (depth == 0) {
        memcpy(out, chunks, 32);
        return;
    }
    half = (size_t)1 << (depth - 1);
    if (n <= half) {
        ref_merkle(chunks, n, depth - 1, l);
        memcpy(r, ref_zero(depth - 1), 32);
    } else {
        ref_merkle(chunks, half, depth - 1, l);
        ref_merkle(chunks + half * 32, n - half, depth - 1, r);
    }
    ref_hash(l, r, out);
}

/* Smallest depth whose tree holds limit leaves. */
static inline int ref_depth(uint64_t limit)
{
    int d = 0;
    while (d < 63 && ((uint64_t)1 << d) < limit)
        d++;
    return d;
}

/* EIP-7916 merkleize_progressive: subtrees of 1, 4, 16, ... leaves. */
static inline void ref_progressive(const uint8_t *chunks, size_t n, int depth, uint8_t out[32])
{
    uint8_t l[32], r[32];
    size_t first, cap = (size_t)1 << depth;
    if (n == 0) {
        memset(out, 0, 32);
        return;
    }
    first = n < cap ? n : cap;
    ref_merkle(chunks, first, depth, l);
    ref_progressive(chunks + first * 32, n - first, depth + 2, r);
    ref_hash(l, r, out);
}

static inline void ref_u64_chunk(uint64_t v, uint8_t out[32])
{
    memset(out, 0, 32);
    fz_put_u64(out, v);
}

static inline void ref_mix_length(const uint8_t root[32], uint64_t len, uint8_t out[32])
{
    uint8_t l[32];
    ref_u64_chunk(len, l);
    ref_hash(root, l, out);
}

/* hash_tree_root of a Bytes96. */
static inline void ref_bytes96(const uint8_t b[96], uint8_t out[32])
{
    ref_merkle(b, 3, 2, out);
}

/*
 * Bitlist[limit] (progressive = 0) or ProgressiveBitList (1) from its SSZ
 * bytes. Returns 0 if the encoding is invalid: empty, no delimiter bit in
 * the last byte, or more than limit bits. Checks bit by bit.
 */
static inline int ref_bitlist(const uint8_t *b, size_t len, uint64_t limit, int progressive,
                              uint8_t out[32])
{
    uint64_t total = (uint64_t)len * 8, bits = 0;
    uint8_t *packed, root[32];
    size_t nchunks;
    int found = 0;
    if (len == 0)
        return 0;
    for (uint64_t i = total; i-- > (uint64_t)(len - 1) * 8;)
        if (b[i / 8] >> (i % 8) & 1) {
            bits = i;
            found = 1;
            break;
        }
    if (!found || bits > limit)
        return 0;
    nchunks = (size_t)((bits + 255) / 256);
    packed = calloc(nchunks ? nchunks * 32 : 1, 1);
    if (!packed)
        abort();
    for (uint64_t i = 0; i < bits; i++)
        if (b[i / 8] >> (i % 8) & 1)
            packed[i / 8] |= (uint8_t)(1u << (i % 8));
    if (progressive)
        ref_progressive(packed, nchunks, 0, root);
    else
        ref_merkle(packed, nchunks, ref_depth((limit + 255) / 256), root);
    free(packed);
    ref_mix_length(root, bits, out);
    return 1;
}

/* Bitvector[n], n <= 256. Returns 0 if a bit past n is set or len is wrong. */
static inline int ref_bitvector(const uint8_t *b, size_t len, uint64_t n, uint8_t out[32])
{
    if (n == 0 || n > 256 || len != (size_t)((n + 7) / 8))
        return 0;
    for (uint64_t i = n; i < (uint64_t)len * 8; i++)
        if (b[i / 8] >> (i % 8) & 1)
            return 0;
    memset(out, 0, 32);
    memcpy(out, b, len);
    return 1;
}

/* ByteList[max] root of data. */
static inline void ref_bytelist(const uint8_t *data, size_t len, uint64_t max, uint8_t out[32])
{
    size_t nchunks = (len + 31) / 32;
    uint8_t *packed = calloc(nchunks ? nchunks * 32 : 1, 1), root[32];
    if (!packed)
        abort();
    if (len)
        memcpy(packed, data, len);
    ref_merkle(packed, nchunks, ref_depth((max + 31) / 32), root);
    free(packed);
    ref_mix_length(root, len, out);
}

#endif
