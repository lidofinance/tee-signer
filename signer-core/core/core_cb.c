/* C side of the cgo binding: host-op trampolines and two blst helpers. */
#include <stdint.h>
#include <string.h>

#include "blst.h"
#include "signer_core.h"
#include "_cgo_export.h"

static int load_cb(void *ctx, const uint8_t pubkey[SC_PUBKEY_LEN], sc_watermark *out)
{
    return scgoLoadWatermark((uintptr_t)ctx, (uint8_t *)pubkey, out);
}

static int store_cb(void *ctx, const uint8_t pubkey[SC_PUBKEY_LEN], const sc_watermark *wm)
{
    return scgoStoreWatermark((uintptr_t)ctx, (uint8_t *)pubkey, (sc_watermark *)wm);
}

static int now_cb(void *ctx, uint64_t *unix_seconds)
{
    return scgoNow((uintptr_t)ctx, unix_seconds);
}

/* Repeat roots travel to Go in the core's 72-byte encoding. */
static int load_roots_cb(void *ctx, const uint8_t pubkey[SC_PUBKEY_LEN], sc_repeat_roots *out)
{
    uint8_t rec[SC_REPEAT_ROOTS_ENCODED_LEN];
    int rc = scgoLoadRepeatRoots((uintptr_t)ctx, (uint8_t *)pubkey, rec);
    if (rc != SC_OK)
        return rc;
    return sc_repeat_roots_decode(rec, sizeof rec, out) == SC_OK ? SC_OK : SC_ERR_STORAGE;
}

static int store_roots_cb(void *ctx, const uint8_t pubkey[SC_PUBKEY_LEN], const sc_repeat_roots *r)
{
    uint8_t rec[SC_REPEAT_ROOTS_ENCODED_LEN];
    sc_repeat_roots_encode(r, rec);
    return scgoStoreRepeatRoots((uintptr_t)ctx, (uint8_t *)pubkey, rec);
}

static int load_device_cb(void *ctx, sc_watermark *out)
{
    return scgoLoadDeviceMark((uintptr_t)ctx, out);
}

static int store_device_cb(void *ctx, const sc_watermark *wm)
{
    return scgoStoreDeviceMark((uintptr_t)ctx, (sc_watermark *)wm);
}

/* ctx carries a cgo.Handle, an integer, never a Go pointer. */
void scgo_make_ops(sc_host_ops *ops, uintptr_t handle)
{
    ops->ctx = (void *)handle;
    ops->load_watermark = load_cb;
    ops->store_watermark = store_cb;
    ops->now = now_cb;
    ops->load_repeat_roots = load_roots_cb;
    ops->store_repeat_roots = store_roots_cb;
    ops->load_device_mark = load_device_cb;
    ops->store_device_mark = store_device_cb;
}

/*
 * sum(scalars[i] * points[i]) in G2. points: n compressed signatures of 96
 * bytes. scalars: n little-endian 32-byte scalars. Returns 0, or 1 if a
 * point does not decode or is not in the group.
 */
int scgo_p2_lincomb(const uint8_t *points, const uint8_t *scalars, size_t n, uint8_t out[96])
{
    blst_p2 acc, p, term;
    blst_p2_affine a;
    memset(&acc, 0, sizeof acc);
    for (size_t i = 0; i < n; i++) {
        if (blst_p2_uncompress(&a, points + 96 * i) != BLST_SUCCESS ||
            !blst_p2_affine_in_g2(&a))
            return 1;
        blst_p2_from_affine(&p, &a);
        blst_p2_mult(&term, &p, scalars + 32 * i, 255);
        if (i == 0)
            acc = term;
        else
            blst_p2_add_or_double(&acc, &acc, &term);
    }
    blst_p2_compress(out, &acc);
    return 0;
}

/* Same in G1 for 48-byte compressed public keys. */
int scgo_p1_lincomb(const uint8_t *points, const uint8_t *scalars, size_t n, uint8_t out[48])
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
