/* C side of the cgo binding: host-op trampolines. */
#include <stdint.h>
#include <string.h>

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
