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
    ops->load_device_mark = load_device_cb;
    ops->store_device_mark = store_device_cb;
}
