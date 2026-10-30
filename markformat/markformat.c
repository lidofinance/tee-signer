#include "markformat.h"
#include <string.h>

#define WM_FLAGS_MASK (MARKFORMAT_HAS_BLOCK | MARKFORMAT_HAS_ATTESTATION)

static void put_u64(uint8_t *p, uint64_t v)
{
    for (unsigned i = 0; i < 8; i++)
        p[i] = (uint8_t)(v >> (8 * i));
}

static uint64_t get_u64(const uint8_t *p)
{
    uint64_t v = 0;
    for (unsigned i = 0; i < 8; i++)
        v |= (uint64_t)p[i] << (8 * i);
    return v;
}

static const uint8_t WM_MAGIC[4] = {'S', 'C', 'W', '1'};

void markformat_encode(const markformat_watermark *wm, uint8_t out[MARKFORMAT_ENCODED_LEN])
{
    memcpy(out, WM_MAGIC, 4);
    out[4] = (uint8_t)(wm->flags & WM_FLAGS_MASK);
    out[5] = out[6] = out[7] = 0;
    put_u64(out + 8, wm->block_slot);
    put_u64(out + 16, wm->source_epoch);
    put_u64(out + 24, wm->target_epoch);
}

int markformat_decode(const uint8_t *in, size_t len, markformat_watermark *out)
{
    if (!in || !out || len != MARKFORMAT_ENCODED_LEN || memcmp(in, WM_MAGIC, 4) != 0 ||
        (in[4] & ~WM_FLAGS_MASK) || in[5] || in[6] || in[7])
        return MARKFORMAT_ERR_DECODE;
    out->flags = in[4];
    out->block_slot = get_u64(in + 8);
    out->source_epoch = get_u64(in + 16);
    out->target_epoch = get_u64(in + 24);
    return MARKFORMAT_OK;
}
