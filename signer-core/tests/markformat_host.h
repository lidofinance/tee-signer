/* Test storage callbacks: the signing core itself does not link the codec. */
#ifndef MARKFORMAT_HOST_H
#define MARKFORMAT_HOST_H
#include "signer_core.h"
#include "markformat.h"

#define SC_WATERMARK_ENCODED_LEN MARKFORMAT_ENCODED_LEN

_Static_assert(SC_WM_HAS_BLOCK == MARKFORMAT_HAS_BLOCK, "block flag");
_Static_assert(SC_WM_HAS_ATTESTATION == MARKFORMAT_HAS_ATTESTATION, "attestation flag");

static inline void test_watermark_encode(const sc_watermark *w, uint8_t out[MARKFORMAT_ENCODED_LEN])
{
    markformat_watermark m = {w->block_slot, w->source_epoch, w->target_epoch, w->flags};
    markformat_encode(&m, out);
}

static inline int test_watermark_decode(const uint8_t *in, size_t len, sc_watermark *out)
{
    markformat_watermark m;
    if (!out || markformat_decode(in, len, &m) != MARKFORMAT_OK)
        return SC_ERR_DECODE;
    *out = (sc_watermark){m.block_slot, m.source_epoch, m.target_epoch, m.flags};
    return SC_OK;
}
#endif
