#include "markformat.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

int main(void)
{
    /* Golden record from the former TestWatermarkStorageFormat. */
    const uint8_t golden[MARKFORMAT_ENCODED_LEN] = {
        0x53,0x43,0x57,0x31,0x03,0,0,0,
        1,2,3,4,5,6,7,8,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,
        0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28
    };
    markformat_watermark w = {UINT64_C(0x0807060504030201), UINT64_C(0x1817161514131211),
                             UINT64_C(0x2827262524232221), 3}, out;
    uint8_t b[MARKFORMAT_ENCODED_LEN];
    markformat_encode(&w, b);
    assert(memcmp(b, golden, sizeof b) == 0);
    assert(markformat_decode(golden, sizeof golden, &out) == MARKFORMAT_OK);
    assert(out.block_slot == w.block_slot && out.source_epoch == w.source_epoch &&
           out.target_epoch == w.target_epoch && out.flags == w.flags);
    for (unsigned flags = 0; flags < 4; flags++) {
        w.flags = flags;
        markformat_encode(&w, b);
        assert(markformat_decode(b, sizeof b, &out) == MARKFORMAT_OK && out.flags == flags);
    }
    w.flags = UINT32_MAX;
    markformat_encode(&w, b);
    assert(b[4] == 3); /* Only the two defined flags are stored. */
    for (size_t n = 0; n <= sizeof b + 1; n++) {
        if (n == sizeof b) continue;
        assert(markformat_decode(b, n, &out) == MARKFORMAT_ERR_DECODE);
    }
    assert(markformat_decode(NULL, sizeof b, &out) == MARKFORMAT_ERR_DECODE);
    assert(markformat_decode(b, sizeof b, NULL) == MARKFORMAT_ERR_DECODE);
    for (size_t i = 0; i < 8; i++) {
        for (unsigned bit = 1; bit < 256; bit <<= 1) {
            if (i == 4 && bit <= 2) continue;
            memcpy(b, golden, sizeof b);
            b[i] ^= (uint8_t)bit;
            out = w;
            assert(markformat_decode(b, sizeof b, &out) == MARKFORMAT_ERR_DECODE);
            assert(out.block_slot == w.block_slot && out.source_epoch == w.source_epoch &&
                   out.target_epoch == w.target_epoch && out.flags == w.flags);
        }
    }
    puts("markformat: C storage format tests passed");
    return 0;
}
