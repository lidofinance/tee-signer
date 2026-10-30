#include "markformat.h"
#include <assert.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    markformat_watermark w;
    uint8_t encoded[MARKFORMAT_ENCODED_LEN];
    assert(markformat_decode(NULL, size, &w) == MARKFORMAT_ERR_DECODE);
    assert(markformat_decode(data, size, NULL) == MARKFORMAT_ERR_DECODE);
    if (markformat_decode(data, size, &w) == MARKFORMAT_OK) {
        assert(size == MARKFORMAT_ENCODED_LEN);
        markformat_encode(&w, encoded);
        assert(memcmp(data, encoded, size) == 0);
    }
    return 0;
}
