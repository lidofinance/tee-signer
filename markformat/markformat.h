/* Portable SCW1 storage format. No signer, blst, allocator or OS dependency. */
#ifndef MARKFORMAT_H
#define MARKFORMAT_H
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MARKFORMAT_ENCODED_LEN 32
#define MARKFORMAT_HAS_BLOCK 0x1u
#define MARKFORMAT_HAS_ATTESTATION 0x2u
#define MARKFORMAT_OK 0
#define MARKFORMAT_ERR_DECODE 1

typedef struct {
    uint64_t block_slot;
    uint64_t source_epoch;
    uint64_t target_epoch;
    uint32_t flags;
} markformat_watermark;

void markformat_encode(const markformat_watermark *wm, uint8_t out[MARKFORMAT_ENCODED_LEN]);
/* Rejects null pointers, wrong lengths, magic, flags and reserved bytes.
 * Leaves out unchanged on failure; does not impose signing policy on values. */
int markformat_decode(const uint8_t *in, size_t len, markformat_watermark *out);

#ifdef __cplusplus
}
#endif
#endif
