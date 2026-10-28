/*
 * Shared helpers for the signer-core fuzz targets. Each target defines
 * LLVMFuzzerTestOneInput and builds with clang's libFuzzer or with
 * fuzz/driver.c (gcc). See fuzz/README.md.
 */
#ifndef SC_FUZZ_H
#define SC_FUZZ_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "signer_core.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

/* An oracle failure: print it and abort, so the engine saves the input. */
#define FUZZ_CHECK(cond)                                                                 \
    do {                                                                                 \
        if (!(cond)) {                                                                   \
            fprintf(stderr, "==FUZZ ORACLE== %s:%d: %s\n", __FILE__, __LINE__, #cond);   \
            abort();                                                                     \
        }                                                                                \
    } while (0)

/* Reads the input front to back. Past the end every read gives zeros. */
typedef struct {
    const uint8_t *p;
    size_t n;
} fz_in;

static inline uint8_t fz_u8(fz_in *in)
{
    uint8_t v = 0;
    if (in->n) {
        v = *in->p++;
        in->n--;
    }
    return v;
}

static inline uint16_t fz_u16(fz_in *in)
{
    uint16_t v = fz_u8(in);
    return (uint16_t)(v | (uint16_t)fz_u8(in) << 8);
}

static inline uint32_t fz_u32(fz_in *in)
{
    uint32_t v = fz_u16(in);
    return v | (uint32_t)fz_u16(in) << 16;
}

static inline uint64_t fz_u64(fz_in *in)
{
    uint64_t v = fz_u32(in);
    return v | (uint64_t)fz_u32(in) << 32;
}

static inline void fz_bytes(fz_in *in, uint8_t *out, size_t n)
{
    for (size_t i = 0; i < n; i++)
        out[i] = fz_u8(in);
}

/* Up to max bytes of the rest of the input, as a pointer into it. */
static inline const uint8_t *fz_take(fz_in *in, size_t max, size_t *len)
{
    const uint8_t *p = in->p;
    *len = in->n < max ? in->n : max;
    in->p += *len;
    in->n -= *len;
    return p;
}

/* A heap copy of exactly n bytes, so ASan reports any read past n. */
static inline uint8_t *fz_dup(const uint8_t *d, size_t n)
{
    uint8_t *b = malloc(n ? n : 1);
    if (!b)
        abort();
    if (n)
        memcpy(b, d, n);
    return b;
}

static inline void fz_put_u64(uint8_t *p, uint64_t v)
{
    for (int i = 0; i < 8; i++)
        p[i] = (uint8_t)(v >> (8 * i));
}

static inline uint64_t fz_get_u64(const uint8_t *p)
{
    uint64_t v = 0;
    for (int i = 7; i >= 0; i--)
        v = v << 8 | p[i];
    return v;
}

static inline uint32_t fz_get_u32(const uint8_t *p)
{
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

#endif
