/* Test helpers: hex, files, tiny YAML field lookup, raw snappy, checks. */
#ifndef TESTUTIL_H
#define TESTUTIL_H

#include <dirent.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "signer_core.h"

static int g_checks __attribute__((unused)), g_failures __attribute__((unused));

#define CHECK(cond)                                                              \
    do {                                                                         \
        g_checks++;                                                              \
        if (!(cond)) {                                                           \
            g_failures++;                                                        \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);    \
        }                                                                        \
    } while (0)

#define CHECK_RC(expr, want)                                                     \
    do {                                                                         \
        int rc_ = (expr);                                                        \
        g_checks++;                                                              \
        if (rc_ != (want)) {                                                     \
            g_failures++;                                                        \
            fprintf(stderr, "FAIL %s:%d: %s = %s, want %s\n", __FILE__, __LINE__, \
                    #expr, sc_status_name(rc_), sc_status_name(want));           \
        }                                                                        \
    } while (0)

static inline int hexval(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Parses exactly 2*n hex digits (optional 0x) into out. Returns 0 on success. */
static inline int parse_hex(const char *s, uint8_t *out, size_t n)
{
    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X'))
        s += 2;
    for (size_t i = 0; i < n; i++) {
        int hi = hexval(s[2 * i]), lo = hexval(s[2 * i + 1]);
        if (hi < 0 || lo < 0)
            return -1;
        out[i] = (uint8_t)(hi << 4 | lo);
    }
    return hexval(s[2 * n]) < 0 ? 0 : -1;
}

/* Parses a hex string of any even length into out (cap bytes). Returns the
 * byte count or -1. */
static inline long parse_hex_any(const char *s, uint8_t *out, size_t cap)
{
    size_t n = 0;
    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X'))
        s += 2;
    while (hexval(s[2 * n]) >= 0 && hexval(s[2 * n + 1]) >= 0) {
        if (n == cap)
            return -1;
        out[n] = (uint8_t)(hexval(s[2 * n]) << 4 | hexval(s[2 * n + 1]));
        n++;
    }
    return (long)n;
}

static inline void to_hex(const uint8_t *b, size_t n, char *out)
{
    static const char d[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[2 * i] = d[b[i] >> 4];
        out[2 * i + 1] = d[b[i] & 15];
    }
    out[2 * n] = 0;
}

static inline uint8_t *read_file(const char *path, size_t *len)
{
    FILE *f = fopen(path, "rb");
    uint8_t *buf = NULL;
    long n;
    if (!f)
        return NULL;
    if (fseek(f, 0, SEEK_END) == 0 && (n = ftell(f)) >= 0 && fseek(f, 0, SEEK_SET) == 0) {
        buf = malloc((size_t)n + 1);
        if (buf && fread(buf, 1, (size_t)n, f) == (size_t)n) {
            buf[n] = 0;
            *len = (size_t)n;
        } else {
            free(buf);
            buf = NULL;
        }
    }
    fclose(f);
    return buf;
}

/* Finds "key:" in simple YAML text and returns a pointer to the value with
 * leading spaces and one quote skipped, or NULL. */
static inline const char *yaml_value(const char *text, const char *key)
{
    size_t kl = strlen(key);
    const char *p = text;
    while ((p = strstr(p, key)) != NULL) {
        int at_start = p == text || p[-1] == '\n' || p[-1] == ' ' || p[-1] == '{';
        if (at_start && p[kl] == ':') {
            p += kl + 1;
            while (*p == ' ')
                p++;
            if (*p == '\'' || *p == '"')
                p++;
            return p;
        }
        p += kl;
    }
    return NULL;
}

/* Raw (block format) snappy decompression. Returns malloc'd data or NULL. */
static inline uint8_t *snappy_decompress(const uint8_t *in, size_t n, size_t *out_len)
{
    size_t pos = 0, op = 0;
    uint64_t len = 0;
    int shift = 0;
    uint8_t *out;

    for (;;) {
        if (pos >= n || shift > 35)
            return NULL;
        uint8_t b = in[pos++];
        len |= (uint64_t)(b & 0x7f) << shift;
        if (!(b & 0x80))
            break;
        shift += 7;
    }
    out = malloc(len ? len : 1);
    if (!out)
        return NULL;
    while (pos < n) {
        uint8_t tag = in[pos++];
        size_t l, off = 0;
        if ((tag & 3) == 0) {
            l = tag >> 2;
            if (l >= 60) {
                size_t nb = l - 59;
                if (pos + nb > n)
                    goto fail;
                l = 0;
                for (size_t i = 0; i < nb; i++)
                    l |= (size_t)in[pos + i] << (8 * i);
                pos += nb;
            }
            l += 1;
            if (pos + l > n || op + l > len)
                goto fail;
            memcpy(out + op, in + pos, l);
            pos += l;
            op += l;
            continue;
        }
        if ((tag & 3) == 1) {
            if (pos >= n)
                goto fail;
            l = 4 + ((tag >> 2) & 7);
            off = ((size_t)(tag >> 5) << 8) | in[pos++];
        } else if ((tag & 3) == 2) {
            if (pos + 2 > n)
                goto fail;
            l = (size_t)(tag >> 2) + 1;
            off = in[pos] | (size_t)in[pos + 1] << 8;
            pos += 2;
        } else {
            if (pos + 4 > n)
                goto fail;
            l = (size_t)(tag >> 2) + 1;
            off = in[pos] | (size_t)in[pos + 1] << 8 | (size_t)in[pos + 2] << 16 |
                  (size_t)in[pos + 3] << 24;
            pos += 4;
        }
        if (off == 0 || off > op || op + l > len)
            goto fail;
        for (size_t i = 0; i < l; i++, op++)
            out[op] = out[op - off];
    }
    if (op != len)
        goto fail;
    *out_len = (size_t)len;
    return out;
fail:
    free(out);
    return NULL;
}

/* Sorted list of subdirectory names of dir (excluding dot entries). */
static inline int list_dir(const char *dir, struct dirent ***names)
{
    return scandir(dir, names, NULL, alphasort);
}

static inline int is_dot(const char *name) { return name[0] == '.'; }

static inline int test_summary(const char *name)
{
    printf("%s: %d checks, %d failures\n", name, g_checks, g_failures);
    return g_failures ? 1 : 0;
}

#endif
