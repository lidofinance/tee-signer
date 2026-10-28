/*
 * covfuzz.c - a small coverage-guided fuzzer for sim_run_bytes.
 *
 * No libFuzzer or AFL on this machine, so this does their core loop with
 * gcc's -fsanitize-coverage=trace-pc: sim.c and the signer-core sources are
 * built with it, each basic block calls __sanitizer_cov_trace_pc, which
 * hashes (previous block, this block) into a 64 KiB edge map. sim.c adds
 * its own features (refusal codes per profile, crash points, events) through
 * sim_feature. An input that reaches a new edge or a new hit-count bucket
 * joins the corpus. An input with a safety violation is saved under
 * OUT/crashes and the fuzzer goes on.
 *
 *   covfuzz -t SECONDS -o OUTDIR [-s SEED] [-j JOB]
 *
 * This file is built without instrumentation.
 */
#include <dirent.h>
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "sim.h"

#define MAP (1u << 16)
#define MAXLEN 4096
#define MAXCORPUS 20000

static uint8_t g_map[MAP];
static uint8_t g_virgin[MAP]; /* bucket bits seen so far, per edge */
static __thread uintptr_t g_prev;

void __sanitizer_cov_trace_pc(void);
void __sanitizer_cov_trace_pc(void)
{
    uintptr_t pc = (uintptr_t)__builtin_return_address(0);
    uintptr_t h = (pc ^ (pc >> 16)) * 0x9e3779b1u;
    g_map[(h ^ g_prev) & (MAP - 1)]++;
    g_prev = (h >> 1) & (MAP - 1);
}

void sim_feature(uint32_t f)
{
    g_map[(f * 2654435761u) >> 16 & (MAP - 1)]++;
}

static uint8_t bucket(uint8_t n)
{
    if (n == 0) return 0;
    if (n == 1) return 1;
    if (n == 2) return 2;
    if (n == 3) return 4;
    if (n < 8) return 8;
    if (n < 16) return 16;
    if (n < 32) return 32;
    if (n < 128) return 64;
    return 128;
}

typedef struct {
    uint8_t *d;
    size_t n;
} input_t;

static input_t g_corpus[MAXCORPUS];
static size_t g_ncorpus;
static uint64_t g_rng;

static uint64_t rnd(void)
{
    uint64_t z = (g_rng += 0x9e3779b97f4a7c15ull);
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ull;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebull;
    return z ^ (z >> 31);
}

/* Runs one input; returns 1 if it reached something new. */
static int run_one(const uint8_t *d, size_t n, int *viol, sim_metrics *m)
{
    int fresh = 0;
    memset(g_map, 0, sizeof g_map);
    g_prev = 0;
    *viol = sim_run_bytes(d, n, m);
    for (uint32_t i = 0; i < MAP; i++) {
        uint8_t b = bucket(g_map[i]);
        if (b & ~g_virgin[i]) {
            g_virgin[i] |= b;
            fresh = 1;
        }
    }
    return fresh;
}

static size_t edges(void)
{
    size_t n = 0;
    for (uint32_t i = 0; i < MAP; i++)
        n += g_virgin[i] != 0;
    return n;
}

static void save(const char *dir, const char *prefix, uint64_t id, const uint8_t *d, size_t n)
{
    char path[512];
    FILE *f;
    snprintf(path, sizeof path, "%s/%s%06" PRIu64, dir, prefix, id);
    f = fopen(path, "wb");
    if (!f)
        return;
    fwrite(d, 1, n, f);
    fclose(f);
}

static void add(const uint8_t *d, size_t n)
{
    if (g_ncorpus == MAXCORPUS)
        return;
    g_corpus[g_ncorpus].d = malloc(n ? n : 1);
    memcpy(g_corpus[g_ncorpus].d, d, n);
    g_corpus[g_ncorpus].n = n;
    g_ncorpus++;
}

static size_t mutate(uint8_t *d, size_t n)
{
    int rounds = 1 + (int)(rnd() % 8);
    for (int r = 0; r < rounds; r++) {
        switch (rnd() % 8) {
        case 0: /* flip a bit */
            if (n)
                d[rnd() % n] ^= (uint8_t)(1u << (rnd() % 8));
            break;
        case 1: /* set a byte */
        case 2:
            if (n)
                d[rnd() % n] = (uint8_t)rnd();
            break;
        case 3: { /* insert random bytes */
            size_t k = 1 + rnd() % 16, at = n ? rnd() % (n + 1) : 0;
            if (n + k > MAXLEN)
                break;
            memmove(d + at + k, d + at, n - at);
            for (size_t i = 0; i < k; i++)
                d[at + i] = (uint8_t)rnd();
            n += k;
            break;
        }
        case 4: { /* delete a range */
            size_t at, k;
            if (n < 8)
                break;
            at = rnd() % n;
            k = 1 + rnd() % (n - at < 32 ? n - at : 32);
            memmove(d + at, d + at + k, n - at - k);
            n -= k;
            break;
        }
        case 5: { /* repeat a range (an event pattern) */
            size_t at, k;
            if (n < 4)
                break;
            at = rnd() % n;
            k = 1 + rnd() % (n - at < 64 ? n - at : 64);
            if (n + k > MAXLEN)
                break;
            memmove(d + at + k, d + at, n - at);
            n += k;
            break;
        }
        case 6: { /* splice in a piece of another input */
            const input_t *o = &g_corpus[rnd() % g_ncorpus];
            size_t from, k, at;
            if (!o->n || !n)
                break;
            from = rnd() % o->n;
            k = 1 + rnd() % (o->n - from);
            if (k > 256)
                k = 256;
            at = rnd() % n;
            if (at + k > MAXLEN)
                break;
            if (at + k > n)
                n = at + k;
            memcpy(d + at, o->d + from, k);
            break;
        }
        default: /* small add or subtract */
            if (n)
                d[rnd() % n] += (uint8_t)(rnd() % 16 - 8);
        }
    }
    return n;
}

int main(int argc, char **argv)
{
    double limit = 60;
    const char *out = "fuzz-out";
    char dir[600];
    uint64_t seed = 1, execs = 0, crashes = 0, last_new = 0, slots = 0;
    struct timespec t0, t;
    double last_print = 0;
    int opt;
    uint8_t buf[MAXLEN];

    while ((opt = getopt(argc, argv, "t:o:s:")) != -1) {
        if (opt == 't')
            limit = atof(optarg);
        else if (opt == 'o')
            out = optarg;
        else if (opt == 's')
            seed = strtoull(optarg, NULL, 0);
    }
    g_rng = seed;
    mkdir(out, 0755);
    snprintf(dir, sizeof dir, "%s/corpus", out);
    mkdir(dir, 0755);
    snprintf(dir, sizeof dir, "%s/crashes", out);
    mkdir(dir, 0755);

    /* Seeds: the existing corpus, then random streams of a few lengths. */
    snprintf(dir, sizeof dir, "%s/corpus", out);
    DIR *dp = opendir(dir);
    struct dirent *de;
    while (dp && (de = readdir(dp))) {
        char path[1200];
        FILE *f;
        size_t n;
        if (de->d_name[0] == '.')
            continue;
        snprintf(path, sizeof path, "%s/%s", dir, de->d_name);
        f = fopen(path, "rb");
        if (!f)
            continue;
        n = fread(buf, 1, sizeof buf, f);
        fclose(f);
        add(buf, n);
    }
    if (dp)
        closedir(dp);
    for (int i = 0; i < 64; i++) {
        size_t n = 16 + rnd() % 1024;
        for (size_t j = 0; j < n; j++)
            buf[j] = (uint8_t)rnd();
        add(buf, n);
    }
    size_t nseed = g_ncorpus;
    for (size_t i = 0; i < nseed; i++) {
        int v;
        sim_metrics m;
        run_one(g_corpus[i].d, g_corpus[i].n, &v, &m);
        execs++;
        slots += m.slots;
    }

    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (;;) {
        double el;
        size_t n;
        int v, fresh;
        sim_metrics m;
        const input_t *in = &g_corpus[rnd() % g_ncorpus];
        clock_gettime(CLOCK_MONOTONIC, &t);
        el = (double)(t.tv_sec - t0.tv_sec) + (double)(t.tv_nsec - t0.tv_nsec) / 1e9;
        if (el - last_print >= 30 || el >= limit) {
            printf("[%7.0f s] execs %" PRIu64 " (%.0f/s), slots %" PRIu64 ", corpus %zu, edges %zu,"
                   " violations %" PRIu64 ", last new at exec %" PRIu64 "\n",
                   el, execs, (double)execs / (el > 0 ? el : 1), slots, g_ncorpus, edges(), crashes,
                   last_new);
            fflush(stdout);
            last_print = el;
            if (el >= limit)
                break;
        }
        memcpy(buf, in->d, in->n);
        n = mutate(buf, in->n);
        fresh = run_one(buf, n, &v, &m);
        execs++;
        slots += m.slots;
        if (v) {
            crashes++;
            snprintf(dir, sizeof dir, "%s/crashes", out);
            save(dir, "viol-", crashes, buf, n);
            printf("violation %" PRIu64 ": %s\n", crashes, m.first_violation);
            fflush(stdout);
        }
        if (fresh) {
            last_new = execs;
            add(buf, n);
            snprintf(dir, sizeof dir, "%s/corpus", out);
            save(dir, "c-", (uint64_t)g_ncorpus, buf, n);
        }
    }
    return crashes ? 1 : 0;
}
