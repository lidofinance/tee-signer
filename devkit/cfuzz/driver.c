/*
 * driver.c - a small coverage-guided fuzz engine for the libFuzzer targets
 * in the repository, for machines with gcc but without clang's libFuzzer.
 * It takes the libFuzzer flags the scripts use, so scripts/fuzz.sh runs
 * either engine the same way.
 *
 * Coverage: the core and the target are built with gcc's
 * -fsanitize-coverage=trace-pc,trace-cmp. Each basic block calls
 * __sanitizer_cov_trace_pc, which hashes (previous block, this block) into
 * a 64 KiB edge map with hit-count buckets. Each comparison calls a
 * __sanitizer_cov_trace_cmp hook: its operands go to a table the mutator
 * writes into inputs, and (pc, number of differing bits) is a feature, so
 * an input that gets closer to passing a comparison is kept too.
 *
 * Crashes: the fuzz loop runs in a child process. Before each run the input
 * goes to a shared memory buffer; when the child dies (sanitizer report,
 * oracle abort, signal) or overruns -timeout, the parent saves that buffer
 * as <artifact_prefix>crash-<hash> (or timeout-<hash>).
 *
 *   driver [flags] CORPUS_DIR [SEED_DIR...]   fuzz; new inputs go to CORPUS_DIR
 *   driver [flags] FILE...                    run each file once
 *   driver -minimize_crash=1 [flags] FILE     shrink a crashing input
 *
 * Flags: -max_total_time=S -runs=N -seed=N -max_len=N -timeout=S
 *        -artifact_prefix=P -exact_artifact_path=F -keep_going=1
 *        -print_final_stats=1 (other -flags are ignored with a note)
 *
 * This file is built without coverage instrumentation.
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
__attribute__((weak)) int LLVMFuzzerInitialize(int *argc, char ***argv);

/* ---- coverage ------------------------------------------------------------ */

#define MAP (1u << 16)
static uint8_t g_map[MAP];      /* edge hit counts of the current run */
static uint8_t g_virgin[MAP];   /* buckets seen so far per edge */
static uint8_t g_vp[MAP / 8];   /* value profile features of the current run */
static uint8_t g_vp_seen[MAP / 8];
static uintptr_t g_prev;
static int g_on;

void __sanitizer_cov_trace_pc(void);
void __sanitizer_cov_trace_pc(void)
{
    uintptr_t pc = (uintptr_t)__builtin_return_address(0);
    uintptr_t h;
    if (!g_on)
        return;
    h = (pc ^ (pc >> 16)) * 0x9e3779b1u;
    g_map[(h ^ g_prev) & (MAP - 1)]++;
    g_prev = (h >> 1) & (MAP - 1);
}

#define CMP_TAB 512
static struct {
    uint64_t a, b;
    uint8_t size;
} g_cmp[CMP_TAB];
static unsigned g_cmp_n;

static void cmp_hook(uint64_t a, uint64_t b, uint8_t size, uintptr_t pc)
{
    unsigned f;
    if (!g_on || a == b)
        return;
    g_cmp[g_cmp_n % CMP_TAB].a = a;
    g_cmp[g_cmp_n % CMP_TAB].b = b;
    g_cmp[g_cmp_n % CMP_TAB].size = size;
    g_cmp_n++;
    f = (unsigned)((pc * 0x9e3779b1u) ^ (uintptr_t)__builtin_popcountll(a ^ b)) & (MAP - 1);
    g_vp[f / 8] |= (uint8_t)(1u << (f % 8));
}

#define PC ((uintptr_t)__builtin_return_address(0))
void __sanitizer_cov_trace_cmp1(uint8_t a, uint8_t b);
void __sanitizer_cov_trace_cmp2(uint16_t a, uint16_t b);
void __sanitizer_cov_trace_cmp4(uint32_t a, uint32_t b);
void __sanitizer_cov_trace_cmp8(uint64_t a, uint64_t b);
void __sanitizer_cov_trace_const_cmp1(uint8_t a, uint8_t b);
void __sanitizer_cov_trace_const_cmp2(uint16_t a, uint16_t b);
void __sanitizer_cov_trace_const_cmp4(uint32_t a, uint32_t b);
void __sanitizer_cov_trace_const_cmp8(uint64_t a, uint64_t b);
void __sanitizer_cov_trace_cmpf(float a, float b);
void __sanitizer_cov_trace_cmpd(double a, double b);
void __sanitizer_cov_trace_switch(uint64_t val, uint64_t *cases);
void __sanitizer_cov_trace_cmp1(uint8_t a, uint8_t b) { cmp_hook(a, b, 1, PC); }
void __sanitizer_cov_trace_cmp2(uint16_t a, uint16_t b) { cmp_hook(a, b, 2, PC); }
void __sanitizer_cov_trace_cmp4(uint32_t a, uint32_t b) { cmp_hook(a, b, 4, PC); }
void __sanitizer_cov_trace_cmp8(uint64_t a, uint64_t b) { cmp_hook(a, b, 8, PC); }
void __sanitizer_cov_trace_const_cmp1(uint8_t a, uint8_t b) { cmp_hook(a, b, 1, PC); }
void __sanitizer_cov_trace_const_cmp2(uint16_t a, uint16_t b) { cmp_hook(a, b, 2, PC); }
void __sanitizer_cov_trace_const_cmp4(uint32_t a, uint32_t b) { cmp_hook(a, b, 4, PC); }
void __sanitizer_cov_trace_const_cmp8(uint64_t a, uint64_t b) { cmp_hook(a, b, 8, PC); }
void __sanitizer_cov_trace_cmpf(float a, float b) { (void)a, (void)b; }
void __sanitizer_cov_trace_cmpd(double a, double b) { (void)a, (void)b; }
void __sanitizer_cov_trace_switch(uint64_t val, uint64_t *cases)
{
    /* cases[0] = count, cases[1] = bit width, then the case values */
    for (uint64_t i = 0; i < cases[0] && i < 64; i++)
        cmp_hook(val, cases[2 + i], (uint8_t)(cases[1] / 8), PC + i);
}

static uint8_t bucket(uint8_t n)
{
    if (n <= 2) return n;
    if (n == 3) return 4;
    if (n < 8) return 8;
    if (n < 16) return 16;
    if (n < 32) return 32;
    if (n < 128) return 64;
    return 128;
}

/* Merges the run's map into the seen sets; non-zero if anything was new. */
static int merge_new(void)
{
    int fresh = 0;
    const uint64_t *w = (const uint64_t *)g_map;
    for (size_t k = 0; k < MAP / 8; k++) {
        if (!w[k])
            continue;
        for (size_t i = k * 8; i < k * 8 + 8; i++) {
            uint8_t b;
            if (!g_map[i])
                continue;
            b = bucket(g_map[i]);
            if (b & ~g_virgin[i]) {
                g_virgin[i] |= b;
                fresh = 1;
            }
        }
    }
    for (size_t i = 0; i < MAP / 8; i++)
        if (g_vp[i] & ~g_vp_seen[i]) {
            g_vp_seen[i] |= g_vp[i];
            fresh = 1;
        }
    return fresh;
}

static size_t count_edges(void)
{
    size_t n = 0;
    for (size_t i = 0; i < MAP; i++)
        n += g_virgin[i] != 0;
    return n;
}

static size_t count_vp(void)
{
    size_t n = 0;
    for (size_t i = 0; i < MAP / 8; i++)
        n += (size_t)__builtin_popcount(g_vp_seen[i]);
    return n;
}

/* ---- options ------------------------------------------------------------- */

static long o_total_time, o_runs = -1, o_timeout = 20, o_keep_going, o_minimize, o_stats;
static unsigned long long o_seed;
static size_t o_max_len = 4096;
static const char *o_prefix = "", *o_exact;

static int parse_flag(const char *a)
{
    const char *eq = strchr(a, '=');
    char name[64];
    size_t n;
    if (a[0] != '-' || !eq || (n = (size_t)(eq - a - 1)) >= sizeof name)
        return 0;
    memcpy(name, a + 1, n);
    name[n] = 0;
    eq++;
    if (!strcmp(name, "max_total_time")) o_total_time = atol(eq);
    else if (!strcmp(name, "runs")) o_runs = atol(eq);
    else if (!strcmp(name, "seed")) o_seed = strtoull(eq, NULL, 0);
    else if (!strcmp(name, "max_len")) o_max_len = (size_t)atol(eq);
    else if (!strcmp(name, "timeout")) o_timeout = atol(eq);
    else if (!strcmp(name, "artifact_prefix")) o_prefix = eq;
    else if (!strcmp(name, "exact_artifact_path")) o_exact = eq;
    else if (!strcmp(name, "keep_going")) o_keep_going = atol(eq);
    else if (!strcmp(name, "minimize_crash")) o_minimize = atol(eq);
    else if (!strcmp(name, "print_final_stats")) o_stats = atol(eq);
    else fprintf(stderr, "driver: ignoring flag %s\n", a);
    return 1;
}

/* ---- shared state between the supervisor and the fuzz child --------------- */

typedef struct {
    volatile uint64_t execs;
    volatile uint64_t run_start_ms; /* 0 while no run is in progress */
    volatile size_t len;
    uint8_t data[];
} shared_t;

static shared_t *g_sh;

static uint64_t now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

static uint64_t fnv(const uint8_t *d, size_t n)
{
    uint64_t h = 1469598103934665603ull;
    for (size_t i = 0; i < n; i++)
        h = (h ^ d[i]) * 1099511628211ull;
    return h;
}

static int write_file(const char *path, const uint8_t *d, size_t n)
{
    FILE *f = fopen(path, "wb");
    if (!f)
        return -1;
    if (n && fwrite(d, 1, n, f) != n) {
        fclose(f);
        return -1;
    }
    return fclose(f);
}

static uint8_t *read_file(const char *path, size_t *n)
{
    FILE *f = fopen(path, "rb");
    uint8_t *d;
    long sz;
    if (!f)
        return NULL;
    fseek(f, 0, SEEK_END);
    sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    d = malloc(sz > 0 ? (size_t)sz : 1);
    if (!d || (sz > 0 && fread(d, 1, (size_t)sz, f) != (size_t)sz)) {
        free(d);
        fclose(f);
        return NULL;
    }
    fclose(f);
    *n = (size_t)(sz > 0 ? sz : 0);
    return d;
}

/* Runs the target once on an exact-size heap copy of d. Returns non-zero if
 * the run reached new coverage. */
static int run_one(const uint8_t *d, size_t n)
{
    uint8_t *copy = malloc(n ? n : 1);
    if (!copy)
        abort();
    memcpy(copy, d, n);
    memset(g_map, 0, sizeof g_map);
    memset(g_vp, 0, sizeof g_vp);
    g_prev = 0;
    if (g_sh) {
        memcpy(g_sh->data, d, n);
        g_sh->len = n;
        g_sh->run_start_ms = now_ms();
    }
    g_on = 1;
    LLVMFuzzerTestOneInput(copy, n);
    g_on = 0;
    if (g_sh) {
        g_sh->run_start_ms = 0;
        g_sh->execs++;
    }
    free(copy);
    return merge_new();
}

/* ---- corpus and mutation ------------------------------------------------- */

typedef struct {
    uint8_t *d;
    size_t n;
} input_t;

#define MAXCORPUS 50000
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

static size_t rndn(size_t n) { return n ? (size_t)(rnd() % n) : 0; }

static void corpus_add(const uint8_t *d, size_t n, const char *dir)
{
    char path[4096];
    if (g_ncorpus == MAXCORPUS)
        return;
    g_corpus[g_ncorpus].d = malloc(n ? n : 1);
    if (!g_corpus[g_ncorpus].d)
        abort();
    memcpy(g_corpus[g_ncorpus].d, d, n);
    g_corpus[g_ncorpus].n = n;
    g_ncorpus++;
    if (dir) {
        snprintf(path, sizeof path, "%s/%016llx", dir, (unsigned long long)fnv(d, n));
        write_file(path, d, n);
    }
}

static const uint64_t INTERESTING[] = {0, 1, 2, 3, 4, 7, 8, 12, 16, 31, 32, 33, 63, 64, 100,
                                       127, 128, 255, 256, 4096, 65535, 65536, 0x7fffffff,
                                       0x80000000ull, 0xffffffffull, 0x100000000ull,
                                       0x7fffffffffffffffull, 0x8000000000000000ull,
                                       0xffffffffffffffffull, 0xfffffffffffffffeull};

static void put_le(uint8_t *p, uint64_t v, size_t size)
{
    for (size_t i = 0; i < size; i++)
        p[i] = (uint8_t)(v >> (8 * i));
}

/* One mutation of buf (length *n, capacity cap) in place. */
static void mutate_once(uint8_t *buf, size_t *n, size_t cap)
{
    size_t len = *n;
    switch (rndn(12)) {
    case 0: /* flip a bit */
        if (len) buf[rndn(len)] ^= (uint8_t)(1u << rndn(8));
        break;
    case 1: /* random byte */
        if (len) buf[rndn(len)] = (uint8_t)rnd();
        break;
    case 2: /* add or subtract a little */
        if (len) buf[rndn(len)] += (uint8_t)(rndn(35) - 17);
        break;
    case 3: { /* interesting value, 1, 2, 4 or 8 bytes */
        size_t size = (size_t)1 << rndn(4);
        if (len >= size)
            put_le(buf + rndn(len - size + 1),
                   INTERESTING[rndn(sizeof INTERESTING / sizeof INTERESTING[0])], size);
        break;
    }
    case 4: { /* a comparison operand, at a random place or where its partner is */
        unsigned k = g_cmp_n < CMP_TAB ? g_cmp_n : CMP_TAB;
        size_t size;
        uint64_t from, to;
        if (!k) break;
        k = (unsigned)rndn(k);
        size = g_cmp[k].size ? g_cmp[k].size : 1;
        from = rnd() & 1 ? g_cmp[k].a : g_cmp[k].b;
        to = from == g_cmp[k].a ? g_cmp[k].b : g_cmp[k].a;
        if (rnd() & 1)
            to += rndn(3) - 1;
        if (len < size) break;
        for (size_t tries = 0; tries < 8; tries++) {
            size_t at = rndn(len - size + 1);
            uint8_t pat[8];
            put_le(pat, from, size);
            if (!memcmp(buf + at, pat, size) || tries == 7) {
                put_le(buf + at, to, size);
                break;
            }
        }
        break;
    }
    case 5: { /* insert bytes */
        size_t k = 1 + rndn(16), at = rndn(len + 1);
        if (len + k > cap) break;
        memmove(buf + at + k, buf + at, len - at);
        for (size_t i = 0; i < k; i++)
            buf[at + i] = rnd() & 1 ? (uint8_t)rnd() : 0;
        *n = len + k;
        break;
    }
    case 6: { /* delete bytes */
        size_t k, at;
        if (!len) break;
        k = 1 + rndn(len < 16 ? len : 16);
        at = rndn(len - k + 1);
        memmove(buf + at, buf + at + k, len - at - k);
        *n = len - k;
        break;
    }
    case 7: { /* copy a chunk inside the input */
        size_t k, from, to;
        if (len < 2) break;
        k = 1 + rndn(len / 2);
        from = rndn(len - k + 1);
        to = rndn(len - k + 1);
        memmove(buf + to, buf + from, k);
        break;
    }
    case 8: { /* splice with another corpus input */
        const input_t *o;
        size_t at, k, from;
        if (!g_ncorpus) break;
        o = &g_corpus[rndn(g_ncorpus)];
        if (!o->n) break;
        k = 1 + rndn(o->n);
        from = rndn(o->n - k + 1);
        at = rndn(len + 1);
        if (at + k > cap) k = cap - at;
        if (!k) break;
        memcpy(buf + at, o->d + from, k);
        if (at + k > len)
            *n = at + k;
        break;
    }
    case 9: { /* fill a run with one byte */
        size_t k, at;
        if (!len) break;
        k = 1 + rndn(len < 32 ? len : 32);
        at = rndn(len - k + 1);
        memset(buf + at, rnd() & 1 ? 0 : (uint8_t)rnd(), k);
        break;
    }
    case 10: /* truncate */
        if (len) *n = rndn(len);
        break;
    default: { /* append random bytes */
        size_t k = 1 + rndn(32);
        if (len + k > cap) k = cap - len;
        for (size_t i = 0; i < k; i++)
            buf[len + i] = (uint8_t)rnd();
        *n = len + k;
        break;
    }
    }
}

static void load_dir(const char *dir, input_t **list, size_t *count, size_t *cap)
{
    DIR *d = opendir(dir);
    struct dirent *e;
    char path[4096];
    if (!d)
        return;
    while ((e = readdir(d))) {
        struct stat st;
        size_t n;
        uint8_t *data;
        if (e->d_name[0] == '.')
            continue;
        snprintf(path, sizeof path, "%s/%s", dir, e->d_name);
        if (stat(path, &st) || !S_ISREG(st.st_mode))
            continue;
        if (!(data = read_file(path, &n)))
            continue;
        if (n > o_max_len)
            n = o_max_len;
        if (*count == *cap) {
            *cap = *cap ? *cap * 2 : 256;
            *list = realloc(*list, *cap * sizeof **list);
            if (!*list)
                abort();
        }
        (*list)[*count].d = data;
        (*list)[*count].n = n;
        (*count)++;
    }
    closedir(d);
}

static int cmp_len(const void *a, const void *b)
{
    const input_t *x = a, *y = b;
    return x->n < y->n ? -1 : x->n > y->n;
}

/* The fuzz loop, in the child. Returns when time or runs are used up. */
static void fuzz_loop(char **dirs, int ndirs, uint64_t deadline_ms)
{
    input_t *seeds = NULL;
    size_t nseeds = 0, capseeds = 0, n;
    uint8_t *buf = malloc(o_max_len ? o_max_len : 1);
    uint64_t execs = 0, last_print = now_ms(), start = now_ms();

    if (!buf)
        abort();
    for (int i = 0; i < ndirs; i++)
        load_dir(dirs[i], &seeds, &nseeds, &capseeds);
    qsort(seeds, nseeds, sizeof *seeds, cmp_len);
    /* Smallest first: a seed joins the corpus only if it adds coverage. */
    for (size_t i = 0; i < nseeds; i++) {
        if (run_one(seeds[i].d, seeds[i].n) || !g_ncorpus)
            corpus_add(seeds[i].d, seeds[i].n, NULL);
        free(seeds[i].d);
        execs++;
    }
    free(seeds);
    if (!g_ncorpus) {
        run_one((const uint8_t *)"", 0);
        corpus_add((const uint8_t *)"", 0, dirs[0]);
    }
    fprintf(stderr, "#%llu INITED cov: %zu vp: %zu corp: %zu (from %zu seeds)\n",
            (unsigned long long)execs, count_edges(), count_vp(), g_ncorpus, nseeds);

    for (;;) {
        const input_t *parent;
        uint64_t t = now_ms();
        if ((o_runs >= 0 && (long)execs >= o_runs) || (deadline_ms && t >= deadline_ms))
            break;
        if (t - last_print >= 10000) {
            fprintf(stderr, "#%llu pulse cov: %zu vp: %zu corp: %zu exec/s: %llu\n",
                    (unsigned long long)execs, count_edges(), count_vp(), g_ncorpus,
                    (unsigned long long)(execs * 1000 / (t - start + 1)));
            last_print = t;
        }
        /* Favour recent additions a little: they are the frontier. */
        parent = &g_corpus[rnd() & 3 ? rndn(g_ncorpus)
                                     : g_ncorpus - 1 - rndn(g_ncorpus < 64 ? g_ncorpus : 64)];
        n = parent->n < o_max_len ? parent->n : o_max_len;
        memcpy(buf, parent->d, n);
        for (size_t k = 1 + rndn(1u << rndn(4)); k; k--)
            mutate_once(buf, &n, o_max_len);
        if (run_one(buf, n))
            corpus_add(buf, n, dirs[0]);
        execs++;
    }
    if (o_stats)
        fprintf(stderr, "stat::number_of_executed_units: %llu\nstat::average_exec_per_sec: %llu\n"
                        "stat::edges: %zu\nstat::value_profile: %zu\nstat::corpus: %zu\n",
                (unsigned long long)execs,
                (unsigned long long)(execs * 1000 / (now_ms() - start + 1)), count_edges(),
                count_vp(), g_ncorpus);
    fprintf(stderr, "#%llu DONE cov: %zu vp: %zu corp: %zu\n", (unsigned long long)execs,
            count_edges(), count_vp(), g_ncorpus);
    free(buf);
}

/* ---- supervisor ---------------------------------------------------------- */

static void save_artifact(const char *kind, const uint8_t *d, size_t n)
{
    char path[4096];
    if (o_exact)
        snprintf(path, sizeof path, "%s", o_exact);
    else
        snprintf(path, sizeof path, "%s%s-%016llx", o_prefix, kind, (unsigned long long)fnv(d, n));
    if (write_file(path, d, n) == 0)
        fprintf(stderr, "==DRIVER== %s input (%zu bytes) saved to %s\n", kind, n, path);
    else
        fprintf(stderr, "==DRIVER== could not write %s: %s\n", path, strerror(errno));
}

static int fuzz_main(char **dirs, int ndirs)
{
    uint64_t start = now_ms();
    uint64_t deadline = o_total_time > 0 ? start + (uint64_t)o_total_time * 1000 : 0;
    int crashes = 0;

    mkdir(dirs[0], 0755);
    g_sh = mmap(NULL, sizeof(shared_t) + o_max_len + 1, PROT_READ | PROT_WRITE,
                MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (g_sh == MAP_FAILED) {
        perror("mmap");
        return 2;
    }
    for (int round = 0;; round++) {
        pid_t pid;
        int status = 0;
        g_sh->len = 0;
        g_sh->run_start_ms = 0;
        fflush(stderr);
        pid = fork();
        if (pid < 0) {
            perror("fork");
            return 2;
        }
        if (pid == 0) {
            g_rng = o_seed + (uint64_t)round * 0x1234567ull;
            fuzz_loop(dirs, ndirs, deadline);
            fflush(stderr);
            _exit(0);
        }
        for (;;) {
            pid_t r = waitpid(pid, &status, WNOHANG);
            uint64_t rs;
            if (r == pid)
                break;
            rs = g_sh->run_start_ms;
            if (o_timeout > 0 && rs && now_ms() - rs > (uint64_t)o_timeout * 1000) {
                fprintf(stderr, "==DRIVER== run over %lds, killing\n", o_timeout);
                kill(pid, SIGKILL);
                waitpid(pid, &status, 0);
                save_artifact("timeout", g_sh->data, g_sh->len);
                status = -1;
                break;
            }
            usleep(50000);
        }
        if (status == 0)
            break;
        if (status != -1) {
            if (WIFSIGNALED(status))
                fprintf(stderr, "==DRIVER== child died with signal %d\n", WTERMSIG(status));
            else
                fprintf(stderr, "==DRIVER== child exited with status %d\n", WEXITSTATUS(status));
            save_artifact("crash", g_sh->data, g_sh->len);
        }
        crashes++;
        if (!o_keep_going || (deadline && now_ms() + 1000 >= deadline) || crashes >= 100)
            break;
    }
    fprintf(stderr, "==DRIVER== done: %d crash(es), %llu execs in the last round\n", crashes,
            (unsigned long long)g_sh->execs);
    return crashes ? 1 : 0;
}

/* ---- replay and minimize ------------------------------------------------- */

/* Runs d in a child; non-zero if it crashes. */
static int crashes_in_child(const uint8_t *d, size_t n, int quiet)
{
    int status;
    pid_t pid = fork();
    if (pid == 0) {
        if (quiet) {
            int fd = open("/dev/null", O_WRONLY);
            if (fd >= 0)
                dup2(fd, 2);
        }
        uint8_t *copy = malloc(n ? n : 1);
        if (!copy)
            _exit(3);
        memcpy(copy, d, n);
        alarm((unsigned)(o_timeout > 0 ? o_timeout : 20));
        LLVMFuzzerTestOneInput(copy, n);
        _exit(0);
    }
    if (pid < 0 || waitpid(pid, &status, 0) < 0)
        return 0;
    return !(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

static int minimize(const char *path)
{
    size_t n, cand_n;
    uint8_t *cur = read_file(path, &n), *cand;
    long budget = o_runs > 0 ? o_runs : 2000, used = 0;
    int progress = 1;

    if (!cur) {
        fprintf(stderr, "driver: cannot read %s\n", path);
        return 2;
    }
    if (!crashes_in_child(cur, n, 0)) {
        fprintf(stderr, "driver: %s does not crash\n", path);
        return 2;
    }
    cand = malloc(n ? n : 1);
    while (progress && used < budget) {
        progress = 0;
        for (size_t chunk = n / 2 ? n / 2 : 1; chunk >= 1 && used < budget; chunk /= 2) {
            for (size_t at = 0; at + chunk <= n && used < budget;) {
                memcpy(cand, cur, at);
                memcpy(cand + at, cur + at + chunk, n - at - chunk);
                cand_n = n - chunk;
                used++;
                if (crashes_in_child(cand, cand_n, 1)) {
                    memcpy(cur, cand, cand_n);
                    n = cand_n;
                    progress = 1;
                } else {
                    at += chunk;
                }
            }
            if (chunk == 1)
                break;
        }
        /* Simplify bytes to zero where the crash stays. */
        for (size_t i = 0; i < n && used < budget; i++) {
            uint8_t old = cur[i];
            if (!old)
                continue;
            cur[i] = 0;
            used++;
            if (crashes_in_child(cur, n, 1))
                progress = 1;
            else
                cur[i] = old;
        }
    }
    fprintf(stderr, "==DRIVER== minimized to %zu bytes in %ld runs\n", n, used);
    save_artifact("minimized", cur, n);
    free(cand);
    free(cur);
    return 0;
}

int main(int argc, char **argv)
{
    char **paths = calloc((size_t)argc, sizeof *paths);
    int npaths = 0, ndirs = 0;
    struct stat st;

    if (LLVMFuzzerInitialize)
        LLVMFuzzerInitialize(&argc, &argv);
    for (int i = 1; i < argc; i++)
        if (!parse_flag(argv[i]))
            paths[npaths++] = argv[i];
    if (!o_seed)
        o_seed = (unsigned long long)time(NULL) ^ ((unsigned long long)getpid() << 32);
    g_rng = o_seed;
    fprintf(stderr, "driver: seed %llu, max_len %zu\n", o_seed, o_max_len);

    if (o_minimize) {
        if (npaths != 1) {
            fprintf(stderr, "driver: -minimize_crash=1 takes one file\n");
            return 2;
        }
        return minimize(paths[0]);
    }
    for (int i = 0; i < npaths; i++)
        if (!stat(paths[i], &st) && S_ISDIR(st.st_mode))
            ndirs++;
    if (npaths == 0 || (ndirs == 0 && stat(paths[0], &st) != 0)) {
        /* A corpus directory that does not exist yet. */
        if (npaths == 0) {
            fprintf(stderr, "usage: %s [flags] CORPUS_DIR [SEED_DIR...] | FILE...\n", argv[0]);
            return 2;
        }
        ndirs = npaths;
    }
    if (ndirs == 0) {
        for (int i = 0; i < npaths; i++) {
            size_t n;
            uint8_t *d = read_file(paths[i], &n);
            if (!d) {
                fprintf(stderr, "driver: cannot read %s\n", paths[i]);
                return 2;
            }
            fprintf(stderr, "Running: %s\n", paths[i]);
            run_one(d, n);
            free(d);
        }
        fprintf(stderr, "Executed %d inputs\n", npaths);
        free(paths);
        return 0;
    }
    {
        int rc = fuzz_main(paths, npaths);
        free(paths);
        return rc;
    }
}
