/*
 * Runs the EIP-3076 slashing-protection-interchange-tests against the core's
 * minimal-strategy slashing protection (sc_slashing_*), in four modes:
 *
 *   minimal            no commit-ahead window, no restarts
 *   window             commit-ahead {32 slots, 1, 1}, no restarts
 *   restart            no window, state rebuilt from storage before every op
 *   window+restart     window and a restart before every op
 *
 * The first three must match should_succeed exactly. In the last mode the
 * window makes the signer refuse more after each restart, so it is checked
 * for safety only: it must never accept an op the test expects to be
 * refused. Extra refusals are counted and reported.
 *
 * usage: test_eip3076 <converted.txt from eip3076_convert.py>
 */
#include "testutil.h"

typedef struct {
    char kind[3]; /* T S IB IA B A E */
    char name[160];
    uint8_t pk[48];
    uint8_t root[32];
    uint64_t a, b;
    int expect;      /* B/A: should_succeed; S: should_succeed */
    int slashable;   /* S only */
    int root_ok;     /* S only: interchange GVR == test GVR */
    int version_ok;  /* S only */
} line_t;

static line_t *lines;
static size_t nlines;

#define MAX_KEYS 64
typedef struct {
    uint8_t pk[48];
    sc_slashing_state st;
    sc_watermark persisted;
    int has_persisted;
} keyrec_t;

typedef struct {
    keyrec_t keys[MAX_KEYS];
    int n;
} db_t;

static keyrec_t *find_key(db_t *db, const uint8_t pk[48], int create)
{
    for (int i = 0; i < db->n; i++)
        if (memcmp(db->keys[i].pk, pk, 48) == 0)
            return &db->keys[i];
    if (!create || db->n == MAX_KEYS)
        return NULL;
    keyrec_t *k = &db->keys[db->n++];
    memset(k, 0, sizeof *k);
    memcpy(k->pk, pk, 48);
    sc_slashing_restore(&k->st, NULL);
    return k;
}

static int store_cb(void *ctx, const uint8_t pk[48], const sc_watermark *wm)
{
    keyrec_t *k = find_key((db_t *)ctx, pk, 1);
    if (!k)
        return SC_ERR_NOMEM;
    k->persisted = *wm;
    k->has_persisted = 1;
    return SC_OK;
}

static void restart(keyrec_t *k)
{
    sc_slashing_restore(&k->st, k->has_persisted ? &k->persisted : NULL);
}

static int load(const char *path)
{
    FILE *f = fopen(path, "r");
    char buf[1024];
    uint8_t gvr[32];
    size_t cap = 0;
    if (!f)
        return -1;
    while (fgets(buf, sizeof buf, f)) {
        char k[4] = {0}, s1[200] = {0}, s2[200] = {0}, s3[200] = {0}, s4[200] = {0};
        int n = sscanf(buf, "%3s %199s %199s %199s %199s", k, s1, s2, s3, s4);
        if (n < 1)
            continue;
        if (nlines == cap) {
            cap = cap ? cap * 2 : 256;
            lines = realloc(lines, cap * sizeof *lines);
        }
        line_t *l = &lines[nlines++];
        memset(l, 0, sizeof *l);
        snprintf(l->kind, sizeof l->kind, "%s", k);
        if (!strcmp(k, "T")) {
            snprintf(l->name, sizeof l->name, "%s", s1);
            if (parse_hex(s2, gvr, 32) != 0)
                return -1;
        } else if (!strcmp(k, "S")) {
            uint8_t igvr[32];
            l->expect = atoi(s1);
            l->slashable = atoi(s2);
            l->root_ok = parse_hex(s3, igvr, 32) == 0 && memcmp(igvr, gvr, 32) == 0;
            l->version_ok = strcmp(s4, "5") == 0;
        } else if (!strcmp(k, "IB") || !strcmp(k, "B")) {
            if (parse_hex(s1, l->pk, 48) != 0)
                return -1;
            l->a = strtoull(s2, NULL, 10);
            l->expect = atoi(s3);
        } else if (!strcmp(k, "IA") || !strcmp(k, "A")) {
            if (parse_hex(s1, l->pk, 48) != 0)
                return -1;
            l->a = strtoull(s2, NULL, 10);
            l->b = strtoull(s3, NULL, 10);
            l->expect = atoi(s4);
        }
    }
    fclose(f);
    return 0;
}

typedef struct {
    const char *name;
    sc_commit_ahead ahead;
    int restart_each_op;
    int exact;
} mode_cfg_t;

typedef struct {
    int tests, tests_pass, ops, ops_match, unsafe, extra_refusals, writes;
} result_t;

static int g_writes;
static int counting_store(void *ctx, const uint8_t pk[48], const sc_watermark *wm)
{
    g_writes++;
    return store_cb(ctx, pk, wm);
}

/* Imports one step's interchange data (lines [from, to)). */
static int import_step(db_t *db, const line_t *step, size_t from, size_t to)
{
    if (!step->root_ok || !step->version_ok)
        return SC_ERR_ARG;
    /* Collect per-key maxima first, then import, so a refused import
     * leaves nothing half applied. */
    struct {
        uint8_t pk[48];
        sc_watermark wm;
    } imp[MAX_KEYS];
    int nimp = 0;
    for (size_t i = from; i < to; i++) {
        const line_t *l = &lines[i];
        int isb = !strcmp(l->kind, "IB"), isa = !strcmp(l->kind, "IA");
        if (!isb && !isa)
            continue;
        int j;
        for (j = 0; j < nimp; j++)
            if (!memcmp(imp[j].pk, l->pk, 48))
                break;
        if (j == nimp) {
            if (nimp == MAX_KEYS)
                return SC_ERR_NOMEM;
            memset(&imp[j], 0, sizeof imp[j]);
            memcpy(imp[j].pk, l->pk, 48);
            nimp++;
        }
        sc_watermark *w = &imp[j].wm;
        if (isb) {
            w->block_slot = (w->flags & SC_WM_HAS_BLOCK) && w->block_slot > l->a ? w->block_slot : l->a;
            w->flags |= SC_WM_HAS_BLOCK;
        } else {
            if (w->flags & SC_WM_HAS_ATTESTATION) {
                if (l->a > w->source_epoch) w->source_epoch = l->a;
                if (l->b > w->target_epoch) w->target_epoch = l->b;
            } else {
                w->source_epoch = l->a;
                w->target_epoch = l->b;
            }
            w->flags |= SC_WM_HAS_ATTESTATION;
        }
    }
    for (int j = 0; j < nimp; j++) {
        keyrec_t *k = find_key(db, imp[j].pk, 1);
        if (!k)
            return SC_ERR_NOMEM;
        int rc = sc_slashing_import(&k->st, &imp[j].wm, counting_store, db, k->pk);
        if (rc != SC_OK)
            return rc;
    }
    return SC_OK;
}

static result_t run_mode(const mode_cfg_t *m, int verbose)
{
    result_t r = {0};
    static db_t db;
    size_t i = 0;
    g_writes = 0;
    while (i < nlines) {
        if (strcmp(lines[i].kind, "T") != 0) {
            i++;
            continue;
        }
        const char *name = lines[i].name;
        int test_ok = 1;
        memset(&db, 0, sizeof db);
        i++;
        while (i < nlines && strcmp(lines[i].kind, "E") != 0) {
            const line_t *step = &lines[i];
            if (strcmp(step->kind, "S") != 0) {
                i++;
                continue;
            }
            size_t from = ++i;
            while (i < nlines && (!strcmp(lines[i].kind, "IB") || !strcmp(lines[i].kind, "IA")))
                i++;
            int imported = import_step(&db, step, from, i) == SC_OK;
            if (imported != step->expect && !(step->slashable && !imported)) {
                test_ok = 0;
                if (verbose)
                    printf("  %s: import %s, expected %s\n", name, imported ? "ok" : "refused",
                           step->expect ? "ok" : "refused");
            }
            for (; i < nlines && (!strcmp(lines[i].kind, "B") || !strcmp(lines[i].kind, "A")); i++) {
                const line_t *l = &lines[i];
                keyrec_t *k = find_key(&db, l->pk, 1);
                int rc;
                if (m->restart_each_op)
                    restart(k);
                if (l->kind[0] == 'B')
                    rc = sc_slashing_approve_block(&k->st, &m->ahead, counting_store, &db, k->pk, l->a);
                else
                    rc = sc_slashing_approve_attestation(&k->st, &m->ahead, counting_store, &db,
                                                         k->pk, l->a, l->b);
                int ok = rc == SC_OK;
                r.ops++;
                if (ok == l->expect) {
                    r.ops_match++;
                } else {
                    if (ok && !l->expect)
                        r.unsafe++;
                    else
                        r.extra_refusals++;
                    if (m->exact || ok)
                        test_ok = 0;
                    if (verbose)
                        printf("  %s: %s %s(%llu,%llu) -> %s, expected %s\n", name, l->kind,
                               ok ? "accepted" : "refused", (unsigned long long)l->a,
                               (unsigned long long)l->b, sc_status_name(rc),
                               l->expect ? "accept" : "refuse");
                }
            }
        }
        r.tests++;
        r.tests_pass += test_ok;
        if (verbose)
            printf("eip3076 %-16s %s %s\n", m->name, test_ok ? "PASS" : "FAIL", name);
        i++;
    }
    r.writes = g_writes;
    return r;
}

int main(int argc, char **argv)
{
    static const mode_cfg_t modes[] = {
        {"minimal", {0, 0, 0}, 0, 1},
        {"window", {32, 1, 1}, 0, 1},
        {"restart", {0, 0, 0}, 1, 1},
        {"window+restart", {32, 1, 1}, 1, 0},
    };
    int bad = 0;
    if (argc != 2) {
        fprintf(stderr, "usage: %s <converted.txt>\n", argv[0]);
        return 2;
    }
    if (load(argv[1]) != 0 || nlines == 0) {
        fprintf(stderr, "cannot load %s\n", argv[1]);
        return 2;
    }
    for (size_t m = 0; m < sizeof modes / sizeof modes[0]; m++) {
        result_t r = run_mode(&modes[m], 1);
        printf("EIP3076 mode=%s tests=%d pass=%d fail=%d ops=%d match=%d unsafe_accepts=%d "
               "extra_refusals=%d watermark_writes=%d\n",
               modes[m].name, r.tests, r.tests_pass, r.tests - r.tests_pass, r.ops, r.ops_match,
               r.unsafe, r.extra_refusals, r.writes);
        if (r.tests_pass != r.tests || r.unsafe || r.tests == 0)
            bad = 1;
    }
    free(lines);
    return bad;
}
