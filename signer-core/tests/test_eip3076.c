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
 * The same ops then run through the signer (sc_sign_block,
 * sc_sign_attestation) with the vectors' signing roots, so the exact-repeat
 * shortcut of signer.c (is_repeat) sees them. The core computes a signing
 * root from the message, so a vector's root cannot be that root; it goes
 * into the message instead, as a block's body_root or an attestation's
 * beacon_block_root. Two ops with the same values and the same vector root
 * then hash to the same signing root, two with different roots to
 * different ones, and that is what the shortcut compares. Four more modes:
 *
 *   signer                  no window, no restarts
 *   signer+window           commit-ahead {32, 1, 1}
 *   signer+restart          no window, persist_repeat_root 1, a restart
 *                           (new signer over the same storage) before every op
 *   signer+window+restart   both; safety only, like window+restart
 *
 * There should_succeed holds, except for an op whose kind, values and root
 * equal the last op the validator signed in this run with no import of its
 * history in between (sc_signer_import drops the roots): that one must sign
 * again as an exact repeat, with the same signature and no mark write. The
 * vectors hold no such op, so after every op that signed the harness sends
 * it once more (after another restart in the restart modes) and checks the
 * same. Imported roots never count: the resign tests send imported messages
 * again, and those must be refused.
 *
 * An import the test expects to succeed may still be refused when the data
 * is slashable (contains_slashable_data). The README then ends the test:
 * the step's ops and all later steps are skipped. These are counted as
 * slashable_skips. The core's max-merge import never refuses today, so the
 * count is 0.
 *
 * usage: test_eip3076 <converted.txt from eip3076_convert.py>
 */
#include "testutil.h"

typedef struct {
    char kind[3]; /* T S IB IA B A E */
    char name[160];
    uint8_t pk[48];
    uint8_t gvr[32]; /* T: the test's root; S: the interchange's root */
    int has_gvr;     /* S only */
    uint8_t root[32]; /* B/A: the signing root, or a root unique to this line */
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
        char k[4] = {0}, s1[200] = {0}, s2[200] = {0}, s3[200] = {0}, s4[200] = {0},
             s5[200] = {0};
        int n = sscanf(buf, "%3s %199s %199s %199s %199s %199s", k, s1, s2, s3, s4, s5);
        const char *root = NULL;
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
            memcpy(l->gvr, gvr, 32);
        } else if (!strcmp(k, "S")) {
            l->expect = atoi(s1);
            l->slashable = atoi(s2);
            l->has_gvr = parse_hex(s3, l->gvr, 32) == 0;
            l->root_ok = l->has_gvr && memcmp(l->gvr, gvr, 32) == 0;
            l->version_ok = strcmp(s4, "5") == 0;
        } else if (!strcmp(k, "IB") || !strcmp(k, "B")) {
            if (parse_hex(s1, l->pk, 48) != 0)
                return -1;
            l->a = strtoull(s2, NULL, 10);
            l->expect = atoi(s3);
            root = s4;
        } else if (!strcmp(k, "IA") || !strcmp(k, "A")) {
            if (parse_hex(s1, l->pk, 48) != 0)
                return -1;
            l->a = strtoull(s2, NULL, 10);
            l->b = strtoull(s3, NULL, 10);
            l->expect = atoi(s4);
            root = s5;
        }
        /* An op without a signing root gets one no other line has, so it
         * never passes as a repeat. */
        if (root && parse_hex(root, l->root, 32) != 0) {
            memset(l->root, 0xee, 32);
            memcpy(l->root, &nlines, sizeof nlines);
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
    int tests, tests_pass, ops, ops_match, unsafe, extra_refusals, slashable_skips, writes, repeats;
} result_t;

static int g_writes;
static int counting_store(void *ctx, const uint8_t pk[48], const sc_watermark *wm)
{
    g_writes++;
    return store_cb(ctx, pk, wm);
}

typedef struct {
    uint8_t pk[48];
    sc_watermark wm;
} import_t;

/* The per-key maxima of one step's interchange data (lines [from, to)):
 * the import of a whole file at once, so a refused import leaves nothing
 * half applied. Returns the key count, or -1 for more than MAX_KEYS. */
static int collect_maxima(size_t from, size_t to, import_t imp[MAX_KEYS])
{
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
                return -1;
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
    return nimp;
}

/*
 * Imports one step's interchange data (lines [from, to)). All or nothing:
 * per-key maxima are collected first, and if the core refuses any key the
 * db is put back as it was, so a refused import leaves nothing half applied.
 */
static int import_step(db_t *db, const line_t *step, size_t from, size_t to)
{
    static db_t before;
    import_t imp[MAX_KEYS];
    int nimp;
    if (!step->root_ok || !step->version_ok)
        return SC_ERR_ARG;
    if ((nimp = collect_maxima(from, to, imp)) < 0)
        return SC_ERR_NOMEM;
    before = *db;
    for (int j = 0; j < nimp; j++) {
        keyrec_t *k = find_key(db, imp[j].pk, 1);
        int rc = k ? sc_slashing_import(&k->st, &imp[j].wm, counting_store, db, k->pk)
                   : SC_ERR_NOMEM;
        if (rc != SC_OK) {
            *db = before;
            return rc;
        }
    }
    return SC_OK;
}

static int is_import(const line_t *l) { return !strcmp(l->kind, "IB") || !strcmp(l->kind, "IA"); }
static int is_op(const line_t *l) { return !strcmp(l->kind, "B") || !strcmp(l->kind, "A"); }

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
            while (i < nlines && is_import(&lines[i]))
                i++;
            int imported = import_step(&db, step, from, i) == SC_OK;
            if (!imported && step->expect && step->slashable) {
                /* Allowed by the README; the rest of the test is skipped. */
                r.slashable_skips++;
                if (verbose)
                    printf("  %s: slashable import refused, rest of test skipped\n", name);
                while (i < nlines && strcmp(lines[i].kind, "E") != 0)
                    i++;
                break;
            }
            if (imported != step->expect) {
                test_ok = 0;
                if (verbose)
                    printf("  %s: import %s, expected %s\n", name, imported ? "ok" : "refused",
                           step->expect ? "ok" : "refused");
            }
            for (; i < nlines && is_op(&lines[i]); i++) {
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
            printf("eip3076 %-21s %s %s\n", m->name, test_ok ? "PASS" : "FAIL", name);
        i++;
    }
    r.writes = g_writes;
    return r;
}

/* ---- the signer modes --------------------------------------------------- */

/* The last op a key signed in this run, per kind: what an exact repeat
 * must equal. */
typedef struct {
    int valid;
    uint64_t a, b;
    uint8_t root[32];
    uint8_t sig[96];
} last_t;

/* The signer's host: marks and repeat roots per key, in memory, and the
 * share secret each key signs with. */
typedef struct {
    uint8_t pk[48];
    uint8_t secret[32];
    sc_watermark wm;
    int has_wm;
    sc_repeat_roots rr;
    int has_rr;
    last_t last[2]; /* 0 block, 1 attestation */
} skey_t;

typedef struct {
    skey_t keys[MAX_KEYS];
    int n;
    int writes, root_writes;
} shost_t;

/* Epoch 2000 of a chain with genesis at 0 and 12 s slots: every epoch
 * and slot the vectors use is behind the clock. */
#define S_NOW (2000ull * 32ull * 12ull)

static skey_t *s_find(shost_t *h, const uint8_t pk[48])
{
    for (int i = 0; i < h->n; i++)
        if (!memcmp(h->keys[i].pk, pk, 48))
            return &h->keys[i];
    return NULL;
}

static int s_load(void *ctx, const uint8_t pk[48], sc_watermark *out)
{
    skey_t *k = s_find(ctx, pk);
    if (!k || !k->has_wm)
        return SC_ERR_UNKNOWN_VALIDATOR;
    *out = k->wm;
    return SC_OK;
}

static int s_store(void *ctx, const uint8_t pk[48], const sc_watermark *wm)
{
    shost_t *h = ctx;
    skey_t *k = s_find(h, pk);
    if (!k)
        return SC_ERR_STORAGE;
    k->wm = *wm;
    k->has_wm = 1;
    h->writes++;
    return SC_OK;
}

static int s_load_roots(void *ctx, const uint8_t pk[48], sc_repeat_roots *out)
{
    skey_t *k = s_find(ctx, pk);
    if (!k || !k->has_rr)
        return SC_ERR_UNKNOWN_VALIDATOR;
    *out = k->rr;
    return SC_OK;
}

static int s_store_roots(void *ctx, const uint8_t pk[48], const sc_repeat_roots *rr)
{
    shost_t *h = ctx;
    skey_t *k = s_find(h, pk);
    if (!k)
        return SC_ERR_STORAGE;
    k->rr = *rr;
    k->has_rr = 1;
    h->root_writes++;
    return SC_OK;
}

static int s_now(void *ctx, uint64_t *t)
{
    (void)ctx;
    *t = S_NOW;
    return SC_OK;
}

static void die(const char *what, int rc)
{
    fprintf(stderr, "test_eip3076: %s: %s\n", what, sc_status_name(rc));
    exit(2);
}

/* A new signer over h's storage, with every key h knows loaded again: the
 * first start of a test, or a restart. */
static sc_signer *signer_start(shost_t *h, void *mem, size_t mem_len, const uint8_t gvr[32],
                               const sc_commit_ahead *ahead, int persist)
{
    sc_config cfg;
    sc_host_ops ops = {.ctx = h,
                       .now = s_now,
                       .load_watermark = s_load,
                       .store_watermark = s_store,
                       .load_repeat_roots = s_load_roots,
                       .store_repeat_roots = s_store_roots};
    sc_signer *s = NULL;
    int rc;

    memset(&cfg, 0, sizeof cfg);
    memcpy(cfg.genesis_validators_root, gvr, 32);
    cfg.seconds_per_slot = 12;
    cfg.slots_per_epoch = 32;
    cfg.commit_ahead = *ahead;
    cfg.persist_repeat_root = (uint32_t)persist;
    if ((rc = sc_signer_init(mem, mem_len, MAX_KEYS, 0, &cfg, &ops, &s)) != SC_OK)
        die("sc_signer_init", rc);
    for (int i = 0; i < h->n; i++) {
        rc = sc_signer_add_validator(s, h->keys[i].pk, h->keys[i].secret, SC_INDEX_UNKNOWN, NULL);
        if (rc != SC_OK)
            die("sc_signer_add_validator", rc);
    }
    return s;
}

/* The key for pk, loaded into s if new. The vector pubkey names the
 * validator; the secret is a share of our own, as a threshold node holds. */
static skey_t *s_key(shost_t *h, sc_signer *s, const uint8_t pk[48])
{
    skey_t *k = s_find(h, pk);
    int rc;
    if (k)
        return k;
    if (h->n == MAX_KEYS)
        die("too many keys", SC_ERR_NOMEM);
    k = &h->keys[h->n];
    memset(k, 0, sizeof *k);
    memcpy(k->pk, pk, 48);
    for (int i = 0; i < 32; i++)
        k->secret[i] = (uint8_t)(h->n * 31 + i * 7 + 1);
    k->secret[0] = 0x11; /* below the group order */
    k->secret[1] = (uint8_t)h->n;
    h->n++;
    rc = sc_signer_add_validator(s, k->pk, k->secret, SC_INDEX_UNKNOWN, NULL);
    if (rc != SC_OK)
        die("sc_signer_add_validator", rc);
    return k;
}

/* Imports one step's interchange data through sc_signer_import. The
 * version check is the parser's; the core checks the root itself. */
static int signer_import_step(shost_t *h, sc_signer *s, const line_t *step, size_t from, size_t to)
{
    import_t imp[MAX_KEYS];
    int nimp;
    if (!step->version_ok || !step->has_gvr)
        return SC_ERR_ARG;
    if ((nimp = collect_maxima(from, to, imp)) < 0)
        return SC_ERR_NOMEM;
    /* A file without entries reaches no core call, so its root check is
     * the parser's (wrong_genesis_validators_root). */
    if (nimp == 0)
        return step->root_ok ? SC_OK : SC_ERR_ARG;
    for (int j = 0; j < nimp; j++) {
        skey_t *k = s_key(h, s, imp[j].pk);
        int rc = sc_signer_import(s, k->pk, step->gvr, &imp[j].wm);
        if (rc != SC_OK)
            return rc;
        /* The import dropped the key's repeat roots. */
        k->last[0].valid = k->last[1].valid = 0;
    }
    return SC_OK;
}

/* Signs op l with the vector's root inside the message. */
static int sign_op(sc_signer *s, const skey_t *k, const line_t *l, uint8_t sig[96])
{
    if (l->kind[0] == 'B') {
        sc_beacon_block_header b;
        memset(&b, 0, sizeof b);
        b.slot = l->a;
        memcpy(b.body_root, l->root, 32);
        return sc_sign_block(s, k->pk, &b, sig);
    }
    sc_attestation_data a;
    memset(&a, 0, sizeof a);
    a.slot = l->b * 32;
    memcpy(a.beacon_block_root, l->root, 32);
    a.source.epoch = l->a;
    a.target.epoch = l->b;
    return sc_sign_attestation(s, k->pk, &a, sig);
}

static result_t run_signer_mode(const mode_cfg_t *m, int verbose)
{
    result_t r = {0};
    static shost_t h;
    size_t mem_len = sc_signer_mem_size(MAX_KEYS, 0);
    void *mem = malloc(mem_len);
    /* The restart modes persist the roots: the repeat must survive. */
    int persist = m->restart_each_op;
    size_t i = 0;
    if (!mem)
        die("malloc", SC_ERR_NOMEM);
    while (i < nlines) {
        if (strcmp(lines[i].kind, "T") != 0) {
            i++;
            continue;
        }
        const line_t *t = &lines[i];
        const char *name = t->name;
        int test_ok = 1;
        memset(&h, 0, sizeof h);
        sc_signer *s = signer_start(&h, mem, mem_len, t->gvr, &m->ahead, persist);
        i++;
        while (i < nlines && strcmp(lines[i].kind, "E") != 0) {
            const line_t *step = &lines[i];
            if (strcmp(step->kind, "S") != 0) {
                i++;
                continue;
            }
            size_t from = ++i;
            while (i < nlines && is_import(&lines[i]))
                i++;
            int imported = signer_import_step(&h, s, step, from, i) == SC_OK;
            if (!imported && step->expect && step->slashable) {
                /* Allowed by the README; the rest of the test is skipped,
                 * so a partly applied import is never signed against. */
                r.slashable_skips++;
                if (verbose)
                    printf("  %s: slashable import refused, rest of test skipped\n", name);
                while (i < nlines && strcmp(lines[i].kind, "E") != 0)
                    i++;
                break;
            }
            if (imported != step->expect) {
                test_ok = 0;
                if (verbose)
                    printf("  %s: import %s, expected %s\n", name, imported ? "ok" : "refused",
                           step->expect ? "ok" : "refused");
            }
            for (; i < nlines && is_op(&lines[i]); i++) {
                const line_t *l = &lines[i];
                uint8_t sig[96], again[96];
                if (m->restart_each_op) {
                    sc_signer_wipe(s);
                    s = signer_start(&h, mem, mem_len, t->gvr, &m->ahead, persist);
                }
                skey_t *k = s_key(&h, s, l->pk);
                last_t *last = &k->last[l->kind[0] == 'B' ? 0 : 1];
                int repeat = last->valid && last->a == l->a && last->b == l->b &&
                             !memcmp(last->root, l->root, 32);
                int writes = h.writes, root_writes = h.root_writes;
                int rc = sign_op(s, k, l, sig);
                int ok = rc == SC_OK;
                r.ops++;
                if (repeat) {
                    r.repeats++;
                    if (!ok || memcmp(sig, last->sig, 96) || h.writes != writes ||
                        h.root_writes != root_writes) {
                        test_ok = 0;
                        if (verbose)
                            printf("  %s: %s(%llu,%llu) repeat -> %s, expected the same signature "
                                   "and no write\n", name, l->kind, (unsigned long long)l->a,
                                   (unsigned long long)l->b, sc_status_name(rc));
                    }
                } else if (ok == l->expect) {
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
                if (!ok)
                    continue;
                last->valid = 1;
                last->a = l->a;
                last->b = l->b;
                memcpy(last->root, l->root, 32);
                memcpy(last->sig, sig, 96);
                /* The same request once more: an exact repeat, whatever the
                 * marks say. */
                if (m->restart_each_op) {
                    sc_signer_wipe(s);
                    s = signer_start(&h, mem, mem_len, t->gvr, &m->ahead, persist);
                }
                writes = h.writes;
                root_writes = h.root_writes;
                rc = sign_op(s, k, l, again);
                r.repeats++;
                if (rc != SC_OK || memcmp(again, sig, 96) || h.writes != writes ||
                    h.root_writes != root_writes) {
                    test_ok = 0;
                    if (verbose)
                        printf("  %s: %s(%llu,%llu) sent again -> %s, expected the same signature "
                               "and no write\n", name, l->kind, (unsigned long long)l->a,
                               (unsigned long long)l->b, sc_status_name(rc));
                }
            }
        }
        sc_signer_wipe(s);
        r.writes += h.writes;
        r.tests++;
        r.tests_pass += test_ok;
        if (verbose)
            printf("eip3076 %-21s %s %s\n", m->name, test_ok ? "PASS" : "FAIL", name);
        i++;
    }
    free(mem);
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
    static const mode_cfg_t signer_modes[] = {
        {"signer", {0, 0, 0}, 0, 1},
        {"signer+window", {32, 1, 1}, 0, 1},
        {"signer+restart", {0, 0, 0}, 1, 1},
        {"signer+window+restart", {32, 1, 1}, 1, 0},
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
               "extra_refusals=%d slashable_skips=%d watermark_writes=%d\n",
               modes[m].name, r.tests, r.tests_pass, r.tests - r.tests_pass, r.ops, r.ops_match,
               r.unsafe, r.extra_refusals, r.slashable_skips, r.writes);
        if (r.tests_pass != r.tests || r.unsafe || r.tests == 0)
            bad = 1;
    }
    for (size_t m = 0; m < sizeof signer_modes / sizeof signer_modes[0]; m++) {
        result_t r = run_signer_mode(&signer_modes[m], 1);
        printf("EIP3076 mode=%s tests=%d pass=%d fail=%d ops=%d match=%d unsafe_accepts=%d "
               "extra_refusals=%d slashable_skips=%d watermark_writes=%d exact_repeats=%d\n",
               signer_modes[m].name, r.tests, r.tests_pass, r.tests - r.tests_pass, r.ops,
               r.ops_match, r.unsafe, r.extra_refusals, r.slashable_skips, r.writes, r.repeats);
        /* Every signed op was sent again, so the shortcut ran. */
        if (r.tests_pass != r.tests || r.unsafe || r.tests == 0 || r.repeats == 0)
            bad = 1;
    }
    free(lines);
    return bad;
}
