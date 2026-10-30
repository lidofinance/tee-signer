/*
 * sim.c - simulator for the slashing protection of the threshold signer.
 *
 * n signers with threshold m (default 3 and 2; SIM_CLUSTER=n/m, n up to 7)
 * run the real signer-core (signer.c, slashing.c, policy.c, ssz.c,
 * typed.c) behind the storage and clock callbacks of either deployment,
 * ported to C here line by line:
 *   - the trusted app (ta/trusted-app/signer_ta.c): one signer/state object
 *     holding the clock floor and the device mark, store_due_floor after
 *     every command, the TA clock with bounded steps (do_sync_clock);
 *   - the cloud runner (tee-signer/state/state.go,
 *     tee-signer/record/record.go, trusted-time/clock/clock.go): restart floor at
 *     clock epoch + margin, the external single-writer record (claim, cover),
 *     the Anchored clock;
 *   - the cloud runner with the mark log (slashing-log): one device mark
 *     in an external locked log (profile cloud-ext), claim at start with the
 *     sealed hint, write-once records, a raise for E+1 at slot 24, the floor
 *     with target and block bounds only, a restart that lost the local store
 *     (the log's keys come from key release, so the log still reads; the
 *     shares come back from the state copy or by import), the
 *     handover to an instance of a new image (tombstone record, a new log
 *     from the old mark); and the same log on a store whose admin can set it
 *     back (cloud-ext-mut, controls only).
 * A chain model makes honest duties; a host model turns hostile on request;
 * clocks drift and jump; signers crash at store calls, restart, roll back
 * and get cloned; fork schedule updates arrive near a fork (scenario sched,
 * sc_signer_set_schedule). An oracle checks every signature (see on_signed):
 * no slashable pair per signer or per validator, nothing past the clock
 * horizon, and no epoch signed under two fork versions by one signer.
 *
 *   sim scen [name|all] [profile|all]   named scenarios, liveness numbers
 *   sim seed FIRST COUNT [profile|all]  seeded random event streams
 *   sim run FILE...                     replay fuzz inputs (SIM_TRACE=1 logs)
 *   sim gen SEED FILE                   write the input a seed makes
 * covfuzz.c feeds sim_run_bytes with coverage feedback.
 */
#include "../tests/markformat_host.h"
#include <inttypes.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "signer_core.h"
#include "sim.h"

/* ---- chain constants (mainnet timing, Fulu-era epochs) ------------------ */

#define SPS ((uint64_t)12)
#define SPE ((uint64_t)32)
#define EPOCH_S (SPS * SPE)
#define GENESIS ((uint64_t)1606824023)
#define E0 ((uint64_t)420000)
#define SLOT0 (E0 * SPE)
#define FORK1 (E0 + 20) /* test forks, version 7 and 8 */
#define FORK2 (E0 + 300)
#define NOFORK1 UINT64_MAX /* a schedule without version 7 */
#define VEP 4096           /* epochs from E0 the fork version oracle tracks */
#define MAXK 16
#define NSIGMAX 7 /* signers: g_n of them, threshold g_m (default 2 of 3) */
#define MAXINST (2 * NSIGMAX)
#define MAXSLOTS (1u << 17)
#define QMAX 4096
#define HISTN 512
#define TA_MAX_STEP ((uint64_t)768)      /* ta/config/mainnet.conf clock_max_step */
#define ANCH_MAXAGE_MS ((uint64_t)75000) /* clock.go: MissedSyncs * DefaultInterval */
#define ANCH_MAXADV_MS ((uint64_t)75000)

__attribute__((weak)) void sim_feature(uint32_t f) { (void)f; }

/* Cluster size and signing threshold. They stay set across runs (run_reset
 * clears g only); sim_set_cluster changes them. */
static int g_n = 3, g_m = 2;
static uint8_t full_mask(void) { return (uint8_t)((1u << g_n) - 1); }

int sim_set_cluster(int n, int m)
{
    if (n < 1 || n > NSIGMAX || m < 1 || m > n)
        return -1;
    g_n = n;
    g_m = m;
    return 0;
}

/* ---- deployment profiles ------------------------------------------------ */

enum { CLK_TA, CLK_ANCH };

typedef struct {
    const char *name;
    uint32_t scope;
    sc_commit_ahead ahead;
    uint64_t mea;        /* max_epochs_ahead */
    int persist_marks;   /* per-validator marks go to the platform store */
    int floor;           /* cloud restart floor at load */
    uint64_t margin;     /* floor margin */
    int guard;           /* external single-writer record (clone guard) */
    uint64_t guard_ahead;
    int clock;
    int rollback;        /* storage rollback is in this profile's threat model */
    int clone;           /* a second instance from the same storage is too */
    int torn;            /* the store can tear at byte level */
    int xlog;            /* device mark in the external locked log (slashing-log) */
    int xlog_mutable;    /* the log's admin can set it back (a mutable store, not WORM) */
} prof_t;

#define PV SC_MARKS_PER_VALIDATOR
#define DV SC_MARKS_PER_DEVICE
static const prof_t PROFS[] = {
    /* Board: ta/config/mainnet.conf (commit_ahead 32,0,0; max_epochs_ahead 1). */
    {"ta", DV, {32, 0, 0}, 1, 1, 0, 0, 0, 0, CLK_TA, 0, 0, 0, 0, 0},
    /* Board with the older booking of 2 target epochs. */
    {"ta-b2", DV, {32, 0, 2}, 1, 1, 0, 0, 0, 0, CLK_TA, 0, 0, 0, 0, 0},
    /* Cloud runner as built for Nitro/Azure/GCP (chain.json 32,2,2, max 2),
     * floor only, margin 3, record with ahead 0. */
    {"cloud", PV, {32, 2, 2}, 2, 0, 1, 3, 1, 0, CLK_ANCH, 1, 1, 0, 0, 0},
    /* Cloud runner with cloud/chain.testnet.json (32,1,1, max 1), margin 2. */
    {"cloud-t", PV, {32, 1, 1}, 1, 0, 1, 2, 1, 0, CLK_ANCH, 1, 1, 0, 0, 0},
    /* Cloud runner with -record none (GCP and Azure today): clones are out
     * of its threat model, rollback is not. */
    {"cloud-norec", PV, {32, 2, 2}, 2, 0, 1, 3, 0, 0, CLK_ANCH, 1, 0, 0, 0, 0},
    /* Persisted per-validator marks only (-persist-watermarks
     * -restart-floor=false): safe only on rollback-proof storage. */
    {"pv-persist", PV, {32, 1, 1}, 1, 1, 0, 0, 0, 0, CLK_ANCH, 0, 0, 0, 0, 0},
    /* Cloud runner with -mark-store (the locked append-only log): one device
     * mark in the log, raised for E+1 at slot 24 of E; the restart floor
     * keeps target and block bounds only; the log refuses clones. The
     * store admin cannot set the log back (WORM). */
    {"cloud-ext", DV, {32, 0, 1}, 2, 0, 1, 3, 0, 0, CLK_ANCH, 1, 1, 0, 1, 0},
    /* The same on a store whose admin can set the record back (a DynamoDB
     * item, a Firestore document): outside the design, for the controls. */
    {"cloud-ext-mut", DV, {32, 0, 1}, 2, 0, 1, 3, 0, 0, CLK_ANCH, 1, 1, 0, 1, 1},
};
#define NPROF (int)(sizeof PROFS / sizeof PROFS[0])
/* Fuzz inputs pick among the profiles of the design; cloud-ext-mut, the
 * last one, is for the controls and by name only (a mutable store is not
 * the design, and the fuzzer finds its rollback on its own). */
#define NPROF_FUZZ (NPROF - 1)

static int prof_by_name(const char *n)
{
    for (int i = 0; i < NPROF; i++)
        if (!strcmp(PROFS[i].name, n))
            return i;
    return -1;
}

/* ---- small helpers ------------------------------------------------------- */

static uint64_t splitmix(uint64_t *s)
{
    uint64_t z = (*s += 0x9e3779b97f4a7c15ull);
    z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ull;
    z = (z ^ (z >> 27)) * 0x94d049bb133111ebull;
    return z ^ (z >> 31);
}

static uint64_t mix(uint64_t x)
{
    uint64_t s = x;
    return splitmix(&s);
}

static void put64(uint8_t *p, uint64_t v)
{
    for (int i = 0; i < 8; i++)
        p[i] = (uint8_t)(v >> (8 * i));
}

static uint64_t get64(const uint8_t *p)
{
    uint64_t v = 0;
    for (int i = 7; i >= 0; i--)
        v = (v << 8) | p[i];
    return v;
}

static void root_of(uint64_t id, uint8_t tag, uint8_t out[32])
{
    memset(out, 0, 32);
    put64(out, id);
    out[8] = tag;
}

static uint64_t epoch_of_s(uint64_t unix_s) { return unix_s <= GENESIS ? 0 : (unix_s - GENESIS) / EPOCH_S; }
static uint64_t slot_ms(uint64_t slot) { return (GENESIS + slot * SPS) * 1000; }

/* ---- input source: fuzz bytes or a seeded stream -------------------------- */

typedef struct {
    const uint8_t *p;
    size_t n, i;
    uint64_t rng;
    int random;
} src_t;

static uint8_t rd8(src_t *s)
{
    if (s->random)
        return (uint8_t)(splitmix(&s->rng) >> 24);
    return s->i < s->n ? s->p[s->i++] : 0;
}

static int src_done(const src_t *s) { return !s->random && s->i >= s->n; }

/* ---- chain model ---------------------------------------------------------- */

typedef struct {
    uint64_t *ids;  /* block id per slot (index slot - SLOT0), 0 = empty slot */
    uint64_t jep, jid; /* justified checkpoint seen from the head */
    int fin;        /* justifies the previous epoch at every epoch start */
} chain_t;

static uint64_t g_ids[2][MAXSLOTS];

/* ---- requests --------------------------------------------------------------- */

enum { R_ATT, R_BLK, R_RANDAO, R_ROOT };

typedef struct {
    uint8_t kind, key, honest, vc, dom, mask, forged, pad;
    uint64_t due_ms, epoch;
    sc_attestation_data a;
    sc_beacon_block_header b;
    uint8_t obj[32];
} req_t;

typedef struct {
    int on, alt, lag;
    uint64_t next;
} vc_t;

/* ---- signer storage, record, instances ------------------------------------- */

typedef struct {
    int has_state; /* TA signer/state: clock floor, last step, device mark */
    uint64_t floor, last_step;
    uint8_t mark[SC_WATERMARK_ENCODED_LEN];
    uint8_t has_wm[MAXK]; /* per-validator marks; 2 = unreadable */
    uint8_t wm[MAXK][SC_WATERMARK_ENCODED_LEN];
    uint64_t x_hint; /* mark log: the version this signer wrote last (sealed hint) */
} disk_t;

typedef struct {
    int exists;
    uint64_t version, owner, epoch;
} record_t;

/* The mark log of one signer (slashing-log): the newest record, and the
 * history an admin of a mutable store could restore. */
#define XHIST 64
typedef struct {
    uint64_t version, owner;
    sc_watermark mark;
    uint64_t hv[XHIST];
    sc_watermark hm[XHIST];
    uint32_t hn;
} xlog_t;

enum { ACT_OK, ACT_BEFORE, ACT_LANDED, ACT_LANDED_ERR, ACT_FAIL, ACT_TORN, ACT_N };

typedef struct {
    int used, alive, idx, clone;
    const prof_t *p;
    void *mem;
    sc_signer *s;
    disk_t disk;
    uint8_t loaded[MAXK];
    int nloaded;
    uint64_t restart_at; /* slot to boot again after a crash; 0 = none */
    /* local counter (TA secure timer, enclave monotonic clock) */
    uint64_t ctr_base_ms, ctr_real0_ms;
    uint32_t rate_ppm;
    /* TA clock and state (signer_ta.c) */
    int ta_loaded, ta_floor_due, ta_voted, ta_vote_in_cmd;
    uint64_t ta_base, ta_base_ms, ta_floor, ta_last_step, ta_vote_target;
    sc_watermark ta_mark;
    /* Anchored clock (clock.go) */
    int a_has;
    uint64_t a_reading_ms, a_fetched_ms, a_highest_ms;
    /* clone guard (record.go) */
    uint64_t g_owner, g_version, g_epoch, g_prior;
    int g_has_prior, g_lost;
    /* mark log (markstore.MarkLog) */
    uint64_t x_owner, x_version;
    sc_watermark x_mark;
    int x_lost, x_claimed;
    int old_gen; /* an instance of the image before a handover: its log is xold */
    /* crash plan */
    int crash_cd, crash_mode, fail_n, down_slots;
    /* the clock value the core read last (for the clock oracle) */
    uint64_t last_now;
    int last_now_ok;
    /* the fork version of the request call_sign sends (for the fork version oracle) */
    uint8_t sign_ver;
    /* what this incarnation signed, for refusal reasons */
    uint64_t ms[MAXK], mt[MAXK], mb[MAXK];
    uint8_t hv[MAXK], hb[MAXK];
    /* epochs lost after the last restart */
    uint8_t recovering[MAXK];
    uint64_t lost[MAXK];
    /* storage writes in the current real epoch */
    uint64_t wr_epoch, wr_n;
} inst_t;

/* ---- oracle ------------------------------------------------------------------ */

typedef struct {
    uint64_t s, t, r; /* source, target, root; for blocks s = slot */
} vote_t;

typedef struct {
    vote_t *v, *b;
    uint32_t nv, cv, nb, cb;
    uint64_t maxs, maxt, maxb;
    int hv, hb;
} hist_t;

typedef struct {
    uint64_t r8, s, t;
    uint32_t gen;
    uint8_t key, kind, mask, pad;
} tent_t;

#define TBITS 18
static tent_t g_tab[1u << TBITS];
static uint32_t g_gen;

/* ---- the run -------------------------------------------------------------------- */

static struct {
    const prof_t *prof[NSIGMAX];
    /* Epoch of fork version 7 in each signer's schedule, NOFORK1 for none.
     * A boot uses it; a schedule update the core takes changes it. */
    uint64_t f1[NSIGMAX];
    int nk;
    int allow_rollback, allow_clone, allow_torn, torn_cut;
    uint64_t max_slots, start_slot;
    uint64_t cur, now_ms;
    int64_t host_off_ms;
    chain_t canon, alt;
    int alt_on, miss_n;
    uint64_t nextid;
    vc_t vc[2];
    req_t q[QMAX];
    int qn;
    req_t hist[HISTN];
    uint32_t histn;
    uint64_t delay_ms;
    int delay_n, reorder, dup, route_n, extras;
    uint64_t prop_div; /* one slot in prop_div has a proposer among our keys */
    uint8_t route_mask;
    uint64_t raise_src[MAXK];
    inst_t inst[MAXINST];
    int prim[NSIGMAX], clon[NSIGMAX];
    disk_t snap[NSIGMAX];
    int has_snap[NSIGMAX];
    record_t rec[NSIGMAX];
    xlog_t xlog[NSIGMAX], xsnap[NSIGMAX];
    int has_xsnap[NSIGMAX];
    xlog_t xold[NSIGMAX]; /* the log of the image before a handover */
    int handed[NSIGMAX];
    uint64_t store_down_until[NSIGMAX];
    int stale_n[NSIGMAX], xsquat[NSIGMAX];
    int allow_stale;
    uint32_t rate_ppm[NSIGMAX];
    int64_t clk_err_ms[NSIGMAX];
    uint64_t sync_block_until[NSIGMAX];
    int ta_hostile[NSIGMAX];
    hist_t sig[NSIGMAX][MAXK], val[MAXK];
    /* Fork version oracle: the version each signer signed each epoch under
     * (0: nothing signed yet, 0xff: none of 6, 7, 8). */
    uint8_t ver[NSIGMAX][VEP];
    uint64_t tab_used;
    jmp_buf *jb;
    inst_t *cur_inst;
    uint64_t rng;
    int stop, trace;
    sim_metrics m;
} g;

static uint8_t g_pk[MAXK][SC_PUBKEY_LEN];

#define TRACE(...)                                                                  \
    do {                                                                            \
        if (g.trace)                                                                \
            printf(__VA_ARGS__);                                                    \
    } while (0)

static uint64_t rnd(void) { return splitmix(&g.rng); }
static uint64_t cur_epoch(void) { return g.cur / SPE; }
static uint64_t real_epoch(void) { return epoch_of_s(g.now_ms / 1000); }

/* ---- oracle data ----------------------------------------------------------------- */

static void hist_add(vote_t **a, uint32_t *n, uint32_t *c, vote_t x)
{
    if (*n == *c) {
        *c = *c ? *c * 2 : 64;
        *a = realloc(*a, *c * sizeof **a);
        if (!*a)
            abort();
    }
    (*a)[(*n)++] = x;
}

static void hist_free(hist_t *h)
{
    free(h->v);
    free(h->b);
    memset(h, 0, sizeof *h);
}

/* A vote in h that (s, t, r) makes slashable with (EIP-3076: double vote or
 * surround), or NULL. Equal roots are the same message. */
static const vote_t *vote_conflict(const hist_t *h, uint64_t s, uint64_t t, uint64_t r)
{
    for (uint32_t i = 0; i < h->nv; i++) {
        const vote_t *o = &h->v[i];
        if (o->r == r)
            continue;
        if (o->t == t || (s < o->s && o->t < t) || (o->s < s && t < o->t))
            return o;
    }
    return NULL;
}

static const vote_t *block_conflict(const hist_t *h, uint64_t slot, uint64_t r)
{
    for (uint32_t i = 0; i < h->nb; i++)
        if (h->b[i].s == slot && h->b[i].r != r)
            return &h->b[i];
    return NULL;
}

static void hist_vote(hist_t *h, uint64_t s, uint64_t t, uint64_t r)
{
    vote_t x = {s, t, r};
    hist_add(&h->v, &h->nv, &h->cv, x);
    if (!h->hv || s > h->maxs)
        h->maxs = s;
    if (!h->hv || t > h->maxt)
        h->maxt = t;
    h->hv = 1;
}

static void hist_block(hist_t *h, uint64_t slot, uint64_t r)
{
    vote_t x = {slot, 0, r};
    hist_add(&h->b, &h->nb, &h->cb, x);
    if (!h->hb || slot > h->maxb)
        h->maxb = slot;
    h->hb = 1;
}

static tent_t *tab_get(uint8_t key, uint8_t kind, uint64_t r8, int create)
{
    uint64_t h = (r8 ^ ((uint64_t)key << 56) ^ ((uint64_t)kind << 48)) * 0x9e3779b97f4a7c15ull;
    uint32_t i = (uint32_t)(h >> (64 - TBITS));
    for (;;) {
        tent_t *e = &g_tab[i];
        if (e->gen != g_gen) {
            if (!create)
                return NULL;
            if (g.tab_used > (3u << TBITS) / 4) {
                g.stop = 1; /* table full: end the run */
                return NULL;
            }
            memset(e, 0, sizeof *e);
            e->gen = g_gen;
            e->r8 = r8;
            e->key = key;
            e->kind = kind;
            g.tab_used++;
            return e;
        }
        if (e->r8 == r8 && e->key == key && e->kind == kind)
            return e;
        i = (i + 1) & ((1u << TBITS) - 1);
    }
}

static void violation(const char *what, int idx, int key, const char *fmt, ...)
    __attribute__((format(printf, 4, 5)));

static void violation(const char *what, int idx, int key, const char *fmt, ...)
{
    char buf[400];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    if (!g.m.first_violation[0])
        snprintf(g.m.first_violation, sizeof g.m.first_violation,
                 "%s: signer %d key %d at slot +%" PRIu64 " (epoch +%" PRIu64 "): %s", what, idx,
                 key, g.cur - SLOT0, cur_epoch() - E0, buf);
    TRACE("VIOLATION %s signer %d key %d: %s\n", what, idx, key, buf);
}

/* ---- local counters and clocks ----------------------------------------------------- */

static uint64_t local_ms(const inst_t *in)
{
    return in->ctr_base_ms + (g.now_ms - in->ctr_real0_ms) * in->rate_ppm / 1000000u;
}

static void rebase_counter(inst_t *in, uint32_t rate)
{
    in->ctr_base_ms = local_ms(in);
    in->ctr_real0_ms = g.now_ms;
    in->rate_ppm = rate;
}

/* signer_ta.c clock_time */
static uint64_t ta_time(const inst_t *in)
{
    uint64_t ms = local_ms(in);
    if (ms < in->ta_base_ms)
        ms = in->ta_base_ms;
    return in->ta_base + (ms - in->ta_base_ms) / 1000;
}

/* clock.go Anchored.Refresh: the reading is real time when the answer
 * arrives, behind by the HTTP Date resolution and the round trip, plus the
 * error of the source quorum. */
static void anch_refresh(inst_t *in)
{
    if (g.sync_block_until[in->idx] > g.cur)
        return;
    in->a_has = 1;
    in->a_reading_ms = g.now_ms - rnd() % 1000 + (uint64_t)g.clk_err_ms[in->idx];
    in->a_fetched_ms = local_ms(in);
}

/* clock.go Anchored.Now plus state.go Hooks.Now (whole seconds). */
static int anch_now(inst_t *in, uint64_t *out)
{
    uint64_t age, t;
    if (!in->a_has)
        return -1;
    age = local_ms(in) - in->a_fetched_ms;
    if (age >= ANCH_MAXAGE_MS)
        return -1;
    t = in->a_reading_ms + (age < ANCH_MAXADV_MS ? age : ANCH_MAXADV_MS);
    if (t < in->a_highest_ms)
        t = in->a_highest_ms;
    in->a_highest_ms = t;
    *out = t / 1000;
    return 0;
}

/* ---- storage actions and crashes ----------------------------------------------------- */

static void count_write(inst_t *in)
{
    uint64_t e = real_epoch();
    g.m.writes_total++;
    if (e != in->wr_epoch) {
        in->wr_epoch = e;
        in->wr_n = 0;
    }
    in->wr_n++;
    if (in->wr_n > g.m.writes_max)
        g.m.writes_max = in->wr_n;
}

static int store_act(inst_t *in)
{
    g.m.store_calls++;
    if (in->fail_n > 0) {
        in->fail_n--;
        return ACT_FAIL;
    }
    if (in->crash_cd > 0 && --in->crash_cd == 0) {
        int m = in->crash_mode;
        in->crash_mode = 0;
        sim_feature(0x1000u + (uint32_t)m);
        return m;
    }
    return ACT_OK;
}

static void crash_now(inst_t *in)
{
    (void)in;
    if (!g.jb)
        abort();
    longjmp(*g.jb, 1);
}

/* ---- trusted app storage and clock (signer_ta.c) -------------------------------------- */

/* state_write: one object, written atomically by OP-TEE. */
static int ta_state_write(inst_t *in, uint64_t floor, uint64_t last, const sc_watermark *mark)
{
    int act = store_act(in);
    if (act == ACT_TORN)
        act = (rnd() & 1) ? ACT_BEFORE : ACT_LANDED;
    if (act == ACT_BEFORE)
        crash_now(in);
    if (act == ACT_FAIL)
        return SC_ERR_STORAGE;
    in->disk.has_state = 1;
    in->disk.floor = floor;
    in->disk.last_step = last;
    test_watermark_encode(mark, in->disk.mark);
    count_write(in);
    TRACE("  write signer %d state: floor epoch +%" PRIu64 " step %s, mark src +%" PRId64
          " tgt +%" PRId64 " blk +%" PRId64 " (n=%" PRIu64 " this epoch)\n",
          in->idx, epoch_of_s(floor) - E0, last == floor ? "yes" : "no",
          (int64_t)mark->source_epoch - (int64_t)E0, (int64_t)mark->target_epoch - (int64_t)E0,
          (int64_t)(mark->block_slot / SPE) - (int64_t)E0, in->wr_n);
    if (act == ACT_LANDED)
        crash_now(in);
    if (act == ACT_LANDED_ERR)
        return SC_ERR_STORAGE;
    in->ta_floor = floor;
    in->ta_last_step = last;
    in->ta_mark = *mark;
    in->ta_floor_due = 0;
    return SC_OK;
}

/* clock_load, at the first command of a new instance. */
static int ta_clock_load(inst_t *in)
{
    sc_watermark mark;
    if (in->ta_loaded)
        return SC_OK;
    if (!in->disk.has_state ||
        test_watermark_decode(in->disk.mark, SC_WATERMARK_ENCODED_LEN, &mark) != SC_OK ||
        in->disk.last_step > in->disk.floor)
        return SC_ERR_STORAGE;
    in->ta_base = in->disk.floor;
    in->ta_base_ms = local_ms(in);
    in->ta_floor = in->disk.floor;
    in->ta_last_step = in->disk.last_step;
    in->ta_mark = mark;
    in->ta_loaded = 1;
    return SC_OK;
}

/* clock_now */
static int ta_clock_now(inst_t *in, uint64_t *now)
{
    int rc = ta_clock_load(in);
    if (rc != SC_OK)
        return rc;
    *now = ta_time(in);
    if (*now >= in->ta_floor + EPOCH_S)
        in->ta_floor_due = 1;
    return SC_OK;
}

static void ta_note_vote(inst_t *in, uint64_t target)
{
    if (in->ta_voted && target < in->ta_vote_target)
        return;
    in->ta_vote_target = target;
    in->ta_voted = 1;
    in->ta_vote_in_cmd = 1;
}

/* store_due_floor, after every command */
static void ta_store_due_floor(inst_t *in)
{
    int vote = in->ta_vote_in_cmd;
    uint64_t now, epoch;
    in->ta_vote_in_cmd = 0;
    if (!in->ta_floor_due || !in->ta_loaded)
        return;
    now = ta_time(in);
    if (in->nloaded) {
        if (!vote && !(now >= in->ta_floor && (now - in->ta_floor) / EPOCH_S >= 2))
            return;
        epoch = epoch_of_s(now);
        if (in->ta_voted && in->ta_vote_target > epoch)
            epoch = in->ta_vote_target;
        sc_signer_cover_epoch(in->s, epoch);
    }
    if (in->ta_floor_due)
        ta_state_write(in, now, in->ta_last_step, &in->ta_mark);
}

/* do_sync_clock */
static void ta_sync(inst_t *in, uint64_t t)
{
    uint64_t now, want, step;
    if (ta_clock_now(in, &now) != SC_OK)
        return;
    if (t > now && t - now >= SPS) {
        want = t - now;
        if (in->ta_last_step && now - in->ta_last_step < TA_MAX_STEP)
            return;
        step = want < TA_MAX_STEP ? want : TA_MAX_STEP;
        if (ta_state_write(in, now + step, now + step, &in->ta_mark) != SC_OK)
            return;
        in->ta_base = now + step;
        in->ta_base_ms = local_ms(in);
    }
}

/* ---- clone guard (record.go) ---------------------------------------------------------- */

static void guard_claim(inst_t *in)
{
    record_t *r = &g.rec[in->idx];
    in->g_owner = rnd() | 1;
    in->g_lost = 0;
    in->g_has_prior = 0;
    in->g_prior = in->g_epoch = 0;
    if (r->exists) {
        in->g_prior = in->g_epoch = r->epoch;
        in->g_has_prior = 1;
    } else {
        r->exists = 1;
        r->version = 0;
        r->epoch = 0;
    }
    r->version++;
    r->owner = in->g_owner;
    in->g_version = r->version;
    g.m.record_writes++;
}

static int guard_cover(inst_t *in, uint64_t e)
{
    record_t *r = &g.rec[in->idx];
    uint64_t target;
    int act;
    if (in->g_lost)
        return -1;
    if (e <= in->g_epoch)
        return 0;
    target = e + in->p->guard_ahead;
    act = store_act(in);
    if (act == ACT_TORN)
        act = ACT_BEFORE; /* a conditional write lands whole or not at all */
    if (act == ACT_BEFORE)
        crash_now(in);
    if (act == ACT_FAIL)
        return -1;
    if (r->version != in->g_version) {
        in->g_lost = 1; /* claimed by another instance */
        sim_feature(0x1100);
        return -1;
    }
    r->version++;
    r->owner = in->g_owner;
    r->epoch = target;
    g.m.record_writes++;
    if (act == ACT_LANDED)
        crash_now(in);
    /* ACT_LANDED_ERR: the reply was lost; record.go reads the record back,
     * finds its own write and carries on. */
    in->g_version = r->version;
    in->g_epoch = target;
    return 0;
}

/* ---- mark log (slashing-log/marklog.go) --------------------------------------------- */

static int xlog_down(int idx) { return g.store_down_until[idx] > g.cur; }

static void xlog_push(xlog_t *x)
{
    x->hv[x->hn % XHIST] = x->version;
    x->hm[x->hn % XHIST] = x->mark;
    x->hn++;
}

/* A conditional create at the next free version. 0, or -1 (store down,
 * write failed, or the version was taken by another instance: lost). The
 * crash plan can stop the instance before or after the write lands. */
/* The log an instance writes: its signer's, or the old image's after a
 * handover. */
static xlog_t *xlog_of(inst_t *in) { return in->old_gen ? &g.xold[in->idx] : &g.xlog[in->idx]; }

static int xlog_write(inst_t *in, const sc_watermark *wm, int may_crash)
{
    xlog_t *x = xlog_of(in);
    int act;
    if (in->x_lost)
        return -1;
    if (xlog_down(in->idx))
        return -1;
    act = may_crash ? store_act(in) : ACT_OK;
    if (act == ACT_TORN)
        act = ACT_BEFORE; /* one object, created whole or not at all */
    if (act == ACT_BEFORE)
        crash_now(in);
    if (act == ACT_FAIL)
        return -1;
    if (x->version != in->x_version) {
        /* The name is taken by a valid record of another owner. */
        in->x_lost = 1;
        g.m.xlog_lost++;
        sim_feature(0x1400);
        return -1;
    }
    /* Objects someone put under future names cost a skip each. */
    x->version += 1 + (uint64_t)g.xsquat[in->idx];
    g.xsquat[in->idx] = 0;
    x->owner = in->x_owner;
    x->mark = *wm;
    xlog_push(x);
    g.m.xlog_writes++;
    g.m.record_writes++;
    in->disk.x_hint = x->version;
    if (act == ACT_LANDED)
        crash_now(in);
    /* ACT_LANDED_ERR: the reply was lost; Append reads the name back, finds
     * its own record and carries on. */
    in->x_version = x->version;
    in->x_mark = *wm;
    return 0;
}

/* Claim: read the newest record (an older one on a stale read, where the
 * run allows it), check the hint, write a claim record. -1: the runner
 * does not start (it is retried at the next slot). */
static int xlog_claim(inst_t *in)
{
    xlog_t *x = xlog_of(in);
    uint64_t ver = x->version;
    sc_watermark mark = x->mark;
    in->x_owner = rnd() | 1;
    in->x_lost = 0;
    in->x_claimed = 0;
    if (xlog_down(in->idx)) {
        g.m.xlog_start_refused++;
        return -1;
    }
    if (g.stale_n[in->idx] > 0 && g.allow_stale && x->hn > 1) {
        uint32_t back = (uint32_t)g.stale_n[in->idx];
        uint32_t i = back < x->hn ? x->hn - 1 - back : 0;
        if (x->hn - i <= XHIST) {
            ver = x->hv[i % XHIST];
            mark = x->hm[i % XHIST];
        }
        g.stale_n[in->idx] = 0;
        sim_feature(0x1401);
    }
    if (in->disk.x_hint > ver) {
        /* marklog.go Claim: the hint says this runner wrote more. */
        g.m.xlog_start_refused++;
        sim_feature(0x1402);
        return -1;
    }
    in->x_version = ver;
    in->x_mark = mark;
    if (xlog_write(in, &mark, 0) != 0) {
        g.m.xlog_start_refused++;
        return -1;
    }
    in->x_claimed = 1;
    return 0;
}

/* Raise the device mark for the next epoch at slot 24 (main.go raiseMarks). */
static void inst_die(inst_t *in, int down_slots);
static void xlog_preraise(inst_t *in)
{
    jmp_buf jb;
    if (!in->alive || !in->nloaded || !in->x_claimed)
        return;
    g.jb = &jb;
    if (setjmp(jb)) {
        g.jb = NULL;
        inst_die(in, in->down_slots);
        return;
    }
    sc_signer_cover_epoch(in->s, cur_epoch() + 1);
    g.jb = NULL;
}

/* ---- host callbacks for signer-core --------------------------------------------------- */

static int key_of(const uint8_t pk[48])
{
    for (int k = 0; k < g.nk; k++)
        if (!memcmp(pk, g_pk[k], 48))
            return k;
    abort();
}

static int cb_now(void *ctx, uint64_t *t)
{
    inst_t *in = ctx;
    int rc;
    if (in->p->clock == CLK_TA)
        rc = ta_clock_now(in, t) == SC_OK ? 0 : -1;
    else
        rc = anch_now(in, t);
    in->last_now_ok = rc == 0;
    if (rc == 0)
        in->last_now = *t;
    return rc == 0 ? SC_OK : SC_ERR_CLOCK;
}

/* state.go LoadDeviceMark with the floor: target and block bounds only; the
 * source bound is the log's. */
static void floor_merge_tb(sc_watermark *wm, uint64_t f)
{
    uint64_t last = (f + 1) * SPE - 1;
    if (!(wm->flags & SC_WM_HAS_BLOCK) || last > wm->block_slot)
        wm->block_slot = last;
    if (!(wm->flags & SC_WM_HAS_ATTESTATION)) {
        wm->source_epoch = 0;
        wm->target_epoch = f;
    } else if (f > wm->target_epoch) {
        wm->target_epoch = f;
    }
    wm->flags |= SC_WM_HAS_BLOCK | SC_WM_HAS_ATTESTATION;
}

static int cb_load_dev(void *ctx, sc_watermark *out)
{
    inst_t *in = ctx;
    if (in->p->xlog) {
        sc_watermark wm = in->x_mark;
        uint64_t now;
        if (!in->x_claimed)
            return SC_ERR_STORAGE;
        if (in->p->floor) {
            if (anch_now(in, &now) != 0)
                return SC_ERR_STORAGE;
            floor_merge_tb(&wm, epoch_of_s(now) + in->p->margin);
        }
        *out = wm;
        return SC_OK;
    }
    if (ta_clock_load(in) != SC_OK)
        return SC_ERR_STORAGE;
    *out = in->ta_mark;
    return SC_OK;
}

static int cb_store_dev(void *ctx, const sc_watermark *wm)
{
    inst_t *in = ctx;
    uint64_t now;
    if (in->p->xlog)
        return xlog_write(in, wm, 1) == 0 ? SC_OK : SC_ERR_STORAGE;
    if (!in->ta_loaded)
        return SC_ERR_STORAGE;
    now = ta_time(in);
    return ta_state_write(in, now > in->ta_floor ? now : in->ta_floor, in->ta_last_step, wm);
}

/* state.go FloorWatermark and Merge */
static void floor_merge(sc_watermark *wm, uint64_t f)
{
    uint64_t last = (f + 1) * SPE - 1;
    if (!(wm->flags & SC_WM_HAS_BLOCK) || last > wm->block_slot)
        wm->block_slot = last;
    if (!(wm->flags & SC_WM_HAS_ATTESTATION)) {
        wm->source_epoch = f;
        wm->target_epoch = f;
    } else {
        if (f > wm->source_epoch)
            wm->source_epoch = f;
        if (f > wm->target_epoch)
            wm->target_epoch = f;
    }
    wm->flags |= SC_WM_HAS_BLOCK | SC_WM_HAS_ATTESTATION;
}

/* state.go LoadWatermark */
static int cb_load_wm(void *ctx, const uint8_t pk[48], sc_watermark *out)
{
    inst_t *in = ctx;
    int k = key_of(pk), found = 0;
    sc_watermark wm;
    memset(&wm, 0, sizeof wm);
    if (in->p->persist_marks && in->disk.has_wm[k]) {
        if (in->disk.has_wm[k] != 1 ||
            test_watermark_decode(in->disk.wm[k], SC_WATERMARK_ENCODED_LEN, &wm) != SC_OK)
            return SC_ERR_STORAGE;
        found = 1;
    }
    if (in->p->floor) {
        uint64_t now;
        if (anch_now(in, &now) != 0)
            return SC_ERR_STORAGE;
        floor_merge(&wm, epoch_of_s(now) + in->p->margin);
        found = 1;
    }
    if (in->p->guard && in->g_has_prior) {
        floor_merge(&wm, in->g_prior);
        found = 1;
    }
    if (!found)
        return SC_ERR_UNKNOWN_VALIDATOR;
    *out = wm;
    return SC_OK;
}

/* state.go StoreWatermark */
static int cb_store_wm(void *ctx, const uint8_t pk[48], const sc_watermark *wm)
{
    inst_t *in = ctx;
    int k = key_of(pk), act;
    uint8_t enc[SC_WATERMARK_ENCODED_LEN];
    if (in->p->guard) {
        uint64_t e = 0;
        if (wm->flags & SC_WM_HAS_ATTESTATION)
            e = wm->source_epoch > wm->target_epoch ? wm->source_epoch : wm->target_epoch;
        if ((wm->flags & SC_WM_HAS_BLOCK) && wm->block_slot / SPE > e)
            e = wm->block_slot / SPE;
        if (guard_cover(in, e) != 0)
            return SC_ERR_STORAGE;
    }
    if (!in->p->persist_marks)
        return SC_OK;
    act = store_act(in);
    if (act == ACT_TORN && !(g.allow_torn || in->p->torn))
        act = (rnd() & 1) ? ACT_BEFORE : ACT_LANDED;
    if (act == ACT_BEFORE)
        crash_now(in);
    if (act == ACT_FAIL)
        return SC_ERR_STORAGE;
    test_watermark_encode(wm, enc);
    if (act == ACT_TORN) {
        size_t cut = g.torn_cut ? (size_t)g.torn_cut : 1 + rnd() % (SC_WATERMARK_ENCODED_LEN - 1);
        if (!in->disk.has_wm[k])
            memset(in->disk.wm[k], 0, SC_WATERMARK_ENCODED_LEN);
        memcpy(in->disk.wm[k], enc, cut);
        in->disk.has_wm[k] = 1;
        count_write(in);
        crash_now(in);
    }
    memcpy(in->disk.wm[k], enc, sizeof enc);
    in->disk.has_wm[k] = 1;
    count_write(in);
    if (act == ACT_LANDED)
        crash_now(in);
    return act == ACT_LANDED_ERR ? SC_ERR_STORAGE : SC_OK;
}

/* ---- signer config --------------------------------------------------------------------- */

static void gvr_of(uint8_t out[32])
{
    for (int i = 0; i < 32; i++)
        out[i] = (uint8_t)(0x4b + i);
}

/* f1: the epoch of version 7 (FORK1 on the chain), or NOFORK1 for a signer
 * that did not upgrade. It stays below FORK2. */
static void make_cfg(sc_config *c, const prof_t *p, uint64_t f1)
{
    static const struct {
        uint64_t epoch;
        uint8_t v;
    } forks[] = {{74240, 1}, {144896, 2}, {194048, 3}, {269568, 4}, {364032, 5}, {411392, 6},
                 {FORK1, 7}, {FORK2, 8}};
    memset(c, 0, sizeof *c);
    gvr_of(c->genesis_validators_root);
    for (size_t i = 0; i < sizeof forks / sizeof forks[0]; i++) {
        uint64_t epoch = forks[i].epoch;
        if (epoch == FORK1) {
            if (f1 == NOFORK1)
                continue; /* this signer did not upgrade */
            epoch = f1;
        }
        c->forks[c->fork_count].epoch = epoch;
        c->forks[c->fork_count].version[0] = forks[i].v;
        c->fork_count++;
    }
    c->voluntary_exit_fork_version[0] = 3;
    c->genesis_time = GENESIS;
    c->seconds_per_slot = SPS;
    c->slots_per_epoch = SPE;
    c->max_epochs_ahead = p->mea;
    memset(c->fee_recipients[0], 0x11, 20);
    c->fee_recipient_count = 1;
    c->gas_limit_min = 30000000;
    c->gas_limit_max = 60000000;
    c->registration_max_future_seconds = 3600;
    c->commit_ahead = p->ahead;
    c->mark_scope = p->scope;
}

static void share_for(int idx, int k, uint8_t sk[32])
{
    for (int i = 0; i < 32; i++)
        sk[i] = (uint8_t)(idx * 71 + k * 13 + i * 7 + 1);
    sk[0] = 0x11;
}

/* ---- instances --------------------------------------------------------------------------- */

static void inst_free(inst_t *in)
{
    if (in->s)
        sc_signer_wipe(in->s);
    free(in->mem);
    in->mem = NULL;
    in->s = NULL;
}

/* Loads the validators not loaded yet; a failure (clock, storage) is retried
 * at the next slot, as a runner the host restarts would. */
static void inst_load(inst_t *in)
{
    for (int k = 0; k < g.nk; k++) {
        uint8_t sk[32];
        int rc;
        if (in->loaded[k])
            continue;
        share_for(in->idx, k, sk);
        rc = sc_signer_add_validator(in->s, g_pk[k], sk, 1000 + (uint64_t)k, NULL);
        sim_feature(0x1200u + (uint32_t)rc);
        if (rc == SC_OK) {
            in->loaded[k] = 1;
            in->nloaded++;
        }
    }
}

static void inst_boot(inst_t *in)
{
    sc_config cfg;
    sc_host_ops ops;
    size_t sz = sc_signer_mem_size(MAXK, 8);
    inst_free(in);
    make_cfg(&cfg, in->p, g.f1[in->idx]);
    memset(&ops, 0, sizeof ops);
    ops.ctx = in;
    ops.now = cb_now;
    ops.load_watermark = cb_load_wm;
    ops.store_watermark = cb_store_wm;
    ops.load_device_mark = cb_load_dev;
    ops.store_device_mark = cb_store_dev;
    in->mem = aligned_alloc(8, (sz + 7) & ~(size_t)7);
    if (!in->mem || sc_signer_init(in->mem, sz, MAXK, 8, &cfg, &ops, &in->s) != SC_OK)
        abort();
    /* RAM of the new instance */
    in->ctr_base_ms = 0;
    in->ctr_real0_ms = g.now_ms;
    in->rate_ppm = g.rate_ppm[in->idx];
    in->ta_loaded = in->ta_floor_due = in->ta_voted = in->ta_vote_in_cmd = 0;
    in->a_has = 0;
    in->a_highest_ms = 0;
    in->crash_cd = in->crash_mode = in->fail_n = 0;
    memset(in->loaded, 0, sizeof in->loaded);
    in->nloaded = 0;
    memset(in->hv, 0, sizeof in->hv);
    memset(in->hb, 0, sizeof in->hb);
    for (int k = 0; k < MAXK; k++) {
        in->recovering[k] = 1;
        in->lost[k] = 0;
    }
    in->alive = 1;
    in->restart_at = 0;
    if (in->p->clock == CLK_ANCH)
        anch_refresh(in);
    if (in->p->guard)
        guard_claim(in);
    if (in->p->xlog && xlog_claim(in) != 0) {
        /* main.go: a runner that cannot claim its log does not start. */
        inst_free(in);
        in->alive = 0;
        in->restart_at = g.cur + 1;
        return;
    }
    inst_load(in);
}

/* Lost epochs of the incarnation that ends now. */
static void inst_close_lost(inst_t *in)
{
    for (int k = 0; k < g.nk; k++)
        if (in->recovering[k] && in->lost[k]) {
            g.m.lost_never++;
            g.m.lost_sum += in->lost[k];
            g.m.lost_n++;
            if (in->lost[k] > g.m.lost_max)
                g.m.lost_max = in->lost[k];
        }
}

static void inst_die(inst_t *in, int down_slots)
{
    inst_close_lost(in);
    inst_free(in);
    in->alive = 0;
    in->restart_at = g.cur + (uint64_t)(down_slots > 0 ? down_slots : 1);
    g.m.crashes++;
    TRACE("  signer %d%s down until slot +%" PRIu64 "\n", in->idx, in->clone ? "'" : "",
          in->restart_at - SLOT0);
}

static void inst_restart(inst_t *in)
{
    if (in->alive)
        inst_close_lost(in);
    g.m.restarts++;
    inst_boot(in);
    TRACE("  signer %d%s restarted, %d of %d keys loaded\n", in->idx, in->clone ? "'" : "",
          in->nloaded, g.nk);
}

static inst_t *new_inst(int idx, int clone)
{
    for (int i = 0; i < MAXINST; i++)
        if (!g.inst[i].used) {
            inst_t *in = &g.inst[i];
            memset(in, 0, sizeof *in);
            in->used = 1;
            in->idx = idx;
            in->clone = clone;
            in->p = g.prof[idx];
            return in;
        }
    return NULL;
}

/* ---- the oracle ------------------------------------------------------------------------------- */

static int reason_of(const inst_t *in, const req_t *r, int rc)
{
    int k = r->key;
    int nf = g.canon.jep + 2 < cur_epoch();
    switch (rc) {
    case SC_ERR_POLICY_FUTURE:
    case SC_ERR_CLOCK:
        return L_CLOCK;
    case SC_ERR_STORAGE:
        return L_STORAGE;
    case SC_ERR_SLASH_SOURCE:
        if (in->hv[k] && in->ms[k] > r->a.source.epoch)
            return L_SRC_BACK;
        return nf ? L_RESTART_NF : L_RESTART_FIN;
    case SC_ERR_SLASH_TARGET:
        if (in->hv[k] && in->mt[k] >= r->a.target.epoch)
            return L_TGT_DUP;
        return nf ? L_RESTART_NF : L_RESTART_FIN;
    case SC_ERR_SLASH_BLOCK:
        if (in->hb[k] && in->mb[k] >= r->b.slot)
            return L_TGT_DUP;
        return nf ? L_RESTART_NF : L_RESTART_FIN;
    case -1:
        return L_CRASH;
    }
    return L_OTHER;
}

/* Would an EIP-3076 minimal signer that kept everything this signer index
 * signed (all its instances) sign r? Exact repeats of a signed root count. */
static int ref_allows(int idx, const req_t *r, uint64_t r8)
{
    const hist_t *h = &g.sig[idx][r->key];
    const tent_t *e = tab_get(r->key, r->kind, r8, 0);
    if (e && (e->mask >> idx & 1))
        return 1;
    if (r->kind == R_ATT) {
        if (r->a.source.epoch > r->a.target.epoch)
            return 0;
        return !h->hv || (r->a.source.epoch >= h->maxs && r->a.target.epoch > h->maxt);
    }
    if (r->kind == R_BLK)
        return !h->hb || r->b.slot > h->maxb;
    return 1;
}

/* The fork version the core of in uses at epoch, read from the core: 6, 7
 * or 8, the version whose attester domain gives the core's root; else 0xff. */
static uint8_t core_version(const inst_t *in, uint64_t epoch)
{
    static const uint8_t ATT[4] = {1, 0, 0, 0};
    static uint8_t want[3][32];
    static int init;
    uint8_t zero[32] = {0}, got[32];
    if (!init) {
        uint8_t gvr[32], dom[32], v[4] = {0};
        gvr_of(gvr);
        for (int i = 0; i < 3; i++) {
            v[0] = (uint8_t)(6 + i);
            sc_compute_domain(ATT, v, gvr, dom);
            sc_compute_signing_root(zero, dom, want[i]);
        }
        init = 1;
    }
    sc_signer_signing_root(in->s, ATT, epoch, zero, got);
    for (int i = 0; i < 3; i++)
        if (!memcmp(got, want[i], 32))
            return (uint8_t)(6 + i);
    return 0xff;
}

static void on_signed(inst_t *in, const req_t *r, const uint8_t root[32])
{
    int idx = in->idx, k = r->key;
    uint64_t r8 = get64(root), epoch;
    hist_t *h = &g.sig[idx][k];
    const vote_t *bad;
    tent_t *e;

    /* Clock: never past the signer's own clock epoch + max_epochs_ahead. */
    epoch = r->kind == R_ATT ? r->a.target.epoch : r->kind == R_BLK ? r->b.slot / SPE : r->epoch;
    if (!in->last_now_ok || epoch > epoch_of_s(in->last_now) + in->p->mea) {
        g.m.viol_clock++;
        violation("clock", idx, k, "signed epoch +%" PRIu64 " with clock epoch +%" PRIu64,
                  epoch - E0, epoch_of_s(in->last_now) - E0);
    }
    /* Fork schedule: a signer signs each epoch under one fork version only,
     * whatever schedule updates and restarts happen. call_sign read the
     * version before the call: a crash in it frees the core. */
    if (epoch >= E0 && epoch - E0 < VEP) {
        uint8_t v = in->sign_ver, *seen = &g.ver[idx][epoch - E0];
        if (*seen && *seen != v) {
            g.m.viol_sched++;
            violation("fork schedule", idx, k, "epoch +%" PRIu64 " signed under version %d and %d",
                      epoch - E0, *seen, v);
        }
        *seen = v;
    }
    if ((int64_t)(epoch - real_epoch()) > g.m.max_ahead_real)
        g.m.max_ahead_real = (int64_t)(epoch - real_epoch());
    if (r->kind != R_ATT && r->kind != R_BLK)
        return;

    if (!ref_allows(idx, r, r8)) {
        g.m.excess++;
        if (getenv("SIM_EXCESS")) {
            const hist_t *hh = &g.sig[idx][r->key];
            printf("EXCESS signer %d%s key %d kind %d slot +%llu: ", idx, in->clone ? "'" : "",
                   r->key, r->kind, (unsigned long long)(g.cur - SLOT0));
            if (r->kind == R_ATT)
                printf("vote (%lld,%lld) ref maxs %lld maxt %lld", (long long)(r->a.source.epoch - E0),
                       (long long)(r->a.target.epoch - E0), (long long)(hh->maxs - E0),
                       (long long)(hh->maxt - E0));
            else
                printf("block slot +%lld ref maxb +%lld", (long long)(r->b.slot - SLOT0),
                       (long long)(hh->maxb - SLOT0));
            printf(" | this instance: ms %lld mt %lld mb +%lld hv %d hb %d forged %d\n",
                   (long long)(in->ms[r->key] - E0), (long long)(in->mt[r->key] - E0),
                   (long long)(in->mb[r->key] - SLOT0), in->hv[r->key], in->hb[r->key], r->forged);
        }
        sim_feature(0x1300);
    }
    if (r->kind == R_ATT) {
        uint64_t s = r->a.source.epoch, t = r->a.target.epoch;
        if ((bad = vote_conflict(h, s, t, r8))) {
            g.m.viol_single++;
            violation("single signer", idx, k,
                      "vote (%" PRIu64 ",%" PRIu64 ") conflicts with (%" PRIu64 ",%" PRIu64 ")",
                      s - E0, t - E0, bad->s - E0, bad->t - E0);
        }
        hist_vote(h, s, t, r8);
        if (!in->hv[k] || s > in->ms[k])
            in->ms[k] = s;
        if (!in->hv[k] || t > in->mt[k])
            in->mt[k] = t;
        in->hv[k] = 1;
    } else {
        if ((bad = block_conflict(h, r->b.slot, r8))) {
            g.m.viol_single++;
            violation("single signer", idx, k, "second block at slot +%" PRIu64,
                      r->b.slot - SLOT0);
        }
        hist_block(h, r->b.slot, r8);
        if (!in->hb[k] || r->b.slot > in->mb[k])
            in->mb[k] = r->b.slot;
        in->hb[k] = 1;
    }

    e = tab_get((uint8_t)k, r->kind, r8, 1);
    if (!e)
        return;
    if (r->kind == R_ATT) {
        e->s = r->a.source.epoch;
        e->t = r->a.target.epoch;
    } else {
        e->s = r->b.slot;
    }
    if (!(e->mask >> idx & 1)) {
        int before = __builtin_popcount(e->mask);
        e->mask |= (uint8_t)(1u << idx);
        if (before == g_m - 1) {
            /* Second share: the validator has signed this message. */
            hist_t *v = &g.val[k];
            if (r->kind == R_ATT) {
                if ((bad = vote_conflict(v, e->s, e->t, r8))) {
                    g.m.viol_combined++;
                    violation("validator (m of n)", idx, k,
                              "vote (%" PRIu64 ",%" PRIu64 ") conflicts with (%" PRIu64
                              ",%" PRIu64 ")",
                              e->s - E0, e->t - E0, bad->s - E0, bad->t - E0);
                }
                hist_vote(v, e->s, e->t, r8);
            } else {
                if ((bad = block_conflict(v, e->s, r8))) {
                    g.m.viol_combined++;
                    violation("validator (m of n)", idx, k, "second block at slot +%" PRIu64,
                              e->s - SLOT0);
                }
                hist_block(v, e->s, r8);
            }
        }
    }
}

/* ---- signing calls ----------------------------------------------------------------------------- */

static void signing_root(const inst_t *in, const req_t *r, uint8_t root[32])
{
    uint8_t obj[32];
    static const uint8_t ATT[4] = {1, 0, 0, 0}, BLK[4] = {0, 0, 0, 0}, RAN[4] = {2, 0, 0, 0};
    uint8_t dom[4] = {r->dom, 0, 0, 0};
    switch (r->kind) {
    case R_ATT:
        sc_htr_attestation_data(&r->a, obj);
        sc_signer_signing_root(in->s, ATT, r->a.target.epoch, obj, root);
        break;
    case R_BLK:
        sc_htr_beacon_block_header(&r->b, obj);
        sc_signer_signing_root(in->s, BLK, r->b.slot / SPE, obj, root);
        break;
    case R_RANDAO:
        sc_htr_uint64(r->epoch, obj);
        sc_signer_signing_root(in->s, RAN, r->epoch, obj, root);
        break;
    default:
        sc_signer_signing_root(in->s, dom, r->epoch, r->obj, root);
    }
}

/* One request to one instance. Returns the status, or -1 if the instance
 * crashed (then *signed says whether the signature was made first). */
static int call_sign(inst_t *in, const req_t *r, uint8_t root[32], int *signed_out)
{
    jmp_buf jb;
    volatile int rc = SC_ERR_ARG, made = 0;
    uint8_t sig[96];
    uint64_t epoch = r->kind == R_ATT ? r->a.target.epoch : r->kind == R_BLK ? r->b.slot / SPE : r->epoch;
    signing_root(in, r, root);
    if (epoch >= E0 && epoch - E0 < VEP)
        in->sign_ver = core_version(in, epoch); /* for the fork version oracle */
    g.jb = &jb;
    g.cur_inst = in;
    if (setjmp(jb)) {
        g.jb = NULL;
        *signed_out = made;
        inst_die(in, in->down_slots);
        return -1;
    }
    in->last_now_ok = 0;
    g.m.sign_calls++;
    switch (r->kind) {
    case R_ATT:
        rc = sc_sign_attestation(in->s, g_pk[r->key], &r->a, sig);
        break;
    case R_BLK:
        rc = sc_sign_block(in->s, g_pk[r->key], &r->b, sig);
        break;
    case R_RANDAO:
        rc = sc_sign_randao_reveal(in->s, g_pk[r->key], r->epoch, sig);
        break;
    default: {
        uint8_t dom[4] = {r->dom, 0, 0, 0};
        rc = sc_sign_root(in->s, g_pk[r->key], dom, r->epoch, r->obj, sig);
    }
    }
    made = rc == SC_OK;
    if (in->p->clock == CLK_TA) {
        if (rc == SC_OK && r->kind == R_ATT)
            ta_note_vote(in, r->a.target.epoch);
        ta_store_due_floor(in);
    }
    g.jb = NULL;
    *signed_out = made;
    return rc;
}

/* Runs a TA clock sync as one command (it may write and crash). */
static void guarded_sync(inst_t *in, uint64_t t)
{
    jmp_buf jb;
    g.jb = &jb;
    if (setjmp(jb)) {
        g.jb = NULL;
        inst_die(in, in->down_slots);
        return;
    }
    ta_sync(in, t);
    ta_store_due_floor(in);
    g.jb = NULL;
}

/* EIP-3076 import of the validator's history maxima, with deltas: what a
 * host may pass (lower values are harmless, the import only raises). */
static void guarded_import(inst_t *in, int k, const sc_watermark *wm)
{
    jmp_buf jb;
    sc_config cfg;
    if (!in->alive || !in->loaded[k])
        return;
    make_cfg(&cfg, in->p, 0);
    g.jb = &jb;
    if (setjmp(jb)) {
        g.jb = NULL;
        inst_die(in, in->down_slots);
        return;
    }
    sim_feature(0x5000u + (uint32_t)sc_signer_import(in->s, g_pk[k], cfg.genesis_validators_root, wm));
    g.jb = NULL;
}

/* Votes and blocks the validator signed before these signers had the key
 * (another setup), from epoch first to last: the oracle's validator view
 * holds them, the signers do not unless imported. */
static void prehistory(uint64_t first, uint64_t last)
{
    for (int k = 0; k < g.nk; k++)
        for (uint64_t t = first; t <= last; t++) {
            hist_vote(&g.val[k], t - 1, t, mix(t * 977 + (uint64_t)k));
            hist_block(&g.val[k], t * SPE + 5, mix(t * 991 + (uint64_t)k));
        }
}

static void import_all(int slack)
{
    for (int i = 0; i < MAXINST; i++)
        for (int k = 0; k < g.nk; k++) {
            sc_watermark wm = {g.val[k].maxb - (uint64_t)slack, g.val[k].maxs,
                               g.val[k].maxt - (uint64_t)slack,
                               SC_WM_HAS_BLOCK | SC_WM_HAS_ATTESTATION};
            if (g.inst[i].used)
                guarded_import(&g.inst[i], k, &wm);
        }
}

/* ---- delivery -------------------------------------------------------------------------------------- */

static void record_hist(const req_t *r)
{
    g.hist[g.histn % HISTN] = *r;
    g.histn++;
}

static void deliver(const req_t *r)
{
    uint64_t roots[NSIGMAX * 2];
    int counts[NSIGMAX * 2], nroots = 0, first_reason = -1, nsigned = 0;
    uint8_t mask = r->mask ? r->mask & full_mask() : full_mask();
    g.m.requests++;
    record_hist(r);
    for (int i = 0; i < g_n; i++) {
        inst_t *targets[2];
        int nt = 0;
        if (!(mask >> i & 1)) {
            if (r->honest && r->kind == R_ATT)
                g.m.refuse[L_NOTSENT]++;
            if (first_reason < 0)
                first_reason = L_NOTSENT;
            continue;
        }
        inst_t *p = &g.inst[g.prim[i]];
        inst_t *c = g.clon[i] >= 0 ? &g.inst[g.clon[i]] : NULL;
        if (c && c->alive && (r->vc == 1 || r->forged))
            targets[nt++] = c;
        else
            targets[nt++] = p;
        for (int j = 0; j < nt; j++) {
            inst_t *in = targets[j];
            uint8_t root[32];
            int made = 0, rc, reason;
            if (!in->alive || !in->loaded[r->key]) {
                if (r->honest && r->kind == R_ATT)
                    g.m.refuse[L_DOWN]++;
                if (first_reason < 0)
                    first_reason = L_DOWN;
                continue;
            }
            rc = call_sign(in, r, root, &made);
            sim_feature(0x2000u + (uint32_t)(in->p - PROFS) * 64u + (uint32_t)(rc + 1) * 4u +
                        r->kind);
            if (made) {
                uint64_t r8 = get64(root);
                int s;
                g.m.signed_ok++;
                on_signed(in, r, root);
                for (s = 0; s < nroots && roots[s] != r8; s++)
                    ;
                if (s == nroots) {
                    roots[nroots] = r8;
                    counts[nroots++] = 0;
                }
                counts[s]++;
                if (in->alive && r->honest && in->recovering[r->key] && r->kind == R_ATT) {
                    in->recovering[r->key] = 0;
                    g.m.lost_sum += in->lost[r->key];
                    g.m.lost_n++;
                    if (in->lost[r->key] > g.m.lost_max)
                        g.m.lost_max = in->lost[r->key];
                }
                nsigned++;
                continue;
            }
            reason = reason_of(in, r, rc);
            if (r->honest && r->kind == R_ATT && ref_allows(i, r, get64(root)))
                g.m.cost[reason]++;
            if (r->honest && r->kind == R_ATT) {
                g.m.refuse[reason]++;
                if (in->alive && in->recovering[r->key])
                    in->lost[r->key]++;
            }
            if (first_reason < 0)
                first_reason = reason;
            TRACE("  refuse signer %d%s key %d kind %d: %s\n", i, in->clone ? "'" : "", r->key,
                  r->kind, sc_status_name(rc));
        }
    }
    if (r->honest && (r->kind == R_ATT || r->kind == R_BLK)) {
        int best = 0;
        for (int s = 0; s < nroots; s++)
            if (counts[s] > best)
                best = counts[s];
        if (r->kind == R_ATT) {
            g.m.honest_att++;
            g.m.honest_att_signed[nsigned > 3 ? 3 : nsigned]++;
        }
        if (best >= g_m) {
            if (r->kind == R_ATT)
                g.m.val_att_ok++;
            else
                g.m.val_blk_ok++;
        } else {
            if (r->kind == R_ATT) {
                g.m.val_att_miss++;
                g.m.val_miss[first_reason < 0 ? L_OTHER : first_reason]++;
            } else {
                g.m.val_blk_miss++;
            }
        }
    }
}

static void enqueue(req_t *r)
{
    if (g.route_n > 0) {
        r->mask = g.route_mask;
        g.route_n--;
    }
    if (g.delay_n > 0) {
        r->due_ms += g.delay_ms;
        g.delay_n--;
    }
    if (g.qn == QMAX) {
        memmove(&g.q[0], &g.q[1], (QMAX - 1) * sizeof g.q[0]);
        g.qn--;
    }
    g.q[g.qn++] = *r;
    if (g.dup && g.qn < QMAX)
        g.q[g.qn++] = *r;
}

static void deliver_due(void)
{
    int i = 0;
    while (i < g.qn && !g.stop) {
        int pick = i;
        if (g.q[i].due_ms > g.now_ms) {
            i++;
            continue;
        }
        if (g.reorder) {
            /* any due request, not the oldest */
            int cand[16], nc = 0;
            for (int j = i; j < g.qn && nc < 16; j++)
                if (g.q[j].due_ms <= g.now_ms)
                    cand[nc++] = j;
            pick = cand[rnd() % (uint64_t)nc];
        }
        req_t r = g.q[pick];
        memmove(&g.q[pick], &g.q[pick + 1], (size_t)(g.qn - pick - 1) * sizeof g.q[0]);
        g.qn--;
        deliver(&r);
    }
}

/* ---- chain and duties ---------------------------------------------------------------------------------- */

static uint64_t head_id(const chain_t *c, uint64_t slot)
{
    if (slot > g.cur)
        slot = g.cur;
    if (slot < SLOT0)
        return c->ids[0];
    for (uint64_t s = slot;; s--) {
        if (c->ids[s - SLOT0])
            return c->ids[s - SLOT0];
        if (s == SLOT0)
            return c->ids[0];
    }
}

static uint64_t cp_id(const chain_t *c, uint64_t e) { return head_id(c, e * SPE); }

static void chain_advance(chain_t *c, int missed)
{
    c->ids[g.cur - SLOT0] = missed ? 0 : ++g.nextid;
    if (g.cur % SPE == 0 && c->fin) {
        c->jep = cur_epoch() - 1;
        c->jid = cp_id(c, c->jep);
    }
}

static void chain_reorg(chain_t *c, uint64_t depth, uint64_t jback)
{
    if (g.cur < g.start_slot)
        return;
    if (depth > g.cur - g.start_slot)
        depth = g.cur - g.start_slot;
    for (uint64_t s = g.cur - depth + 1; s <= g.cur; s++)
        c->ids[s - SLOT0] = rnd() % 8 == 0 ? 0 : ++g.nextid;
    if (jback && c->jep > E0 + jback) {
        c->jep -= jback;
        c->jid = cp_id(c, c->jep);
    } else if (c->jep * SPE > g.cur - depth) {
        c->jid = cp_id(c, c->jep);
    }
    sim_feature(0x3000u + (uint32_t)(depth > SPE) * 2u + (jback > 0));
    TRACE("  reorg depth %" PRIu64 ", justified now +%" PRIu64 "\n", depth, c->jep - E0);
}

static uint64_t att_slot(int k, uint64_t e) { return e * SPE + mix((uint64_t)k * 7919u + e) % SPE; }

static int proposer(uint64_t slot)
{
    uint64_t x = mix(slot ^ 0xb10cull) % (g.prop_div * (uint64_t)g.nk);
    return x < (uint64_t)g.nk ? (int)x : -1;
}

static void make_att(const chain_t *c, uint64_t hs, uint64_t cs, sc_attestation_data *a)
{
    uint64_t e = hs / SPE;
    memset(a, 0, sizeof *a);
    a->slot = hs;
    root_of(head_id(c, cs), 0xb0, a->beacon_block_root);
    a->source.epoch = c->jep;
    root_of(c->jid, 0xc0, a->source.root);
    a->target.epoch = e;
    root_of(cp_id(c, e * SPE <= cs ? e : cs / SPE), 0xc0, a->target.root);
}

static void gen_duties(int v, uint64_t hs, uint64_t host_ms)
{
    vc_t *vc = &g.vc[v];
    const chain_t *c = vc->alt && g.alt_on ? &g.alt : &g.canon;
    uint64_t e = hs / SPE, cs = hs < g.cur ? hs : g.cur;
    int pk = proposer(hs);
    req_t r;
    if (cs > SLOT0 + (uint64_t)vc->lag)
        cs -= (uint64_t)vc->lag;
    (void)host_ms;
    if (pk >= 0 && (c->ids[(hs < g.cur ? hs : g.cur) - SLOT0] || hs > g.cur)) {
        memset(&r, 0, sizeof r);
        r.kind = R_RANDAO;
        r.key = (uint8_t)pk;
        r.vc = (uint8_t)v;
        r.epoch = e;
        r.due_ms = g.now_ms;
        enqueue(&r);
        r.kind = R_BLK;
        r.honest = v == 0;
        r.b.slot = hs;
        r.b.proposer_index = 1000 + (uint64_t)pk;
        root_of(head_id(c, hs - 1), 0xb0, r.b.parent_root);
        root_of(mix(hs * 3 + (uint64_t)v), 0xd0, r.b.state_root);
        root_of(hs <= g.cur ? c->ids[hs - SLOT0] : mix(hs + 77 * (uint64_t)v), 0xe0, r.b.body_root);
        enqueue(&r);
    }
    for (int k = 0; k < g.nk; k++) {
        if (g.extras && k < 2) {
            memset(&r, 0, sizeof r);
            r.kind = R_ROOT;
            r.dom = 7; /* sync committee message */
            r.key = (uint8_t)k;
            r.vc = (uint8_t)v;
            r.epoch = e;
            root_of(head_id(c, cs), 0xb0, r.obj);
            r.due_ms = g.now_ms;
            enqueue(&r);
        }
        if (att_slot(k, e) != hs)
            continue;
        memset(&r, 0, sizeof r);
        r.kind = R_ATT;
        r.key = (uint8_t)k;
        r.honest = v == 0; /* the second VC is the fault, not a duty */
        r.vc = (uint8_t)v;
        make_att(c, hs, cs, &r.a);
        if (r.a.source.epoch > r.a.target.epoch)
            continue; /* host clock behind the chain: no duty */
        r.due_ms = g.now_ms;
        enqueue(&r);
        if (g.extras && mix((uint64_t)k * 31 + e) % 4 == 0) {
            req_t s;
            memset(&s, 0, sizeof s);
            s.kind = R_ROOT;
            s.dom = 5; /* selection proof */
            s.key = (uint8_t)k;
            s.vc = (uint8_t)v;
            s.epoch = e;
            root_of(hs, 0xa5, s.obj);
            s.due_ms = g.now_ms;
            enqueue(&s);
            s.dom = 6; /* aggregate and proof */
            root_of(mix(hs + 5), 0xa6, s.obj);
            s.due_ms = g.now_ms + 4000;
            enqueue(&s);
        }
    }
}

/* ---- one slot ------------------------------------------------------------------------------------------------ */

static void tick(void)
{
    uint64_t host_ms, hs;
    g.cur++;
    g.m.slots++;
    g.now_ms = slot_ms(g.cur);
    chain_advance(&g.canon, g.miss_n > 0);
    if (g.miss_n > 0)
        g.miss_n--;
    if (g.alt_on)
        chain_advance(&g.alt, rnd() % 16 == 0);
    for (int i = 0; i < MAXINST; i++) {
        inst_t *in = &g.inst[i];
        if (!in->used)
            continue;
        if (!in->alive) {
            if (in->restart_at && g.cur >= in->restart_at)
                inst_restart(in);
            continue;
        }
        if (in->p->clock == CLK_ANCH) {
            anch_refresh(in);
            if (in->p->xlog && g.cur % SPE == SPE * 3 / 4)
                xlog_preraise(in);
            if (!in->alive)
                continue;
        } else {
            uint64_t t = (g.now_ms + (uint64_t)g.host_off_ms) / 1000;
            if (g.ta_hostile[in->idx])
                t += 100000;
            guarded_sync(in, t);
            if (in->alive && in->ta_loaded) {
                uint64_t tt = ta_time(in), real = g.now_ms / 1000;
                if (tt > real && tt - real > g.m.ta_clock_ahead_max)
                    g.m.ta_clock_ahead_max = tt - real;
            }
        }
        if (in->alive && in->nloaded < g.nk)
            inst_load(in);
    }
    host_ms = g.now_ms + (uint64_t)g.host_off_ms;
    hs = (host_ms / 1000 - GENESIS) / SPS;
    for (int v = 0; v < 2; v++) {
        vc_t *vc = &g.vc[v];
        if (!vc->on) {
            vc->next = hs + 1;
            continue;
        }
        if (hs > vc->next + 2 * SPE)
            vc->next = hs - 2 * SPE;
        while (vc->next <= hs && vc->next < SLOT0 + MAXSLOTS - 1) {
            gen_duties(v, vc->next, host_ms);
            vc->next++;
        }
    }
    g.now_ms += 4000;
    deliver_due();
}

/* ---- per-epoch write histogram ------------------------------------------------------------------------------- */

static void writes_flush_epoch(void)
{
    /* Called at each epoch start: bucket the write counts of the epoch that ended. */
    for (int i = 0; i < MAXINST; i++) {
        inst_t *in = &g.inst[i];
        uint64_t n;
        if (!in->used || !in->alive)
            continue;
        n = in->wr_epoch == real_epoch() ? in->wr_n : 0;
        g.m.writes_hist[n == 0 ? 0 : n == 1 ? 1 : n == 2 ? 2 : n == 3 ? 3 : n < 16 ? 4 : 5]++;
    }
}

/* ---- run setup --------------------------------------------------------------------------------------------------- */

static void run_reset(void)
{
    for (int i = 0; i < MAXINST; i++)
        inst_free(&g.inst[i]);
    for (int i = 0; i < g_n; i++)
        for (int k = 0; k < MAXK; k++)
            hist_free(&g.sig[i][k]);
    for (int k = 0; k < MAXK; k++)
        hist_free(&g.val[k]);
    if (g.cur >= SLOT0) {
        uint64_t n = g.cur - SLOT0 + 1;
        if (n > MAXSLOTS)
            n = MAXSLOTS;
        memset(g_ids[0], 0, n * 8);
        memset(g_ids[1], 0, n * 8);
    }
    memset(&g, 0, sizeof g);
    g_gen++;
    if (!g_gen)
        g_gen = 1;
    for (int k = 0; k < MAXK; k++) {
        memset(g_pk[k], 0xa0 + k, SC_PUBKEY_LEN);
        g_pk[k][0] = 0x99;
    }
}

/* Sets up chain, host and three signers; the chain starts at epoch
 * E0 + start_off, finalizing. */
static void run_start(const int profs[NSIGMAX], int nk, uint64_t start_off, uint64_t seed,
                      int nofork_mask)
{
    run_reset();
    g.rng = seed ^ 0x5eedull;
    g.nk = nk < 1 ? 1 : nk > MAXK ? MAXK : nk;
    g.trace = getenv("SIM_TRACE") != NULL;
    g.canon.ids = g_ids[0];
    g.alt.ids = g_ids[1];
    g.start_slot = (E0 + 1 + start_off) * SPE;
    for (uint64_t s = SLOT0; s < g.start_slot; s++)
        g.canon.ids[s - SLOT0] = ++g.nextid;
    g.cur = g.start_slot - 1;
    g.canon.fin = 1;
    g.canon.jep = g.start_slot / SPE - 1;
    g.canon.jid = cp_id(&g.canon, g.canon.jep);
    g.now_ms = slot_ms(g.cur);
    g.vc[0].on = 1;
    g.vc[0].next = g.start_slot;
    g.max_slots = 3000;
    g.prop_div = 4; /* fuzzing: many blocks */
    for (int i = 0; i < g_n; i++) {
        inst_t *in;
        g.prof[i] = &PROFS[profs[i]];
        g.f1[i] = nofork_mask >> i & 1 ? NOFORK1 : FORK1;
        g.rate_ppm[i] = 1000000;
        g.clon[i] = -1;
        in = new_inst(i, 0);
        g.prim[i] = (int)(in - g.inst);
        in->down_slots = 1;
        if (g.prof[i]->clock == CLK_TA) {
            /* PROVISION: the clock from the signed record, an empty mark. */
            sc_watermark none = {0, 0, 0, 0};
            in->disk.has_state = 1;
            in->disk.floor = g.now_ms / 1000;
            in->disk.last_step = 0;
            test_watermark_encode(&none, in->disk.mark);
        }
        inst_boot(in);
        memset(in->recovering, 0, sizeof in->recovering); /* first start, not a restart */
    }
}

static void run_finish(sim_metrics *out)
{
    for (int i = 0; i < MAXINST; i++)
        if (g.inst[i].used && g.inst[i].alive)
            inst_close_lost(&g.inst[i]);
    if (out)
        *out = g.m;
}

/* ---- events ---------------------------------------------------------------------------------------------------------- */

enum {
    OP_ADV, OP_MISS, OP_REORG, OP_FINAL, OP_RESTART, OP_CRASHPLAN, OP_DOWN, OP_SNAP, OP_ROLLBACK,
    OP_CLONE, OP_HOSTCLK, OP_SYNCBLOCK, OP_DRIFT, OP_TAHOSTILE, OP_FORGE, OP_REPLAY, OP_DELAY,
    OP_REORDER, OP_DUP, OP_DVC, OP_SPLIT, OP_RAISE, OP_FUTURE, OP_ROUTE, OP_BLKFORGE,
    OP_STOREFAIL, OP_EXTRAS, OP_SWITCH, OP_CLKERR, OP_IMPORT,
    OP_STORE_RB, OP_STORE_DOWN, OP_STALE, OP_STORE_REPLAY, OP_WIPE, OP_HANDOVER, OP_N
};

static const uint8_t OP_WEIGHT[OP_N] = {
    [OP_ADV] = 70,     [OP_MISS] = 6,       [OP_REORG] = 14,   [OP_FINAL] = 8,
    [OP_RESTART] = 7,  [OP_CRASHPLAN] = 14, [OP_DOWN] = 4,     [OP_SNAP] = 4,
    [OP_ROLLBACK] = 4, [OP_CLONE] = 4,      [OP_HOSTCLK] = 6,  [OP_SYNCBLOCK] = 5,
    [OP_DRIFT] = 3,    [OP_TAHOSTILE] = 3,  [OP_FORGE] = 18,   [OP_REPLAY] = 8,
    [OP_DELAY] = 4,    [OP_REORDER] = 3,    [OP_DUP] = 3,      [OP_DVC] = 6,
    [OP_SPLIT] = 3,    [OP_RAISE] = 4,      [OP_FUTURE] = 6,   [OP_ROUTE] = 7,
    [OP_BLKFORGE] = 6, [OP_STOREFAIL] = 3,  [OP_EXTRAS] = 3,   [OP_SWITCH] = 3,
    [OP_CLKERR] = 3,   [OP_IMPORT] = 4,     [OP_STORE_RB] = 3, [OP_STORE_DOWN] = 3,
    [OP_STALE] = 2,    [OP_STORE_REPLAY] = 2, [OP_WIPE] = 3, [OP_HANDOVER] = 1,
};

static uint8_t g_optab[256];

static void optab_init(void)
{
    int sum = 0, j = 0;
    for (int o = 0; o < OP_N; o++)
        sum += OP_WEIGHT[o];
    for (int o = 0; o < OP_N; o++) {
        int n = OP_WEIGHT[o] * 256 / sum;
        for (int i = 0; i < n && j < 256; i++)
            g_optab[j++] = (uint8_t)o;
    }
    while (j < 256)
        g_optab[j++] = OP_ADV;
}

static void adv(uint64_t n)
{
    for (uint64_t i = 0; i < n && !g.stop; i++) {
        if (g.cur + 1 >= g.start_slot + g.max_slots || g.cur + 2 >= SLOT0 + MAXSLOTS) {
            g.stop = 2;
            return;
        }
        if ((g.cur + 1) % SPE == 0)
            writes_flush_epoch();
        tick();
    }
}

static void forge_vote(int k, uint64_t s, uint64_t t, uint8_t tag, uint8_t mask)
{
    req_t r;
    memset(&r, 0, sizeof r);
    r.kind = R_ATT;
    r.key = (uint8_t)k;
    r.forged = 1;
    r.mask = mask;
    r.a.slot = t * SPE + tag % SPE;
    root_of(mix(tag + t), 0xb0, r.a.beacon_block_root);
    r.a.source.epoch = s;
    root_of(cp_id(&g.canon, s), 0xc0, r.a.source.root);
    r.a.target.epoch = t;
    root_of(t * SPE <= g.cur ? cp_id(&g.canon, t) : mix(t), 0xc0, r.a.target.root);
    r.due_ms = g.now_ms;
    deliver(&r);
}

static inst_t *prim(int i) { return &g.inst[g.prim[i % g_n]]; }

static void do_rollback(int i)
{
    inst_t *in = prim(i);
    if (!g.has_snap[i])
        return;
    in->disk = g.snap[i];
    g.m.rollbacks++;
    TRACE("  rollback signer %d\n", i);
    inst_restart(in);
}

/* A restart that lost the local store (ACI or a Confidential Space VM
 * that comes back without its disk): no sealed marks or hint. The mark log's record keys come from the platform's key release,
 * not from the store (slashing-log, platform.Keys), so the claim reads
 * the log as on any restart. The shares come back (share_for): from the
 * durable state copy (slashing-log/statestore, which does not hold the
 * hint), or by import. */
static void do_wipe(int i)
{
    inst_t *in = prim(i);
    memset(&in->disk, 0, sizeof in->disk);
    g.m.state_wipes++;
    TRACE("  signer %d restarts with its local store lost\n", i);
    inst_restart(in);
}

static void do_clone(int i)
{
    inst_t *p = prim(i), *c;
    if (g.clon[i] >= 0) {
        inst_free(&g.inst[g.clon[i]]);
        g.inst[g.clon[i]].used = 0;
        g.clon[i] = -1;
    }
    c = new_inst(i, 1);
    if (!c)
        return;
    c->disk = p->disk;
    c->down_slots = 1;
    g.clon[i] = (int)(c - g.inst);
    g.m.clones++;
    TRACE("  clone of signer %d started\n", i);
    inst_boot(c);
}

/* The handover (tee-signer/server/handover_source.go,
 * slashing-log/docs/durable-state.md). The running instance ends its log with a
 * tombstone record (every bound at its maximum) and gives the mark before
 * it to an instance of a new image, which keeps a log of its own: the share
 * comes as a sealed import with that mark as interchange maxima, which
 * raises the new log before the share is stored. The old instance stays up
 * in the clone slot and still gets the clone's requests; its log takes no
 * record after the tombstone, so it signs only inside its committed mark
 * (the runner also refuses every request, which the model leaves out), and
 * a restart reads the tombstone. One handover per signer and run.
 * tombstone = 0 is the negative control: the old log stays open. */
static void do_handover(int i, int tombstone)
{
    inst_t *o = prim(i), *n;
    sc_watermark mark;
    const sc_watermark tomb = {UINT64_MAX, UINT64_MAX, UINT64_MAX, SC_WM_HAS_BLOCK | SC_WM_HAS_ATTESTATION};
    if (!o->p->xlog || o->p->xlog_mutable || g.handed[i] || !o->alive || !o->x_claimed || o->x_lost)
        return;
    if (g.clon[i] >= 0) {
        inst_free(&g.inst[g.clon[i]]);
        g.inst[g.clon[i]].used = 0;
        g.clon[i] = -1;
    }
    n = new_inst(i, 0);
    if (!n)
        return;
    mark = o->x_mark;
    if (tombstone) {
        int ok = xlog_write(o, &tomb, 0) == 0;
        o->x_lost = 1; /* stopped in the process, written or not */
        if (!ok) {
            n->used = 0; /* store down: no handover, ask again later */
            g.m.handover_failed++;
            return;
        }
    }
    g.xold[i] = g.xlog[i];
    o->old_gen = 1;
    o->clone = 1;
    g.clon[i] = g.prim[i];
    memset(&g.xlog[i], 0, sizeof g.xlog[i]);
    g.xlog[i].mark = mark;
    xlog_push(&g.xlog[i]);
    g.has_snap[i] = g.has_xsnap[i] = 0;
    n->down_slots = 1;
    g.prim[i] = (int)(n - g.inst);
    g.handed[i] = 1;
    g.m.handovers++;
    TRACE("  signer %d handed over to a new image at target +%" PRIu64 "%s\n", i,
          (mark.flags & SC_WM_HAS_ATTESTATION) ? mark.target_epoch - E0 : 0, tombstone ? "" : " (no tombstone)");
    inst_boot(n);
}

static void apply_op(src_t *src)
{
    uint8_t op = g_optab[rd8(src)];
    int i = rd8(src) % g_n;
    uint8_t a = rd8(src), b = rd8(src);
    g.m.events++;
    sim_feature(0x4000u + op);
    TRACE("event %d (%u %u %u) at slot +%" PRIu64 "\n", op, i, a, b, g.cur - SLOT0);
    switch (op) {
    case OP_ADV:
        adv(1 + a % 96);
        break;
    case OP_MISS:
        g.miss_n = 1 + a % 3;
        break;
    case OP_REORG:
        chain_reorg(b & 0x80 && g.alt_on ? &g.alt : &g.canon, 1 + a % 64, b % 8 == 0 ? 1 + b % 3 : 0);
        break;
    case OP_FINAL:
        g.canon.fin = a & 1;
        break;
    case OP_RESTART:
        inst_restart(prim(i));
        break;
    case OP_CRASHPLAN: {
        inst_t *in = prim(i);
        in->crash_cd = 1 + a % 4;
        in->crash_mode = 1 + b % (ACT_N - 1);
        in->down_slots = 1 + (b >> 4) % 8;
        break;
    }
    case OP_DOWN:
        if (prim(i)->alive)
            inst_die(prim(i), 1 + a % 64);
        break;
    case OP_SNAP:
        g.snap[i] = prim(i)->disk;
        g.has_snap[i] = 1;
        g.xsnap[i] = g.xlog[i];
        g.has_xsnap[i] = 1;
        break;
    case OP_ROLLBACK:
        if (g.allow_rollback || prim(i)->p->rollback)
            do_rollback(i);
        break;
    case OP_CLONE:
        if (g.allow_clone || prim(i)->p->clone)
            do_clone(i);
        break;
    case OP_HOSTCLK:
        g.host_off_ms = (int64_t)(int8_t)a * (b % 3 == 0 ? 384000 : 12000);
        break;
    case OP_SYNCBLOCK:
        g.sync_block_until[i] = g.cur + a % 32;
        break;
    case OP_DRIFT: {
        uint32_t rate = 1000000u - 200000u + (uint32_t)a * 1600u; /* 0.8x to 1.2x */
        for (int j = 0; j < MAXINST; j++)
            if (g.inst[j].used && g.inst[j].idx == i && g.inst[j].alive)
                rebase_counter(&g.inst[j], rate);
        g.rate_ppm[i] = rate;
        break;
    }
    case OP_TAHOSTILE:
        g.ta_hostile[i] = a & 1;
        break;
    case OP_CLKERR:
        g.clk_err_ms[i] = ((int64_t)(int8_t)a) * 100; /* +-12.8 s source error */
        break;
    case OP_FORGE: {
        /* near the clock, or up to 63 epochs back (reaches rolled-back marks) */
        uint64_t t = b & 0x20 ? cur_epoch() - a % 64 : cur_epoch() + (a % 8) - 5, s;
        uint64_t back = b % 6;
        s = t > back + E0 ? t - back : E0;
        if (b & 0x40)
            s = t + 1; /* source above target */
        forge_vote(a % g.nk, s, t, (uint8_t)(a ^ b), (uint8_t)(rd8(src) & full_mask()));
        break;
    }
    case OP_REPLAY:
        if (g.histn) {
            uint32_t n = g.histn < HISTN ? g.histn : HISTN;
            req_t r = g.hist[(g.histn - 1 - a % n) % HISTN];
            r.honest = 0;
            r.forged = 1;
            r.mask = b & full_mask();
            deliver(&r);
        }
        break;
    case OP_DELAY:
        g.delay_ms = (uint64_t)(a % 64) * SPS * 1000;
        g.delay_n = 1 + b % 64;
        break;
    case OP_REORDER:
        g.reorder = a & 1;
        break;
    case OP_DUP:
        g.dup = a & 1;
        break;
    case OP_DVC:
        g.vc[1].on = a & 1;
        g.vc[1].alt = (a >> 1) & 1;
        g.vc[1].lag = b % 3;
        g.vc[1].next = g.vc[0].next;
        break;
    case OP_SPLIT:
        memcpy(g.alt.ids, g.canon.ids, (g.cur - SLOT0 + 1) * 8);
        g.alt.jep = g.canon.jep;
        g.alt.jid = g.canon.jid;
        g.alt.fin = a & 1;
        g.alt_on = 1;
        break;
    case OP_RAISE:
        /* A higher source each time, for every key: one write per vote. */
        for (int k = 0; k < g.nk; k++) {
            uint64_t t = cur_epoch(), s = g.raise_src[k] ? g.raise_src[k] + 1 : g.canon.jep;
            if (s > t)
                s = t;
            g.raise_src[k] = s;
            forge_vote(k, s, t + (a & 1), (uint8_t)(k + b), 0);
        }
        break;
    case OP_FUTURE: {
        uint64_t t = cur_epoch() + 1 + (b & 0x80 ? 100 + a : a % 4);
        forge_vote(a % g.nk, g.canon.jep, t, b, 0);
        break;
    }
    case OP_ROUTE:
        g.route_mask = a & full_mask();
        g.route_n = b % 32;
        break;
    case OP_BLKFORGE: {
        req_t r;
        memset(&r, 0, sizeof r);
        r.kind = R_BLK;
        r.key = (uint8_t)(a % g.nk);
        r.forged = 1;
        r.mask = rd8(src) & full_mask();
        r.b.slot = g.cur + (b % 8) - 4;
        r.b.proposer_index = 1000 + r.key;
        root_of(mix(b), 0xe1, r.b.body_root);
        r.due_ms = g.now_ms;
        deliver(&r);
        break;
    }
    case OP_STOREFAIL:
        prim(i)->fail_n = 1 + a % 4;
        break;
    case OP_EXTRAS:
        g.extras = a & 1;
        break;
    case OP_SWITCH:
        g.vc[0].alt = g.alt_on && (a & 1);
        break;
    case OP_STORE_RB:
        /* The store's admin restores an older copy of the log. A locked
         * log refuses (no delete, no overwrite); a mutable store does it. */
        if (!prim(i)->p->xlog)
            break;
        if (prim(i)->p->xlog_mutable && g.has_xsnap[i]) {
            g.xlog[i] = g.xsnap[i];
            g.m.store_rb_done++;
        } else {
            g.m.store_rb_refused++;
        }
        break;
    case OP_STORE_DOWN:
        g.store_down_until[i] = g.cur + 1 + a % 64;
        g.m.xlog_down_slots += 1 + a % 64;
        break;
    case OP_STALE:
        g.stale_n[i] = 1 + a % 3;
        break;
    case OP_STORE_REPLAY:
        /* An old record copied under a new name. On a locked log it does
         * not verify there (name and version differ) and costs a skip; on a
         * mutable store it is a rollback to that copy. */
        if (!prim(i)->p->xlog)
            break;
        if (prim(i)->p->xlog_mutable && g.xlog[i].hn > 1) {
            xlog_t *x = &g.xlog[i];
            uint32_t back = 1 + (uint32_t)(a % 8), j = back < x->hn ? x->hn - 1 - back : 0;
            if (x->hn - j <= XHIST) {
                x->version = x->hv[j % XHIST];
                x->mark = x->hm[j % XHIST];
                g.m.store_rb_done++;
            }
        } else {
            g.xsquat[i]++;
            g.m.store_replays++;
        }
        break;
    case OP_WIPE:
        if (prim(i)->p->xlog)
            do_wipe(i);
        break;
    case OP_HANDOVER:
        do_handover(i, 1);
        break;
    case OP_IMPORT: {
        int k = a % g.nk;
        const hist_t *h = &g.val[k];
        sc_watermark wm = {h->maxb + (uint64_t)(b % 64) - 32, h->maxs + (uint64_t)(b % 4) - 2,
                           h->maxt + (uint64_t)(b % 6) - 3, (uint32_t)(rd8(src) & 3)};
        if (h->hv && h->hb)
            guarded_import(prim(i), k, &wm);
        break;
    }
    }
}

/* Header: profiles, keys, variants; then events. */
static void run_src(src_t *src, uint64_t max_slots, sim_metrics *out, uint64_t seed,
                    int force_prof)
{
    uint8_t h0 = rd8(src), h1 = rd8(src), h2 = rd8(src);
    int profs[NSIGMAX], nk;
    static int init;
    if (!init) {
        optab_init();
        init = 1;
    }
    for (int i = 0; i < g_n; i++)
        profs[i] = force_prof >= 0 ? force_prof
                                   : (h0 & 0x80 ? (h0 + i) % NPROF_FUZZ : h0 % NPROF_FUZZ);
    nk = h1 >= 240 ? 16 : h1 >= 200 ? 8 : 1 + h1 % 4;
    run_start(profs, nk, (h2 >> 1) % 24, seed, (h2 & 1) << 2);
    g.max_slots = max_slots;
    while (!g.stop && !src_done(src))
        apply_op(src);
    if (!g.stop)
        adv(2 * SPE); /* let delayed requests and restarts play out */
    run_finish(out);
}

int sim_run_bytes(const uint8_t *data, size_t len, sim_metrics *out)
{
    src_t src = {data, len, 0, 0, 0};
    sim_metrics m;
    uint64_t seed = 0;
    for (size_t i = 0; i < len && i < 16; i++)
        seed = seed * 131 + data[i];
    run_src(&src, 3000, &m, seed, -1);
    if (out)
        *out = m;
    return (int)(m.viol_single + m.viol_combined + m.viol_clock + m.viol_sched);
}

/* ---- named scenarios --------------------------------------------------------------------------------------------------- */

typedef struct {
    const char *name;
    int nk, nofork_mask;
    void (*run)(void);
} scen_t;

static void crash_at_next_store(int i, int mode, int down)
{
    inst_t *in = prim(i);
    in->crash_cd = 1;
    in->crash_mode = mode;
    in->down_slots = down;
}

/*
 * An `open` config update for signer i: fork version 7 from epoch f1
 * (NOFORK1: none), given to its running instance through
 * sc_signer_set_schedule. When the core takes it, later boots of the signer
 * start with it, as a runner reads its config state back from the log.
 * want is the status the rule must give; any other counts as a violation.
 */
static void sched_update(int i, uint64_t f1, uint64_t activate_at, int want)
{
    inst_t *in = prim(i);
    sc_config cfg;
    sc_schedule n;
    int rc = -1;
    if (in->alive && in->s) {
        make_cfg(&cfg, in->p, f1);
        memset(&n, 0, sizeof n);
        memcpy(n.forks, cfg.forks, sizeof n.forks);
        n.fork_count = cfg.fork_count;
        rc = sc_signer_set_schedule(in->s, &n, activate_at);
    }
    if (rc == SC_OK) {
        g.f1[i] = f1;
        g.m.sched_set++;
    } else {
        g.m.sched_refused++;
    }
    TRACE("  signer %d: schedule with version 7 from epoch +%" PRId64 ": %s\n", i,
          f1 == NOFORK1 ? -1 : (int64_t)(f1 - E0), rc < 0 ? "signer down" : sc_status_name(rc));
    if (rc != want) {
        g.m.viol_sched++;
        violation("fork schedule", i, 0, "update to version 7 from epoch +%" PRId64 ": %s, want %s",
                  f1 == NOFORK1 ? -1 : (int64_t)(f1 - E0), rc < 0 ? "signer down" : sc_status_name(rc),
                  sc_status_name(want));
    }
}

/* Runs to slot `slot` of epoch e. */
static void adv_to(uint64_t e, uint64_t slot)
{
    while (g.cur < e * SPE + slot && !g.stop)
        adv(1);
}

/* Mainnet-like: a 7-slot reorg every 3 epochs at a random slot, some across
 * an epoch boundary; signer 0 restarts once. */
static void scn_reorg7(void)
{
    for (int e = 0; e < 120 && !g.stop; e++) {
        adv(SPE / 2 + rnd() % 8);
        if (e % 3 == 0)
            chain_reorg(&g.canon, 7, 0);
        if (e == 60)
            inst_restart(prim(0));
        adv(SPE - (g.cur + 1) % SPE);
    }
}

/* Deep reorgs (40 to 64 slots) across an epoch boundary that also move the
 * justified checkpoint back one epoch; one restart right after. */
static void scn_deepreorg(void)
{
    for (int e = 0; e < 120 && !g.stop; e++) {
        adv(SPE);
        if (e % 20 == 10) {
            adv(4 + rnd() % 20);
            chain_reorg(&g.canon, 40 + rnd() % 25, 1 + (uint64_t)(e / 20 % 2));
            if (e == 50)
                inst_restart(prim(1));
        }
    }
}

/* 200 epochs without finality, restarts in it, then recovery. */
static void scn_nonfinal200(void)
{
    adv(10 * SPE);
    g.canon.fin = 0;
    for (int e = 0; e < 200 && !g.stop; e++) {
        adv(SPE);
        if (e == 100)
            inst_restart(prim(0));
        if (e == 150)
            inst_restart(prim(1));
    }
    g.canon.fin = 1;
    adv(30 * SPE);
}

/* Crash loop without finality: signer 0 crashes at a store call about every
 * 2 epochs, signer 1 every 5, with every crash point in turn. */
static void scn_crashloop(void)
{
    adv(5 * SPE);
    g.canon.fin = 0;
    for (int e = 0; e < 100 && !g.stop; e++) {
        if (e % 2 == 0)
            crash_at_next_store(0, 1 + e / 2 % (ACT_N - 1), 1 + e % 5);
        if (e % 5 == 0)
            crash_at_next_store(1, 1 + e / 5 % (ACT_N - 1), 2);
        adv(SPE);
    }
    g.canon.fin = 1;
    adv(20 * SPE);
}

/* Fork boundary: signer 2 did not upgrade (its config lacks FORK1, so its
 * signing roots differ from the fork on); duties just before and after the
 * fork; a reorg across the boundary; a minority chain that did not upgrade
 * (alt, not finalizing) splits off 3 slots before the fork; signer 1 goes
 * down for 2 epochs after the fork; then the node's beacon node follows the
 * minority chain for 5 epochs and comes back. */
static void scn_fork(void)
{
    while (cur_epoch() < FORK1 - 1 && !g.stop)
        adv(1);
    adv(SPE - 3);
    memcpy(g.alt.ids, g.canon.ids, (g.cur - SLOT0 + 1) * 8);
    g.alt.jep = g.canon.jep;
    g.alt.jid = g.canon.jid;
    g.alt.fin = 0;
    g.alt_on = 1;
    adv(6);
    chain_reorg(&g.canon, 8, 0);
    adv(2 * SPE);
    inst_die(prim(1), (int)(2 * SPE));
    adv(3 * SPE);
    g.vc[0].alt = 1;
    adv(5 * SPE);
    g.vc[0].alt = 0;
    adv(10 * SPE);
}

/* Double VC during reorgs: a second VC on a branch that splits off and
 * rejoins, and on the same chain one slot behind. */
static void scn_dvcreorg(void)
{
    adv(4 * SPE);
    for (int round = 0; round < 6 && !g.stop; round++) {
        memcpy(g.alt.ids, g.canon.ids, (g.cur - SLOT0 + 1) * 8);
        g.alt.jep = g.canon.jep;
        g.alt.jid = g.canon.jid;
        g.alt.fin = 1;
        g.alt_on = 1;
        g.vc[1].on = 1;
        g.vc[1].alt = round % 2 == 0;
        g.vc[1].lag = round % 2;
        g.vc[1].next = g.vc[0].next;
        adv(SPE + 5);
        chain_reorg(&g.canon, 12 + rnd() % 30, round % 3 == 2);
        adv(2 * SPE);
        g.vc[1].on = 0;
        adv(2 * SPE);
    }
}

/* Clock jump plus restart: host clock one epoch ahead for 3 epochs (early
 * duties), then 40 minutes of downtime for signer 0, then a restart of signer
 * 1 with no trusted time for 6 slots, then 2 epochs behind. */
static void scn_clockjump(void)
{
    adv(5 * SPE);
    g.host_off_ms = (int64_t)EPOCH_S * 1000;
    adv(3 * SPE);
    g.host_off_ms = 0;
    adv(5 * SPE);
    inst_die(prim(0), (int)(40 * 60 / SPS));
    adv(10 * SPE);
    g.sync_block_until[1] = g.cur + 6;
    inst_restart(prim(1));
    adv(5 * SPE);
    g.host_off_ms = -(int64_t)(2 * EPOCH_S * 1000);
    adv(4 * SPE);
    g.host_off_ms = 0;
    adv(10 * SPE);
}

/* 16 keys; the host raises each key's source one by one every epoch while
 * the chain does not finalize (TASKS.md, "16 writes in one epoch"). */
static void scn_raise16(void)
{
    adv(3 * SPE);
    g.canon.fin = 0;
    adv(40 * SPE + 1); /* first slot of an epoch, before most duties */
    for (int e = 0; e < 2 && !g.stop; e++) {
        uint64_t t = cur_epoch(), s = g.canon.jep + 1 + (uint64_t)e * (uint64_t)g.nk;
        for (int k = 0; k < g.nk; k++, s++)
            forge_vote(k, s < t ? s : t, t, (uint8_t)(k + e), 0);
        adv(SPE);
    }
    adv(4 * SPE);
}

/* Restart at a random point of every epoch for 40 epochs, finalizing, one
 * signer at a time: the per-restart cost with finality. */
static void scn_restarts(void)
{
    adv(3 * SPE);
    for (int e = 0; e < 60 && !g.stop; e++) {
        adv(rnd() % SPE);
        if (e % 6 == 0)
            inst_restart(prim(e / 6 % g_n));
        adv(SPE - (g.cur + 1) % SPE);
    }
    adv(5 * SPE);
}

/* A key moves in from another setup that signed it for 20 epochs: the
 * maxima are imported (EIP-3076) into all three signers before the first
 * duty; then the old setup's last votes come again from a hostile host. */
static void scn_migrate(void)
{
    prehistory(cur_epoch() - 20, cur_epoch());
    import_all(0);
    for (int e = 0; e < 20 && !g.stop; e++) {
        adv(SPE);
        if (e < 5)
            for (int k = 0; k < g.nk; k++)
                forge_vote(k, cur_epoch() - 3, cur_epoch() - 2, (uint8_t)(0x90 + e), 0);
    }
}

/*
 * Fork schedule updates near the fork (sc_signer_set_schedule, the `open`
 * config group). No signer has FORK1 at the start, and the update that adds
 * it reaches each signer at another time. With m = max_epochs_ahead the rule
 * takes it until epoch FORK1 - m - 2:
 *   signer 0 gets it early, first with activate_at at the fork (refused),
 *     then without (taken), and restarts as the fork starts;
 *   signer 1 gets it in the last epoch the rule allows (taken) and restarts
 *     right after;
 *   signer 2 gets it one epoch later (refused). It signs the fork's first
 *     epochs under the old version, then takes a late fix: version 7 from the
 *     first epoch the rule allows at that time.
 * Signers 0 and 1 make the threshold across the fork. The oracles check that
 * no pair is slashable and that no signer signs an epoch under two versions.
 */
static void scn_sched(void)
{
    uint64_t m = g.prof[0]->mea, at_fork = GENESIS + FORK1 * EPOCH_S;
    adv_to(FORK1 - m - 10, 2);
    sched_update(0, FORK1, at_fork, SC_ERR_SCHEDULE);
    sched_update(0, FORK1, 0, SC_OK);
    adv_to(FORK1 - m - 2, SPE / 2);
    sched_update(1, FORK1, 0, SC_OK);
    inst_restart(prim(1));
    adv_to(FORK1 - m - 1, SPE / 2);
    sched_update(2, FORK1, 0, SC_ERR_SCHEDULE);
    adv_to(FORK1, 0);
    inst_restart(prim(0));
    adv_to(FORK1 + 3, 2);
    sched_update(2, cur_epoch() + m + 2, 0, SC_OK);
    adv(10 * SPE);
}

static const scen_t SCENS[] = {
    {"reorg7", 8, 0, scn_reorg7},         {"deepreorg", 8, 0, scn_deepreorg},
    {"nonfinal200", 8, 0, scn_nonfinal200}, {"crashloop-nf", 8, 0, scn_crashloop},
    {"fork", 8, 4, scn_fork},             {"dvc-reorg", 8, 0, scn_dvcreorg},
    {"clock-restart", 8, 0, scn_clockjump}, {"raise16", 16, 0, scn_raise16},
    {"restarts", 8, 0, scn_restarts},    {"migrate", 8, 0, scn_migrate},
    {"sched", 8, 7, scn_sched},
};
#define NSCEN (int)(sizeof SCENS / sizeof SCENS[0])

/* ---- reports ------------------------------------------------------------------------------------------------------------ */

static const char *LNAME[L_N] = {"down", "notsent", "clock", "storage", "restart-fin",
                                 "restart-nf", "src-back", "tgt-dup", "crash", "other"};

static void print_reasons(const char *label, const uint64_t *v)
{
    int any = 0;
    printf("    %-14s", label);
    for (int i = 0; i < L_N; i++)
        if (v[i]) {
            printf(" %s=%" PRIu64, LNAME[i], v[i]);
            any = 1;
        }
    printf("%s\n", any ? "" : " none");
}

static void print_metrics(const char *scen, const char *prof, const sim_metrics *m)
{
    uint64_t wh = 0;
    for (int i = 0; i < 6; i++)
        wh += m->writes_hist[i];
    printf("%-13s %-11s slots %-6" PRIu64 " signed %-7" PRIu64 " | validator att missed %" PRIu64
           " of %" PRIu64 ", blocks missed %" PRIu64 " of %" PRIu64
           " | restarts %" PRIu64 " crashes %" PRIu64 " | violations single %" PRIu64
           " combined %" PRIu64 " clock %" PRIu64 " sched %" PRIu64 "\n",
           scen, prof, m->slots, m->signed_ok, m->val_att_miss, m->val_att_ok + m->val_att_miss,
           m->val_blk_miss, m->val_blk_ok + m->val_blk_miss, m->restarts, m->crashes,
           m->viol_single, m->viol_combined, m->viol_clock, m->viol_sched);
    if (m->sched_set + m->sched_refused)
        printf("    fork schedule updates: %" PRIu64 " taken, %" PRIu64 " refused\n", m->sched_set,
               m->sched_refused);
    print_reasons("refused/signer", m->refuse);
    print_reasons("missed/valid.", m->val_miss);
    print_reasons("cost vs ref", m->cost);
    printf("    after restart: %" PRIu64 " key-restarts lost epochs, mean %.2f, max %" PRIu64
           ", not recovered by the end %" PRIu64 "\n",
           m->lost_n, m->lost_n ? (double)m->lost_sum / (double)m->lost_n : 0.0, m->lost_max,
           m->lost_never);
    printf("    writes: max %" PRIu64 " in one epoch on one signer, %" PRIu64
           " total (+%" PRIu64 " record writes); signer-epochs with 0/1/2/3/4-15/16+ writes:"
           " %" PRIu64 "/%" PRIu64 "/%" PRIu64 "/%" PRIu64 "/%" PRIu64 "/%" PRIu64
           "; signed up to %" PRId64 " epochs past real time; TA clock ahead max %" PRIu64
           " s; excess vs ref %" PRIu64 "\n",
           m->writes_max, m->writes_total, m->record_writes, m->writes_hist[0], m->writes_hist[1],
           m->writes_hist[2], m->writes_hist[3], m->writes_hist[4], m->writes_hist[5],
           m->max_ahead_real, m->ta_clock_ahead_max, m->excess);
    if (m->first_violation[0])
        printf("    FIRST VIOLATION: %s\n", m->first_violation);
    (void)wh;
}

static int run_scenario(const scen_t *sc, int prof, uint64_t seed, sim_metrics *m)
{
    int profs[NSIGMAX];
    for (int i = 0; i < NSIGMAX; i++)
        profs[i] = prof;
    static int init;
    if (!init) {
        optab_init();
        init = 1;
    }
    run_start(profs, sc->nk, 0, seed, sc->nofork_mask);
    g.max_slots = 100000;
    g.prop_div = 64; /* about one block every 2 epochs over 8 keys */
    adv(4 * SPE); /* warm-up: a fresh cloud runner refuses up to its floor */
    memset(&g.m, 0, sizeof g.m);
    sc->run();
    adv(2 * SPE);
    run_finish(m);
    return (int)(m->viol_single + m->viol_combined + m->viol_clock + m->viol_sched);
}

/* Negative controls: setups outside a profile's threat model, run on
 * purpose, that must produce violations, so the oracle is known to catch
 * them; and the same attacks inside the model, which must not. */

/* Every key, every target from back epochs ago to now, a vote with a root
 * no honest VC makes, to all three signers. */
static void forge_sweep(uint64_t back, uint8_t tag)
{
    for (int k = 0; k < g.nk; k++)
        for (uint64_t t = cur_epoch() - back; t <= cur_epoch(); t++)
            forge_vote(k, t - 1, t, tag, 0);
}

/* Storage of m signers (2 of 3: signers 0 and 1) rolled back 10 epochs,
 * then forged votes. */
static void nc_rollback(void)
{
    adv(5 * SPE);
    for (int i = 0; i < g_m; i++) {
        g.snap[i] = prim(i)->disk;
        g.has_snap[i] = 1;
    }
    adv(10 * SPE);
    for (int i = 0; i < g_m; i++)
        do_rollback(i);
    for (int e = 0; e < 30 && !g.stop; e++) {
        forge_sweep(12, (uint8_t)(0x40 + e));
        adv(SPE);
    }
}

/* Clones of signers 0 and 1; a second VC on another branch talks to the
 * clones, the first VC to the originals. */
static void nc_clone(void)
{
    adv(5 * SPE);
    memcpy(g.alt.ids, g.canon.ids, (g.cur - SLOT0 + 1) * 8);
    g.alt.jep = g.canon.jep;
    g.alt.jid = g.canon.jid;
    g.alt.fin = 1;
    g.alt_on = 1;
    for (int i = 0; i < g_m; i++)
        do_clone(i);
    g.vc[1].on = 1;
    g.vc[1].alt = 1;
    g.vc[1].next = g.vc[0].next;
    for (int e = 0; e < 10 && !g.stop; e++) {
        adv(SPE);
        forge_sweep(3, (uint8_t)(0x60 + e));
    }
}

/* Crashes in the middle of mark writes, every one torn, then forged votes
 * and blocks. A byte-torn mark is old or new per field except where a carry
 * crosses the cut (block slots wrap their low byte every 8 epochs). */
static void nc_torn(void)
{
    g.torn_cut = 9; /* new magic, flags and low byte of block_slot; old rest */
    adv(3 * SPE);
    for (int e = 0; e < 400 && !g.stop; e++) {
        for (int i = 0; i < g_n; i++)
            crash_at_next_store(i, ACT_TORN, 1);
        adv(SPE);
        forge_sweep(4, (uint8_t)(0x20 + e));
        for (int k = 0; k < g.nk; k++)
            for (uint64_t sl = g.cur - 2 * SPE; sl <= g.cur; sl += 3) {
                req_t r;
                memset(&r, 0, sizeof r);
                r.kind = R_BLK;
                r.key = (uint8_t)k;
                r.forged = 1;
                r.b.slot = sl;
                r.b.proposer_index = 1000 + (uint64_t)k;
                root_of(mix(sl + (uint64_t)e), 0xe1, r.b.body_root);
                r.due_ms = g.now_ms;
                deliver(&r);
            }
    }
}

/* Trusted clock 500 s fast on signers 0 and 1, far-ahead votes, restart
 * with the clock 300 s slow: the floor (clock epoch + margin) lands below
 * what was signed. Outside the model (the quorum clock is sub-second);
 * the record floor still covers it. */
static void nc_clockerr(void)
{
    adv(5 * SPE + SPE / 2);
    uint8_t mm = (uint8_t)((1u << g_m) - 1);
    for (int i = 0; i < g_m; i++) {
        g.clk_err_ms[i] = 500000;
        anch_refresh(prim(i));
    }
    for (int k = 0; k < g.nk; k++)
        forge_vote(k, g.canon.jep, epoch_of_s((g.now_ms + 500000) / 1000) + prim(0)->p->mea,
                   0x71, mm);
    for (int i = 0; i < g_m; i++) {
        g.clk_err_ms[i] = -300000;
        inst_restart(prim(i));
    }
    for (int e = 0; e < 4 && !g.stop; e++) {
        forge_sweep(0, (uint8_t)(0x72 + e));
        for (int k = 0; k < g.nk; k++)
            forge_vote(k, g.canon.jep, cur_epoch() + 1 + (uint64_t)e % 2, (uint8_t)(0x80 + e), mm);
        adv(SPE);
    }
}

/* Hostile routing (research/cloud-slashing-ledger.md section 2.4), for any
 * m of n with n > m: the host stops honest duties, sends vote m1 to signers
 * 0..m-1, rolls back signers 0..m-2 (their disks, and the mark log where
 * its admin can), then sends a vote that surrounds m1 to signers 0..m-2
 * and signer m, which never saw m1. m signatures on each: a slashable pair
 * unless every rolled-back signer still refuses the second vote. */
static void nc_hostile_route(void)
{
    uint8_t m1mask = (uint8_t)((1u << g_m) - 1);
    uint8_t m2mask = (uint8_t)(((1u << (g_m - 1)) - 1) | (1u << g_m));
    uint64_t ta;
    if (g_n < g_m + 1)
        return;
    adv(6 * SPE);
    g.vc[0].on = 0; /* only the host's votes from here */
    adv(SPE);
    ta = cur_epoch();
    for (int i = 0; i < g_m - 1; i++) {
        g.snap[i] = prim(i)->disk;
        g.has_snap[i] = 1;
        g.xsnap[i] = g.xlog[i];
        g.has_xsnap[i] = 1;
    }
    for (int k = 0; k < g.nk; k++)
        forge_vote(k, ta, ta + 1, 0x51, m1mask);
    adv(SPE / 2);
    for (int i = 0; i < g_m - 1; i++) {
        if (prim(i)->p->xlog_mutable && g.has_xsnap[i]) {
            g.xlog[i] = g.xsnap[i]; /* the store's admin restores the older copy */
            g.m.store_rb_done++;
        }
        if (g.allow_stale) /* and a listing that lags by exactly the records since */
            g.stale_n[i] = (int)(g.xlog[i].hn - g.xsnap[i].hn);
        do_rollback(i);
    }
    for (int e = 0; e < 8 && !g.stop; e++) {
        adv(SPE);
        for (int k = 0; k < g.nk; k++)
            forge_vote(k, ta - 1, cur_epoch() + 2, (uint8_t)(0x60 + e), m2mask);
    }
}

static void nc_hostile_route_stale(void)
{
    g.allow_stale = 1;
    nc_hostile_route();
}

/* Hostile routing where signers 0..m-2 come back with their local store
 * lost instead of rolled back: no hint, no sealed state; the log alone
 * must make them refuse the surrounding vote. */
static void nc_hostile_route_wipe(void)
{
    uint8_t m1mask = (uint8_t)((1u << g_m) - 1);
    uint8_t m2mask = (uint8_t)(((1u << (g_m - 1)) - 1) | (1u << g_m));
    uint64_t ta;
    if (g_n < g_m + 1)
        return;
    adv(6 * SPE);
    g.vc[0].on = 0;
    adv(SPE);
    ta = cur_epoch();
    for (int k = 0; k < g.nk; k++)
        forge_vote(k, ta, ta + 1, 0x51, m1mask);
    adv(SPE / 2);
    for (int i = 0; i < g_m - 1; i++)
        do_wipe(i);
    for (int e = 0; e < 8 && !g.stop; e++) {
        adv(SPE);
        for (int k = 0; k < g.nk; k++)
            forge_vote(k, ta - 1, cur_epoch() + 2, (uint8_t)(0x60 + e), m2mask);
    }
}

/* Signers 0..m-1 hand over to a new image; then a second validator client
 * on a diverging chain drives the old instances (the clone slot) while the
 * first drives the new ones, with forged sweeps on top. With the tombstone
 * the old instances sign only inside their committed mark and the new ones
 * start above it; without it both sides sign the same epochs. */
static void nc_handover_run(int tombstone)
{
    adv(5 * SPE);
    memcpy(g.alt.ids, g.canon.ids, (g.cur - SLOT0 + 1) * 8);
    g.alt.jep = g.canon.jep;
    g.alt.jid = g.canon.jid;
    g.alt.fin = 1;
    g.alt_on = 1;
    for (int i = 0; i < g_m; i++)
        do_handover(i, tombstone);
    g.vc[1].on = 1;
    g.vc[1].alt = 1;
    g.vc[1].next = g.vc[0].next;
    for (int e = 0; e < 10 && !g.stop; e++) {
        adv(SPE);
        forge_sweep(3, (uint8_t)(0x70 + e));
    }
}

static void nc_handover(void) { nc_handover_run(1); }
static void nc_handover_open(void) { nc_handover_run(0); }

/* The same migration with no import. */
static void nc_noimport(void)
{
    prehistory(cur_epoch() - 20, cur_epoch() + 1);
    for (int e = 0; e < 3 && !g.stop; e++) {
        adv(SPE);
        forge_sweep(4, (uint8_t)(0x90 + e));
    }
}

static void nc_import(void)
{
    prehistory(cur_epoch() - 20, cur_epoch() + 1);
    import_all(0);
    for (int e = 0; e < 3 && !g.stop; e++) {
        adv(SPE);
        forge_sweep(4, (uint8_t)(0x90 + e));
    }
}

/*
 * One epoch into the fork, an update moves FORK1 three epochs later, which
 * sc_signer_set_schedule refuses (checked). With bypass the host then
 * restarts signer 0 with that schedule anyway. The fork version oracle must
 * catch the epoch signed under two versions. Marks count epochs, never the
 * domain, so the slashing oracles must not fire (invariant 13): a slashable
 * pair clears the counts, which fails the control.
 */
static void nc_sched_run(int bypass)
{
    adv_to(FORK1 + 1, SPE / 2);
    sched_update(0, FORK1 + 3, 0, SC_ERR_SCHEDULE);
    if (bypass) {
        g.f1[0] = FORK1 + 3;
        inst_restart(prim(0));
    }
    adv(4 * SPE);
    if (bypass && g.m.viol_single + g.m.viol_combined)
        g.m.viol_single = g.m.viol_combined = g.m.viol_clock = g.m.viol_sched = 0;
}

static void nc_sched_bypass(void) { nc_sched_run(1); }
static void nc_sched_rule(void) { nc_sched_run(0); }

static int negative_controls(void)
{
    struct {
        const char *name, *prof;
        int rollback, clone, torn, nk, expect;
        void (*run)(void);
    } nc[] = {
        {"ta storage rollback (no RPMB)", "ta", 1, 0, 0, 4, 1, nc_rollback},
        {"cloud-ext-mut hostile routing, store admin rolls the log back", "cloud-ext-mut", 1, 0, 0, 4, 1, nc_hostile_route},
        {"cloud-ext hostile routing, stale listing and rolled-back hint (in model: the claim's create conflicts)", "cloud-ext", 1, 0, 0, 4, 0, nc_hostile_route_stale},
        {"cloud-ext hostile routing (in model: locked log)", "cloud-ext", 1, 0, 0, 4, 0, nc_hostile_route},
        {"cloud-ext hostile routing, local store lost (in model: the log's keys come from key release)", "cloud-ext", 1, 0, 0, 4, 0, nc_hostile_route_wipe},
        {"cloud hostile routing (in model: floor with source bound)", "cloud", 1, 0, 0, 4, 0, nc_hostile_route},
        {"cloud-norec hostile routing (in model)", "cloud-norec", 1, 0, 0, 4, 0, nc_hostile_route},
        {"cloud-ext rollback (in model)", "cloud-ext", 1, 0, 0, 4, 0, nc_rollback},
        {"cloud-ext clone (in model)", "cloud-ext", 0, 1, 0, 4, 0, nc_clone},
        {"cloud-ext handover (in model: tombstone)", "cloud-ext", 0, 0, 0, 4, 0, nc_handover},
        {"cloud-ext handover, old log left open", "cloud-ext", 0, 0, 0, 4, 1, nc_handover_open},
        {"cloud-ext clock 13 min off (log)", "cloud-ext", 0, 0, 0, 4, 0, nc_clockerr},
        {"pv-persist storage rollback", "pv-persist", 1, 0, 0, 4, 1, nc_rollback},
        {"cloud-norec clone", "cloud-norec", 0, 1, 0, 4, 1, nc_clone},
        {"pv-persist torn writes", "pv-persist", 0, 0, 1, 4, 1, nc_torn},
        {"cloud rollback (in model)", "cloud", 1, 0, 0, 4, 0, nc_rollback},
        {"cloud clone (in model)", "cloud", 0, 1, 0, 4, 0, nc_clone},
        {"cloud-t clone (in model)", "cloud-t", 0, 1, 0, 4, 0, nc_clone},
        {"cloud-norec rollback (in model)", "cloud-norec", 1, 0, 0, 4, 0, nc_rollback},
        {"ta torn writes (atomic store)", "ta", 0, 0, 1, 4, 0, nc_torn},
        {"cloud-norec clock 13 min off", "cloud-norec", 0, 0, 0, 4, 1, nc_clockerr},
        {"cloud clock 13 min off (record)", "cloud", 0, 0, 0, 4, 0, nc_clockerr},
        {"ta key moved in, no import", "ta", 0, 0, 0, 4, 1, nc_noimport},
        {"pv-persist key moved in, no import", "pv-persist", 0, 0, 0, 4, 1, nc_noimport},
        {"ta key moved in, import", "ta", 0, 0, 0, 4, 0, nc_import},
        {"cloud key moved in, import", "cloud", 0, 0, 0, 4, 0, nc_import},
        {"pv-persist key moved in, import", "pv-persist", 0, 0, 0, 4, 0, nc_import},
        {"cloud started fork moved by a restart", "cloud", 0, 0, 0, 4, 1, nc_sched_bypass},
        {"cloud started fork moved by an update (in model: refused)", "cloud", 0, 0, 0, 4, 0, nc_sched_rule},
        {"ta started fork moved by a restart", "ta", 0, 0, 0, 4, 1, nc_sched_bypass},
        {"ta started fork moved by an update (in model: refused)", "ta", 0, 0, 0, 4, 0, nc_sched_rule},
    };
    int fails = 0;
    for (size_t n = 0; n < sizeof nc / sizeof nc[0]; n++) {
        int p = prof_by_name(nc[n].prof), profs[NSIGMAX];
        for (int i = 0; i < NSIGMAX; i++)
            profs[i] = p;
        sim_metrics m;
        uint64_t v;
        run_start(profs, nc[n].nk, 0, 77 + n, 0);
        g.allow_rollback = nc[n].rollback;
        g.allow_clone = nc[n].clone;
        g.allow_torn = nc[n].torn;
        g.max_slots = 100000;
        nc[n].run();
        run_finish(&m);
        v = m.viol_single + m.viol_combined + m.viol_clock + m.viol_sched;
        printf("%-34s %-11s violations single %4" PRIu64 " combined %4" PRIu64 " clock %" PRIu64
               " sched %" PRIu64 " -> %s\n",
               nc[n].name, nc[n].prof, m.viol_single, m.viol_combined, m.viol_clock, m.viol_sched,
               (v != 0) == nc[n].expect ? "as expected" : "UNEXPECTED");
        if (m.first_violation[0])
            printf("    first: %s\n", m.first_violation);
        fails += (v != 0) != nc[n].expect;
    }
    return fails;
}

static double now_s(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static void sum_metrics(sim_metrics *a, const sim_metrics *b)
{
    uint64_t *pa = (uint64_t *)a;
    const uint64_t *pb = (const uint64_t *)b;
    /* every field before max_ahead_real is a counter */
    size_t n = offsetof(sim_metrics, max_ahead_real) / sizeof(uint64_t);
    uint64_t wmax = a->writes_max > b->writes_max ? a->writes_max : b->writes_max;
    uint64_t lmax = a->lost_max > b->lost_max ? a->lost_max : b->lost_max;
    for (size_t i = 0; i < n; i++)
        pa[i] += pb[i];
    a->writes_max = wmax;
    a->lost_max = lmax;
    if (b->max_ahead_real > a->max_ahead_real)
        a->max_ahead_real = b->max_ahead_real;
    if (b->ta_clock_ahead_max > a->ta_clock_ahead_max)
        a->ta_clock_ahead_max = b->ta_clock_ahead_max;
    if (!a->first_violation[0] && b->first_violation[0])
        memcpy(a->first_violation, b->first_violation, sizeof a->first_violation);
}

#ifndef SIM_NO_MAIN

static int read_file(const char *path, uint8_t **buf, size_t *len)
{
    FILE *f = fopen(path, "rb");
    long n;
    if (!f)
        return -1;
    fseek(f, 0, SEEK_END);
    n = ftell(f);
    fseek(f, 0, SEEK_SET);
    *buf = malloc((size_t)n + 1);
    *len = fread(*buf, 1, (size_t)n, f);
    fclose(f);
    return 0;
}

int main(int argc, char **argv)
{
    const char *mode = argc > 1 ? argv[1] : "scen";
    const char *cl = getenv("SIM_CLUSTER"); /* "n/m", default 3/2 */
    if (cl) {
        int n = 0, m = 0;
        if (sscanf(cl, "%d/%d", &n, &m) != 2 || sim_set_cluster(n, m) != 0) {
            fprintf(stderr, "SIM_CLUSTER=%s: want n/m with 1 <= m <= n <= %d\n", cl, NSIGMAX);
            return 2;
        }
        printf("cluster: %d signers, threshold %d\n", n, m);
    }
    if (!strcmp(mode, "scen")) {
        const char *which = argc > 2 ? argv[2] : "all", *pw = argc > 3 ? argv[3] : "all";
        int bad = 0;
        double t0 = now_s();
        uint64_t slots = 0;
        for (int s = 0; s < NSCEN; s++) {
            if (strcmp(which, "all") && strcmp(which, SCENS[s].name))
                continue;
            for (int p = 0; p < NPROF; p++) {
                sim_metrics m;
                if (strcmp(pw, "all") ? strcmp(pw, PROFS[p].name) != 0 : PROFS[p].xlog_mutable)
                    continue; /* cloud-ext-mut is outside the design: by name only */
                bad += run_scenario(&SCENS[s], p, 1000 + (uint64_t)s, &m) != 0;
                print_metrics(SCENS[s].name, PROFS[p].name, &m);
                slots += m.slots;
            }
        }
        printf("scenarios: %" PRIu64 " slots in %.1f s, %d with violations\n", slots, now_s() - t0,
               bad);
        return bad != 0;
    }
    if (!strcmp(mode, "nc"))
        return negative_controls() != 0;
    if (!strcmp(mode, "seed")) {
        uint64_t first = argc > 2 ? strtoull(argv[2], NULL, 0) : 1;
        uint64_t count = argc > 3 ? strtoull(argv[3], NULL, 0) : 100;
        const char *pw = argc > 4 ? argv[4] : "all";
        uint64_t max_slots = argc > 5 ? strtoull(argv[5], NULL, 0) : 20000;
        double t0 = now_s();
        int bad = 0;
        for (int p = 0; p < NPROF; p++) {
            sim_metrics tot;
            if (strcmp(pw, "all") ? strcmp(pw, PROFS[p].name) != 0 : PROFS[p].xlog_mutable)
                continue; /* cloud-ext-mut is outside the design: by name only */
            memset(&tot, 0, sizeof tot);
            for (uint64_t sd = first; sd < first + count; sd++) {
                src_t src = {NULL, 0, 0, sd * 0x9e3779b97f4a7c15ull + (uint64_t)p, 1};
                sim_metrics m;
                run_src(&src, max_slots, &m, sd, p);
                if (m.viol_single + m.viol_combined + m.viol_clock + m.viol_sched) {
                    printf("seed %" PRIu64 " profile %s: %s\n", sd, PROFS[p].name,
                           m.first_violation);
                    bad++;
                }
                sum_metrics(&tot, &m);
            }
            print_metrics("seeded", PROFS[p].name, &tot);
            printf("    runs %" PRIu64 ", events %" PRIu64 ", requests %" PRIu64
                   ", sign calls %" PRIu64 ", store calls %" PRIu64 ", rollbacks %" PRIu64
                   ", clones %" PRIu64 ", lost-state restarts %" PRIu64 ", handovers %" PRIu64
                   " (%" PRIu64 " refused, store down), %.1f s so far\n",
                   count, tot.events, tot.requests, tot.sign_calls, tot.store_calls,
                   tot.rollbacks, tot.clones, tot.state_wipes, tot.handovers, tot.handover_failed,
                   now_s() - t0);
            fflush(stdout);
        }
        return bad != 0;
    }
    if (!strcmp(mode, "run")) {
        int bad = 0;
        for (int i = 2; i < argc; i++) {
            uint8_t *buf;
            size_t len;
            sim_metrics m;
            if (read_file(argv[i], &buf, &len)) {
                perror(argv[i]);
                return 2;
            }
            bad += sim_run_bytes(buf, len, &m) != 0;
            print_metrics(argv[i], "(input)", &m);
            free(buf);
        }
        return bad != 0;
    }
    if (!strcmp(mode, "gen") && argc > 3) {
        uint64_t sd = strtoull(argv[2], NULL, 0);
        FILE *f = fopen(argv[3], "wb");
        src_t src = {NULL, 0, 0, sd, 1};
        for (int i = 0; i < 1024; i++)
            fputc(rd8(&src), f);
        fclose(f);
        return 0;
    }
    fprintf(stderr, "usage: sim scen [name|all] [profile|all] | sim seed FIRST COUNT [profile|all] "
                    "[max_slots] | sim nc | sim run FILE... | sim gen SEED FILE\n");
    return 2;
}
#endif
