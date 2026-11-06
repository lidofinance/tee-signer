/*
 * Config readers: sc_signer_init_ext with a patched config and slot time
 * changes (what the runner builds from a setup), then sc_signer_set_policy,
 * the fork schedule update (sc_signer_check/set_schedule_under with pending
 * slot time lists) and the slot time update. The runner passes all of
 * these over cgo.
 *
 * Oracles: an out-of-range count, scope or zero slot length is refused;
 * the slot clock never runs backwards; a schedule update the core accepts
 * keeps the fork version of every epoch up to epoch(T) + max_epochs_ahead
 * + 1; a slot time update it accepts keeps the slot clock up to that epoch;
 * a policy update keeps the chain fields; check and set agree, except that
 * a set with activate_at counts the clock only as far as a signing call
 * read it, so T is then the later of activate_at and that reading. With
 * flag 8 the input also signs randao reveals and may pass activate_at 0;
 * a reveal signs no epoch past the clock horizon, and no schedule set
 * changes the fork version of an epoch a reveal signed.
 */
#include "base_config.h"

static uint64_t g_now;
static uint64_t g_sign_now; /* the latest clock reading of a signing call */
static int g_extra;         /* flag 8: signing calls and activate_at 0 */
static int g_loaded;        /* the validator is loaded */
static const uint8_t g_pk[48] = {0xa5};

/* Epochs a reveal signed and their version roots then. */
#define NSIGNED 8
static uint64_t g_signed[NSIGNED];
static uint8_t g_signed_root[NSIGNED][32];
static int g_nsigned;

static int h_now(void *ctx, uint64_t *t)
{
    (void)ctx;
    *t = g_now;
    return SC_OK;
}

static int h_load(void *ctx, const uint8_t pk[48], sc_watermark *out)
{
    (void)ctx, (void)pk, (void)out;
    return SC_ERR_UNKNOWN_VALIDATOR;
}

static int h_store(void *ctx, const uint8_t pk[48], const sc_watermark *wm)
{
    (void)ctx, (void)pk, (void)wm;
    return SC_OK;
}

static int h_load_dev(void *ctx, sc_watermark *out)
{
    (void)ctx, (void)out;
    return SC_ERR_UNKNOWN_VALIDATOR;
}

static int h_store_dev(void *ctx, const sc_watermark *wm)
{
    (void)ctx, (void)wm;
    return SC_OK;
}

static int surely_bad(const sc_config *c, const sc_slot_times *t)
{
    return c->seconds_per_slot == 0 || c->slots_per_epoch == 0 ||
           c->fork_count > SC_MAX_FORKS || c->fee_recipient_count > SC_MAX_FEE_RECIPIENTS ||
           c->builder_auth_root_count > SC_MAX_BUILDER_AUTH_ROOTS || c->mark_scope > 1 ||
           c->gloas_scheduled > 1 ||
           c->gas_limit_min > c->gas_limit_max || t->count > SC_MAX_SLOT_TIMES;
}

static void version_root(const sc_signer *s, uint64_t epoch, uint8_t out[32])
{
    static const uint8_t attester[4] = {1, 0, 0, 0};
    static const uint8_t zero[32];
    FUZZ_CHECK(sc_signer_signing_root(s, attester, epoch, zero, out) == SC_OK);
}

/* Smallest t with sc_epoch_at(cfg, times, t) >= epoch, or UINT64_MAX. */
static uint64_t epoch_start(const sc_config *cfg, const sc_slot_times *times, uint64_t epoch)
{
    uint64_t lo = 0, hi = UINT64_MAX;
    if (sc_epoch_at(cfg, times, hi) < epoch)
        return UINT64_MAX;
    while (lo < hi) {
        uint64_t mid = lo + (hi - lo) / 2;
        if (sc_epoch_at(cfg, times, mid) >= epoch)
            hi = mid;
        else
            lo = mid + 1;
    }
    return lo;
}

static uint64_t sat_add(uint64_t a, uint64_t b) { return a > UINT64_MAX - b ? UINT64_MAX : a + b; }

/* epoch(t) + max_epochs_ahead + 1 under times and the pending lists. */
static uint64_t limit_at(const sc_config *cfg, const sc_slot_times *times,
                         const sc_slot_times *pending, uint32_t np, uint64_t t)
{
    uint64_t lim = sc_epoch_at(cfg, times, t);
    for (uint32_t i = 0; i < np; i++) {
        uint64_t e = sc_epoch_at(cfg, &pending[i], t);
        lim = e > lim ? e : lim;
    }
    return sat_add(sat_add(lim, cfg->max_epochs_ahead), 1);
}

/* The README's rule: limit_at the later of activate_at and now. */
static uint64_t rule_limit(const sc_config *cfg, const sc_slot_times *times,
                           const sc_slot_times *pending, uint32_t np, uint64_t activate_at)
{
    return limit_at(cfg, times, pending, np, activate_at > g_now ? activate_at : g_now);
}

/* The clock a set with activate_at counts. */
static uint64_t set_clock(uint64_t activate_at)
{
    return activate_at > g_sign_now ? activate_at : g_sign_now;
}

/* Non-zero if a set may refuse what the check passed: its clock is later. */
static int set_later(uint64_t activate_at)
{
    return activate_at && set_clock(activate_at) > (activate_at > g_now ? activate_at : g_now);
}

static uint64_t max64(uint64_t a, uint64_t b) { return a > b ? a : b; }

/* activate_at near the clock; with flag 8, 0 one time in 8. */
static uint64_t fz_activate_at(fz_in *in)
{
    uint64_t at = fz_near(in, g_now);
    if (g_extra && (fz_u8(in) & 7) == 0)
        at = 0;
    return at;
}

static void do_sign(sc_signer *s, const sc_config *cfg, const sc_slot_times *times, fz_in *in)
{
    uint8_t sig[96];
    uint64_t epoch = fz_near(in, sc_epoch_at(cfg, times, g_now));
    int rc;
    if (!g_loaded)
        return;
    rc = sc_sign_randao_reveal(s, g_pk, epoch, sig);
    FUZZ_CHECK(rc == SC_OK || rc == SC_ERR_POLICY_FUTURE);
    g_sign_now = max64(g_sign_now, g_now); /* the core reads the clock first */
    if (rc != SC_OK)
        return;
    FUZZ_CHECK(epoch <= sat_add(sc_epoch_at(cfg, times, g_now), cfg->max_epochs_ahead));
    if (g_nsigned < NSIGNED) {
        g_signed[g_nsigned] = epoch;
        version_root(s, epoch, g_signed_root[g_nsigned++]);
    }
}

static void check_clock(const sc_config *cfg, const sc_slot_times *times, fz_in *in)
{
    uint64_t t[8], prev = 0;
    for (int i = 0; i < 8; i++)
        t[i] = fz_near(in, cfg->genesis_time + FZ_E * FZ_EPOCH_SECONDS) + (uint64_t)i;
    for (int i = 1; i < 8; i++) /* sort */
        for (int k = i; k > 0 && t[k] < t[k - 1]; k--) {
            uint64_t x = t[k];
            t[k] = t[k - 1];
            t[k - 1] = x;
        }
    for (int i = 0; i < 8; i++) {
        uint64_t slot = sc_slot_at(cfg, times, t[i]);
        FUZZ_CHECK(slot >= prev);
        FUZZ_CHECK(sc_epoch_at(cfg, times, t[i]) == slot / cfg->slots_per_epoch);
        prev = slot;
    }
}

static void do_schedule(sc_signer *s, sc_config *cfg, const sc_slot_times *times, fz_in *in)
{
    sc_schedule next;
    sc_slot_times pending[3];
    uint32_t np = fz_u8(in) % 4;
    uint64_t activate_at = fz_activate_at(in), lim, epochs[2 * SC_MAX_FORKS + 6];
    uint8_t before[2 * SC_MAX_FORKS + 6][32], after[32];
    int rc, rc2, rc_set, n = 0;

    fz_schedule(&next, cfg, in);
    for (uint32_t i = 0; i < np; i++)
        fz_slot_times(&pending[i], in);
    rc = sc_signer_check_schedule_under(s, &next, activate_at, np ? pending : NULL, np);
    FUZZ_CHECK(rc == SC_OK || rc == SC_ERR_ARG || rc == SC_ERR_SCHEDULE);
    /* A set with activate_at counts the clock only as far as a signing call
     * read it: only a schedule refusal may differ, and a set it lets through
     * keeps the epochs up to the limit at set_clock. One the check passed
     * also keeps those up to the limit of the check. */
    if (rc != SC_OK && (rc != SC_ERR_SCHEDULE || !activate_at)) {
        FUZZ_CHECK(sc_signer_set_schedule_under(s, &next, activate_at, np ? pending : NULL, np) == rc);
        return;
    }
    lim = activate_at ? limit_at(cfg, times, pending, np, set_clock(activate_at)) : 0;
    if (rc == SC_OK)
        lim = max64(lim, rule_limit(cfg, times, pending, np, activate_at));
    epochs[n++] = 0;
    epochs[n++] = lim;
    epochs[n++] = lim / 2;
    epochs[n] = g_now > cfg->genesis_time ? sc_epoch_at(cfg, times, g_now) : 0;
    if (epochs[n] <= lim)
        n++;
    for (uint32_t i = 0; i < SC_MAX_FORKS; i++) {
        if (i < next.fork_count && next.forks[i].epoch <= lim)
            epochs[n++] = next.forks[i].epoch;
        if (i < cfg->fork_count && cfg->forks[i].epoch <= lim)
            epochs[n++] = cfg->forks[i].epoch;
    }
    for (int i = 0; i < n; i++)
        version_root(s, epochs[i], before[i]);
    rc_set = sc_signer_set_schedule_under(s, &next, activate_at, np ? pending : NULL, np);
    FUZZ_CHECK(rc_set == SC_OK ||
               (rc_set == SC_ERR_SCHEDULE && (rc != SC_OK || set_later(activate_at))));
    if (rc_set != SC_OK)
        return;
    for (int i = 0; i < n; i++) {
        version_root(s, epochs[i], after);
        FUZZ_CHECK(memcmp(before[i], after, 32) == 0);
    }
    /* activate_at 0 counts the trusted clock, and the rule assumes it does
     * not run back below a reading a signing call made. */
    for (int i = 0; i < g_nsigned && (activate_at || g_now >= g_sign_now); i++) {
        version_root(s, g_signed[i], after);
        FUZZ_CHECK(memcmp(g_signed_root[i], after, 32) == 0);
    }
    rc2 = sc_signer_check_schedule_under(s, &next, activate_at, NULL, 0);
    FUZZ_CHECK(rc2 == SC_OK); /* the schedule in force is always acceptable */
    memcpy(cfg->forks, next.forks, sizeof cfg->forks);
    cfg->fork_count = next.fork_count;
    cfg->gloas_scheduled = next.gloas_scheduled;
    cfg->gloas_fork_epoch = next.gloas_fork_epoch;
}

static void do_slot_times(sc_signer *s, const sc_config *cfg, sc_slot_times *times, fz_in *in)
{
    sc_slot_times next, held;
    uint64_t activate_at = fz_activate_at(in), lim, ts[2 * SC_MAX_SLOT_TIMES + 9];
    int rc, rc_set, n = 0;

    fz_slot_times(&next, in);
    rc = sc_signer_check_slot_times(s, &next, activate_at);
    FUZZ_CHECK(rc == SC_OK || rc == SC_ERR_ARG || rc == SC_ERR_SCHEDULE);
    if (next.count > SC_MAX_SLOT_TIMES)
        FUZZ_CHECK(rc == SC_ERR_ARG);
    /* A set with activate_at counts the clock only as far as a signing call
     * read it: only a schedule refusal may differ. */
    rc_set = sc_signer_set_slot_times(s, &next, activate_at);
    if (rc != SC_ERR_SCHEDULE || !activate_at)
        FUZZ_CHECK(rc_set == rc || (rc == SC_OK && rc_set == SC_ERR_SCHEDULE && set_later(activate_at)));
    if (rc_set != SC_OK)
        return;
    sc_signer_get_slot_times(s, &held);
    FUZZ_CHECK(held.count == next.count);
    lim = activate_at ? limit_at(cfg, times, NULL, 0, set_clock(activate_at)) : 0;
    if (rc == SC_OK)
        lim = max64(lim, rule_limit(cfg, times, NULL, 0, activate_at));
    /* Times up to the start of epoch lim + 1 under the old list. */
    ts[n++] = g_now;
    ts[n++] = g_sign_now;
    ts[n++] = activate_at;
    ts[n++] = epoch_start(cfg, times, sat_add(lim, 1));
    if (ts[n - 1] != UINT64_MAX && ts[n - 1] > 0)
        ts[n - 1]--;
    for (uint32_t i = 0; i < times->count && i < SC_MAX_SLOT_TIMES; i++)
        ts[n++] = epoch_start(cfg, times, times->changes[i].epoch);
    for (uint32_t i = 0; i < next.count && i < SC_MAX_SLOT_TIMES; i++)
        ts[n++] = epoch_start(cfg, times, next.changes[i].epoch);
    for (int i = 0; i < n; i++) {
        if (ts[i] == UINT64_MAX || sc_epoch_at(cfg, times, ts[i]) > lim)
            continue;
        FUZZ_CHECK(sc_slot_at(cfg, times, ts[i]) == sc_slot_at(cfg, &next, ts[i]));
    }
    *times = next;
}

static void do_policy(sc_signer *s, const sc_config *cfg, fz_in *in)
{
    sc_config pol = *cfg;
    uint8_t before[32], after[32];
    uint8_t n = fz_u8(in) % 4;
    int rc;
    for (uint8_t i = 0; i < n; i++)
        fz_patch_config(&pol, in);
    version_root(s, FZ_E, before);
    rc = sc_signer_set_policy(s, &pol);
    FUZZ_CHECK(rc == SC_OK || rc == SC_ERR_ARG);
    if (pol.fee_recipient_count > SC_MAX_FEE_RECIPIENTS ||
        pol.builder_auth_root_count > SC_MAX_BUILDER_AUTH_ROOTS ||
        pol.gas_limit_min > pol.gas_limit_max)
        FUZZ_CHECK(rc == SC_ERR_ARG);
    version_root(s, FZ_E, after);
    FUZZ_CHECK(memcmp(before, after, 32) == 0);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    fz_in in = {data, size};
    sc_config cfg;
    sc_slot_times times;
    sc_host_ops ops = {0};
    sc_signer *s = NULL;
    uint8_t flags = fz_u8(&in), npatch = fz_u8(&in) % 8;
    uint32_t maxv = flags & 0x80 ? fz_u32(&in) : 1u + fz_u8(&in) % 8u;
    uint32_t cache = flags & 0x40 ? fz_u32(&in) : fz_u8(&in) % 5;
    size_t need, mem_len;
    void *mem;
    int rc;

    g_extra = flags & 8;
    g_loaded = 0;
    g_sign_now = 0;
    g_nsigned = 0;
    fz_base_config(&cfg);
    for (uint8_t i = 0; i < npatch; i++)
        fz_patch_config(&cfg, &in);
    fz_slot_times(&times, &in);
    g_now = fz_near(&in, FZ_GENESIS_TIME + FZ_E * FZ_EPOCH_SECONDS);

    ops.now = h_now;
    if (!(flags & 1)) ops.load_watermark = h_load;
    if (!(flags & 2)) ops.store_watermark = h_store;
    if (!(flags & 4)) ops.load_device_mark = h_load_dev, ops.store_device_mark = h_store_dev;

    need = sc_signer_mem_size(maxv, cache);
    if (need == 0 || need > (64u << 20))
        need = sc_signer_mem_size(1, 0);
    mem_len = flags & 0x10 ? need - 8 : need;
    mem = aligned_alloc(8, (need + 7) & ~(size_t)7);
    if (!mem)
        abort();
    rc = sc_signer_init_ext(mem, mem_len, maxv, cache, &cfg, (flags & 0x20) ? NULL : &times, &ops,
                            &s);
    FUZZ_CHECK(rc == SC_OK || rc == SC_ERR_ARG || rc == SC_ERR_NOMEM);
    if (surely_bad(&cfg, (flags & 0x20) ? &(sc_slot_times){0} : &times))
        FUZZ_CHECK(rc != SC_OK);
    if (rc != SC_OK) {
        free(mem);
        return 0;
    }
    if (flags & 0x20)
        memset(&times, 0, sizeof times);

    check_clock(&cfg, &times, &in);
    if (g_extra) {
        static const uint8_t sk[32] = {[31] = 7};
        g_loaded = sc_signer_add_validator(s, g_pk, sk, 1, NULL) == SC_OK;
    }
    for (int step = 0; step < 8 && in.n; step++) {
        switch (fz_u8(&in) % (g_extra ? 5 : 4)) {
        case 0: do_schedule(s, &cfg, &times, &in); break;
        case 1: do_slot_times(s, &cfg, &times, &in); break;
        case 2: do_policy(s, &cfg, &in); break;
        case 4: do_sign(s, &cfg, &times, &in); break;
        default: g_now = fz_near(&in, g_now); check_clock(&cfg, &times, &in); break;
        }
    }
    sc_signer_wipe(s);
    free(mem);
    return 0;
}
