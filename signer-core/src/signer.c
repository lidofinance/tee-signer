/* Signer object: validator table, policy, slashing protection, exact
 * repeats, signing. */
#include "sc_internal.h"

typedef struct {
    uint8_t pubkey[SC_PUBKEY_LEN];       /* validator (account) pubkey */
    uint8_t share_pubkey[SC_PUBKEY_LEN]; /* pubkey of the loaded secret */
    uint64_t index;
    blst_scalar sk;
    /* With SC_MARKS_PER_DEVICE only slash.ram is used; the signer's device
     * mark stands in for slash.committed. */
    sc_slashing_state slash;
    sc_repeat_roots repeat;
    /* Gloas, RAM only (see sc_sign_payload_attestation in signer_core.h). */
    uint32_t gloas;                     /* G_* flags */
    uint64_t ptc_slot;                  /* G_PTC: no PTC vote at or below this slot */
    uint64_t envelope_slot;             /* G_ENVELOPE: no envelope at or below this slot */
    uint8_t ptc_root[SC_ROOT_LEN];      /* G_PTC_ROOT: last PTC vote's signing root */
    uint8_t envelope_root[SC_ROOT_LEN]; /* G_ENVELOPE_ROOT: last envelope's signing root */
    uint64_t block_slot;                /* G_BLOCK: the last block signed in this run */
    uint8_t block_root[SC_ROOT_LEN];    /* its hash_tree_root */
    uint8_t block_parent[SC_ROOT_LEN];  /* its parent_root */
} sc_validator;

#define G_PTC 0x1u
#define G_ENVELOPE 0x2u
#define G_PTC_ROOT 0x4u
#define G_ENVELOPE_ROOT 0x8u
#define G_BLOCK 0x10u

struct sc_signer {
    sc_config cfg;
    sc_host_ops ops;
    uint32_t max_validators;
    uint32_t count;
    uint32_t table_mask; /* table size - 1, size is a power of two */
    sc_validator *validators;
    uint32_t *table; /* 0 = empty, else validator position + 1 */
    sc_h2g2_cache cache;
    sc_signer_stats stats;
    sc_watermark device; /* SC_MARKS_PER_DEVICE: the stored device mark */
    int device_loaded;
    sc_slot_times slot_times; /* the slot time changes in force */
};

#define MAX_VALIDATORS_LIMIT (1u << 24)

static size_t align8(size_t n) { return (n + 7u) & ~(size_t)7u; }

static uint32_t table_size_for(uint32_t max_validators)
{
    uint32_t size = 2;
    while (size < 2u * max_validators)
        size <<= 1;
    return size;
}

size_t sc_signer_mem_size(uint32_t max_validators, uint32_t hash_cache_entries)
{
    if (max_validators == 0 || max_validators > MAX_VALIDATORS_LIMIT ||
        hash_cache_entries > 65536)
        return 0;
    return align8(sizeof(struct sc_signer)) +
           align8((size_t)max_validators * sizeof(sc_validator)) +
           align8((size_t)table_size_for(max_validators) * sizeof(uint32_t)) +
           align8((size_t)hash_cache_entries * sizeof(sc_h2g2_entry));
}

int sc_signer_init(void *mem, size_t mem_len, uint32_t max_validators,
                   uint32_t hash_cache_entries, const sc_config *cfg,
                   const sc_host_ops *ops, sc_signer **out)
{
    return sc_signer_init_ext(mem, mem_len, max_validators, hash_cache_entries, cfg, NULL, ops, out);
}

int sc_signer_init_ext(void *mem, size_t mem_len, uint32_t max_validators,
                       uint32_t hash_cache_entries, const sc_config *cfg,
                       const sc_slot_times *times, const sc_host_ops *ops, sc_signer **out)
{
    size_t need = sc_signer_mem_size(max_validators, hash_cache_entries);
    uint8_t *p = (uint8_t *)mem;
    sc_signer *s;
    uint32_t table_size;

    if (!mem || !cfg || !ops || !out || need == 0 || ((uintptr_t)mem & 7u))
        return SC_ERR_ARG;
    if (!ops->now || cfg->mark_scope > SC_MARKS_PER_DEVICE)
        return SC_ERR_ARG;
    if (cfg->mark_scope == SC_MARKS_PER_VALIDATOR && (!ops->load_watermark || !ops->store_watermark))
        return SC_ERR_ARG;
    if (cfg->mark_scope == SC_MARKS_PER_DEVICE && (!ops->load_device_mark || !ops->store_device_mark))
        return SC_ERR_ARG;
    if (sc_policy_check_config(cfg) != SC_OK || sc_slot_times_check(cfg, times) != SC_OK)
        return SC_ERR_ARG;
    if (mem_len < need)
        return SC_ERR_NOMEM;

    memset(mem, 0, need);
    s = (sc_signer *)p;
    p += align8(sizeof *s);
    s->validators = (sc_validator *)p;
    p += align8((size_t)max_validators * sizeof(sc_validator));
    table_size = table_size_for(max_validators);
    s->table = (uint32_t *)p;
    p += align8((size_t)table_size * sizeof(uint32_t));
    sc_h2g2_cache_init(&s->cache, hash_cache_entries ? (sc_h2g2_entry *)p : NULL,
                       hash_cache_entries);

    s->cfg = *cfg;
    if (times)
        s->slot_times = *times;
    s->ops = *ops;
    s->max_validators = max_validators;
    s->table_mask = table_size - 1;
    *out = s;
    return SC_OK;
}

void sc_signer_wipe(sc_signer *s)
{
    if (!s)
        return;
    sc_wipe(s->validators, (size_t)s->max_validators * sizeof(sc_validator));
    sc_wipe(s->table, (size_t)(s->table_mask + 1) * sizeof(uint32_t));
    sc_h2g2_cache_wipe(&s->cache);
    s->count = 0;
    s->device_loaded = 0;
}

/* FNV-1a over the compressed pubkey. */
static uint32_t pubkey_hash(const uint8_t pk[SC_PUBKEY_LEN])
{
    uint64_t h = 0xcbf29ce484222325ull;
    for (int i = 0; i < SC_PUBKEY_LEN; i++) {
        h ^= pk[i];
        h *= 0x100000001b3ull;
    }
    return (uint32_t)(h ^ (h >> 32));
}

/* Returns the table position holding pk, or the empty position where it
 * would go. The table is never full: it has at least 2x max_validators. */
static uint32_t table_probe(const sc_signer *s, const uint8_t pk[SC_PUBKEY_LEN])
{
    uint32_t pos = pubkey_hash(pk) & s->table_mask;
    for (;;) {
        uint32_t v = s->table[pos];
        if (v == 0 || memcmp(s->validators[v - 1].pubkey, pk, SC_PUBKEY_LEN) == 0)
            return pos;
        pos = (pos + 1) & s->table_mask;
    }
}

static sc_validator *find_validator(const sc_signer *s, const uint8_t pk[SC_PUBKEY_LEN])
{
    uint32_t v;
    if (!s || !pk)
        return NULL;
    v = s->table[table_probe(s, pk)];
    return v ? &s->validators[v - 1] : NULL;
}

/* Gloas slot bounds after a load: the stored block bound covers every slot
 * this device or validator may have signed a PTC vote or envelope for. */
static void gloas_restore(sc_validator *v, const sc_watermark *mark)
{
    v->gloas = 0;
    if (mark->flags & SC_WM_HAS_BLOCK) {
        v->ptc_slot = v->envelope_slot = mark->block_slot;
        v->gloas = G_PTC | G_ENVELOPE;
    }
}

/* Starts v's slashing state from its own stored mark, or from the device
 * mark (read from storage once, with the first validator). */
static int load_marks(sc_signer *s, sc_validator *v, const uint8_t pubkey[SC_PUBKEY_LEN])
{
    sc_watermark wm;
    int rc;

    memset(&wm, 0, sizeof wm);
    if (s->cfg.mark_scope == SC_MARKS_PER_DEVICE) {
        if (!s->device_loaded) {
            rc = s->ops.load_device_mark(s->ops.ctx, &wm);
            if (rc == SC_ERR_UNKNOWN_VALIDATOR)
                memset(&wm, 0, sizeof wm);
            else if (rc != SC_OK)
                return SC_ERR_STORAGE;
            wm.flags &= SC_WM_HAS_BLOCK | SC_WM_HAS_ATTESTATION;
            s->device = wm;
            s->device_loaded = 1;
        }
        sc_slashing_restore(&v->slash, &s->device);
        gloas_restore(v, &s->device);
        return SC_OK;
    }
    rc = s->ops.load_watermark(s->ops.ctx, pubkey, &wm);
    if (rc == SC_OK)
        sc_slashing_restore(&v->slash, &wm);
    else if (rc == SC_ERR_UNKNOWN_VALIDATOR)
        sc_slashing_restore(&v->slash, NULL);
    else
        return SC_ERR_STORAGE;
    gloas_restore(v, &v->slash.committed);
    return SC_OK;
}

int sc_signer_add_validator(sc_signer *s, const uint8_t pubkey[SC_PUBKEY_LEN],
                            const uint8_t secret[SC_SECRET_LEN], uint64_t validator_index,
                            uint8_t share_pubkey_out[SC_PUBKEY_LEN])
{
    sc_validator *v;
    blst_p1 pk;
    uint32_t pos;
    int rc;

    if (!s || !pubkey || !secret)
        return SC_ERR_ARG;
    pos = table_probe(s, pubkey);
    if (s->table[pos])
        return SC_ERR_DUPLICATE;
    if (s->count >= s->max_validators)
        return SC_ERR_NOMEM;

    /* The slot is already zero (init, or the wipe after a failed load);
     * zero it again so a load never starts with old repeat roots. */
    v = &s->validators[s->count];
    memset(v, 0, sizeof *v);
    rc = sc_bls_load_secret(&v->sk, secret);
    if (rc != SC_OK)
        return rc;

    rc = load_marks(s, v, pubkey);
    if (rc != SC_OK) {
        sc_wipe(v, sizeof *v);
        return rc;
    }

    memcpy(v->pubkey, pubkey, SC_PUBKEY_LEN);
    blst_sk_to_pk_in_g1(&pk, &v->sk);
    blst_p1_compress(v->share_pubkey, &pk);
    v->index = validator_index;
    if (share_pubkey_out)
        memcpy(share_pubkey_out, v->share_pubkey, SC_PUBKEY_LEN);

    s->count++;
    s->table[pos] = s->count;
    return SC_OK;
}

/* Wraps the host store callback to count writes. */
static int counted_store(void *ctx, const uint8_t pubkey[SC_PUBKEY_LEN], const sc_watermark *wm)
{
    sc_signer *s = (sc_signer *)ctx;
    int rc = s->ops.store_watermark(s->ops.ctx, pubkey, wm);
    if (rc == SC_OK)
        s->stats.watermark_writes++;
    return rc;
}

/* Wraps the host's device mark callback to count writes. */
static int counted_store_device(void *ctx, const sc_watermark *wm)
{
    sc_signer *s = (sc_signer *)ctx;
    int rc = s->ops.store_device_mark(s->ops.ctx, wm);
    if (rc == SC_OK)
        s->stats.watermark_writes++;
    return rc;
}

/* The same in the sc_store_fn shape sc_slashing_import takes; the device
 * mark belongs to no pubkey. */
static int counted_store_device_pk(void *ctx, const uint8_t pubkey[SC_PUBKEY_LEN],
                                   const sc_watermark *wm)
{
    (void)pubkey;
    return counted_store_device(ctx, wm);
}

/* Slashing check, commit ahead, record: per-validator or per-device marks. */
static int approve_attestation(sc_signer *s, sc_validator *v, const uint8_t pubkey[SC_PUBKEY_LEN],
                               uint64_t source, uint64_t target)
{
    if (s->cfg.mark_scope == SC_MARKS_PER_DEVICE)
        return sc_slashing_approve_attestation_device(&v->slash, &s->device, &s->cfg.commit_ahead,
                                                      s->cfg.slots_per_epoch, counted_store_device,
                                                      s, source, target);
    return sc_slashing_approve_attestation(&v->slash, &s->cfg.commit_ahead, counted_store, s,
                                           pubkey, source, target);
}

static int approve_block(sc_signer *s, sc_validator *v, const uint8_t pubkey[SC_PUBKEY_LEN],
                         uint64_t slot)
{
    if (s->cfg.mark_scope == SC_MARKS_PER_DEVICE)
        return sc_slashing_approve_block_device(&v->slash, &s->device, &s->cfg.commit_ahead,
                                                s->cfg.slots_per_epoch, counted_store_device, s,
                                                slot);
    return sc_slashing_approve_block(&v->slash, &s->cfg.commit_ahead, counted_store, s, pubkey,
                                     slot);
}

/* Non-zero if root is the validator's last signed root of this kind. */
static int is_repeat(const sc_validator *v, uint32_t kind, const uint8_t root[SC_ROOT_LEN])
{
    const uint8_t *last = kind == SC_REPEAT_HAS_BLOCK ? v->repeat.block_root
                                                      : v->repeat.attestation_root;
    return (v->repeat.flags & kind) && memcmp(last, root, SC_ROOT_LEN) == 0;
}

/* Keeps root as the last one of its kind, in RAM only: after a restart the
 * marks refuse a repeat. */
static void remember_root(sc_validator *v, uint32_t kind, const uint8_t root[SC_ROOT_LEN])
{
    memcpy(kind == SC_REPEAT_HAS_BLOCK ? v->repeat.block_root : v->repeat.attestation_root, root,
           SC_ROOT_LEN);
    v->repeat.flags |= kind;
}

/* Raises the Gloas slot bounds to an imported block bound: the history
 * may hold a PTC vote or envelope for any slot up to it (VSGLOAS-01). */
static void gloas_raise(sc_validator *v, const sc_watermark *imported)
{
    if (!(imported->flags & SC_WM_HAS_BLOCK))
        return;
    if (!(v->gloas & G_PTC) || v->ptc_slot < imported->block_slot)
        v->ptc_slot = imported->block_slot;
    if (!(v->gloas & G_ENVELOPE) || v->envelope_slot < imported->block_slot)
        v->envelope_slot = imported->block_slot;
    v->gloas |= G_PTC | G_ENVELOPE;
}

/*
 * Forgets the validator's repeat roots of every kind. An import brings
 * history signed elsewhere: the last root may be a vote that history
 * conflicts with (a signature lost before release, then a vote inside it
 * signed by another signer), and a repeat skips the slashing check.
 */
static void drop_repeat(sc_validator *v)
{
    memset(&v->repeat, 0, sizeof v->repeat);
    v->gloas &= ~(G_PTC_ROOT | G_ENVELOPE_ROOT);
}

int sc_signer_import(sc_signer *s, const uint8_t pubkey[SC_PUBKEY_LEN],
                     const uint8_t genesis_validators_root[SC_ROOT_LEN],
                     const sc_watermark *imported)
{
    sc_validator *v = find_validator(s, pubkey);
    sc_slashing_state tmp;
    int rc;

    if (!v)
        return s && pubkey ? SC_ERR_UNKNOWN_VALIDATOR : SC_ERR_ARG;
    if (!genesis_validators_root ||
        memcmp(genesis_validators_root, s->cfg.genesis_validators_root, SC_ROOT_LEN) != 0)
        return SC_ERR_ARG;
    drop_repeat(v);
    if (s->cfg.mark_scope == SC_MARKS_PER_VALIDATOR) {
        rc = sc_slashing_import(&v->slash, imported, counted_store, s, pubkey);
        if (rc == SC_OK)
            gloas_raise(v, imported);
        return rc;
    }
    /* Per device: the import raises the device mark and this validator's RAM. */
    tmp.ram = v->slash.ram;
    tmp.committed = s->device;
    rc = sc_slashing_import(&tmp, imported, counted_store_device_pk, s, pubkey);
    if (rc == SC_OK) {
        v->slash.ram = tmp.ram;
        s->device = tmp.committed;
        gloas_raise(v, imported);
    }
    return rc;
}

int sc_signer_get_state(const sc_signer *s, const uint8_t pubkey[SC_PUBKEY_LEN],
                        sc_slashing_state *out)
{
    const sc_validator *v = find_validator(s, pubkey);
    if (!out)
        return SC_ERR_ARG;
    if (!v)
        return s && pubkey ? SC_ERR_UNKNOWN_VALIDATOR : SC_ERR_ARG;
    *out = v->slash;
    if (s->cfg.mark_scope == SC_MARKS_PER_DEVICE)
        out->committed = s->device;
    return SC_OK;
}

int sc_signer_cover_epoch(sc_signer *s, uint64_t epoch)
{
    if (!s || s->cfg.mark_scope != SC_MARKS_PER_DEVICE)
        return SC_ERR_ARG;
    if (!s->device_loaded)
        return SC_OK; /* no validator yet: nothing to cover */
    return sc_slashing_cover_device(&s->device, &s->cfg.commit_ahead, s->cfg.slots_per_epoch,
                                    counted_store_device, s, epoch);
}

int sc_signer_get_repeat_roots(const sc_signer *s, const uint8_t pubkey[SC_PUBKEY_LEN],
                               sc_repeat_roots *out)
{
    const sc_validator *v = find_validator(s, pubkey);
    if (!out)
        return SC_ERR_ARG;
    if (!v)
        return s && pubkey ? SC_ERR_UNKNOWN_VALIDATOR : SC_ERR_ARG;
    *out = v->repeat;
    return SC_OK;
}

int sc_signer_set_policy(sc_signer *s, const sc_config *policy)
{
    sc_config merged;

    if (!s || !policy)
        return SC_ERR_ARG;
    merged = s->cfg;
    memcpy(merged.exit_allowlist, policy->exit_allowlist, sizeof merged.exit_allowlist);
    merged.exit_allowlist_count = policy->exit_allowlist_count;
    memcpy(merged.fee_recipients, policy->fee_recipients, sizeof merged.fee_recipients);
    merged.fee_recipient_count = policy->fee_recipient_count;
    merged.gas_limit_min = policy->gas_limit_min;
    merged.gas_limit_max = policy->gas_limit_max;
    merged.registration_max_future_seconds = policy->registration_max_future_seconds;
    memcpy(merged.builder_auth_roots, policy->builder_auth_roots, sizeof merged.builder_auth_roots);
    merged.builder_auth_root_count = policy->builder_auth_root_count;
    if (sc_policy_check_config(&merged) != SC_OK)
        return SC_ERR_ARG;
    s->cfg = merged;
    return SC_OK;
}

static int gloas_on(const sc_config *cfg, uint64_t epoch)
{
    return cfg->gloas_scheduled && epoch >= cfg->gloas_fork_epoch;
}

/* Non-zero if a and b give epoch the same fork version and Gloas state. */
static int same_schedule_at(const sc_config *a, const sc_config *b, uint64_t epoch)
{
    uint8_t va[SC_VERSION_LEN], vb[SC_VERSION_LEN];
    sc_fork_version_at(a, epoch, va);
    sc_fork_version_at(b, epoch, vb);
    return memcmp(va, vb, SC_VERSION_LEN) == 0 && gloas_on(a, epoch) == gloas_on(b, epoch);
}

/*
 * Non-zero if a and b agree at every epoch up to limit. A schedule changes
 * only at its fork epochs and its Gloas epoch, so epoch 0 and those epochs of
 * both schedules, up to limit, cover every epoch up to limit.
 */
static int same_schedule_through(const sc_config *a, const sc_config *b, uint64_t limit)
{
    const sc_config *both[2] = {a, b};
    if (!same_schedule_at(a, b, 0))
        return 0;
    for (int k = 0; k < 2; k++) {
        const sc_config *c = both[k];
        for (uint32_t i = 0; i < c->fork_count; i++)
            if (c->forks[i].epoch <= limit && !same_schedule_at(a, b, c->forks[i].epoch))
                return 0;
        if (c->gloas_scheduled && c->gloas_fork_epoch <= limit &&
            !same_schedule_at(a, b, c->gloas_fork_epoch))
            return 0;
    }
    return 1;
}

/* The checks of sc_signer_check_schedule_under. On SC_OK, *merged is the
 * signer's config with next in place. */
static int schedule_rule(const sc_signer *s, const sc_schedule *next, uint64_t activate_at,
                         const sc_slot_times *pending, uint32_t pending_count, sc_config *merged)
{
    uint64_t now, t, limit;

    if (!s || !next || next->fork_count > SC_MAX_FORKS || (pending_count && !pending))
        return SC_ERR_ARG;
    for (uint32_t i = 0; i < pending_count; i++)
        if (sc_slot_times_check(&s->cfg, &pending[i]) != SC_OK)
            return SC_ERR_ARG;
    *merged = s->cfg;
    memcpy(merged->forks, next->forks, sizeof merged->forks);
    merged->fork_count = next->fork_count;
    merged->gloas_scheduled = next->gloas_scheduled;
    merged->gloas_fork_epoch = next->gloas_fork_epoch;
    if (sc_policy_check_config(merged) != SC_OK)
        return SC_ERR_ARG;
    if (s->ops.now(s->ops.ctx, &now) != SC_OK)
        return SC_ERR_CLOCK;
    /* Before T the signer may sign up to epoch(T) + max_epochs_ahead under
     * whichever slot times are in force by then: the ones it holds, or a
     * pending list that comes into force before T. The largest epoch counts;
     * the rule keeps one more epoch unchanged as a margin. */
    t = sc_max64(activate_at, now);
    limit = sc_epoch_at(&s->cfg, &s->slot_times, t);
    for (uint32_t i = 0; i < pending_count; i++)
        limit = sc_max64(limit, sc_epoch_at(&s->cfg, &pending[i], t));
    limit = sc_sat_add(sc_sat_add(limit, s->cfg.max_epochs_ahead), 1);
    return same_schedule_through(&s->cfg, merged, limit) ? SC_OK : SC_ERR_SCHEDULE;
}

int sc_signer_check_schedule(const sc_signer *s, const sc_schedule *next, uint64_t activate_at)
{
    return sc_signer_check_schedule_under(s, next, activate_at, NULL, 0);
}

int sc_signer_set_schedule(sc_signer *s, const sc_schedule *next, uint64_t activate_at)
{
    return sc_signer_set_schedule_under(s, next, activate_at, NULL, 0);
}

int sc_signer_check_schedule_under(const sc_signer *s, const sc_schedule *next, uint64_t activate_at,
                                   const sc_slot_times *pending, uint32_t pending_count)
{
    sc_config merged;
    return schedule_rule(s, next, activate_at, pending, pending_count, &merged);
}

int sc_signer_set_schedule_under(sc_signer *s, const sc_schedule *next, uint64_t activate_at,
                                 const sc_slot_times *pending, uint32_t pending_count)
{
    sc_config merged;
    int rc = schedule_rule(s, next, activate_at, pending, pending_count, &merged);
    if (rc == SC_OK)
        s->cfg = merged;
    return rc;
}

/* The slot time of epoch under times. */
static uint64_t slot_time_at(const sc_config *cfg, const sc_slot_times *times, uint64_t epoch)
{
    uint64_t secs = cfg->seconds_per_slot;
    for (uint32_t i = 0; i < times->count; i++)
        if (times->changes[i].epoch <= epoch)
            secs = times->changes[i].seconds_per_slot;
    return secs;
}

/*
 * Non-zero if a and b give every epoch up to limit the same slot time. A list
 * changes the slot time only at its change epochs, and epoch 0 is the genesis
 * slot time in both, so those epochs of both lists, up to limit, cover every
 * epoch up to limit.
 */
static int same_slot_times_through(const sc_config *cfg, const sc_slot_times *a,
                                   const sc_slot_times *b, uint64_t limit)
{
    const sc_slot_times *both[2] = {a, b};
    for (int k = 0; k < 2; k++)
        for (uint32_t i = 0; i < both[k]->count; i++) {
            uint64_t e = both[k]->changes[i].epoch;
            if (e <= limit && slot_time_at(cfg, a, e) != slot_time_at(cfg, b, e))
                return 0;
        }
    return 1;
}

/* The checks of sc_signer_check_slot_times. */
static int slot_time_rule(const sc_signer *s, const sc_slot_times *next, uint64_t activate_at)
{
    uint64_t now, limit;

    if (!s || !next || sc_slot_times_check(&s->cfg, next) != SC_OK)
        return SC_ERR_ARG;
    if (s->ops.now(s->ops.ctx, &now) != SC_OK)
        return SC_ERR_CLOCK;
    /* As schedule_rule: before T the signer signs up to epoch(T) +
     * max_epochs_ahead, and one more epoch stays unchanged as a margin. */
    limit = sc_epoch_at(&s->cfg, &s->slot_times, sc_max64(activate_at, now));
    limit = sc_sat_add(sc_sat_add(limit, s->cfg.max_epochs_ahead), 1);
    return same_slot_times_through(&s->cfg, &s->slot_times, next, limit) ? SC_OK : SC_ERR_SCHEDULE;
}

int sc_signer_check_slot_times(const sc_signer *s, const sc_slot_times *next, uint64_t activate_at)
{
    return slot_time_rule(s, next, activate_at);
}

int sc_signer_set_slot_times(sc_signer *s, const sc_slot_times *next, uint64_t activate_at)
{
    int rc = slot_time_rule(s, next, activate_at);
    if (rc == SC_OK)
        s->slot_times = *next;
    return rc;
}

void sc_signer_get_slot_times(const sc_signer *s, sc_slot_times *out)
{
    if (!s || !out)
        return;
    *out = s->slot_times;
}

void sc_signer_get_stats(const sc_signer *s, sc_signer_stats *out)
{
    if (!s || !out)
        return;
    *out = s->stats;
    out->hash_cache_hits = s->cache.hits;
    out->hash_cache_misses = s->cache.misses;
}

int sc_signer_signing_root(const sc_signer *s, const uint8_t domain_type[SC_DOMAIN_TYPE_LEN],
                           uint64_t epoch, const uint8_t object_root[SC_ROOT_LEN],
                           uint8_t out[SC_ROOT_LEN])
{
    uint8_t domain[SC_ROOT_LEN], version[SC_VERSION_LEN];
    if (!s || !domain_type || !object_root || !out)
        return SC_ERR_ARG;
    if (memcmp(domain_type, SC_DOMAIN_APPLICATION_BUILDER, SC_DOMAIN_TYPE_LEN) == 0) {
        sc_compute_builder_domain(s->cfg.genesis_fork_version, domain);
    } else if (memcmp(domain_type, SC_DOMAIN_BUILDER_REQUEST_AUTH, SC_DOMAIN_TYPE_LEN) == 0) {
        static const uint8_t zero[SC_ROOT_LEN] = {0};
        sc_compute_domain(domain_type, s->cfg.genesis_fork_version, zero, domain);
    } else {
        if (memcmp(domain_type, SC_DOMAIN_VOLUNTARY_EXIT, SC_DOMAIN_TYPE_LEN) == 0)
            memcpy(version, s->cfg.voluntary_exit_fork_version, SC_VERSION_LEN);
        else
            sc_fork_version_at(&s->cfg, epoch, version);
        sc_compute_domain(domain_type, version, s->cfg.genesis_validators_root, domain);
    }
    sc_compute_signing_root(object_root, domain, out);
    return SC_OK;
}

static int read_clock(sc_signer *s, uint64_t *now)
{
    return s->ops.now(s->ops.ctx, now) == SC_OK ? SC_OK : SC_ERR_CLOCK;
}

/* Signs a 32-byte signing root through the hash_to_G2 cache. */
static void sign_root(sc_signer *s, const sc_validator *v, const uint8_t root[SC_ROOT_LEN],
                      uint8_t signature[SC_SIGNATURE_LEN])
{
    blst_p2 scratch;
    const blst_p2 *h = sc_h2g2_cache_get(&s->cache, root, &scratch);
    sc_bls_sign_hashed(&v->sk, h, signature);
    s->stats.signatures++;
}

/* The block a Gloas envelope of this validator must belong to. */
static void remember_block(sc_validator *v, const sc_beacon_block_header *b,
                           const uint8_t obj[SC_ROOT_LEN])
{
    v->block_slot = b->slot;
    memcpy(v->block_root, obj, SC_ROOT_LEN);
    memcpy(v->block_parent, b->parent_root, SC_ROOT_LEN);
    v->gloas |= G_BLOCK;
}

int sc_sign_block(sc_signer *s, const uint8_t pubkey[SC_PUBKEY_LEN],
                  const sc_beacon_block_header *block, uint8_t signature[SC_SIGNATURE_LEN])
{
    sc_validator *v = find_validator(s, pubkey);
    uint8_t obj[SC_ROOT_LEN], root[SC_ROOT_LEN];
    uint64_t now, epoch;
    int rc;

    if (!s || !pubkey || !block || !signature)
        return SC_ERR_ARG;
    if (!v)
        return SC_ERR_UNKNOWN_VALIDATOR;
    if (v->index != SC_INDEX_UNKNOWN && block->proposer_index != v->index)
        return SC_ERR_POLICY_INDEX;
    if ((rc = read_clock(s, &now)) != SC_OK)
        return rc;
    epoch = block->slot / s->cfg.slots_per_epoch;
    if ((rc = sc_policy_check_epoch(&s->cfg, &s->slot_times, now, epoch)) != SC_OK)
        return rc;

    sc_htr_beacon_block_header(block, obj);
    sc_signer_signing_root(s, SC_DOMAIN_BEACON_PROPOSER, epoch, obj, root);
    if (is_repeat(v, SC_REPEAT_HAS_BLOCK, root)) {
        s->stats.exact_repeats++;
        remember_block(v, block, obj);
        sign_root(s, v, root, signature);
        return SC_OK;
    }
    rc = approve_block(s, v, pubkey, block->slot);
    if (rc != SC_OK)
        return rc;
    remember_root(v, SC_REPEAT_HAS_BLOCK, root);
    remember_block(v, block, obj);
    sign_root(s, v, root, signature);
    return SC_OK;
}

int sc_sign_attestation(sc_signer *s, const uint8_t pubkey[SC_PUBKEY_LEN],
                        const sc_attestation_data *data, uint8_t signature[SC_SIGNATURE_LEN])
{
    sc_validator *v = find_validator(s, pubkey);
    uint8_t obj[SC_ROOT_LEN], root[SC_ROOT_LEN];
    uint64_t now;
    int rc;

    if (!s || !pubkey || !data || !signature)
        return SC_ERR_ARG;
    if (!v)
        return SC_ERR_UNKNOWN_VALIDATOR;
    if (data->source.epoch > data->target.epoch)
        return SC_ERR_SLASH_SOURCE_GT_TARGET;
    if ((rc = read_clock(s, &now)) != SC_OK)
        return rc;
    if ((rc = sc_policy_check_epoch(&s->cfg, &s->slot_times, now, data->target.epoch)) != SC_OK)
        return rc;

    sc_htr_attestation_data(data, obj);
    sc_signer_signing_root(s, SC_DOMAIN_BEACON_ATTESTER, data->target.epoch, obj, root);
    if (is_repeat(v, SC_REPEAT_HAS_ATTESTATION, root)) {
        s->stats.exact_repeats++;
        sign_root(s, v, root, signature);
        return SC_OK;
    }
    rc = approve_attestation(s, v, pubkey, data->source.epoch, data->target.epoch);
    if (rc != SC_OK)
        return rc;
    remember_root(v, SC_REPEAT_HAS_ATTESTATION, root);
    sign_root(s, v, root, signature);
    return SC_OK;
}

int sc_sign_randao_reveal(sc_signer *s, const uint8_t pubkey[SC_PUBKEY_LEN], uint64_t epoch,
                          uint8_t signature[SC_SIGNATURE_LEN])
{
    sc_validator *v = find_validator(s, pubkey);
    uint8_t obj[SC_ROOT_LEN], root[SC_ROOT_LEN];
    uint64_t now;
    int rc;

    if (!s || !pubkey || !signature)
        return SC_ERR_ARG;
    if (!v)
        return SC_ERR_UNKNOWN_VALIDATOR;
    if ((rc = read_clock(s, &now)) != SC_OK)
        return rc;
    if ((rc = sc_policy_check_epoch(&s->cfg, &s->slot_times, now, epoch)) != SC_OK)
        return rc;
    sc_htr_uint64(epoch, obj);
    sc_signer_signing_root(s, SC_DOMAIN_RANDAO, epoch, obj, root);
    sign_root(s, v, root, signature);
    return SC_OK;
}

int sc_sign_voluntary_exit(sc_signer *s, const uint8_t pubkey[SC_PUBKEY_LEN],
                           const sc_voluntary_exit *exit, uint8_t signature[SC_SIGNATURE_LEN])
{
    sc_validator *v = find_validator(s, pubkey);
    uint8_t obj[SC_ROOT_LEN], root[SC_ROOT_LEN];
    int rc;

    if (!s || !pubkey || !exit || !signature)
        return SC_ERR_ARG;
    if (!v)
        return SC_ERR_UNKNOWN_VALIDATOR;
    if ((rc = sc_policy_check_exit(&s->cfg, exit, v->index)) != SC_OK)
        return rc;
    sc_htr_voluntary_exit(exit, obj);
    sc_signer_signing_root(s, SC_DOMAIN_VOLUNTARY_EXIT, exit->epoch, obj, root);
    sign_root(s, v, root, signature);
    return SC_OK;
}

int sc_sign_validator_registration(sc_signer *s, const uint8_t pubkey[SC_PUBKEY_LEN],
                                   const sc_validator_registration *reg,
                                   uint8_t signature[SC_SIGNATURE_LEN])
{
    sc_validator *v = find_validator(s, pubkey);
    uint8_t obj[SC_ROOT_LEN], root[SC_ROOT_LEN];
    uint64_t now;
    int rc;

    if (!s || !pubkey || !reg || !signature)
        return SC_ERR_ARG;
    if (!v)
        return SC_ERR_UNKNOWN_VALIDATOR;
    if ((rc = read_clock(s, &now)) != SC_OK)
        return rc;
    if ((rc = sc_policy_check_registration(&s->cfg, now, reg, v->pubkey)) != SC_OK)
        return rc;
    sc_htr_validator_registration(reg, obj);
    sc_signer_signing_root(s, SC_DOMAIN_APPLICATION_BUILDER, 0, obj, root);
    sign_root(s, v, root, signature);
    return SC_OK;
}

/* ---- Gloas ------------------------------------------------------------- */

/*
 * Makes the stored block bound cover slot (one store call if it does not):
 * the device mark by the vote window, or the validator's own mark by
 * commit_ahead.block_slots. PTC votes and envelopes rely on it after a
 * restart, see gloas_restore.
 */
static int cover_slot(sc_signer *s, sc_validator *v, const uint8_t pubkey[SC_PUBKEY_LEN],
                      uint64_t slot)
{
    if (s->cfg.mark_scope == SC_MARKS_PER_DEVICE) {
        if ((s->device.flags & SC_WM_HAS_BLOCK) && slot <= s->device.block_slot)
            return SC_OK;
        return sc_slashing_cover_device(&s->device, &s->cfg.commit_ahead, s->cfg.slots_per_epoch,
                                        counted_store_device, s, slot / s->cfg.slots_per_epoch);
    }
    return sc_slashing_cover_slot(&v->slash, &s->cfg.commit_ahead, counted_store, s, pubkey, slot);
}

/*
 * One message per slot for a slot-keyed Gloas kind: an exact repeat of the
 * last one signs again; anything else at or below the last slot is an
 * equivocation. *repeat is set for a repeat, which needs no further check.
 */
static int slot_rule(const sc_validator *v, uint32_t has_slot, uint64_t last, uint32_t has_root,
                     const uint8_t *last_root, uint64_t slot, const uint8_t root[SC_ROOT_LEN],
                     int *repeat)
{
    *repeat = (v->gloas & has_root) && memcmp(last_root, root, SC_ROOT_LEN) == 0;
    if (*repeat)
        return SC_OK;
    if ((v->gloas & has_slot) && slot <= last)
        return SC_ERR_EQUIVOCATION;
    return SC_OK;
}

/* Gloas in force at epoch, and epoch within the clock horizon. */
static int gloas_epoch_ok(sc_signer *s, uint64_t epoch)
{
    uint64_t now;
    int rc = sc_policy_check_gloas(&s->cfg, epoch);
    if (rc != SC_OK)
        return rc;
    if ((rc = read_clock(s, &now)) != SC_OK)
        return rc;
    return sc_policy_check_epoch(&s->cfg, &s->slot_times, now, epoch);
}

int sc_sign_payload_attestation(sc_signer *s, const uint8_t pubkey[SC_PUBKEY_LEN],
                                const sc_payload_attestation_data *data,
                                uint8_t signature[SC_SIGNATURE_LEN])
{
    sc_validator *v = find_validator(s, pubkey);
    uint8_t obj[SC_ROOT_LEN], root[SC_ROOT_LEN];
    uint64_t epoch;
    int rc, repeat;

    if (!s || !pubkey || !data || !signature || data->payload_present > 1 ||
        data->blob_data_available > 1)
        return SC_ERR_ARG;
    if (!v)
        return SC_ERR_UNKNOWN_VALIDATOR;
    epoch = data->slot / s->cfg.slots_per_epoch;
    if ((rc = gloas_epoch_ok(s, epoch)) != SC_OK)
        return rc;
    sc_htr_payload_attestation_data(data, obj);
    sc_signer_signing_root(s, SC_DOMAIN_PTC_ATTESTER, epoch, obj, root);
    rc = slot_rule(v, G_PTC, v->ptc_slot, G_PTC_ROOT, v->ptc_root, data->slot, root, &repeat);
    if (rc != SC_OK)
        return rc;
    if (repeat) {
        s->stats.exact_repeats++;
    } else {
        if ((rc = cover_slot(s, v, pubkey, data->slot)) != SC_OK)
            return rc;
        v->ptc_slot = data->slot;
        memcpy(v->ptc_root, root, SC_ROOT_LEN);
        v->gloas |= G_PTC | G_PTC_ROOT;
    }
    sign_root(s, v, root, signature);
    return SC_OK;
}

int sc_sign_payload_envelope(sc_signer *s, const uint8_t pubkey[SC_PUBKEY_LEN],
                             const sc_payload_envelope *env, uint8_t signature[SC_SIGNATURE_LEN])
{
    sc_validator *v = find_validator(s, pubkey);
    uint8_t obj[SC_ROOT_LEN], root[SC_ROOT_LEN];
    uint64_t slot, epoch;
    int rc, repeat;

    if (!s || !pubkey || !env || !signature)
        return SC_ERR_ARG;
    if (!v)
        return SC_ERR_UNKNOWN_VALIDATOR;
    slot = env->payload.slot_number;
    epoch = slot / s->cfg.slots_per_epoch;
    if ((rc = gloas_epoch_ok(s, epoch)) != SC_OK)
        return rc;
    /* Our keys are validators, never builders (builder.md: builders are a
     * separate registry). A validator key signs an envelope only for its
     * own self-built payload. */
    if (env->builder_index != SC_BUILDER_INDEX_SELF_BUILD)
        return SC_ERR_POLICY_BUILDER;
    if ((rc = sc_policy_check_fee_recipient(&s->cfg, env->payload.fee_recipient)) != SC_OK)
        return rc;
    /* builder.md: beacon_block_root = hash_tree_root(block) and
     * parent_beacon_block_root = block.parent_root, for the block of this
     * slot. Only the last block this validator signed qualifies. */
    if (!(v->gloas & G_BLOCK) || v->block_slot != slot ||
        memcmp(v->block_root, env->beacon_block_root, SC_ROOT_LEN) != 0 ||
        memcmp(v->block_parent, env->parent_beacon_block_root, SC_ROOT_LEN) != 0)
        return SC_ERR_POLICY_ENVELOPE;
    sc_htr_payload_envelope(env, obj);
    sc_signer_signing_root(s, SC_DOMAIN_BEACON_BUILDER, epoch, obj, root);
    rc = slot_rule(v, G_ENVELOPE, v->envelope_slot, G_ENVELOPE_ROOT, v->envelope_root, slot, root,
                   &repeat);
    if (rc != SC_OK)
        return rc;
    if (repeat) {
        s->stats.exact_repeats++;
    } else {
        if ((rc = cover_slot(s, v, pubkey, slot)) != SC_OK)
            return rc;
        v->envelope_slot = slot;
        memcpy(v->envelope_root, root, SC_ROOT_LEN);
        v->gloas |= G_ENVELOPE | G_ENVELOPE_ROOT;
    }
    sign_root(s, v, root, signature);
    return SC_OK;
}

int sc_sign_proposer_preferences(sc_signer *s, const uint8_t pubkey[SC_PUBKEY_LEN],
                                 const sc_proposer_preferences *pref,
                                 uint8_t signature[SC_SIGNATURE_LEN])
{
    sc_validator *v = find_validator(s, pubkey);
    uint8_t obj[SC_ROOT_LEN], root[SC_ROOT_LEN];
    uint64_t epoch;
    int rc;

    if (!s || !pubkey || !pref || !signature)
        return SC_ERR_ARG;
    if (!v)
        return SC_ERR_UNKNOWN_VALIDATOR;
    if (v->index != SC_INDEX_UNKNOWN && pref->validator_index != v->index)
        return SC_ERR_POLICY_INDEX;
    /* validator.md: compute_fork_version(compute_epoch_at_slot(proposal_slot)). */
    epoch = pref->proposal_slot / s->cfg.slots_per_epoch;
    if ((rc = gloas_epoch_ok(s, epoch)) != SC_OK)
        return rc;
    if ((rc = sc_policy_check_fee_recipient(&s->cfg, pref->fee_recipient)) != SC_OK)
        return rc;
    if (pref->target_gas_limit < s->cfg.gas_limit_min ||
        pref->target_gas_limit > s->cfg.gas_limit_max)
        return SC_ERR_POLICY_GAS_LIMIT;
    sc_htr_proposer_preferences(pref, obj);
    sc_signer_signing_root(s, SC_DOMAIN_PROPOSER_PREFERENCES, epoch, obj, root);
    sign_root(s, v, root, signature);
    return SC_OK;
}

int sc_sign_builder_request_auth(sc_signer *s, const uint8_t pubkey[SC_PUBKEY_LEN],
                                 const sc_builder_request_auth *req,
                                 uint8_t signature[SC_SIGNATURE_LEN])
{
    sc_validator *v = find_validator(s, pubkey);
    uint8_t data_root[SC_ROOT_LEN], obj[SC_ROOT_LEN], root[SC_ROOT_LEN];
    uint32_t i;
    int rc;

    if (!s || !pubkey || !req || !signature || (!req->data && req->data_len))
        return SC_ERR_ARG;
    if (req->data_len > SC_BUILDER_AUTH_MAX_DATA)
        return SC_ERR_DECODE;
    if (!v)
        return SC_ERR_UNKNOWN_VALIDATOR;
    if ((rc = gloas_epoch_ok(s, req->slot / s->cfg.slots_per_epoch)) != SC_OK)
        return rc;
    sc_htr_builder_auth_data(req->data, req->data_len, data_root);
    for (i = 0; i < s->cfg.builder_auth_root_count; i++)
        if (memcmp(s->cfg.builder_auth_roots[i], data_root, SC_ROOT_LEN) == 0)
            break;
    if (i == s->cfg.builder_auth_root_count)
        return SC_ERR_POLICY_BUILDER_AUTH;
    sc_htr_builder_request_auth(req, obj);
    sc_signer_signing_root(s, SC_DOMAIN_BUILDER_REQUEST_AUTH, 0, obj, root);
    sign_root(s, v, root, signature);
    return SC_OK;
}

/* ---- Aggregates and sync committee messages (see signer_core.h) ---- */

static const uint8_t D_SELECTION_PROOF[SC_DOMAIN_TYPE_LEN] = {0x05, 0, 0, 0};
static const uint8_t D_AGGREGATE_AND_PROOF[SC_DOMAIN_TYPE_LEN] = {0x06, 0, 0, 0};
static const uint8_t D_SYNC_COMMITTEE[SC_DOMAIN_TYPE_LEN] = {0x07, 0, 0, 0};
static const uint8_t D_SYNC_SELECTION_PROOF[SC_DOMAIN_TYPE_LEN] = {0x08, 0, 0, 0};
static const uint8_t D_CONTRIBUTION_AND_PROOF[SC_DOMAIN_TYPE_LEN] = {0x09, 0, 0, 0};

/* The checks every typed call makes: arguments, validator, clock horizon. */
static int typed_begin(sc_signer *s, const uint8_t *pubkey, const uint8_t *signature,
                       uint64_t epoch, sc_validator **v)
{
    uint64_t now;
    int rc;

    if (!s || !pubkey || !signature)
        return SC_ERR_ARG;
    if (!(*v = find_validator(s, pubkey)))
        return SC_ERR_UNKNOWN_VALIDATOR;
    if ((rc = read_clock(s, &now)) != SC_OK)
        return rc;
    return sc_policy_check_epoch(&s->cfg, &s->slot_times, now, epoch);
}

/* Signs obj under domain_type at epoch and reports the signing root. */
static void typed_sign(sc_signer *s, const sc_validator *v,
                       const uint8_t domain_type[SC_DOMAIN_TYPE_LEN], uint64_t epoch,
                       const uint8_t obj[SC_ROOT_LEN], uint8_t signature[SC_SIGNATURE_LEN],
                       uint8_t *signing_root)
{
    uint8_t root[SC_ROOT_LEN];

    sc_signer_signing_root(s, domain_type, epoch, obj, root);
    sign_root(s, v, root, signature);
    if (signing_root)
        memcpy(signing_root, root, SC_ROOT_LEN);
}

/* A selection proof must be the validator's (group) signature over obj. */
static int check_selection_proof(const sc_signer *s, const sc_validator *v,
                                 const uint8_t domain_type[SC_DOMAIN_TYPE_LEN], uint64_t epoch,
                                 const uint8_t obj[SC_ROOT_LEN],
                                 const uint8_t proof[SC_SIGNATURE_LEN])
{
    uint8_t root[SC_ROOT_LEN];

    sc_signer_signing_root(s, domain_type, epoch, obj, root);
    return sc_bls_verify(v->pubkey, root, sizeof root, proof) == SC_OK ? SC_OK
                                                                        : SC_ERR_SELECTION_PROOF;
}

static int check_bound_index(const sc_validator *v, uint64_t index)
{
    return v->index != SC_INDEX_UNKNOWN && index != v->index ? SC_ERR_POLICY_INDEX : SC_OK;
}

int sc_sign_selection_proof(sc_signer *s, const uint8_t pubkey[SC_PUBKEY_LEN], uint64_t slot,
                            uint8_t signature[SC_SIGNATURE_LEN], uint8_t *signing_root)
{
    sc_validator *v = NULL;
    uint8_t obj[SC_ROOT_LEN];
    uint64_t epoch;
    int rc;

    if (!s)
        return SC_ERR_ARG;
    epoch = slot / s->cfg.slots_per_epoch;
    if ((rc = typed_begin(s, pubkey, signature, epoch, &v)) != SC_OK)
        return rc;
    sc_htr_uint64(slot, obj);
    typed_sign(s, v, D_SELECTION_PROOF, epoch, obj, signature, signing_root);
    return SC_OK;
}

int sc_sign_aggregate_and_proof(sc_signer *s, const uint8_t pubkey[SC_PUBKEY_LEN],
                                const uint8_t *ssz, size_t len, int form, const sc_preset *p,
                                uint8_t *scratch, uint8_t signature[SC_SIGNATURE_LEN],
                                uint8_t *signing_root)
{
    sc_validator *v = NULL;
    sc_aggregate_info a;
    uint8_t sel[SC_ROOT_LEN];
    uint64_t epoch;
    int gloas, rc;

    if (!s || !ssz || !p || !scratch)
        return SC_ERR_ARG;
    if ((rc = sc_decode_aggregate_and_proof(ssz, len, form, p, scratch, &a)) != SC_OK)
        return rc;
    epoch = a.data.slot / s->cfg.slots_per_epoch;
    if ((rc = typed_begin(s, pubkey, signature, epoch, &v)) != SC_OK)
        return rc;
    /* The form must be the one the aggregate's epoch hashes with: Gloas from
     * the Gloas fork on (beacon-chain.md "Attestation"), the older ones before. */
    gloas = s->cfg.gloas_scheduled && epoch >= s->cfg.gloas_fork_epoch;
    if ((form == SC_AGGREGATE_GLOAS) != gloas)
        return SC_ERR_POLICY_FORK;
    if ((rc = check_bound_index(v, a.aggregator_index)) != SC_OK)
        return rc;
    sc_htr_uint64(a.data.slot, sel);
    rc = check_selection_proof(s, v, D_SELECTION_PROOF, epoch, sel, a.selection_proof);
    if (rc != SC_OK)
        return rc;
    typed_sign(s, v, D_AGGREGATE_AND_PROOF, epoch, a.object_root, signature, signing_root);
    return SC_OK;
}

int sc_sign_sync_committee_message(sc_signer *s, const uint8_t pubkey[SC_PUBKEY_LEN],
                                   uint64_t slot, const uint8_t beacon_block_root[SC_ROOT_LEN],
                                   uint8_t signature[SC_SIGNATURE_LEN], uint8_t *signing_root)
{
    sc_validator *v = NULL;
    uint64_t epoch;
    int rc;

    if (!s || !beacon_block_root)
        return SC_ERR_ARG;
    epoch = slot / s->cfg.slots_per_epoch;
    if ((rc = typed_begin(s, pubkey, signature, epoch, &v)) != SC_OK)
        return rc;
    /* get_sync_committee_message: the object root is the block root itself. */
    typed_sign(s, v, D_SYNC_COMMITTEE, epoch, beacon_block_root, signature, signing_root);
    return SC_OK;
}

int sc_sign_sync_selection_proof(sc_signer *s, const uint8_t pubkey[SC_PUBKEY_LEN],
                                 uint64_t slot, uint64_t subcommittee_index,
                                 const sc_preset *p, uint8_t signature[SC_SIGNATURE_LEN],
                                 uint8_t *signing_root)
{
    sc_validator *v = NULL;
    uint8_t obj[SC_ROOT_LEN];
    uint64_t epoch;
    int rc;

    if (!s || !p)
        return SC_ERR_ARG;
    if (subcommittee_index >= p->sync_committee_subnet_count)
        return SC_ERR_ARG;
    epoch = slot / s->cfg.slots_per_epoch;
    if ((rc = typed_begin(s, pubkey, signature, epoch, &v)) != SC_OK)
        return rc;
    sc_htr_sync_aggregator_selection_data(slot, subcommittee_index, obj);
    typed_sign(s, v, D_SYNC_SELECTION_PROOF, epoch, obj, signature, signing_root);
    return SC_OK;
}

int sc_sign_contribution_and_proof(sc_signer *s, const uint8_t pubkey[SC_PUBKEY_LEN],
                                   const uint8_t *ssz, size_t len, const sc_preset *p,
                                   uint8_t signature[SC_SIGNATURE_LEN], uint8_t *signing_root)
{
    sc_validator *v = NULL;
    sc_contribution_info c;
    uint8_t sel[SC_ROOT_LEN];
    uint64_t epoch;
    int rc;

    if (!s || !ssz || !p)
        return SC_ERR_ARG;
    if ((rc = sc_decode_contribution_and_proof(ssz, len, p, &c)) != SC_OK)
        return rc;
    if (c.subcommittee_index >= p->sync_committee_subnet_count)
        return SC_ERR_ARG;
    epoch = c.slot / s->cfg.slots_per_epoch;
    if ((rc = typed_begin(s, pubkey, signature, epoch, &v)) != SC_OK)
        return rc;
    if ((rc = check_bound_index(v, c.aggregator_index)) != SC_OK)
        return rc;
    sc_htr_sync_aggregator_selection_data(c.slot, c.subcommittee_index, sel);
    rc = check_selection_proof(s, v, D_SYNC_SELECTION_PROOF, epoch, sel, c.selection_proof);
    if (rc != SC_OK)
        return rc;
    typed_sign(s, v, D_CONTRIBUTION_AND_PROOF, epoch, c.object_root, signature, signing_root);
    return SC_OK;
}

/* Domain types sc_sign_root accepts. The last three are Gloas types: none
 * is slashable (no slashing container covers them), and the core signs them
 * only from the Gloas fork epoch on. */
static const uint8_t ROOT_DOMAINS[][SC_DOMAIN_TYPE_LEN] = {
    {0x02, 0, 0, 0}, /* DOMAIN_RANDAO */
    {0x05, 0, 0, 0}, /* DOMAIN_SELECTION_PROOF */
    {0x06, 0, 0, 0}, /* DOMAIN_AGGREGATE_AND_PROOF */
    {0x07, 0, 0, 0}, /* DOMAIN_SYNC_COMMITTEE */
    {0x08, 0, 0, 0}, /* DOMAIN_SYNC_COMMITTEE_SELECTION_PROOF */
    {0x09, 0, 0, 0}, /* DOMAIN_CONTRIBUTION_AND_PROOF */
    {0x0b, 0, 0, 0}, /* DOMAIN_BEACON_BUILDER (Gloas, payload envelope) */
    {0x0c, 0, 0, 0}, /* DOMAIN_PTC_ATTESTER (Gloas) */
    {0x0d, 0, 0, 0}, /* DOMAIN_PROPOSER_PREFERENCES (Gloas) */
};
#define ROOT_DOMAINS_FIRST_GLOAS 6

int sc_sign_root(sc_signer *s, const uint8_t pubkey[SC_PUBKEY_LEN],
                 const uint8_t domain_type[SC_DOMAIN_TYPE_LEN], uint64_t epoch,
                 const uint8_t object_root[SC_ROOT_LEN],
                 uint8_t signature[SC_SIGNATURE_LEN])
{
    const size_t n = sizeof ROOT_DOMAINS / sizeof ROOT_DOMAINS[0];
    sc_validator *v = find_validator(s, pubkey);
    uint8_t root[SC_ROOT_LEN], want[SC_ROOT_LEN];
    uint64_t now;
    size_t i;
    int rc;

    if (!s || !pubkey || !domain_type || !object_root || !signature)
        return SC_ERR_ARG;
    if (!v)
        return SC_ERR_UNKNOWN_VALIDATOR;
    for (i = 0; i < n; i++)
        if (memcmp(domain_type, ROOT_DOMAINS[i], SC_DOMAIN_TYPE_LEN) == 0)
            break;
    if (i == n)
        return SC_ERR_POLICY_DOMAIN;
    if (i >= ROOT_DOMAINS_FIRST_GLOAS && (rc = sc_policy_check_gloas(&s->cfg, epoch)) != SC_OK)
        return rc;
    if (memcmp(domain_type, SC_DOMAIN_RANDAO, SC_DOMAIN_TYPE_LEN) == 0) {
        sc_htr_uint64(epoch, want);
        if (memcmp(want, object_root, SC_ROOT_LEN) != 0)
            return SC_ERR_ARG;
    }
    if ((rc = read_clock(s, &now)) != SC_OK)
        return rc;
    if ((rc = sc_policy_check_epoch(&s->cfg, &s->slot_times, now, epoch)) != SC_OK)
        return rc;
    sc_signer_signing_root(s, domain_type, epoch, object_root, root);
    sign_root(s, v, root, signature);
    return SC_OK;
}

const char *sc_status_name(int status)
{
    switch (status) {
    case SC_OK: return "SC_OK";
    case SC_ERR_ARG: return "SC_ERR_ARG";
    case SC_ERR_NOMEM: return "SC_ERR_NOMEM";
    case SC_ERR_DECODE: return "SC_ERR_DECODE";
    case SC_ERR_BAD_KEY: return "SC_ERR_BAD_KEY";
    case SC_ERR_DUPLICATE: return "SC_ERR_DUPLICATE";
    case SC_ERR_UNKNOWN_VALIDATOR: return "SC_ERR_UNKNOWN_VALIDATOR";
    case SC_ERR_STORAGE: return "SC_ERR_STORAGE";
    case SC_ERR_CLOCK: return "SC_ERR_CLOCK";
    case SC_ERR_SLASH_BLOCK: return "SC_ERR_SLASH_BLOCK";
    case SC_ERR_SLASH_SOURCE: return "SC_ERR_SLASH_SOURCE";
    case SC_ERR_SLASH_TARGET: return "SC_ERR_SLASH_TARGET";
    case SC_ERR_SLASH_SOURCE_GT_TARGET: return "SC_ERR_SLASH_SOURCE_GT_TARGET";
    case SC_ERR_POLICY_FUTURE: return "SC_ERR_POLICY_FUTURE";
    case SC_ERR_POLICY_EXIT: return "SC_ERR_POLICY_EXIT";
    case SC_ERR_POLICY_FEE_RECIPIENT: return "SC_ERR_POLICY_FEE_RECIPIENT";
    case SC_ERR_POLICY_GAS_LIMIT: return "SC_ERR_POLICY_GAS_LIMIT";
    case SC_ERR_POLICY_TIMESTAMP: return "SC_ERR_POLICY_TIMESTAMP";
    case SC_ERR_POLICY_PUBKEY: return "SC_ERR_POLICY_PUBKEY";
    case SC_ERR_POLICY_INDEX: return "SC_ERR_POLICY_INDEX";
    case SC_ERR_POLICY_DOMAIN: return "SC_ERR_POLICY_DOMAIN";
    case SC_ERR_POLICY_FORK: return "SC_ERR_POLICY_FORK";
    case SC_ERR_POLICY_BUILDER: return "SC_ERR_POLICY_BUILDER";
    case SC_ERR_POLICY_ENVELOPE: return "SC_ERR_POLICY_ENVELOPE";
    case SC_ERR_EQUIVOCATION: return "SC_ERR_EQUIVOCATION";
    case SC_ERR_SELECTION_PROOF: return "SC_ERR_SELECTION_PROOF";
    case SC_ERR_SCHEDULE: return "SC_ERR_SCHEDULE";
    case SC_ERR_POLICY_BUILDER_AUTH: return "SC_ERR_POLICY_BUILDER_AUTH";
    default: return "SC_ERR_UNKNOWN";
    }
}
