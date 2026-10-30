/*
 * The signer as the runner drives it over cgo: a config, validators with
 * their stored marks, and a stream of requests of every
 * kind (1 to 14 on the wire, plus import, policy, schedule and slot time
 * updates, restarts and storage or clock failures).
 *
 * Input: a header (flags, config patches, slot times, clock), then up to 64
 * operations; see the OP_* list. Real blst throughout.
 *
 * Oracles, besides the sanitizers:
 *  - every call returns a defined status;
 *  - per validator, over the whole input and across restarts: no two signed
 *    attestations with the same target and different data, none surrounding
 *    another, none with source > target; no two different blocks, PTC votes
 *    or envelopes for one slot;
 *  - with flag F_VERIFY, attestation and block signatures verify under the
 *    share key over the signing root sc_signer_signing_root gives.
 * Stored records only change through the core, so rollback is out of scope;
 * preloaded marks come only before a validator's first signature.
 */
#include "../tests/markformat_host.h"
#include "base_config.h"
#include "signer_ops.h"

#define NV 4       /* validator keys */
#define MAXOPS 64  /* operations per input */
#define HIST 64    /* signed messages remembered per validator and kind */

static uint8_t g_sk[NV][32], g_pk[NV][48];
static uint8_t g_scratch[SC_TYPED_SCRATCH_LEN];

typedef struct {
    uint8_t enc[SC_WATERMARK_ENCODED_LEN];
    int has_wm;
} record_t;

typedef struct {
    record_t rec[NV];
    uint8_t device[SC_WATERMARK_ENCODED_LEN];
    int has_device;
    uint64_t now;
    uint8_t fail; /* FAIL_* bits */
} host_t;

enum { FAIL_STORE = 1, FAIL_CLOCK = 2, FAIL_LOAD = 4, FAIL_DEVICE = 16 };

typedef struct {
    uint64_t a, b; /* attestation: source, target; others: slot */
    uint8_t root[32];
} signed_t;

typedef struct {
    signed_t att[HIST], blk[HIST], ptc[HIST], env[HIST];
    int natt, nblk, nptc, nenv;
    /* last signed block, for envelopes */
    int has_block;
    sc_beacon_block_header block;
} history_t;

typedef struct {
    host_t host;
    sc_config cfg, cfg0;
    sc_slot_times times, times0;
    uint32_t maxv, cache;
    void *mem;
    sc_signer *s;
    int loaded[NV];      /* in the current signer */
    int added[NV];       /* added once: re-added after a restart */
    uint8_t secret[NV];  /* index into g_sk of the loaded secret */
    uint64_t index[NV];  /* bound validator index */
    uint8_t share[NV][48];
    int signed_any[NV];
    int any_signed;
    history_t hist[NV];
    int verify;
} world_t;

static world_t W;

/* SC_FUZZ_TRACE=1 prints each operation and its status (for replays). */
static int g_trace = -1, g_op, g_v;

/* The rest of the input after the current argument block, for bulk data. */
static fz_in *g_bulk;

/* ---- host callbacks ------------------------------------------------------ */

static int key_of(const uint8_t pk[48])
{
    for (int i = 0; i < NV; i++)
        if (!memcmp(pk, g_pk[i], 48))
            return i;
    return -1;
}

static int h_now(void *ctx, uint64_t *t)
{
    host_t *h = ctx;
    if (h->fail & FAIL_CLOCK)
        return SC_ERR_CLOCK;
    *t = h->now;
    return SC_OK;
}

static int h_load(void *ctx, const uint8_t pk[48], sc_watermark *out)
{
    host_t *h = ctx;
    int i = key_of(pk);
    FUZZ_CHECK(i >= 0);
    if (h->fail & FAIL_LOAD)
        return SC_ERR_STORAGE;
    if (!h->rec[i].has_wm)
        return SC_ERR_UNKNOWN_VALIDATOR;
    return test_watermark_decode(h->rec[i].enc, sizeof h->rec[i].enc, out) == SC_OK ? SC_OK
                                                                                : SC_ERR_STORAGE;
}

static int h_store(void *ctx, const uint8_t pk[48], const sc_watermark *wm)
{
    host_t *h = ctx;
    int i = key_of(pk);
    FUZZ_CHECK(i >= 0);
    if (h->fail & FAIL_STORE)
        return SC_ERR_STORAGE;
    test_watermark_encode(wm, h->rec[i].enc);
    h->rec[i].has_wm = 1;
    return SC_OK;
}

static int h_load_dev(void *ctx, sc_watermark *out)
{
    host_t *h = ctx;
    if (h->fail & (FAIL_LOAD | FAIL_DEVICE))
        return SC_ERR_STORAGE;
    if (!h->has_device)
        return SC_ERR_UNKNOWN_VALIDATOR;
    return test_watermark_decode(h->device, sizeof h->device, out) == SC_OK ? SC_OK : SC_ERR_STORAGE;
}

static int h_store_dev(void *ctx, const sc_watermark *wm)
{
    host_t *h = ctx;
    if (h->fail & (FAIL_STORE | FAIL_DEVICE))
        return SC_ERR_STORAGE;
    test_watermark_encode(wm, h->device);
    h->has_device = 1;
    return SC_OK;
}

/* ---- signer lifecycle ---------------------------------------------------- */

static int start_signer(void)
{
    sc_host_ops ops = {.ctx = &W.host,
                       .now = h_now,
                       .load_watermark = h_load,
                       .store_watermark = h_store,
                       .load_device_mark = h_load_dev,
                       .store_device_mark = h_store_dev};
    size_t need = sc_signer_mem_size(W.maxv, W.cache);
    int rc;
    FUZZ_CHECK(need > 0);
    W.mem = aligned_alloc(8, (need + 7) & ~(size_t)7);
    if (!W.mem)
        abort();
    W.cfg = W.cfg0;
    W.times = W.times0;
    rc = sc_signer_init_ext(W.mem, need, W.maxv, W.cache, &W.cfg, &W.times, &ops, &W.s);
    FUZZ_CHECK(rc == SC_OK || rc == SC_ERR_ARG);
    if (rc != SC_OK) {
        free(W.mem);
        W.mem = NULL;
        W.s = NULL;
    }
    memset(W.loaded, 0, sizeof W.loaded);
    return rc;
}

static void stop_signer(void)
{
    if (W.s)
        sc_signer_wipe(W.s);
    free(W.mem);
    W.mem = NULL;
    W.s = NULL;
}

static void add(int v, int secret, uint64_t index)
{
    static const uint8_t zero[32];
    static const uint8_t big[32] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    const uint8_t *sk = secret < NV ? g_sk[secret] : secret == NV ? zero : big;
    uint8_t share[48];
    int rc = sc_signer_add_validator(W.s, g_pk[v], sk, index, share);
    if (g_trace)
        fprintf(stderr, "  add v%d secret %d: %s\n", v, secret, sc_status_name(rc));
    FUZZ_CHECK(rc == SC_OK || rc == SC_ERR_DUPLICATE || rc == SC_ERR_NOMEM ||
               rc == SC_ERR_BAD_KEY || rc == SC_ERR_STORAGE);
    if (W.loaded[v])
        FUZZ_CHECK(rc == SC_ERR_DUPLICATE);
    if (secret >= NV)
        FUZZ_CHECK(rc != SC_OK);
    if (rc != SC_OK)
        return;
    W.loaded[v] = W.added[v] = 1;
    W.secret[v] = (uint8_t)secret;
    W.index[v] = index;
    memcpy(W.share[v], share, 48);
}

static void restart(void)
{
    stop_signer();
    if (start_signer() != SC_OK)
        return;
    for (int v = 0; v < NV; v++)
        if (W.added[v])
            add(v, W.secret[v], W.index[v]);
}

/* ---- pickers ------------------------------------------------------------- */

static uint64_t clock_epoch(void)
{
    return sc_epoch_at(&W.cfg, &W.times, W.host.now);
}

/* An epoch near the clock (most of the time) or any 64-bit value. */
static uint64_t pick_epoch(fz_in *in)
{
    uint8_t sel = fz_u8(in);
    if (sel & 0x80)
        return fz_u64(in);
    return clock_epoch() + (uint64_t)((int64_t)(sel & 0x3f) - 24);
}

static uint64_t pick_slot(fz_in *in)
{
    uint8_t sel = fz_u8(in), off = fz_u8(in);
    if (sel & 0x80)
        return fz_u64(in);
    return (clock_epoch() + (uint64_t)((int64_t)(sel & 0x3f) - 24)) * W.cfg.slots_per_epoch +
           off % (W.cfg.slots_per_epoch ? W.cfg.slots_per_epoch : 1);
}

static uint64_t pick_index(fz_in *in, int v)
{
    uint8_t sel = fz_u8(in);
    if (sel < 0xc0)
        return W.index[v];
    if (sel < 0xe0)
        return 100 + (sel & 3);
    return fz_u64(in);
}

static void pick_fee(fz_in *in, uint8_t out[20])
{
    uint8_t sel = fz_u8(in);
    if (sel < 0x80)
        memset(out, 0x11, 20);
    else if (sel < 0xc0)
        memset(out, 0x22, 20);
    else
        fz_bytes(in, out, 20);
}

static void pick_root(fz_in *in, uint8_t out[32])
{
    memset(out, fz_u8(in), 32);
}

/* ---- oracles ------------------------------------------------------------- */

static void check_status(int rc)
{
    if (g_trace)
        fprintf(stderr, "  op %d v%d: %s\n", g_op, g_v, sc_status_name(rc));
    FUZZ_CHECK(rc >= SC_OK && rc <= SC_ERR_POLICY_BUILDER_AUTH);
}

static void record_slot(signed_t *h, int *n, uint64_t slot, const uint8_t root[32], const char *what)
{
    for (int i = 0; i < *n; i++)
        if (h[i].a == slot && memcmp(h[i].root, root, 32) != 0) {
            fprintf(stderr, "two different %s for slot %llu\n", what, (unsigned long long)slot);
            FUZZ_CHECK(!"slot equivocation");
        }
    if (*n < HIST) {
        h[*n].a = slot;
        memcpy(h[*n].root, root, 32);
        (*n)++;
    }
}

static void record_attestation(int v, const sc_attestation_data *d)
{
    history_t *h = &W.hist[v];
    uint8_t root[32];
    uint64_t s = d->source.epoch, t = d->target.epoch;
    sc_htr_attestation_data(d, root);
    FUZZ_CHECK(s <= t);
    for (int i = 0; i < h->natt; i++) {
        const signed_t *p = &h->att[i];
        if (p->b == t && memcmp(p->root, root, 32) != 0)
            FUZZ_CHECK(!"double vote");
        if ((p->a < s && t < p->b) || (s < p->a && p->b < t))
            FUZZ_CHECK(!"surround vote");
    }
    if (h->natt < HIST) {
        h->att[h->natt].a = s;
        h->att[h->natt].b = t;
        memcpy(h->att[h->natt].root, root, 32);
        h->natt++;
    }
}

static void verify_sig(int v, const uint8_t domain[4], uint64_t epoch, const uint8_t obj[32],
                       const uint8_t sig[96])
{
    uint8_t root[32];
    if (!W.verify)
        return;
    FUZZ_CHECK(sc_signer_signing_root(W.s, domain, epoch, obj, root) == SC_OK);
    FUZZ_CHECK(sc_bls_verify(W.share[v], root, 32, sig) == SC_OK);
}

static void signed_ok(int v)
{
    W.signed_any[v] = 1;
    W.any_signed = 1;
}

/* ---- operations ---------------------------------------------------------- */

static void op_attestation(fz_in *in, int v)
{
    static const uint8_t attester[4] = {1, 0, 0, 0};
    history_t *h = &W.hist[v];
    sc_attestation_data d;
    uint8_t sig[96], obj[32];
    uint8_t sel = fz_u8(in);
    int rc;

    if ((sel & 0xc0) == 0xc0 && h->natt) {
        /* Same source and target as an earlier vote: a repeat or a double. */
        const signed_t *p = &h->att[fz_u8(in) % h->natt];
        memset(&d, 0, sizeof d);
        d.source.epoch = p->a;
        d.target.epoch = p->b;
        d.slot = p->b * W.cfg.slots_per_epoch;
        pick_root(in, d.beacon_block_root);
    } else {
        memset(&d, 0, sizeof d);
        d.slot = pick_slot(in);
        d.source.epoch = pick_epoch(in);
        d.target.epoch = sel & 0x40 ? d.source.epoch + (fz_u8(in) & 7) : pick_epoch(in);
        pick_root(in, d.beacon_block_root);
        pick_root(in, d.source.root);
        pick_root(in, d.target.root);
        if (sel & 0x20)
            d.index = fz_u64(in);
    }
    rc = sc_sign_attestation(W.s, g_pk[v], &d, sig);
    check_status(rc);
    if (rc != SC_OK)
        return;
    FUZZ_CHECK(W.loaded[v]);
    signed_ok(v);
    record_attestation(v, &d);
    sc_htr_attestation_data(&d, obj);
    verify_sig(v, attester, d.target.epoch, obj, sig);
}

static void op_block(fz_in *in, int v)
{
    static const uint8_t proposer[4] = {0, 0, 0, 0};
    history_t *h = &W.hist[v];
    sc_beacon_block_header b;
    uint8_t sig[96], obj[32];
    uint8_t sel = fz_u8(in);
    int rc;

    memset(&b, 0, sizeof b);
    if ((sel & 0xc0) == 0xc0 && h->nblk)
        b.slot = h->blk[fz_u8(in) % h->nblk].a;
    else
        b.slot = pick_slot(in);
    b.proposer_index = pick_index(in, v);
    pick_root(in, b.parent_root);
    pick_root(in, b.state_root);
    pick_root(in, b.body_root);
    rc = sc_sign_block(W.s, g_pk[v], &b, sig);
    check_status(rc);
    if (rc != SC_OK)
        return;
    signed_ok(v);
    sc_htr_beacon_block_header(&b, obj);
    record_slot(h->blk, &h->nblk, b.slot, obj, "blocks");
    h->has_block = 1;
    h->block = b;
    verify_sig(v, proposer, W.cfg.slots_per_epoch ? b.slot / W.cfg.slots_per_epoch : 0, obj, sig);
}

static void op_ptc(fz_in *in, int v)
{
    history_t *h = &W.hist[v];
    sc_payload_attestation_data d;
    uint8_t sig[96], obj[32];
    int rc;

    memset(&d, 0, sizeof d);
    d.slot = pick_slot(in);
    pick_root(in, d.beacon_block_root);
    d.payload_present = fz_u8(in);
    d.blob_data_available = fz_u8(in);
    if (d.payload_present < 0xf0)
        d.payload_present &= 1;
    if (d.blob_data_available < 0xf0)
        d.blob_data_available &= 1;
    rc = sc_sign_payload_attestation(W.s, g_pk[v], &d, sig);
    check_status(rc);
    if (rc != SC_OK)
        return;
    FUZZ_CHECK(d.payload_present <= 1 && d.blob_data_available <= 1);
    signed_ok(v);
    sc_htr_payload_attestation_data(&d, obj);
    record_slot(h->ptc, &h->nptc, d.slot, obj, "PTC votes");
}

static void op_envelope(fz_in *in, int v)
{
    history_t *h = &W.hist[v];
    sc_payload_envelope e;
    uint8_t sig[96], obj[32];
    uint8_t sel = fz_u8(in);
    int rc;

    memset(&e, 0, sizeof e);
    if (!(sel & 0x80) && h->has_block) {
        /* For the last block: the envelope the core expects. */
        e.payload.slot_number = h->block.slot;
        sc_htr_beacon_block_header(&h->block, e.beacon_block_root);
        memcpy(e.parent_beacon_block_root, h->block.parent_root, 32);
    } else {
        e.payload.slot_number = pick_slot(in);
        pick_root(in, e.beacon_block_root);
        pick_root(in, e.parent_beacon_block_root);
    }
    e.builder_index = sel & 0x40 ? fz_u64(in) : SC_BUILDER_INDEX_SELF_BUILD;
    pick_fee(in, e.payload.fee_recipient);
    pick_root(in, e.payload.block_hash);
    e.payload.gas_limit = fz_u64(in);
    if (sel & 0x20)
        fz_bytes(g_bulk, (uint8_t *)&e.payload, sizeof e.payload);
    rc = sc_sign_payload_envelope(W.s, g_pk[v], &e, sig);
    check_status(rc);
    if (rc != SC_OK)
        return;
    FUZZ_CHECK(e.builder_index == SC_BUILDER_INDEX_SELF_BUILD);
    signed_ok(v);
    sc_htr_payload_envelope(&e, obj);
    record_slot(h->env, &h->nenv, e.payload.slot_number, obj, "envelopes");
}

static void op_preferences(fz_in *in, int v)
{
    sc_proposer_preferences p;
    uint8_t sig[96];
    memset(&p, 0, sizeof p);
    p.proposal_slot = pick_slot(in);
    p.validator_index = pick_index(in, v);
    pick_fee(in, p.fee_recipient);
    p.target_gas_limit = fz_u8(in) < 0xc0 ? 30000000 + (uint64_t)fz_u8(in) * 1000000 : fz_u64(in);
    pick_root(in, p.dependent_root);
    check_status(sc_sign_proposer_preferences(W.s, g_pk[v], &p, sig));
}

static void op_builder_auth(fz_in *in, int v)
{
    sc_builder_request_auth r;
    uint8_t sig[96], *copy = NULL;
    uint8_t sel = fz_u8(in);
    size_t len;
    const uint8_t *d;

    r.slot = pick_slot(in);
    if (sel & 0x80) {
        d = fz_take(g_bulk, fz_u16(in) % 4200, &len);
        copy = fz_dup(d, len);
        r.data = copy;
        r.data_len = len;
    } else {
        r.data = (const uint8_t *)FZ_AUTH_DATA;
        r.data_len = sizeof FZ_AUTH_DATA - 1;
    }
    check_status(sc_sign_builder_request_auth(W.s, g_pk[v], &r, sig));
    free(copy);
}

/* A selection proof the validator key makes for (domain, epoch, root). */
static void make_proof(int v, const uint8_t domain[4], uint64_t epoch, const uint8_t obj[32],
                       uint8_t proof[96])
{
    uint8_t root[32];
    memset(proof, 0x99, 96);
    if (sc_signer_signing_root(W.s, domain, epoch, obj, root) == SC_OK)
        FUZZ_CHECK(sc_bls_sign(g_sk[v], root, 32, proof) == SC_OK);
}

/* Applies k byte patches to buf. */
static void patch_bytes(fz_in *in, uint8_t *buf, size_t len)
{
    uint8_t k = fz_u8(in) % 4;
    for (uint8_t i = 0; i < k && len; i++) {
        size_t at = fz_u16(in) % len;
        buf[at] = fz_u8(in);
    }
}

static void op_aggregate(fz_in *in, int v)
{
    static const uint8_t sel_domain[4] = {5, 0, 0, 0};
    uint8_t ssz[MAX_AGG_SSZ], sig[96], obj[32], sr[32];
    uint8_t sel = fz_u8(in);
    int form = fz_u8(in);
    const sc_preset *p = sel & 1 ? &SC_PRESET_MINIMAL : &SC_PRESET_MAINNET;
    size_t n;

    if (form >= 0xf0)
        form = (int)(int8_t)form; /* a negative int, as a bad caller might pass */
    else if (form >= 0x10)
        form %= 3;
    if (sel & 0x80) {
        const uint8_t *d = fz_take(g_bulk, fz_u16(in) % sizeof ssz, &n);
        memcpy(ssz, d, n);
    } else {
        sc_attestation_data d;
        size_t cb = (size_t)((p->max_committees_per_slot + 7) / 8), bits = 1 + fz_u8(in) % 8;
        uint64_t slot = pick_slot(in);
        memset(&d, 0, sizeof d);
        d.slot = slot;
        d.source.epoch = pick_epoch(in);
        d.target.epoch = pick_epoch(in);
        fz_put_u64(ssz, pick_index(in, v));
        ssz[8] = 108, ssz[9] = ssz[10] = ssz[11] = 0;
        sc_htr_uint64(slot, obj);
        if (sel & 0x40)
            fz_bytes(g_bulk, ssz + 12, 96);
        else
            make_proof(v, sel_domain, W.cfg.slots_per_epoch ? slot / W.cfg.slots_per_epoch : 0,
                       obj, ssz + 12);
        n = 108;
        if (form == SC_AGGREGATE_PHASE0)
            cb = 0;
        fz_put_u64(ssz + n, 4 + 128 + 96 + cb); /* offset (4 bytes used) */
        sc_ssz_encode_attestation_data(&d, ssz + n + 4);
        memset(ssz + n + 4 + 128, 0x77, 96);
        memset(ssz + n + 4 + 128 + 96, 0, cb);
        if (cb)
            ssz[n + 4 + 128 + 96] = 1;
        n += 4 + 128 + 96 + cb;
        for (size_t i = 0; i < bits; i++)
            ssz[n + i] = fz_u8(in);
        ssz[n + bits - 1] |= 0x80; /* delimiter */
        n += bits;
    }
    patch_bytes(in, ssz, n);
    {
        uint8_t *copy = fz_dup(ssz, n);
        int rc = sc_sign_aggregate_and_proof(W.s, g_pk[v], copy, n, form, p, g_scratch, sig, sr);
        check_status(rc);
        if (form < 0 || form > 2)
            FUZZ_CHECK(rc != SC_OK);
        free(copy);
    }
}

static void op_contribution(fz_in *in, int v)
{
    static const uint8_t sel_domain[4] = {8, 0, 0, 0};
    uint8_t ssz[512], sig[96], obj[32];
    uint8_t sel = fz_u8(in);
    const sc_preset *p = sel & 1 ? &SC_PRESET_MINIMAL : &SC_PRESET_MAINNET;
    size_t n = sc_contribution_and_proof_len(p), bl = n - 8 - 48 - 96 - 96;
    uint64_t slot = pick_slot(in), sub = fz_u8(in) % 6;

    FUZZ_CHECK(n <= sizeof ssz);
    memset(ssz, 0, sizeof ssz);
    fz_put_u64(ssz, pick_index(in, v));
    fz_put_u64(ssz + 8, slot);
    pick_root(in, ssz + 16);
    fz_put_u64(ssz + 48, sub);
    fz_bytes(in, ssz + 56, bl);
    memset(ssz + 56 + bl, 0x66, 96);
    sc_htr_sync_aggregator_selection_data(slot, sub, obj);
    if (sel & 0x40)
        fz_bytes(g_bulk, ssz + 56 + bl + 96, 96);
    else
        make_proof(v, sel_domain, W.cfg.slots_per_epoch ? slot / W.cfg.slots_per_epoch : 0, obj,
                   ssz + 56 + bl + 96);
    if (sel & 0x20)
        n = fz_u16(in) % sizeof ssz; /* a wrong length */
    patch_bytes(in, ssz, n);
    {
        uint8_t *copy = fz_dup(ssz, n);
        check_status(sc_sign_contribution_and_proof(W.s, g_pk[v], copy, n, p, sig, NULL));
        free(copy);
    }
}

static void op_root(fz_in *in, int v)
{
    uint8_t domain[4] = {0}, root[32], sig[96];
    uint8_t sel = fz_u8(in);
    uint64_t epoch = pick_epoch(in);
    int rc;
    if (sel & 0x80)
        fz_bytes(in, domain, 4);
    else
        domain[0] = sel % 16;
    if (sel & 0x40)
        sc_htr_uint64(epoch, root);
    else
        fz_bytes(in, root, 32);
    rc = sc_sign_root(W.s, g_pk[v], domain, epoch, root, sig);
    check_status(rc);
    if (rc == SC_OK)
        FUZZ_CHECK(domain[1] == 0 && domain[2] == 0 && domain[3] == 0 &&
                   (domain[0] == 2 || (domain[0] >= 5 && domain[0] <= 9) ||
                    (domain[0] >= 0x0b && domain[0] <= 0x0d)));
}

static void op_import(fz_in *in, int v)
{
    sc_watermark wm;
    uint8_t gvr[32];
    uint8_t sel = fz_u8(in);
    memcpy(gvr, W.cfg.genesis_validators_root, 32);
    if (sel & 0x80)
        gvr[fz_u8(in) % 32] ^= 1;
    wm.flags = sel & 0x40 ? fz_u32(in) : sel & 3;
    wm.block_slot = pick_slot(in);
    wm.source_epoch = pick_epoch(in);
    wm.target_epoch = pick_epoch(in);
    check_status(sc_signer_import(W.s, g_pk[v], gvr, &wm));
}

static void op_policy(fz_in *in)
{
    sc_config pol = W.cfg;
    uint8_t n = fz_u8(in) % 4;
    for (uint8_t i = 0; i < n; i++)
        fz_patch_config(&pol, in);
    if (sc_signer_set_policy(W.s, &pol) == SC_OK) {
        memcpy(W.cfg.exit_allowlist, pol.exit_allowlist, sizeof pol.exit_allowlist);
        W.cfg.exit_allowlist_count = pol.exit_allowlist_count;
        memcpy(W.cfg.fee_recipients, pol.fee_recipients, sizeof pol.fee_recipients);
        W.cfg.fee_recipient_count = pol.fee_recipient_count;
        W.cfg.gas_limit_min = pol.gas_limit_min;
        W.cfg.gas_limit_max = pol.gas_limit_max;
        W.cfg.registration_max_future_seconds = pol.registration_max_future_seconds;
        memcpy(W.cfg.builder_auth_roots, pol.builder_auth_roots, sizeof pol.builder_auth_roots);
        W.cfg.builder_auth_root_count = pol.builder_auth_root_count;
    }
}

static void op_schedule(fz_in *in)
{
    sc_schedule next;
    sc_slot_times pending;
    uint8_t sel = fz_u8(in);
    uint64_t at = fz_near(in, W.host.now);
    int rc;
    fz_schedule(&next, &W.cfg, in);
    if (sel & 1)
        fz_slot_times(&pending, in);
    if (sel & 2)
        rc = sc_signer_check_schedule_under(W.s, &next, at, sel & 1 ? &pending : NULL, sel & 1);
    else
        rc = sc_signer_set_schedule_under(W.s, &next, at, sel & 1 ? &pending : NULL, sel & 1);
    check_status(rc);
    if (rc == SC_OK && !(sel & 2)) {
        memcpy(W.cfg.forks, next.forks, sizeof next.forks);
        W.cfg.fork_count = next.fork_count;
        W.cfg.gloas_scheduled = next.gloas_scheduled;
        W.cfg.gloas_fork_epoch = next.gloas_fork_epoch;
    }
}

static void op_slot_times(fz_in *in)
{
    sc_slot_times next;
    uint8_t sel = fz_u8(in);
    uint64_t at = fz_near(in, W.host.now);
    int rc;
    fz_slot_times(&next, in);
    rc = sel & 1 ? sc_signer_check_slot_times(W.s, &next, at)
                 : sc_signer_set_slot_times(W.s, &next, at);
    check_status(rc);
    if (rc == SC_OK && !(sel & 1))
        W.times = next;
}

static void op_query(fz_in *in, int v)
{
    sc_slashing_state st;
    sc_repeat_roots rr;
    sc_signer_stats stats;
    sc_slot_times t;
    uint8_t domain[4] = {fz_u8(in), 0, 0, 0}, obj[32] = {0}, root[32];
    check_status(sc_signer_get_state(W.s, g_pk[v], &st));
    check_status(sc_signer_get_repeat_roots(W.s, g_pk[v], &rr));
    sc_signer_get_stats(W.s, &stats);
    sc_signer_get_slot_times(W.s, &t);
    FUZZ_CHECK(t.count <= SC_MAX_SLOT_TIMES);
    check_status(sc_signer_signing_root(W.s, domain, pick_epoch(in), obj, root));
}

static void op_preload(fz_in *in, int v, int what)
{
    if (W.loaded[v])
        return;
    if (what == OP_PRELOAD_DEVICE) {
        if (W.any_signed)
            return;
        for (int i = 0; i < NV; i++)
            if (W.loaded[i])
                return; /* the core reads the device mark with the first validator */
    } else if (W.signed_any[v]) {
        return;
    }
    {
        sc_watermark wm;
        uint8_t *dst = what == OP_PRELOAD_DEVICE ? W.host.device : W.host.rec[v].enc;
        uint8_t sel = fz_u8(in);
        wm.flags = sel & 3;
        wm.block_slot = pick_slot(in);
        wm.source_epoch = pick_epoch(in);
        wm.target_epoch = pick_epoch(in);
        test_watermark_encode(&wm, dst);
        if (sel & 0x80)
            dst[fz_u8(in) % SC_WATERMARK_ENCODED_LEN] = fz_u8(in); /* a damaged record */
        if (what == OP_PRELOAD_DEVICE)
            W.host.has_device = !(sel & 0x40);
        else
            W.host.rec[v].has_wm = !(sel & 0x40);
    }
}

/* ---- entry --------------------------------------------------------------- */

static void init_keys(void)
{
    static int done;
    if (done)
        return;
    for (int i = 0; i < NV; i++) {
        for (int k = 0; k < 32; k++)
            g_sk[i][k] = (uint8_t)(0x21 * (k + 1) + 7 * i);
        g_sk[i][0] = (uint8_t)(0x10 + i); /* below the group order */
        FUZZ_CHECK(sc_bls_pubkey(g_sk[i], g_pk[i]) == SC_OK);
    }
    done = 1;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    fz_in in = {data, size};
    uint8_t flags, npatch;

    init_keys();
    if (g_trace < 0)
        g_trace = getenv("SC_FUZZ_TRACE") != NULL;
    memset(&W, 0, sizeof W);
    {
        /* The header is a block of HEADER_LEN bytes, so the operations
         * after it start at a fixed offset whatever the patches read. */
        fz_in h;
        h.p = in.p;
        h.n = in.n < HEADER_LEN ? in.n : HEADER_LEN;
        in.p += h.n;
        in.n -= h.n;
        flags = fz_u8(&h);
        npatch = fz_u8(&h) % 6;
        W.maxv = 1 + fz_u8(&h) % NV;
        W.cache = fz_u8(&h) % 5;
        W.host.now = FZ_GENESIS_TIME + FZ_E * FZ_EPOCH_SECONDS + fz_u8(&h);
        fz_base_config(&W.cfg0);
        W.cfg0.mark_scope = flags & F_DEVICE ? SC_MARKS_PER_DEVICE : SC_MARKS_PER_VALIDATOR;
        if (flags & F_NO_GLOAS)
            W.cfg0.gloas_scheduled = 0;
        W.verify = flags & F_VERIFY ? 1 : 0;
        for (uint8_t i = 0; i < npatch; i++)
            fz_patch_config(&W.cfg0, &h);
        if (flags & F_SLOT_TIMES)
            fz_slot_times(&W.times0, &h);
    }

    if (start_signer() != SC_OK)
        return 0;

    /* Each operation: opcode, validator, then an argument block of ARGS_LEN
     * bytes (zeros past the end). Bulk data (raw SSZ, auth data, proofs)
     * comes from the rest of the input after the block. */
    g_bulk = &in;
    for (int step = 0; step < MAXOPS && in.n; step++) {
        uint8_t op = fz_u8(&in) % OP_COUNT;
        int v = fz_u8(&in) % NV;
        fz_in a;
        a.p = in.p;
        a.n = in.n < ARGS_LEN ? in.n : ARGS_LEN;
        in.p += a.n;
        in.n -= a.n;
        g_op = op, g_v = v;
        if (!W.s) { /* a restart that failed (only after a bad patch) */
            break;
        }
        switch (op) {
        case OP_TIME: {
            uint8_t sel = fz_u8(&a);
            if (sel & 0x80)
                W.host.now = fz_u64(&a);
            else
                W.host.now += (uint64_t)((int64_t)(int8_t)fz_u8(&a) * (sel & 0x40 ? 384 : 12));
            break;
        }
        case OP_ADD: {
            uint8_t sel = fz_u8(&a);
            add(v, sel < 0xf0 ? v : sel < 0xf8 ? (sel & 3) : NV + (sel & 1),
                sel & 0x40 ? SC_INDEX_UNKNOWN : 100 + (uint64_t)v);
            break;
        }
        case OP_RESTART: restart(); break;
        case OP_FAIL: W.host.fail = fz_u8(&a) & 0x1f; break;
        case OP_PRELOAD_MARK:
        case OP_PRELOAD_DEVICE: op_preload(&a, v, op); break;
        case OP_ATTESTATION: op_attestation(&a, v); break;
        case OP_BLOCK: op_block(&a, v); break;
        case OP_RANDAO: {
            uint8_t sig[96];
            check_status(sc_sign_randao_reveal(W.s, g_pk[v], pick_epoch(&a), sig));
            break;
        }
        case OP_EXIT: {
            sc_voluntary_exit e;
            uint8_t sig[96];
            e.epoch = pick_epoch(&a);
            e.validator_index = pick_index(&a, v);
            check_status(sc_sign_voluntary_exit(W.s, g_pk[v], &e, sig));
            break;
        }
        case OP_REGISTRATION: {
            sc_validator_registration r;
            uint8_t sig[96];
            uint8_t sel = fz_u8(&a);
            pick_fee(&a, r.fee_recipient);
            r.gas_limit = sel & 1 ? fz_u64(&a) : 30000000 + (uint64_t)fz_u8(&a) * 1000000;
            r.timestamp = sel & 2 ? fz_u64(&a) : W.host.now + (uint64_t)(int64_t)(int16_t)fz_u16(&a);
            memcpy(r.pubkey, g_pk[sel & 4 ? (v + 1) % NV : v], 48);
            check_status(sc_sign_validator_registration(W.s, g_pk[v], &r, sig));
            break;
        }
        case OP_PTC: op_ptc(&a, v); break;
        case OP_ENVELOPE: op_envelope(&a, v); break;
        case OP_PREFERENCES: op_preferences(&a, v); break;
        case OP_BUILDER_AUTH: op_builder_auth(&a, v); break;
        case OP_SELECTION_PROOF: {
            uint8_t sig[96], sr[32];
            check_status(sc_sign_selection_proof(W.s, g_pk[v], pick_slot(&a), sig, sr));
            break;
        }
        case OP_AGGREGATE: op_aggregate(&a, v); break;
        case OP_SYNC_MESSAGE: {
            uint8_t sig[96], root[32];
            uint64_t slot = pick_slot(&a);
            pick_root(&a, root);
            check_status(sc_sign_sync_committee_message(W.s, g_pk[v], slot, root, sig, NULL));
            break;
        }
        case OP_SYNC_SELECTION: {
            uint8_t sig[96];
            uint8_t sel = fz_u8(&a);
            uint64_t slot = pick_slot(&a);
            check_status(sc_sign_sync_selection_proof(W.s, g_pk[v], slot,
                                                      sel & 0x80 ? fz_u64(&a) : sel % 6,
                                                      sel & 0x40 ? &SC_PRESET_MINIMAL
                                                                 : &SC_PRESET_MAINNET,
                                                      sig, NULL));
            break;
        }
        case OP_CONTRIBUTION: op_contribution(&a, v); break;
        case OP_ROOT: op_root(&a, v); break;
        case OP_IMPORT: op_import(&a, v); break;
        case OP_COVER: check_status(sc_signer_cover_epoch(W.s, pick_epoch(&a))); break;
        case OP_POLICY: op_policy(&a); break;
        case OP_SCHEDULE: op_schedule(&a); break;
        case OP_SLOT_TIMES: op_slot_times(&a); break;
        default: op_query(&a, v); break;
        }
    }
    stop_signer();
    return 0;
}
