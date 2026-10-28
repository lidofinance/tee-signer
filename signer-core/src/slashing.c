/*
 * EIP-3076 minimal slashing protection with commit-ahead watermarks.
 *
 * RAM rules (minimal strategy, per validator):
 *   block:        refuse slot <= highest signed slot
 *   attestation:  refuse source > target
 *                 refuse source < highest signed source  (new could surround old)
 *                 refuse target <= highest signed target (double vote, or
 *                                                         old could surround new)
 *
 * Commit ahead: the durable watermark is an upper bound on everything that
 * may have been signed. Before signing a message above it, the core
 * persists a wider window, e.g. "targets up to E+1". After a restart the
 * RAM state starts at the durable bounds, so everything at or below them is
 * refused. Sources need a bound too: a new attestation with a lower source
 * than one signed before the crash could surround it.
 *
 * Per-device marks (*_device): one durable mark for all validators of a
 * device, so a board writes once per window whatever its number of keys.
 * The RAM rules stay per validator. Exact repeats are handled above this
 * layer, in signer.c. The device mark's source bound is the highest source
 * signed (or imported), with no window: the chain's source stays put while it
 * does not finalize, so a bound above the signed sources would refuse every
 * vote after a restart until the chain justifies an epoch at or above it.
 */
#include "sc_internal.h"

#define WM_FLAGS_MASK (SC_WM_HAS_BLOCK | SC_WM_HAS_ATTESTATION)

static const uint8_t WM_MAGIC[4] = {'S', 'C', 'W', '1'};

void sc_watermark_encode(const sc_watermark *wm, uint8_t out[SC_WATERMARK_ENCODED_LEN])
{
    memcpy(out, WM_MAGIC, 4);
    out[4] = (uint8_t)(wm->flags & WM_FLAGS_MASK);
    out[5] = out[6] = out[7] = 0;
    sc_put_u64(out + 8, wm->block_slot);
    sc_put_u64(out + 16, wm->source_epoch);
    sc_put_u64(out + 24, wm->target_epoch);
}

int sc_watermark_decode(const uint8_t *in, size_t len, sc_watermark *out)
{
    if (!in || !out || len != SC_WATERMARK_ENCODED_LEN || memcmp(in, WM_MAGIC, 4) != 0 ||
        (in[4] & ~WM_FLAGS_MASK) || in[5] || in[6] || in[7])
        return SC_ERR_DECODE;
    out->flags = in[4];
    out->block_slot = sc_get_u64(in + 8);
    out->source_epoch = sc_get_u64(in + 16);
    out->target_epoch = sc_get_u64(in + 24);
    return SC_OK;
}

#define REPEAT_FLAGS_MASK (SC_REPEAT_HAS_ATTESTATION | SC_REPEAT_HAS_BLOCK)

static const uint8_t RR_MAGIC[4] = {'S', 'C', 'R', '1'};

void sc_repeat_roots_encode(const sc_repeat_roots *r, uint8_t out[SC_REPEAT_ROOTS_ENCODED_LEN])
{
    memcpy(out, RR_MAGIC, 4);
    out[4] = (uint8_t)(r->flags & REPEAT_FLAGS_MASK);
    out[5] = out[6] = out[7] = 0;
    memcpy(out + 8, r->attestation_root, SC_ROOT_LEN);
    memcpy(out + 8 + SC_ROOT_LEN, r->block_root, SC_ROOT_LEN);
}

int sc_repeat_roots_decode(const uint8_t *in, size_t len, sc_repeat_roots *out)
{
    if (!in || !out || len != SC_REPEAT_ROOTS_ENCODED_LEN || memcmp(in, RR_MAGIC, 4) != 0 ||
        (in[4] & ~REPEAT_FLAGS_MASK) || in[5] || in[6] || in[7])
        return SC_ERR_DECODE;
    out->flags = in[4];
    memcpy(out->attestation_root, in + 8, SC_ROOT_LEN);
    memcpy(out->block_root, in + 8 + SC_ROOT_LEN, SC_ROOT_LEN);
    return SC_OK;
}

void sc_slashing_restore(sc_slashing_state *st, const sc_watermark *persisted)
{
    memset(st, 0, sizeof *st);
    if (persisted) {
        st->committed = *persisted;
        st->committed.flags &= WM_FLAGS_MASK;
        st->ram = st->committed;
    }
}

int sc_slashing_check_block(const sc_slashing_state *st, uint64_t slot)
{
    if (!st)
        return SC_ERR_ARG;
    if ((st->ram.flags & SC_WM_HAS_BLOCK) && slot <= st->ram.block_slot)
        return SC_ERR_SLASH_BLOCK;
    return SC_OK;
}

int sc_slashing_check_attestation(const sc_slashing_state *st, uint64_t source_epoch,
                                  uint64_t target_epoch)
{
    if (!st)
        return SC_ERR_ARG;
    if (source_epoch > target_epoch)
        return SC_ERR_SLASH_SOURCE_GT_TARGET;
    if (st->ram.flags & SC_WM_HAS_ATTESTATION) {
        if (source_epoch < st->ram.source_epoch)
            return SC_ERR_SLASH_SOURCE;
        if (target_epoch <= st->ram.target_epoch)
            return SC_ERR_SLASH_TARGET;
    }
    return SC_OK;
}

static const sc_commit_ahead NO_AHEAD = {0, 0, 0};

int sc_slashing_approve_block(sc_slashing_state *st, const sc_commit_ahead *ahead,
                              sc_store_fn store, void *ctx,
                              const uint8_t pubkey[SC_PUBKEY_LEN], uint64_t slot)
{
    int rc;
    if (!st || !store || !pubkey)
        return SC_ERR_ARG;
    if (!ahead)
        ahead = &NO_AHEAD;
    rc = sc_slashing_check_block(st, slot);
    if (rc != SC_OK)
        return rc;

    const sc_watermark *c = &st->committed;
    int have = (c->flags & SC_WM_HAS_BLOCK) != 0;
    if (!have || slot > c->block_slot) {
        sc_watermark next = *c;
        uint64_t hi = sc_sat_add(slot, ahead->block_slots);
        next.block_slot = have ? sc_max64(c->block_slot, hi) : hi;
        next.flags |= SC_WM_HAS_BLOCK;
        if (store(ctx, pubkey, &next) != SC_OK)
            return SC_ERR_STORAGE;
        st->committed = next;
    }
    sc_slashing_record_block(st, slot);
    return SC_OK;
}

int sc_slashing_cover_slot(sc_slashing_state *st, const sc_commit_ahead *ahead, sc_store_fn store,
                           void *ctx, const uint8_t pubkey[SC_PUBKEY_LEN], uint64_t slot)
{
    const sc_watermark *c;
    sc_watermark next;
    if (!st || !store || !pubkey)
        return SC_ERR_ARG;
    if (!ahead)
        ahead = &NO_AHEAD;
    c = &st->committed;
    if ((c->flags & SC_WM_HAS_BLOCK) && slot <= c->block_slot)
        return SC_OK;
    next = *c;
    next.block_slot = sc_sat_add(slot, ahead->block_slots);
    if (c->flags & SC_WM_HAS_BLOCK)
        next.block_slot = sc_max64(c->block_slot, next.block_slot);
    next.flags |= SC_WM_HAS_BLOCK;
    if (store(ctx, pubkey, &next) != SC_OK)
        return SC_ERR_STORAGE;
    st->committed = next;
    return SC_OK;
}

void sc_slashing_record_block(sc_slashing_state *st, uint64_t slot)
{
    st->ram.block_slot = slot;
    st->ram.flags |= SC_WM_HAS_BLOCK;
}

int sc_slashing_approve_attestation(sc_slashing_state *st, const sc_commit_ahead *ahead,
                                    sc_store_fn store, void *ctx,
                                    const uint8_t pubkey[SC_PUBKEY_LEN],
                                    uint64_t source_epoch, uint64_t target_epoch)
{
    int rc;
    if (!st || !store || !pubkey)
        return SC_ERR_ARG;
    if (!ahead)
        ahead = &NO_AHEAD;
    rc = sc_slashing_check_attestation(st, source_epoch, target_epoch);
    if (rc != SC_OK)
        return rc;

    const sc_watermark *c = &st->committed;
    int have = (c->flags & SC_WM_HAS_ATTESTATION) != 0;
    if (!have || target_epoch > c->target_epoch || source_epoch > c->source_epoch) {
        sc_watermark next = *c;
        uint64_t t_hi = sc_sat_add(target_epoch, ahead->target_epochs);
        if (have)
            t_hi = sc_max64(c->target_epoch, t_hi);
        /* A source above the target bound is never valid, so cap it there.
         * t_hi >= target >= source, so the signed source stays covered. */
        uint64_t s_hi = sc_min64(sc_sat_add(source_epoch, ahead->source_epochs), t_hi);
        if (have)
            s_hi = sc_max64(c->source_epoch, s_hi);
        next.target_epoch = t_hi;
        next.source_epoch = s_hi;
        next.flags |= SC_WM_HAS_ATTESTATION;
        if (store(ctx, pubkey, &next) != SC_OK)
            return SC_ERR_STORAGE;
        st->committed = next;
    }
    sc_slashing_record_attestation(st, source_epoch, target_epoch);
    return SC_OK;
}

void sc_slashing_record_attestation(sc_slashing_state *st, uint64_t source_epoch,
                                    uint64_t target_epoch)
{
    if (st->ram.flags & SC_WM_HAS_ATTESTATION)
        st->ram.source_epoch = sc_max64(st->ram.source_epoch, source_epoch);
    else
        st->ram.source_epoch = source_epoch;
    st->ram.target_epoch = target_epoch;
    st->ram.flags |= SC_WM_HAS_ATTESTATION;
}

/* Last slot of epoch e, saturating. */
static uint64_t last_slot_of(uint64_t e, uint64_t slots_per_epoch)
{
    uint64_t n = sc_sat_add(e, 1);
    if (n > UINT64_MAX / slots_per_epoch)
        return UINT64_MAX;
    return n * slots_per_epoch - 1;
}

/*
 * Raises the device mark so it covers a message of this epoch, and the source
 * of an attestation about to be signed. One store call. The source bound
 * moves only to a source that is signed next (no window), so only a vote
 * raises it. A vote whose target the mark already covers moves only the
 * source bound, so a new source does not push the target bound further.
 */
static int device_raise(sc_watermark *device, const sc_commit_ahead *ahead,
                        uint64_t slots_per_epoch, sc_store_device_fn store, void *ctx,
                        uint64_t epoch, int has_source, uint64_t source)
{
    const sc_watermark *c = device;
    int have_att = (c->flags & SC_WM_HAS_ATTESTATION) != 0;
    int have_block = (c->flags & SC_WM_HAS_BLOCK) != 0;
    sc_watermark next = *c;
    uint64_t h = sc_sat_add(epoch, ahead->target_epochs);
    uint64_t s_hi = 0;

    if (!have_att || !have_block || epoch > c->target_epoch ||
        last_slot_of(epoch, slots_per_epoch) > c->block_slot) {
        next.target_epoch = have_att ? sc_max64(c->target_epoch, h) : h;
        next.block_slot = last_slot_of(next.target_epoch, slots_per_epoch);
        if (have_block)
            next.block_slot = sc_max64(c->block_slot, next.block_slot);
    }
    if (has_source)
        s_hi = source;
    next.source_epoch = have_att ? sc_max64(c->source_epoch, s_hi) : s_hi;
    next.flags = SC_WM_HAS_BLOCK | SC_WM_HAS_ATTESTATION;
    if (store(ctx, &next) != SC_OK)
        return SC_ERR_STORAGE;
    *device = next;
    return SC_OK;
}

int sc_slashing_approve_block_device(sc_slashing_state *st, sc_watermark *device,
                                     const sc_commit_ahead *ahead, uint64_t slots_per_epoch,
                                     sc_store_device_fn store, void *ctx, uint64_t slot)
{
    int rc;
    if (!st || !device || !store || !slots_per_epoch)
        return SC_ERR_ARG;
    if (!ahead)
        ahead = &NO_AHEAD;
    rc = sc_slashing_check_block(st, slot);
    if (rc != SC_OK)
        return rc;
    if (!(device->flags & SC_WM_HAS_BLOCK) || slot > device->block_slot) {
        rc = device_raise(device, ahead, slots_per_epoch, store, ctx, slot / slots_per_epoch, 0, 0);
        if (rc != SC_OK)
            return rc;
    }
    sc_slashing_record_block(st, slot);
    return SC_OK;
}

int sc_slashing_approve_attestation_device(sc_slashing_state *st, sc_watermark *device,
                                           const sc_commit_ahead *ahead,
                                           uint64_t slots_per_epoch, sc_store_device_fn store,
                                           void *ctx, uint64_t source_epoch,
                                           uint64_t target_epoch)
{
    int rc;
    if (!st || !device || !store || !slots_per_epoch)
        return SC_ERR_ARG;
    if (!ahead)
        ahead = &NO_AHEAD;
    rc = sc_slashing_check_attestation(st, source_epoch, target_epoch);
    if (rc != SC_OK)
        return rc;
    if (!(device->flags & SC_WM_HAS_ATTESTATION) || target_epoch > device->target_epoch ||
        source_epoch > device->source_epoch) {
        rc = device_raise(device, ahead, slots_per_epoch, store, ctx, target_epoch, 1,
                          source_epoch);
        if (rc != SC_OK)
            return rc;
    }
    sc_slashing_record_attestation(st, source_epoch, target_epoch);
    return SC_OK;
}

/* Covers targets and blocks of epoch; the source bound stays where votes put it. */
int sc_slashing_cover_device(sc_watermark *device, const sc_commit_ahead *ahead,
                             uint64_t slots_per_epoch, sc_store_device_fn store, void *ctx,
                             uint64_t epoch)
{
    if (!device || !store || !slots_per_epoch)
        return SC_ERR_ARG;
    if (!ahead)
        ahead = &NO_AHEAD;
    if ((device->flags & SC_WM_HAS_ATTESTATION) && (device->flags & SC_WM_HAS_BLOCK) &&
        epoch <= device->target_epoch && last_slot_of(epoch, slots_per_epoch) <= device->block_slot)
        return SC_OK;
    return device_raise(device, ahead, slots_per_epoch, store, ctx, epoch, 0, 0);
}

/* Raises dst to at least src, field by field. */
static void wm_merge(sc_watermark *dst, const sc_watermark *src)
{
    if (src->flags & SC_WM_HAS_BLOCK) {
        dst->block_slot = (dst->flags & SC_WM_HAS_BLOCK)
                              ? sc_max64(dst->block_slot, src->block_slot)
                              : src->block_slot;
        dst->flags |= SC_WM_HAS_BLOCK;
    }
    if (src->flags & SC_WM_HAS_ATTESTATION) {
        if (dst->flags & SC_WM_HAS_ATTESTATION) {
            dst->source_epoch = sc_max64(dst->source_epoch, src->source_epoch);
            dst->target_epoch = sc_max64(dst->target_epoch, src->target_epoch);
        } else {
            dst->source_epoch = src->source_epoch;
            dst->target_epoch = src->target_epoch;
        }
        dst->flags |= SC_WM_HAS_ATTESTATION;
    }
}

static int wm_equal(const sc_watermark *a, const sc_watermark *b)
{
    return a->flags == b->flags && a->block_slot == b->block_slot &&
           a->source_epoch == b->source_epoch && a->target_epoch == b->target_epoch;
}

int sc_slashing_import(sc_slashing_state *st, const sc_watermark *imported,
                       sc_store_fn store, void *ctx, const uint8_t pubkey[SC_PUBKEY_LEN])
{
    sc_watermark next;
    if (!st || !imported || !store || !pubkey || (imported->flags & ~WM_FLAGS_MASK))
        return SC_ERR_ARG;
    next = st->committed;
    wm_merge(&next, imported);
    if (!wm_equal(&next, &st->committed)) {
        if (store(ctx, pubkey, &next) != SC_OK)
            return SC_ERR_STORAGE;
        st->committed = next;
    }
    wm_merge(&st->ram, imported);
    return SC_OK;
}
