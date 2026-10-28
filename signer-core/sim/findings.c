/*
 * findings.c - minimal repros for what the simulator found. Each case
 * prints what it shows; a case that documents a liveness cost the design
 * accepts today is marked EXPECTED-FAIL with its id and exits 0, so this
 * file can run in CI and turns red only if the behaviour changes.
 *
 * SIM-L1: per-validator marks with a source window (commit_ahead
 * source_epochs > 0, as in the cloud chain.json 32,2,2 with
 * -persist-watermarks) stall after a restart during non-finality, the way
 * finding 22 did for device marks before its fix: the stored source bound is
 * the signed source + source_epochs, the chain's source stays at the signed
 * one, so every vote is refused until the chain justifies an epoch at or
 * above the bound.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "signer_core.h"

#define GENESIS 1606824023ull
#define EPOCH_S 384ull
#define E 420000ull

typedef struct {
    sc_watermark wm;
    int has;
    uint64_t now;
} host_t;

static int h_load(void *ctx, const uint8_t pk[48], sc_watermark *out)
{
    host_t *h = ctx;
    (void)pk;
    if (!h->has)
        return SC_ERR_UNKNOWN_VALIDATOR;
    *out = h->wm;
    return SC_OK;
}

static int h_store(void *ctx, const uint8_t pk[48], const sc_watermark *wm)
{
    host_t *h = ctx;
    (void)pk;
    h->wm = *wm;
    h->has = 1;
    return SC_OK;
}

static int h_now(void *ctx, uint64_t *t)
{
    *t = ((host_t *)ctx)->now;
    return SC_OK;
}

static sc_signer *boot(host_t *h, void **mem)
{
    sc_config c;
    sc_host_ops ops = {.ctx = h, .load_watermark = h_load, .store_watermark = h_store, .now = h_now};
    uint8_t pk[48], sk[32];
    size_t sz = sc_signer_mem_size(1, 0);
    sc_signer *s = NULL;
    memset(&c, 0, sizeof c);
    c.genesis_time = GENESIS;
    c.seconds_per_slot = 12;
    c.slots_per_epoch = 32;
    c.max_epochs_ahead = 2;
    c.commit_ahead.block_slots = 32;
    c.commit_ahead.source_epochs = 2;
    c.commit_ahead.target_epochs = 2;
    c.mark_scope = SC_MARKS_PER_VALIDATOR;
    *mem = aligned_alloc(8, (sz + 7) & ~(size_t)7);
    if (sc_signer_init(*mem, sz, 1, 0, &c, &ops, &s) != SC_OK)
        abort();
    memset(pk, 0x99, sizeof pk);
    memset(sk, 0x22, sizeof sk);
    sk[0] = 0x11;
    if (sc_signer_add_validator(s, pk, sk, SC_INDEX_UNKNOWN, NULL) != SC_OK)
        abort();
    return s;
}

static int vote(sc_signer *s, host_t *h, uint64_t src, uint64_t tgt)
{
    sc_attestation_data a;
    uint8_t pk[48], sig[96];
    memset(&a, 0, sizeof a);
    memset(pk, 0x99, sizeof pk);
    a.slot = tgt * 32 + 3;
    a.source.epoch = src;
    a.target.epoch = tgt;
    a.beacon_block_root[0] = (uint8_t)tgt;
    h->now = GENESIS + tgt * EPOCH_S + 7;
    return sc_sign_attestation(s, pk, &a, sig);
}

int main(void)
{
    host_t h = {0};
    void *mem;
    sc_signer *s = boot(&h, &mem);
    const uint64_t S = E + 3;
    int refused = 0, first_ok = -1;
    for (uint64_t t = E + 1; t <= S + 1; t++)
        if (vote(s, &h, t - 1, t) != SC_OK)
            abort();
    for (uint64_t t = S + 2; t <= S + 40; t++) /* no finality: source stays S */
        if (vote(s, &h, S, t) != SC_OK)
            abort();
    printf("SIM-L1 stored mark before restart: source <= %llu, target <= %llu (epochs from E)\n",
           (unsigned long long)(h.wm.source_epoch - E), (unsigned long long)(h.wm.target_epoch - E));
    sc_signer_wipe(s);
    free(mem);
    s = boot(&h, &mem);
    for (uint64_t t = S + 41; t <= S + 140; t++) {
        int rc = vote(s, &h, S, t);
        if (rc == SC_OK) {
            first_ok = (int)(t - E);
            break;
        }
        refused++;
    }
    sc_signer_wipe(s);
    free(mem);
    if (first_ok < 0) {
        printf("EXPECTED-FAIL SIM-L1: per-validator marks, source window 2: after a restart in a "
               "non-finality period every vote with the chain's source is refused (%d of %d "
               "epochs, until the chain justifies epoch %llu from E)\n",
               refused, refused, (unsigned long long)(S + 2 - E));
        return 0;
    }
    printf("SIM-L1 changed: a vote signed again %d epochs after the restart; update this test\n",
           first_ok);
    return 1;
}
