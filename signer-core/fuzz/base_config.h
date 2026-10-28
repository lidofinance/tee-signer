/*
 * A mainnet-like config with Gloas scheduled (the one tests/test_unit.c
 * uses, plus a Gloas fork), and field patches read from the fuzz input.
 * Starting from a valid config and patching a few fields reaches more code
 * than a config read whole from random bytes, which init refuses at once.
 */
#ifndef SC_FUZZ_BASE_CONFIG_H
#define SC_FUZZ_BASE_CONFIG_H

#include "fuzz.h"

#define FZ_GENESIS_TIME 1606824023ull
#define FZ_EPOCH_SECONDS (12ull * 32ull)
#define FZ_E 420000ull     /* the clock epoch inputs start near */
#define FZ_GLOAS 420016ull /* Gloas fork epoch of the base config */

static const char FZ_AUTH_DATA[] = "builder.example.org";

static inline void fz_base_config(sc_config *c)
{
    static const struct {
        uint64_t epoch;
        uint8_t v;
    } forks[] = {{74240, 1}, {144896, 2}, {194048, 3}, {269568, 4},
                 {364032, 5}, {411392, 6}, {FZ_GLOAS, 7}};
    memset(c, 0, sizeof *c);
    for (int i = 0; i < 32; i++)
        c->genesis_validators_root[i] = (uint8_t)(0x4b + i);
    for (size_t i = 0; i < sizeof forks / sizeof forks[0]; i++) {
        c->forks[i].epoch = forks[i].epoch;
        c->forks[i].version[0] = forks[i].v;
    }
    c->fork_count = sizeof forks / sizeof forks[0];
    c->voluntary_exit_fork_version[0] = 3;
    c->genesis_time = FZ_GENESIS_TIME;
    c->seconds_per_slot = 12;
    c->slots_per_epoch = 32;
    c->max_epochs_ahead = 2;
    c->exit_allowlist[0] = 100;
    c->exit_allowlist[1] = 101;
    c->exit_allowlist_count = 2;
    memset(c->fee_recipients[0], 0x11, 20);
    memset(c->fee_recipients[1], 0x22, 20);
    c->fee_recipient_count = 2;
    c->gas_limit_min = 30000000;
    c->gas_limit_max = 60000000;
    c->registration_max_future_seconds = 3600;
    c->commit_ahead.block_slots = 32;
    c->commit_ahead.source_epochs = 1;
    c->commit_ahead.target_epochs = 1;
    c->gloas_scheduled = 1;
    c->gloas_fork_epoch = FZ_GLOAS;
    sc_htr_builder_auth_data((const uint8_t *)FZ_AUTH_DATA, sizeof FZ_AUTH_DATA - 1,
                             c->builder_auth_roots[0]);
    c->builder_auth_root_count = 1;
}

/* A value near base, or (top bit of sel) a raw 64-bit value. */
static inline uint64_t fz_near(fz_in *in, uint64_t base)
{
    uint8_t sel = fz_u8(in);
    if (sel & 0x80)
        return fz_u64(in);
    return base + (uint64_t)(int64_t)(int8_t)fz_u8(in) * (sel & 0x40 ? 64 : 1);
}

/* Changes one field of c. Counts can go past their arrays on purpose:
 * the core must refuse them. */
static inline void fz_patch_config(sc_config *c, fz_in *in)
{
    uint8_t field = fz_u8(in);
    uint8_t i = fz_u8(in);
    switch (field % 24) {
    case 0: c->genesis_time = fz_near(in, c->genesis_time); break;
    case 1: c->seconds_per_slot = fz_near(in, c->seconds_per_slot); break;
    case 2: c->slots_per_epoch = fz_near(in, c->slots_per_epoch); break;
    case 3: c->fork_count = (uint32_t)fz_near(in, c->fork_count); break;
    case 4: c->forks[i % SC_MAX_FORKS].epoch = fz_near(in, c->forks[i % SC_MAX_FORKS].epoch); break;
    case 5: c->forks[i % SC_MAX_FORKS].version[0] = fz_u8(in); break;
    case 6: c->max_epochs_ahead = fz_near(in, c->max_epochs_ahead); break;
    case 7: c->exit_allowlist_count = (uint32_t)fz_near(in, c->exit_allowlist_count); break;
    case 8: c->exit_allowlist[i] = fz_near(in, 100); break;
    case 9: c->fee_recipient_count = (uint32_t)fz_near(in, c->fee_recipient_count); break;
    case 10: fz_bytes(in, c->fee_recipients[i % SC_MAX_FEE_RECIPIENTS], SC_ADDRESS_LEN); break;
    case 11: c->gas_limit_min = fz_near(in, c->gas_limit_min); break;
    case 12: c->gas_limit_max = fz_near(in, c->gas_limit_max); break;
    case 13: c->registration_max_future_seconds = fz_near(in, c->registration_max_future_seconds); break;
    case 14: c->commit_ahead.block_slots = fz_near(in, c->commit_ahead.block_slots); break;
    case 15: c->commit_ahead.source_epochs = fz_near(in, c->commit_ahead.source_epochs); break;
    case 16: c->commit_ahead.target_epochs = fz_near(in, c->commit_ahead.target_epochs); break;
    case 17: c->mark_scope = (uint32_t)fz_near(in, c->mark_scope); break;
    case 18: c->persist_repeat_root = (uint32_t)fz_near(in, c->persist_repeat_root); break;
    case 19: c->gloas_scheduled = (uint32_t)fz_near(in, c->gloas_scheduled); break;
    case 20: c->gloas_fork_epoch = fz_near(in, c->gloas_fork_epoch); break;
    case 21: c->builder_auth_root_count = (uint32_t)fz_near(in, c->builder_auth_root_count); break;
    case 22: fz_bytes(in, c->builder_auth_roots[i % SC_MAX_BUILDER_AUTH_ROOTS], 32); break;
    default: fz_bytes(in, c->genesis_validators_root, 32); break;
    }
}

/* Slot time changes: count (may exceed the array), then epochs relative to
 * FZ_E and slot times. */
static inline void fz_slot_times(sc_slot_times *t, fz_in *in)
{
    uint8_t n = fz_u8(in);
    memset(t, 0, sizeof *t);
    t->count = n % 20;
    for (uint32_t i = 0; i < SC_MAX_SLOT_TIMES && i < t->count; i++) {
        t->changes[i].epoch = fz_near(in, FZ_E + 8 * i);
        t->changes[i].seconds_per_slot = fz_near(in, 6);
    }
    if (n & 0x80) /* a count past the array */
        t->count = fz_u32(in);
}

/* A fork schedule near the base one. */
static inline void fz_schedule(sc_schedule *s, const sc_config *base, fz_in *in)
{
    uint8_t n = fz_u8(in);
    memcpy(s->forks, base->forks, sizeof s->forks);
    s->fork_count = base->fork_count;
    s->gloas_scheduled = base->gloas_scheduled;
    s->gloas_fork_epoch = base->gloas_fork_epoch;
    for (uint8_t k = 0; k < n % 4; k++) {
        uint8_t what = fz_u8(in), i = fz_u8(in) % SC_MAX_FORKS;
        switch (what % 5) {
        case 0: s->forks[i].epoch = fz_near(in, s->forks[i].epoch); break;
        case 1: s->forks[i].version[0] = fz_u8(in); break;
        case 2: s->fork_count = (uint32_t)fz_near(in, s->fork_count); break;
        case 3: s->gloas_scheduled = (uint32_t)fz_near(in, s->gloas_scheduled); break;
        default: s->gloas_fork_epoch = fz_near(in, s->gloas_fork_epoch); break;
        }
    }
}

#endif
