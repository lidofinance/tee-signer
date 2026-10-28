/* Signing policy: clock horizon, exit allowlist, builder registration rules. */
#include "sc_internal.h"

int sc_policy_check_config(const sc_config *cfg)
{
    if (!cfg || cfg->seconds_per_slot == 0 || cfg->slots_per_epoch == 0)
        return SC_ERR_ARG;
    if (cfg->seconds_per_slot > UINT64_MAX / cfg->slots_per_epoch)
        return SC_ERR_ARG;
    if (cfg->fork_count > SC_MAX_FORKS || cfg->exit_allowlist_count > SC_MAX_EXIT_ALLOWLIST ||
        cfg->fee_recipient_count > SC_MAX_FEE_RECIPIENTS ||
        cfg->builder_auth_root_count > SC_MAX_BUILDER_AUTH_ROOTS)
        return SC_ERR_ARG;
    for (uint32_t i = 1; i < cfg->fork_count; i++)
        if (cfg->forks[i].epoch < cfg->forks[i - 1].epoch)
            return SC_ERR_ARG;
    if (cfg->gas_limit_min > cfg->gas_limit_max)
        return SC_ERR_ARG;
    if (cfg->gloas_scheduled > 1)
        return SC_ERR_ARG;
    if (cfg->gloas_scheduled) {
        /* The Gloas epoch must be a fork of the schedule, so the domains of
         * Gloas messages use the Gloas fork version. */
        uint32_t i;
        for (i = 0; i < cfg->fork_count; i++)
            if (cfg->forks[i].epoch == cfg->gloas_fork_epoch)
                break;
        if (i == cfg->fork_count)
            return SC_ERR_ARG;
    }
    return SC_OK;
}

int sc_policy_check_gloas(const sc_config *cfg, uint64_t epoch)
{
    if (!cfg->gloas_scheduled || epoch < cfg->gloas_fork_epoch)
        return SC_ERR_POLICY_FORK;
    return SC_OK;
}

int sc_policy_check_fee_recipient(const sc_config *cfg, const uint8_t addr[SC_ADDRESS_LEN])
{
    for (uint32_t i = 0; i < cfg->fee_recipient_count; i++)
        if (memcmp(cfg->fee_recipients[i], addr, SC_ADDRESS_LEN) == 0)
            return SC_OK;
    return SC_ERR_POLICY_FEE_RECIPIENT;
}

/* a * b into *out; 0 if it does not fit 64 bits. */
static int mul_fits(uint64_t a, uint64_t b, uint64_t *out)
{
    if (a != 0 && b > UINT64_MAX / a)
        return 0;
    *out = a * b;
    return 1;
}

int sc_slot_times_check(const sc_config *cfg, const sc_slot_times *times)
{
    uint64_t start_slot = 0, start, secs;

    if (!cfg || cfg->seconds_per_slot == 0 || cfg->slots_per_epoch == 0)
        return SC_ERR_ARG;
    if (!times || times->count == 0)
        return SC_OK;
    if (times->count > SC_MAX_SLOT_TIMES)
        return SC_ERR_ARG;
    start = cfg->genesis_time;
    secs = cfg->seconds_per_slot;
    for (uint32_t i = 0; i < times->count; i++) {
        const sc_slot_time *c = &times->changes[i];
        uint64_t slot, dur, unused;
        if (c->epoch == 0 || c->seconds_per_slot == 0 || c->seconds_per_slot == secs)
            return SC_ERR_ARG;
        if (i > 0 && c->epoch <= times->changes[i - 1].epoch)
            return SC_ERR_ARG;
        if (!mul_fits(c->seconds_per_slot, cfg->slots_per_epoch, &unused) ||
            !mul_fits(c->epoch, cfg->slots_per_epoch, &slot) ||
            !mul_fits(slot - start_slot, secs, &dur) || start > UINT64_MAX - dur)
            return SC_ERR_ARG;
        start += dur;
        start_slot = slot;
        secs = c->seconds_per_slot;
    }
    return SC_OK;
}

uint64_t sc_slot_at(const sc_config *cfg, const sc_slot_times *times, uint64_t now)
{
    uint64_t start_slot = 0, start = cfg->genesis_time, secs = cfg->seconds_per_slot;
    uint32_t count = times ? times->count : 0;

    if (now <= cfg->genesis_time || secs == 0)
        return 0;
    if (count > SC_MAX_SLOT_TIMES)
        count = SC_MAX_SLOT_TIMES;
    for (uint32_t i = 0; i < count; i++) {
        uint64_t slot, dur;
        /* A change whose start does not fit 64 bits never comes;
         * sc_slot_times_check refuses it anyway. */
        if (!mul_fits(times->changes[i].epoch, cfg->slots_per_epoch, &slot) || slot < start_slot ||
            !mul_fits(slot - start_slot, secs, &dur) || start > UINT64_MAX - dur)
            break;
        if (now < start + dur)
            break;
        start += dur;
        start_slot = slot;
        secs = times->changes[i].seconds_per_slot;
    }
    return sc_sat_add(start_slot, (now - start) / secs);
}

uint64_t sc_epoch_at(const sc_config *cfg, const sc_slot_times *times, uint64_t now)
{
    if (cfg->slots_per_epoch == 0)
        return 0;
    return sc_slot_at(cfg, times, now) / cfg->slots_per_epoch;
}

int sc_policy_check_epoch(const sc_config *cfg, const sc_slot_times *times, uint64_t now,
                          uint64_t epoch)
{
    uint64_t limit = sc_sat_add(sc_epoch_at(cfg, times, now), cfg->max_epochs_ahead);
    return epoch > limit ? SC_ERR_POLICY_FUTURE : SC_OK;
}

int sc_policy_check_exit(const sc_config *cfg, const sc_voluntary_exit *exit,
                         uint64_t bound_index)
{
    if (bound_index != SC_INDEX_UNKNOWN && exit->validator_index != bound_index)
        return SC_ERR_POLICY_INDEX;
    for (uint32_t i = 0; i < cfg->exit_allowlist_count; i++)
        if (cfg->exit_allowlist[i] == exit->validator_index)
            return SC_OK;
    return SC_ERR_POLICY_EXIT;
}

int sc_policy_check_registration(const sc_config *cfg, uint64_t now,
                                 const sc_validator_registration *reg,
                                 const uint8_t validator_pubkey[SC_PUBKEY_LEN])
{
    uint32_t i;
    if (memcmp(reg->pubkey, validator_pubkey, SC_PUBKEY_LEN) != 0)
        return SC_ERR_POLICY_PUBKEY;
    for (i = 0; i < cfg->fee_recipient_count; i++)
        if (memcmp(cfg->fee_recipients[i], reg->fee_recipient, SC_ADDRESS_LEN) == 0)
            break;
    if (i == cfg->fee_recipient_count)
        return SC_ERR_POLICY_FEE_RECIPIENT;
    if (reg->gas_limit < cfg->gas_limit_min || reg->gas_limit > cfg->gas_limit_max)
        return SC_ERR_POLICY_GAS_LIMIT;
    if (cfg->registration_max_future_seconds &&
        reg->timestamp > sc_sat_add(now, cfg->registration_max_future_seconds))
        return SC_ERR_POLICY_TIMESTAMP;
    return SC_OK;
}

void sc_fork_version_at(const sc_config *cfg, uint64_t epoch, uint8_t out[SC_VERSION_LEN])
{
    memcpy(out, cfg->genesis_fork_version, SC_VERSION_LEN);
    for (uint32_t i = 0; i < cfg->fork_count; i++)
        if (cfg->forks[i].epoch <= epoch)
            memcpy(out, cfg->forks[i].version, SC_VERSION_LEN);
}
