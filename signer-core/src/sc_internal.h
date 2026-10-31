/* Internal helpers shared by the core sources. Not part of the public API. */
#ifndef SC_INTERNAL_H
#define SC_INTERNAL_H

#include <string.h> /* memcpy, memset, memcmp only */

#include "blst.h"
#include "signer_core.h"

static inline uint64_t sc_sat_add(uint64_t a, uint64_t b)
{
    return a > UINT64_MAX - b ? UINT64_MAX : a + b;
}

static inline uint64_t sc_max64(uint64_t a, uint64_t b) { return a > b ? a : b; }
static inline uint64_t sc_min64(uint64_t a, uint64_t b) { return a < b ? a : b; }

static inline void sc_put_u64(uint8_t *p, uint64_t v)
{
    for (int i = 0; i < 8; i++)
        p[i] = (uint8_t)(v >> (8 * i));
}

static inline uint64_t sc_get_u64(const uint8_t *p)
{
    uint64_t v = 0;
    for (int i = 7; i >= 0; i--)
        v = (v << 8) | p[i];
    return v;
}

/* Zeroes memory in a way the compiler cannot drop as a dead store. */
void sc_wipe(void *p, size_t n);

/* SHA-256 of a||b, the SSZ merkle node hash. */
void sc_hash_pair(const uint8_t a[32], const uint8_t b[32], uint8_t out[32]);

/* BLS internals used by the signer and by tests of the cache path. */
int sc_bls_load_secret(blst_scalar *sk, const uint8_t secret[SC_SECRET_LEN]);
void sc_bls_hash_to_g2(blst_p2 *out, const uint8_t *msg, size_t msg_len);
void sc_bls_sign_hashed(const blst_scalar *sk, const blst_p2 *hashed,
                        uint8_t signature[SC_SIGNATURE_LEN]);

/* Small LRU cache of hash_to_G2(signing_root). */
typedef struct {
    uint8_t msg[SC_ROOT_LEN];
    uint64_t stamp; /* 0 = empty */
    blst_p2 point;
} sc_h2g2_entry;

typedef struct {
    sc_h2g2_entry *entries;
    uint32_t count;
    uint64_t clock;
    uint64_t hits;
    uint64_t misses;
} sc_h2g2_cache;

void sc_h2g2_cache_init(sc_h2g2_cache *c, sc_h2g2_entry *entries, uint32_t count);
/* Returns H(msg): from the cache, or computed into a cache slot (or into
 * *scratch when the cache has no entries). */
const blst_p2 *sc_h2g2_cache_get(sc_h2g2_cache *c, const uint8_t msg[SC_ROOT_LEN],
                                 blst_p2 *scratch);
void sc_h2g2_cache_wipe(sc_h2g2_cache *c);

/* Records a message as signed in the RAM state: the last step of
 * sc_slashing_approve_block and sc_slashing_approve_attestation. */
void sc_slashing_record_block(sc_slashing_state *st, uint64_t slot);
void sc_slashing_record_attestation(sc_slashing_state *st, uint64_t source_epoch,
                                    uint64_t target_epoch);

/* Policy. */
int sc_policy_check_config(const sc_config *cfg);
/* SC_ERR_POLICY_FUTURE if epoch is past the clock horizon at now: the epoch
 * at now under the slot time changes times, plus max_epochs_ahead. */
int sc_policy_check_epoch(const sc_config *cfg, const sc_slot_times *times, uint64_t now,
                          uint64_t epoch);
/* SC_ERR_POLICY_FUTURE if slot has not started at now + SC_SLOT_MARGIN_SECONDS
 * under the slot time changes times (the slot rule, see signer_core.h). */
int sc_policy_check_slot(const sc_config *cfg, const sc_slot_times *times, uint64_t now,
                         uint64_t slot);
int sc_policy_check_exit(const sc_config *cfg, const sc_voluntary_exit *exit,
                         uint64_t bound_index);
int sc_policy_check_registration(const sc_config *cfg, uint64_t now,
                                 const sc_validator_registration *reg,
                                 const uint8_t validator_pubkey[SC_PUBKEY_LEN]);
/* SC_ERR_POLICY_FORK unless Gloas is scheduled and in force at epoch. */
int sc_policy_check_gloas(const sc_config *cfg, uint64_t epoch);
/* SC_ERR_POLICY_FEE_RECIPIENT unless addr is in the fee recipient allowlist. */
int sc_policy_check_fee_recipient(const sc_config *cfg, const uint8_t addr[SC_ADDRESS_LEN]);
/* Fork version active at epoch (genesis version if no fork applies). */
void sc_fork_version_at(const sc_config *cfg, uint64_t epoch, uint8_t out[SC_VERSION_LEN]);

#endif
