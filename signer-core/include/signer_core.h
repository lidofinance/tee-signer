/*
 * signer_core.h - portable Ethereum validator signing core.
 *
 * The core does SSZ hashing, BLS signing (blst), EIP-3076 minimal slashing
 * protection with commit-ahead watermarks, and a small signing policy.
 * It makes no OS calls. Storage and the trusted clock come in through
 * sc_host_ops callbacks, and the caller provides all memory.
 *
 * Nothing here is thread safe. A caller that signs from several threads
 * must serialize calls on one sc_signer.
 *
 * All multi-byte integers in SSZ are little endian. Fixed-size byte fields
 * (roots, pubkeys, versions, addresses) are passed as raw bytes.
 */
#ifndef SIGNER_CORE_H
#define SIGNER_CORE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SC_PUBKEY_LEN 48
#define SC_SIGNATURE_LEN 96
#define SC_SECRET_LEN 32
#define SC_ROOT_LEN 32
#define SC_VERSION_LEN 4
#define SC_DOMAIN_TYPE_LEN 4
#define SC_ADDRESS_LEN 20

/* Capacities of the fixed arrays in sc_config. Override with -D. */
#ifndef SC_MAX_FORKS
#define SC_MAX_FORKS 16
#endif
#ifndef SC_MAX_EXIT_ALLOWLIST
#define SC_MAX_EXIT_ALLOWLIST 1024
#endif
#ifndef SC_MAX_FEE_RECIPIENTS
#define SC_MAX_FEE_RECIPIENTS 64
#endif
#ifndef SC_MAX_BUILDER_AUTH_ROOTS
#define SC_MAX_BUILDER_AUTH_ROOTS 16
#endif

/* BuilderRequestAuth (builder-specs gloas): data is ByteList[4096]; the SSZ
 * is offset:u32 slot:u64 data. */
#define SC_BUILDER_AUTH_MAX_DATA 4096
#define SC_SSZ_BUILDER_REQUEST_AUTH_MIN_LEN 12
#define SC_SSZ_BUILDER_REQUEST_AUTH_MAX_LEN (12 + SC_BUILDER_AUTH_MAX_DATA)

/* Validator index value meaning "not bound to an index". */
#define SC_INDEX_UNKNOWN UINT64_MAX

/* ------------------------------------------------------------------------ */
/* Status codes                                                             */
/* ------------------------------------------------------------------------ */

typedef enum {
    SC_OK = 0,
    SC_ERR_ARG,               /* bad argument or config */
    SC_ERR_NOMEM,             /* buffer too small or validator table full */
    SC_ERR_DECODE,            /* SSZ input has the wrong length */
    SC_ERR_BAD_KEY,           /* secret is zero or not below the group order */
    SC_ERR_DUPLICATE,         /* validator already loaded */
    SC_ERR_UNKNOWN_VALIDATOR, /* no such validator; load_watermark: nothing stored */
    SC_ERR_STORAGE,           /* load_watermark or store_watermark failed */
    SC_ERR_CLOCK,             /* clock callback failed */

    /* Slashing protection refusals (EIP-3076 minimal strategy). */
    SC_ERR_SLASH_BLOCK,       /* block slot <= highest signed block slot */
    SC_ERR_SLASH_SOURCE,      /* source epoch < highest signed source epoch */
    SC_ERR_SLASH_TARGET,      /* target epoch <= highest signed target epoch */
    SC_ERR_SLASH_SOURCE_GT_TARGET,

    /* Policy refusals. */
    SC_ERR_POLICY_FUTURE,        /* too far ahead of the trusted clock */
    SC_ERR_POLICY_EXIT,          /* validator index not in the exit allowlist */
    SC_ERR_POLICY_FEE_RECIPIENT, /* fee recipient not in the allowlist */
    SC_ERR_POLICY_GAS_LIMIT,     /* gas limit outside [min, max] */
    SC_ERR_POLICY_TIMESTAMP,     /* registration timestamp too far in the future */
    SC_ERR_POLICY_PUBKEY,        /* registration pubkey is not the signing validator */
    SC_ERR_POLICY_INDEX,         /* message index differs from the bound index */
    SC_ERR_POLICY_DOMAIN,        /* sc_sign_root: domain type not allowed */

    /* Gloas (EIP-7732). Appended, so the codes above keep their values. */
    SC_ERR_POLICY_FORK,     /* message type not in force at its epoch (before Gloas,
                               or Gloas not scheduled in the config) */
    SC_ERR_POLICY_BUILDER,  /* envelope builder_index is not BUILDER_INDEX_SELF_BUILD */
    SC_ERR_POLICY_ENVELOPE, /* envelope is not for the last block this validator signed */
    SC_ERR_EQUIVOCATION,    /* a second, different PTC vote or envelope for a slot at or
                               below the last one signed */

    /* Aggregates and sync committee contributions. Appended. */
    SC_ERR_SELECTION_PROOF, /* the selection proof in an aggregate or a contribution does
                               not verify under the validator key */

    /* Fork schedule updates. Appended. */
    SC_ERR_SCHEDULE, /* sc_signer_set_schedule: the new schedule changes an epoch the
                        signer may sign before the update takes effect */

    /* Builder API authentication. Appended. */
    SC_ERR_POLICY_BUILDER_AUTH, /* BuilderRequestAuth whose data root is not in
                                   builder_auth_roots (an empty list refuses all) */

    /* Attestation data consistency. Appended. */
    SC_ERR_POLICY_TARGET_SLOT /* attestation target epoch is not the epoch of its
                                 slot: no chain includes it, and signing it would
                                 only raise the target mark */
} sc_status;

/* Short constant name for a status code, e.g. "SC_ERR_SLASH_TARGET". */
const char *sc_status_name(int status);

/* ------------------------------------------------------------------------ */
/* SSZ containers                                                           */
/* ------------------------------------------------------------------------ */

typedef struct {
    uint64_t epoch;
    uint8_t root[SC_ROOT_LEN];
} sc_checkpoint;

/* Since Electra, index is always 0, but it is still part of the container. */
typedef struct {
    uint64_t slot;
    uint64_t index;
    uint8_t beacon_block_root[SC_ROOT_LEN];
    sc_checkpoint source;
    sc_checkpoint target;
} sc_attestation_data;

typedef struct {
    uint64_t slot;
    uint64_t proposer_index;
    uint8_t parent_root[SC_ROOT_LEN];
    uint8_t state_root[SC_ROOT_LEN];
    uint8_t body_root[SC_ROOT_LEN];
} sc_beacon_block_header;

typedef struct {
    uint64_t epoch;
    uint64_t validator_index;
} sc_voluntary_exit;

/* builder-specs ValidatorRegistrationV1 */
typedef struct {
    uint8_t fee_recipient[SC_ADDRESS_LEN];
    uint64_t gas_limit;
    uint64_t timestamp;
    uint8_t pubkey[SC_PUBKEY_LEN];
} sc_validator_registration;

typedef struct {
    uint8_t current_version[SC_VERSION_LEN];
    uint8_t genesis_validators_root[SC_ROOT_LEN];
} sc_fork_data;

typedef struct {
    uint8_t object_root[SC_ROOT_LEN];
    uint8_t domain[SC_ROOT_LEN];
} sc_signing_data;

/*
 * Gloas containers (consensus-specs specs/gloas/beacon-chain.md, commit
 * 460fd37c). PayloadAttestationData and ProposerPreferences are plain
 * containers. ExecutionPayloadEnvelope is a ProgressiveContainer whose
 * payload carries the transactions; the signer takes it as
 * sc_payload_envelope, with the variable-size payload fields given as their
 * hash_tree_root, as a block comes as its header with body_root. The core
 * still computes the envelope root from every field, and reads slot_number,
 * fee_recipient, builder_index and the block roots itself.
 */
#define SC_BUILDER_INDEX_SELF_BUILD UINT64_MAX /* BUILDER_INDEX_SELF_BUILD */

typedef struct {
    uint8_t beacon_block_root[SC_ROOT_LEN];
    uint64_t slot;
    uint8_t payload_present;     /* Boolean: 0 or 1 */
    uint8_t blob_data_available; /* Boolean: 0 or 1 */
} sc_payload_attestation_data;

/* p2p-interface.md "ProposerPreferences" */
typedef struct {
    uint8_t dependent_root[SC_ROOT_LEN];
    uint64_t proposal_slot;
    uint64_t validator_index;
    uint8_t fee_recipient[SC_ADDRESS_LEN];
    uint64_t target_gas_limit;
} sc_proposer_preferences;

/*
 * ExecutionPayload (ProgressiveContainer, 19 fields). Fixed-size fields as
 * values; logs_bloom, extra_data, transactions, withdrawals and
 * block_access_list as their hash_tree_root. base_fee_per_gas is the uint256
 * in little endian, which is also its root.
 */
typedef struct {
    uint8_t parent_hash[SC_ROOT_LEN];
    uint8_t fee_recipient[SC_ADDRESS_LEN];
    uint8_t state_root[SC_ROOT_LEN];
    uint8_t receipts_root[SC_ROOT_LEN];
    uint8_t logs_bloom_root[SC_ROOT_LEN];
    uint8_t prev_randao[SC_ROOT_LEN];
    uint64_t block_number;
    uint64_t gas_limit;
    uint64_t gas_used;
    uint64_t timestamp;
    uint8_t extra_data_root[SC_ROOT_LEN];
    uint8_t base_fee_per_gas[SC_ROOT_LEN];
    uint8_t block_hash[SC_ROOT_LEN];
    uint8_t transactions_root[SC_ROOT_LEN];
    uint8_t withdrawals_root[SC_ROOT_LEN];
    uint64_t blob_gas_used;
    uint64_t excess_blob_gas;
    uint8_t block_access_list_root[SC_ROOT_LEN];
    uint64_t slot_number;
} sc_execution_payload_summary;

/* ExecutionPayloadEnvelope (ProgressiveContainer, 5 fields). */
typedef struct {
    sc_execution_payload_summary payload;
    uint8_t execution_requests_root[SC_ROOT_LEN]; /* hash_tree_root(ExecutionRequests) */
    uint64_t builder_index;
    uint8_t beacon_block_root[SC_ROOT_LEN];
    uint8_t parent_beacon_block_root[SC_ROOT_LEN];
} sc_payload_envelope;

/* Serialized SSZ sizes. All these containers are fixed size. */
#define SC_SSZ_CHECKPOINT_LEN 40
#define SC_SSZ_ATTESTATION_DATA_LEN 128
#define SC_SSZ_BEACON_BLOCK_HEADER_LEN 112
#define SC_SSZ_VOLUNTARY_EXIT_LEN 16
#define SC_SSZ_VALIDATOR_REGISTRATION_LEN 84
#define SC_SSZ_FORK_DATA_LEN 36
#define SC_SSZ_SIGNING_DATA_LEN 64
#define SC_SSZ_PAYLOAD_ATTESTATION_DATA_LEN 42
#define SC_SSZ_PROPOSER_PREFERENCES_LEN 76
/* sc_payload_envelope in a fixed layout of this core, not spec SSZ: the
 * fields in the order above, integers little endian (payload summary 428
 * bytes, then 32 + 8 + 32 + 32). */
#define SC_PAYLOAD_SUMMARY_ENCODED_LEN 428
#define SC_PAYLOAD_ENVELOPE_ENCODED_LEN 532

/* hash_tree_root */
void sc_htr_checkpoint(const sc_checkpoint *v, uint8_t out[SC_ROOT_LEN]);
void sc_htr_attestation_data(const sc_attestation_data *v, uint8_t out[SC_ROOT_LEN]);
void sc_htr_beacon_block_header(const sc_beacon_block_header *v, uint8_t out[SC_ROOT_LEN]);
void sc_htr_voluntary_exit(const sc_voluntary_exit *v, uint8_t out[SC_ROOT_LEN]);
void sc_htr_validator_registration(const sc_validator_registration *v, uint8_t out[SC_ROOT_LEN]);
void sc_htr_fork_data(const sc_fork_data *v, uint8_t out[SC_ROOT_LEN]);
void sc_htr_signing_data(const sc_signing_data *v, uint8_t out[SC_ROOT_LEN]);
void sc_htr_uint64(uint64_t v, uint8_t out[SC_ROOT_LEN]);
void sc_htr_payload_attestation_data(const sc_payload_attestation_data *v, uint8_t out[SC_ROOT_LEN]);
void sc_htr_proposer_preferences(const sc_proposer_preferences *v, uint8_t out[SC_ROOT_LEN]);
void sc_htr_execution_payload_summary(const sc_execution_payload_summary *v,
                                      uint8_t out[SC_ROOT_LEN]);
void sc_htr_payload_envelope(const sc_payload_envelope *v, uint8_t out[SC_ROOT_LEN]);
/*
 * Progressive merkleization (EIP-7916, remerkleable subtree_fill_progressive):
 * hash(binary tree of chunks[0..1), progressive rest), the rest split the same
 * way with 4, 16, 64, ... chunks per level; a zero chunk when n is 0.
 * n at most 85 (levels of 1, 4, 16 and 64 chunks), else SC_ERR_ARG.
 */
int sc_merkleize_progressive(const uint8_t (*chunks)[SC_ROOT_LEN], size_t n,
                             uint8_t out[SC_ROOT_LEN]);

/* SSZ decode: len must equal the container size, else SC_ERR_DECODE. */
int sc_ssz_decode_checkpoint(const uint8_t *in, size_t len, sc_checkpoint *out);
int sc_ssz_decode_attestation_data(const uint8_t *in, size_t len, sc_attestation_data *out);
int sc_ssz_decode_beacon_block_header(const uint8_t *in, size_t len, sc_beacon_block_header *out);
int sc_ssz_decode_voluntary_exit(const uint8_t *in, size_t len, sc_voluntary_exit *out);
int sc_ssz_decode_validator_registration(const uint8_t *in, size_t len, sc_validator_registration *out);
int sc_ssz_decode_fork_data(const uint8_t *in, size_t len, sc_fork_data *out);
int sc_ssz_decode_signing_data(const uint8_t *in, size_t len, sc_signing_data *out);
/* Booleans other than 0 and 1 are SC_ERR_DECODE. */
int sc_ssz_decode_payload_attestation_data(const uint8_t *in, size_t len,
                                           sc_payload_attestation_data *out);
int sc_ssz_decode_proposer_preferences(const uint8_t *in, size_t len, sc_proposer_preferences *out);
int sc_decode_payload_envelope(const uint8_t *in, size_t len, sc_payload_envelope *out);

/* SSZ encode into a buffer of exactly the container size. */
void sc_ssz_encode_checkpoint(const sc_checkpoint *v, uint8_t out[SC_SSZ_CHECKPOINT_LEN]);
void sc_ssz_encode_attestation_data(const sc_attestation_data *v, uint8_t out[SC_SSZ_ATTESTATION_DATA_LEN]);
void sc_ssz_encode_beacon_block_header(const sc_beacon_block_header *v, uint8_t out[SC_SSZ_BEACON_BLOCK_HEADER_LEN]);
void sc_ssz_encode_voluntary_exit(const sc_voluntary_exit *v, uint8_t out[SC_SSZ_VOLUNTARY_EXIT_LEN]);
void sc_ssz_encode_validator_registration(const sc_validator_registration *v, uint8_t out[SC_SSZ_VALIDATOR_REGISTRATION_LEN]);
void sc_ssz_encode_fork_data(const sc_fork_data *v, uint8_t out[SC_SSZ_FORK_DATA_LEN]);
void sc_ssz_encode_signing_data(const sc_signing_data *v, uint8_t out[SC_SSZ_SIGNING_DATA_LEN]);
void sc_ssz_encode_payload_attestation_data(const sc_payload_attestation_data *v,
                                            uint8_t out[SC_SSZ_PAYLOAD_ATTESTATION_DATA_LEN]);
void sc_ssz_encode_proposer_preferences(const sc_proposer_preferences *v,
                                        uint8_t out[SC_SSZ_PROPOSER_PREFERENCES_LEN]);
void sc_encode_payload_envelope(const sc_payload_envelope *v,
                                uint8_t out[SC_PAYLOAD_ENVELOPE_ENCODED_LEN]);

/* ------------------------------------------------------------------------ */
/* Domains and signing roots (consensus-specs phase0 helpers)               */
/* ------------------------------------------------------------------------ */

extern const uint8_t SC_DOMAIN_BEACON_PROPOSER[SC_DOMAIN_TYPE_LEN];   /* 0x00000000 */
extern const uint8_t SC_DOMAIN_BEACON_ATTESTER[SC_DOMAIN_TYPE_LEN];   /* 0x01000000 */
extern const uint8_t SC_DOMAIN_RANDAO[SC_DOMAIN_TYPE_LEN];            /* 0x02000000 */
extern const uint8_t SC_DOMAIN_VOLUNTARY_EXIT[SC_DOMAIN_TYPE_LEN];    /* 0x04000000 */
extern const uint8_t SC_DOMAIN_APPLICATION_BUILDER[SC_DOMAIN_TYPE_LEN]; /* 0x00000001 */
/* Gloas, beacon-chain.md "Domains" */
extern const uint8_t SC_DOMAIN_BEACON_BUILDER[SC_DOMAIN_TYPE_LEN];       /* 0x0B000000 */
extern const uint8_t SC_DOMAIN_PTC_ATTESTER[SC_DOMAIN_TYPE_LEN];         /* 0x0C000000 */
extern const uint8_t SC_DOMAIN_PROPOSER_PREFERENCES[SC_DOMAIN_TYPE_LEN]; /* 0x0D000000 */
/* builder-specs gloas builder.md: genesis fork version, zero root */
extern const uint8_t SC_DOMAIN_BUILDER_REQUEST_AUTH[SC_DOMAIN_TYPE_LEN]; /* 0x0B000001 */

void sc_compute_fork_data_root(const uint8_t current_version[SC_VERSION_LEN],
                               const uint8_t genesis_validators_root[SC_ROOT_LEN],
                               uint8_t out[SC_ROOT_LEN]);
/* domain_type || fork_data_root[0:28] */
void sc_compute_domain(const uint8_t domain_type[SC_DOMAIN_TYPE_LEN],
                       const uint8_t fork_version[SC_VERSION_LEN],
                       const uint8_t genesis_validators_root[SC_ROOT_LEN],
                       uint8_t out[SC_ROOT_LEN]);
/* hash_tree_root(SigningData(object_root, domain)) */
void sc_compute_signing_root(const uint8_t object_root[SC_ROOT_LEN],
                             const uint8_t domain[SC_ROOT_LEN],
                             uint8_t out[SC_ROOT_LEN]);
/* Builder domain: GENESIS_FORK_VERSION and an all-zero genesis_validators_root. */
void sc_compute_builder_domain(const uint8_t genesis_fork_version[SC_VERSION_LEN],
                               uint8_t out[SC_ROOT_LEN]);

/* ------------------------------------------------------------------------ */
/* BLS (min-pubkey-size, DST BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_)     */
/* ------------------------------------------------------------------------ */

/* SC_OK if secret is a valid scalar (non-zero, below r), else SC_ERR_BAD_KEY. */
int sc_bls_check_secret(const uint8_t secret[SC_SECRET_LEN]);
int sc_bls_pubkey(const uint8_t secret[SC_SECRET_LEN], uint8_t pubkey[SC_PUBKEY_LEN]);
/* Signs msg with no caching. */
int sc_bls_sign(const uint8_t secret[SC_SECRET_LEN], const uint8_t *msg, size_t msg_len,
                uint8_t signature[SC_SIGNATURE_LEN]);
/* SC_OK if signature verifies, SC_ERR_ARG otherwise. */
int sc_bls_verify(const uint8_t pubkey[SC_PUBKEY_LEN], const uint8_t *msg, size_t msg_len,
                  const uint8_t signature[SC_SIGNATURE_LEN]);

/* ------------------------------------------------------------------------ */
/* Slashing protection                                                      */
/* ------------------------------------------------------------------------ */

#define SC_WM_HAS_BLOCK 0x1u
#define SC_WM_HAS_ATTESTATION 0x2u

/*
 * Per-validator watermark. Fields are valid only when the matching flag is
 * set. A watermark means "nothing at or below these values may be signed":
 * refuse block slot <= block_slot, source < source_epoch,
 * target <= target_epoch.
 */
typedef struct {
    uint64_t block_slot;
    uint64_t source_epoch;
    uint64_t target_epoch;
    uint32_t flags;
} sc_watermark;

/*
 * Commit-ahead window sizes. Before signing a message above the committed
 * window, the core persists a new window that reaches this far past the
 * message. Zero means "persist exactly what is signed" (a write per new
 * message). Larger values mean fewer writes but more messages refused
 * after a restart.
 */
typedef struct {
    uint64_t block_slots;
    uint64_t source_epochs;
    uint64_t target_epochs;
} sc_commit_ahead;

/*
 * Slashing state of one validator.
 *   ram:       exact highest values signed in this run (or imported).
 *   committed: durable upper bounds; everything signed is at or below them.
 * After a restart both start from the persisted committed watermark.
 */
typedef struct {
    sc_watermark ram;
    sc_watermark committed;
} sc_slashing_state;

/* Persists wm for pubkey. Must return SC_OK only once the write is durable. */
typedef int (*sc_store_fn)(void *ctx, const uint8_t pubkey[SC_PUBKEY_LEN], const sc_watermark *wm);

/* Initializes state from a persisted watermark; NULL means nothing ever signed. */
void sc_slashing_restore(sc_slashing_state *st, const sc_watermark *persisted);

/* Pure checks against the RAM state. */
int sc_slashing_check_block(const sc_slashing_state *st, uint64_t slot);
int sc_slashing_check_attestation(const sc_slashing_state *st, uint64_t source_epoch,
                                  uint64_t target_epoch);

/*
 * Check, commit ahead if needed (via store), then record. On SC_OK the caller
 * may sign. On any error the state is unchanged.
 */
int sc_slashing_approve_block(sc_slashing_state *st, const sc_commit_ahead *ahead,
                              sc_store_fn store, void *ctx,
                              const uint8_t pubkey[SC_PUBKEY_LEN], uint64_t slot);
int sc_slashing_approve_attestation(sc_slashing_state *st, const sc_commit_ahead *ahead,
                                    sc_store_fn store, void *ctx,
                                    const uint8_t pubkey[SC_PUBKEY_LEN],
                                    uint64_t source_epoch, uint64_t target_epoch);

/*
 * EIP-3076 import, minimal strategy: raise both watermarks to at least the
 * imported maxima (max block slot, max source, max target) and persist.
 */
int sc_slashing_import(sc_slashing_state *st, const sc_watermark *imported,
                       sc_store_fn store, void *ctx, const uint8_t pubkey[SC_PUBKEY_LEN]);

/* Where the commit-ahead marks live (sc_config.mark_scope). */
#define SC_MARKS_PER_VALIDATOR 0u /* one mark per validator: load_watermark, store_watermark */
#define SC_MARKS_PER_DEVICE 1u    /* one mark for all validators: load_device_mark,
                                     store_device_mark */

/*
 * Per-device marks. *device is the one durable mark of all validators on the
 * device; st->committed is not used (restore each validator with
 * sc_slashing_restore(st, device)). A message above *device raises it, with
 * one store call, to targets and block epochs up to
 * h = epoch + ahead->target_epochs (blocks to the last slot of epoch h) and,
 * for an attestation, sources up to its own source: the source bound is the
 * highest source signed, with no window. A vote whose target the mark covers
 * but whose source is new moves only the source bound. ahead->block_slots and
 * ahead->source_epochs are not used. Check, commit and record as the
 * per-validator calls do: on SC_OK the caller may sign, on any error st and
 * *device are unchanged.
 */
typedef int (*sc_store_device_fn)(void *ctx, const sc_watermark *wm);
int sc_slashing_approve_block_device(sc_slashing_state *st, sc_watermark *device,
                                     const sc_commit_ahead *ahead, uint64_t slots_per_epoch,
                                     sc_store_device_fn store, void *ctx, uint64_t slot);
int sc_slashing_approve_attestation_device(sc_slashing_state *st, sc_watermark *device,
                                           const sc_commit_ahead *ahead,
                                           uint64_t slots_per_epoch, sc_store_device_fn store,
                                           void *ctx, uint64_t source_epoch,
                                           uint64_t target_epoch);
/* Raises *device the same way, with one store call, so it covers attestation
 * targets and blocks of epoch; SC_OK without a call if it does already. It
 * never raises the source bound: only a signed vote (or an import) does. */
int sc_slashing_cover_device(sc_watermark *device, const sc_commit_ahead *ahead,
                             uint64_t slots_per_epoch, sc_store_device_fn store, void *ctx,
                             uint64_t epoch);
/*
 * Per-validator marks: makes st->committed's block bound cover slot, raising
 * it to slot + ahead->block_slots with one store call if it does not yet. The
 * RAM state stays as it is. Gloas PTC votes and envelopes are keyed by slot
 * and share the block bound: after a restart the core refuses them at or
 * below it, so they need no field of their own in the stored mark.
 */
int sc_slashing_cover_slot(sc_slashing_state *st, const sc_commit_ahead *ahead, sc_store_fn store,
                           void *ctx, const uint8_t pubkey[SC_PUBKEY_LEN], uint64_t slot);

/* ------------------------------------------------------------------------ */
/* Exact repeats                                                            */
/* ------------------------------------------------------------------------ */

#define SC_REPEAT_HAS_ATTESTATION 0x1u
#define SC_REPEAT_HAS_BLOCK 0x2u

/*
 * Signing roots of the last attestation and the last block a validator
 * signed. A request with one of these roots is an exact repeat: the core
 * signs it again without the slashing check (the signature is the one it
 * already gave, BLS signing is deterministic). Policy checks still run.
 * Only these two roots qualify; an older vote or any other message at or
 * below the marks is refused as before. The roots live in RAM only: a
 * validator starts with none when it is loaded, so after a restart the
 * marks refuse a repeat.
 */
typedef struct {
    uint32_t flags; /* SC_REPEAT_HAS_ATTESTATION, SC_REPEAT_HAS_BLOCK */
    uint8_t attestation_root[SC_ROOT_LEN];
    uint8_t block_root[SC_ROOT_LEN];
} sc_repeat_roots;

/* ------------------------------------------------------------------------ */
/* Signer                                                                   */
/* ------------------------------------------------------------------------ */

/*
 * Host callbacks. Which storage callbacks a signer needs depends on its
 * config; sc_signer_init refuses a config whose callbacks are missing.
 */
typedef struct {
    void *ctx;
    /* SC_MARKS_PER_VALIDATOR. Fill *out with the stored watermark for
     * pubkey. Return SC_OK, or SC_ERR_UNKNOWN_VALIDATOR if nothing is
     * stored, or any other code to refuse loading the validator. */
    int (*load_watermark)(void *ctx, const uint8_t pubkey[SC_PUBKEY_LEN], sc_watermark *out);
    sc_store_fn store_watermark;
    /* Trusted wall clock in unix seconds. Non-SC_OK refuses the request. */
    int (*now)(void *ctx, uint64_t *unix_seconds);
    /* SC_MARKS_PER_DEVICE: the one mark that covers every validator. Same
     * contract as load_watermark and store_watermark. The core loads it
     * once, when the first validator is added. */
    int (*load_device_mark)(void *ctx, sc_watermark *out);
    int (*store_device_mark)(void *ctx, const sc_watermark *wm);
} sc_host_ops;

typedef struct {
    uint64_t epoch;
    uint8_t version[SC_VERSION_LEN];
} sc_fork;

typedef struct {
    /* Chain. */
    uint8_t genesis_validators_root[SC_ROOT_LEN];
    uint8_t genesis_fork_version[SC_VERSION_LEN];
    sc_fork forks[SC_MAX_FORKS]; /* ascending epochs; empty means genesis version */
    uint32_t fork_count;
    /* EIP-7044: from Deneb, exits always use the Capella fork version. */
    uint8_t voluntary_exit_fork_version[SC_VERSION_LEN];
    uint64_t genesis_time;
    uint64_t seconds_per_slot;
    uint64_t slots_per_epoch;

    /* Policy. */
    uint64_t max_epochs_ahead; /* refuse epochs > clock epoch + this */
    uint64_t exit_allowlist[SC_MAX_EXIT_ALLOWLIST];
    uint32_t exit_allowlist_count;
    uint8_t fee_recipients[SC_MAX_FEE_RECIPIENTS][SC_ADDRESS_LEN];
    uint32_t fee_recipient_count;
    uint64_t gas_limit_min;
    uint64_t gas_limit_max;
    uint64_t registration_max_future_seconds; /* 0 disables the check */

    /* Slashing protection. */
    sc_commit_ahead commit_ahead;
    /*
     * SC_MARKS_PER_VALIDATOR: each validator has its own mark and moves it
     * with its own window (sc_slashing_approve_*).
     * SC_MARKS_PER_DEVICE (boards): one mark covers every validator. A
     * message above it raises it to targets and block epochs up to
     * h = epoch + commit_ahead.target_epochs (blocks to the last slot of
     * epoch h) and sources up to the highest source signed (no window).
     * One write then covers all validators and both message types. While
     * sources stay put (no finality) a device writes at most once per
     * target_epochs + 1 epochs whatever its number of keys; while the source
     * moves every epoch, once an epoch. commit_ahead.block_slots and
     * commit_ahead.source_epochs are not used. After a restart every
     * validator starts from this mark.
     */
    uint32_t mark_scope;

    /*
     * Gloas (EIP-7732). 0: Gloas is not scheduled and every Gloas-only
     * message type (PTC vote, payload envelope, proposer preferences) is
     * refused with SC_ERR_POLICY_FORK. 1: those types are refused for epochs
     * before gloas_fork_epoch, which must be the epoch of a fork in forks[].
     * A zeroed config leaves Gloas off.
     */
    uint32_t gloas_scheduled;
    uint64_t gloas_fork_epoch;

    /*
     * BuilderRequestAuth allowlist: hash_tree_root of each allowed data
     * value (ByteList[4096]), the data a builder agreed with the operator.
     * A policy field (sc_signer_set_policy). Count 0, as in a zeroed
     * config, refuses every BuilderRequestAuth.
     */
    uint8_t builder_auth_roots[SC_MAX_BUILDER_AUTH_ROOTS][SC_ROOT_LEN];
    uint32_t builder_auth_root_count;
} sc_config;

typedef struct sc_signer sc_signer;

typedef struct {
    uint64_t signatures;
    uint64_t hash_cache_hits;
    uint64_t hash_cache_misses;
    uint64_t watermark_writes; /* commit-ahead mark writes, per validator or per device */
    uint64_t exact_repeats;    /* requests signed as exact repeats */
} sc_signer_stats;

/* Bytes of memory sc_signer_init needs. */
size_t sc_signer_mem_size(uint32_t max_validators, uint32_t hash_cache_entries);

/*
 * Lays out a signer in mem (8-byte aligned, at least sc_signer_mem_size bytes).
 * Copies cfg and ops. hash_cache_entries may be 0 to disable the cache.
 */
int sc_signer_init(void *mem, size_t mem_len, uint32_t max_validators,
                   uint32_t hash_cache_entries, const sc_config *cfg,
                   const sc_host_ops *ops, sc_signer **out);

/* Zeroizes all secret keys and cached state. */
void sc_signer_wipe(sc_signer *s);

/*
 * Loads a validator. pubkey is the validator's (account) public key that
 * identifies it on chain and in slashing protection. secret may be a
 * threshold share of the key; share_pubkey_out (may be NULL) receives the
 * public key of that share. Calls ops.load_watermark. The validator
 * starts with no repeat roots.
 */
int sc_signer_add_validator(sc_signer *s, const uint8_t pubkey[SC_PUBKEY_LEN],
                            const uint8_t secret[SC_SECRET_LEN], uint64_t validator_index,
                            uint8_t share_pubkey_out[SC_PUBKEY_LEN]);

/*
 * EIP-3076 minimal import for one loaded validator. The caller parses the
 * interchange file and passes its metadata.genesis_validators_root, which
 * must equal the configured one (else SC_ERR_ARG), and the per-validator
 * maxima: highest block slot, source epoch and target epoch. A block slot
 * also raises the validator's Gloas slot bounds: no PTC vote or envelope at
 * or below it signs afterwards. Every import first drops the validator's
 * repeat roots (attestation, block, PTC vote, envelope): no exact repeat
 * signs until the next new signature of that kind.
 */
int sc_signer_import(sc_signer *s, const uint8_t pubkey[SC_PUBKEY_LEN],
                     const uint8_t genesis_validators_root[SC_ROOT_LEN],
                     const sc_watermark *imported);

/* Slashing state of a validator. With SC_MARKS_PER_DEVICE, committed is the
 * device mark. */
int sc_signer_get_state(const sc_signer *s, const uint8_t pubkey[SC_PUBKEY_LEN],
                        sc_slashing_state *out);
/* The roots an exact repeat of this validator may have. */
int sc_signer_get_repeat_roots(const sc_signer *s, const uint8_t pubkey[SC_PUBKEY_LEN],
                               sc_repeat_roots *out);

/*
 * SC_MARKS_PER_DEVICE: makes the device mark cover attestation targets and
 * blocks of epoch, with one store_device_mark call if it does not yet;
 * nothing before the first validator is added. The source bound stays at the
 * highest source signed: a cover never raises it, so a restart in a long
 * period without finality, where the chain's source stays put, does not stop
 * the device. A host that writes other state once an epoch can call it then,
 * so the votes that follow find the mark in place. Call it after the epoch's
 * first vote: a vote with a new source writes the mark itself, and the host
 * write then goes with it (the TA does this with its clock floor). Raising
 * the target bound is always safe; after a restart it refuses what a vote of
 * that epoch would have made it refuse. SC_ERR_ARG with per-validator marks.
 */
int sc_signer_cover_epoch(sc_signer *s, uint64_t epoch);
void sc_signer_get_stats(const sc_signer *s, sc_signer_stats *out);

/*
 * Replaces the policy part of a running signer's config with the same fields
 * of policy: exit allowlist, fee recipients, gas limit range and
 * registration_max_future_seconds. Chain, clock horizon and slashing settings
 * stay as they are, and so do the loaded validators and their slashing state,
 * so a policy update needs no restart. SC_ERR_ARG (and no change) if the
 * merged config fails the checks sc_signer_init makes.
 */
int sc_signer_set_policy(sc_signer *s, const sc_config *policy);

/* The fork schedule: the fields of sc_config that sc_signer_set_schedule
 * replaces, with the same meaning as there. */
typedef struct {
    sc_fork forks[SC_MAX_FORKS]; /* ascending epochs */
    uint32_t fork_count;
    uint32_t gloas_scheduled;
    uint64_t gloas_fork_epoch;
} sc_schedule;

/*
 * Replaces the fork schedule of a running signer with next, which takes
 * effect at activate_at (unix seconds). Let T be the later of activate_at and
 * the trusted clock, and L = epoch(T) + max_epochs_ahead + 1 (sums saturate).
 * The call accepts next only if it gives every epoch up to L the same fork
 * version and the same Gloas state as the current schedule. Before T the
 * signer signs no epoch past epoch(T) + max_epochs_ahead, so no epoch is ever
 * signed under both schedules, and a fork that has started never changes. For
 * the same reason a host may apply next as soon as it arrives: until T both
 * schedules give the same result. The chain (genesis fork version, genesis
 * validators root, exit fork version, slot timing), the clock horizon, the
 * slashing settings and the policy are not part of next, so no schedule
 * update changes them. Loaded validators and their slashing state stay.
 *
 * SC_OK: replaced. SC_ERR_SCHEDULE: the rule refused next. SC_ERR_ARG: next
 * fails the checks sc_signer_init makes. SC_ERR_CLOCK: the clock failed. On
 * any error nothing changes. sc_signer_check_schedule makes the same checks
 * and changes nothing, for a host that checks an update before it stores it.
 */
int sc_signer_check_schedule(const sc_signer *s, const sc_schedule *next, uint64_t activate_at);
int sc_signer_set_schedule(sc_signer *s, const sc_schedule *next, uint64_t activate_at);

/*
 * Slot time changes (research/attestation-prover.md, "Signer changes", item
 * 5). The slot time at genesis is cfg.seconds_per_slot. Each change starts
 * another slot time at the first slot of its epoch; slots_per_epoch never
 * changes. Time maps to slots piece by piece: piece 0 starts at slot 0 at
 * genesis_time, piece i at slot epoch_i * slots_per_epoch, at the time piece
 * i-1 reaches that slot. A signer made with sc_signer_init has no changes, so
 * a host that passes none (the board TA) keeps the plain clock.
 */
#ifndef SC_MAX_SLOT_TIMES
#define SC_MAX_SLOT_TIMES 16
#endif

typedef struct {
    uint64_t epoch;            /* the first epoch of the new slot time, above 0 */
    uint64_t seconds_per_slot; /* above 0 */
} sc_slot_time;

typedef struct {
    sc_slot_time changes[SC_MAX_SLOT_TIMES]; /* ascending epochs */
    uint32_t count;
} sc_slot_times;

/*
 * SC_OK if times (NULL: none) fit cfg: at most SC_MAX_SLOT_TIMES changes,
 * epochs ascending and above 0, each change another slot time than the one
 * before it (the first another than cfg->seconds_per_slot), seconds_per_slot
 * * slots_per_epoch within 64 bits, and the start time of every change within
 * 64 bits. Else SC_ERR_ARG.
 */
int sc_slot_times_check(const sc_config *cfg, const sc_slot_times *times);

/*
 * The slot and the epoch at unix time now under cfg's genesis_time,
 * seconds_per_slot and slots_per_epoch and the changes in times (NULL: none).
 * 0 before genesis; the slot saturates at UINT64_MAX. times must pass
 * sc_slot_times_check.
 */
uint64_t sc_slot_at(const sc_config *cfg, const sc_slot_times *times, uint64_t now);
uint64_t sc_epoch_at(const sc_config *cfg, const sc_slot_times *times, uint64_t now);

/*
 * sc_signer_init with the slot time changes times (NULL: none) in force from
 * the start: the clock horizon of every signing call follows them.
 * SC_ERR_ARG if they fail sc_slot_times_check.
 */
int sc_signer_init_ext(void *mem, size_t mem_len, uint32_t max_validators,
                       uint32_t hash_cache_entries, const sc_config *cfg,
                       const sc_slot_times *times, const sc_host_ops *ops, sc_signer **out);

/*
 * Replaces the slot time changes of a running signer with next, in force from
 * activate_at (unix seconds), by the rule of sc_signer_set_schedule: let T be
 * the later of activate_at and the trusted clock, and L = epoch(T) +
 * max_epochs_ahead + 1 under the changes in force (sums saturate). The call
 * accepts next only if it gives every epoch up to L the same slot time as the
 * changes in force, so the first epoch whose slot time changes is at least
 * epoch(T) + max_epochs_ahead + 2. Before T the signer signs no epoch past
 * epoch(T) + max_epochs_ahead, and both lists give the same clock for every
 * one of those epochs. Loaded validators and their slashing state stay.
 *
 * SC_OK: replaced. SC_ERR_SCHEDULE: the rule refused next. SC_ERR_ARG: next
 * fails sc_slot_times_check. SC_ERR_CLOCK: the clock failed. On any error
 * nothing changes. sc_signer_check_slot_times makes the same checks and
 * changes nothing.
 */
int sc_signer_check_slot_times(const sc_signer *s, const sc_slot_times *next, uint64_t activate_at);
int sc_signer_set_slot_times(sc_signer *s, const sc_slot_times *next, uint64_t activate_at);

/*
 * sc_signer_check_schedule and sc_signer_set_schedule, with epoch(T) taken as
 * the largest under the slot time changes the signer holds and under each of
 * the pending_count lists in pending (NULL when 0): slot time changes the
 * host has accepted but that are not yet in force. Either may be in force
 * before T, so the rule keeps every epoch up to that largest epoch(T) +
 * max_epochs_ahead + 1 as it is, and no fork lands on an epoch the signer
 * may reach before T under either clock. A host that checks a slot time
 * change while a fork update is pending calls sc_signer_check_schedule_under
 * with the schedule in force before that update as next, its effective time
 * as activate_at and the new changes as pending: the rule is symmetric, so
 * this checks that the pending fork keeps clear under the new clock.
 * SC_ERR_ARG also when a pending list fails sc_slot_times_check.
 * sc_signer_check_schedule and sc_signer_set_schedule are these with no
 * pending list.
 */
int sc_signer_check_schedule_under(const sc_signer *s, const sc_schedule *next, uint64_t activate_at,
                                   const sc_slot_times *pending, uint32_t pending_count);
int sc_signer_set_schedule_under(sc_signer *s, const sc_schedule *next, uint64_t activate_at,
                                 const sc_slot_times *pending, uint32_t pending_count);

/* The slot time changes in force. */
void sc_signer_get_slot_times(const sc_signer *s, sc_slot_times *out);

/* Signing. Each returns SC_OK and a 96-byte compressed G2 signature, or an
 * error code and leaves signature untouched. sc_sign_block and
 * sc_sign_attestation sign an exact repeat (see sc_repeat_roots).
 * sc_sign_attestation refuses data whose target epoch is not the epoch of
 * its slot (SC_ERR_POLICY_TARGET_SLOT) before the repeat shortcut and the
 * slashing check, so such a request moves no mark and no repeat root. */
int sc_sign_block(sc_signer *s, const uint8_t pubkey[SC_PUBKEY_LEN],
                  const sc_beacon_block_header *block, uint8_t signature[SC_SIGNATURE_LEN]);
int sc_sign_attestation(sc_signer *s, const uint8_t pubkey[SC_PUBKEY_LEN],
                        const sc_attestation_data *data, uint8_t signature[SC_SIGNATURE_LEN]);
int sc_sign_randao_reveal(sc_signer *s, const uint8_t pubkey[SC_PUBKEY_LEN], uint64_t epoch,
                          uint8_t signature[SC_SIGNATURE_LEN]);
int sc_sign_voluntary_exit(sc_signer *s, const uint8_t pubkey[SC_PUBKEY_LEN],
                           const sc_voluntary_exit *exit, uint8_t signature[SC_SIGNATURE_LEN]);
int sc_sign_validator_registration(sc_signer *s, const uint8_t pubkey[SC_PUBKEY_LEN],
                                   const sc_validator_registration *reg,
                                   uint8_t signature[SC_SIGNATURE_LEN]);

/*
 * Gloas signing. Each refuses with SC_ERR_POLICY_FORK unless Gloas is in
 * force at the message's epoch, and with SC_ERR_POLICY_FUTURE past the clock
 * horizon. None of these messages is slashable in the spec (no slashing
 * container covers them), but a second, different PTC vote or envelope for
 * one slot is an equivocation the signer refuses:
 *
 * sc_sign_payload_attestation: PayloadAttestationData, DOMAIN_PTC_ATTESTER at
 *   epoch(data.slot) (validator.md get_payload_attestation_message_signature).
 *   Refuses slot <= the last PTC vote's slot, except an exact repeat.
 * sc_sign_payload_envelope: a self-built ExecutionPayloadEnvelope,
 *   DOMAIN_BEACON_BUILDER at epoch(payload.slot_number) (builder.md
 *   get_execution_payload_envelope_signature; the proposer key signs it for
 *   BUILDER_INDEX_SELF_BUILD, beacon-chain.md
 *   verify_execution_payload_envelope_signature). Refuses another
 *   builder_index (our keys are never builders), a fee recipient not in the
 *   allowlist, an envelope whose beacon_block_root, parent_beacon_block_root
 *   and slot are not those of the last block this validator signed in this
 *   run, and slot <= the last envelope's slot except an exact repeat.
 * sc_sign_proposer_preferences: ProposerPreferences, DOMAIN_PROPOSER_PREFERENCES
 *   with the fork version of epoch(proposal_slot) (validator.md). Checks the
 *   bound validator index, the fee recipient allowlist and the gas limit
 *   range, as for a builder registration. No slot rule: preferences are not
 *   slashable and gossip keeps the first per slot.
 *
 * PTC and envelope slots share the commit-ahead block bound: a slot above the
 * stored bound raises it with one store call (with per-device marks by the
 * same window as a vote, so a device that votes every epoch writes nothing
 * more), and after a restart both kinds start from that bound. Their exact
 * repeat roots live in RAM only, as do those of attestations and blocks.
 */
int sc_sign_payload_attestation(sc_signer *s, const uint8_t pubkey[SC_PUBKEY_LEN],
                                const sc_payload_attestation_data *data,
                                uint8_t signature[SC_SIGNATURE_LEN]);
int sc_sign_payload_envelope(sc_signer *s, const uint8_t pubkey[SC_PUBKEY_LEN],
                             const sc_payload_envelope *env, uint8_t signature[SC_SIGNATURE_LEN]);
int sc_sign_proposer_preferences(sc_signer *s, const uint8_t pubkey[SC_PUBKEY_LEN],
                                 const sc_proposer_preferences *pref,
                                 uint8_t signature[SC_SIGNATURE_LEN]);

/*
 * BuilderRequestAuth (builder-specs gloas builder.md, a ProgressiveContainer
 * of data and slot): data (at most 4096
 * bytes, agreed with one builder) and the proposal slot, signed to
 * authenticate requests to that builder. It never reaches the chain and is
 * not slashable, so no slashing state is read or written. The signing root
 * uses DOMAIN_BUILDER_REQUEST_AUTH with the genesis fork version and a zero
 * genesis_validators_root. The core refuses it with SC_ERR_POLICY_FORK unless
 * Gloas is in force at epoch(slot), SC_ERR_POLICY_FUTURE past the clock
 * horizon, and SC_ERR_POLICY_BUILDER_AUTH unless hash_tree_root(data) is in
 * builder_auth_roots.
 *
 * sc_ssz_decode_builder_request_auth: strict SSZ (first offset 12, data at
 * most 4096 bytes); out->data points into in.
 */
typedef struct {
    const uint8_t *data;
    size_t data_len;
    uint64_t slot;
} sc_builder_request_auth;

int sc_ssz_decode_builder_request_auth(const uint8_t *in, size_t len, sc_builder_request_auth *out);
/* hash_tree_root of data as ByteList[4096]. SC_ERR_ARG above 4096 bytes. */
int sc_htr_builder_auth_data(const uint8_t *data, size_t len, uint8_t out[SC_ROOT_LEN]);
int sc_htr_builder_request_auth(const sc_builder_request_auth *v, uint8_t out[SC_ROOT_LEN]);
int sc_sign_builder_request_auth(sc_signer *s, const uint8_t pubkey[SC_PUBKEY_LEN],
                                 const sc_builder_request_auth *req,
                                 uint8_t signature[SC_SIGNATURE_LEN]);

/* ------------------------------------------------------------------------ */
/* Aggregates and sync committee messages                                   */
/* ------------------------------------------------------------------------ */

/* The preset values that change these roots (consensus-specs presets). */
typedef struct {
    uint64_t max_validators_per_committee;
    uint64_t max_committees_per_slot;
    uint64_t sync_committee_size;
    uint64_t sync_committee_subnet_count;
} sc_preset;

extern const sc_preset SC_PRESET_MAINNET;
extern const sc_preset SC_PRESET_MINIMAL;

/* Scratch space an aggregate needs: its largest bit list, rounded up to a chunk. */
#define SC_TYPED_SCRATCH_LEN (16384 + 64)

/* Forms of AggregateAndProof: phase0, Electra (committee_bits), and Gloas
 * (the Electra bytes, with a progressive Attestation root). */
#define SC_AGGREGATE_PHASE0 0
#define SC_AGGREGATE_ELECTRA 1
#define SC_AGGREGATE_GLOAS 2

typedef struct {
    uint64_t aggregator_index;
    sc_attestation_data data;         /* aggregate.data */
    uint8_t selection_proof[SC_SIGNATURE_LEN];
    uint8_t object_root[SC_ROOT_LEN]; /* hash_tree_root(AggregateAndProof) */
} sc_aggregate_info;

typedef struct {
    uint64_t aggregator_index;
    uint64_t slot;
    uint8_t beacon_block_root[SC_ROOT_LEN];
    uint64_t subcommittee_index;
    uint8_t selection_proof[SC_SIGNATURE_LEN];
    uint8_t object_root[SC_ROOT_LEN]; /* hash_tree_root(ContributionAndProof) */
} sc_contribution_info;

/*
 * Decodes an AggregateAndProof of the given SC_AGGREGATE_* form and computes
 * its hash_tree_root. scratch must hold SC_TYPED_SCRATCH_LEN bytes.
 * SC_OK, SC_ERR_ARG or SC_ERR_DECODE.
 */
int sc_decode_aggregate_and_proof(const uint8_t *ssz, size_t len, int form,
                                  const sc_preset *p, uint8_t *scratch,
                                  sc_aggregate_info *out);
/* SSZ size of a ContributionAndProof under preset p. */
size_t sc_contribution_and_proof_len(const sc_preset *p);
/* Decodes a ContributionAndProof and computes its root. */
int sc_decode_contribution_and_proof(const uint8_t *ssz, size_t len, const sc_preset *p,
                                     sc_contribution_info *out);
/* hash_tree_root(SyncAggregatorSelectionData(slot, subcommittee_index)) */
void sc_htr_sync_aggregator_selection_data(uint64_t slot, uint64_t subcommittee_index,
                                           uint8_t out[SC_ROOT_LEN]);

/*
 * Signing of the aggregate and sync committee messages from their content.
 * None is slashable and none touches the marks. Each computes its own object
 * root, uses the domain of the fork in force at the message's epoch, and
 * refuses an epoch past the clock horizon (SC_ERR_POLICY_FUTURE).
 *
 * sc_sign_selection_proof: the slot, DOMAIN_SELECTION_PROOF at epoch(slot).
 * sc_sign_aggregate_and_proof: the AggregateAndProof SSZ in the given form.
 *   The form must match the epoch of aggregate.data.slot: SC_AGGREGATE_GLOAS
 *   from the Gloas fork epoch on, the older forms before it
 *   (SC_ERR_POLICY_FORK). aggregator_index must equal the validator's bound
 *   index (SC_ERR_POLICY_INDEX, unless the index is SC_INDEX_UNKNOWN), and
 *   the selection proof must verify under the validator (group) public key
 *   over the slot's selection proof signing root (SC_ERR_SELECTION_PROOF).
 *   scratch holds SC_TYPED_SCRATCH_LEN bytes.
 * sc_sign_sync_committee_message: the slot and the block root,
 *   DOMAIN_SYNC_COMMITTEE at epoch(slot).
 * sc_sign_sync_selection_proof: SyncAggregatorSelectionData. The
 *   subcommittee index must be below the preset's subnet count (SC_ERR_ARG).
 * sc_sign_contribution_and_proof: the ContributionAndProof SSZ, with the
 *   index binding, the subcommittee index check and the selection proof
 *   check (over the SyncAggregatorSelectionData of its slot and
 *   subcommittee), as for aggregates.
 *
 * Each writes the signing root it signed to signing_root when that is not
 * NULL, for callers that log or check it.
 */
int sc_sign_selection_proof(sc_signer *s, const uint8_t pubkey[SC_PUBKEY_LEN], uint64_t slot,
                            uint8_t signature[SC_SIGNATURE_LEN], uint8_t *signing_root);
int sc_sign_aggregate_and_proof(sc_signer *s, const uint8_t pubkey[SC_PUBKEY_LEN],
                                const uint8_t *ssz, size_t len, int form, const sc_preset *p,
                                uint8_t *scratch, uint8_t signature[SC_SIGNATURE_LEN],
                                uint8_t *signing_root);
int sc_sign_sync_committee_message(sc_signer *s, const uint8_t pubkey[SC_PUBKEY_LEN],
                                   uint64_t slot, const uint8_t beacon_block_root[SC_ROOT_LEN],
                                   uint8_t signature[SC_SIGNATURE_LEN], uint8_t *signing_root);
int sc_sign_sync_selection_proof(sc_signer *s, const uint8_t pubkey[SC_PUBKEY_LEN],
                                 uint64_t slot, uint64_t subcommittee_index,
                                 const sc_preset *p, uint8_t signature[SC_SIGNATURE_LEN],
                                 uint8_t *signing_root);
int sc_sign_contribution_and_proof(sc_signer *s, const uint8_t pubkey[SC_PUBKEY_LEN],
                                   const uint8_t *ssz, size_t len, const sc_preset *p,
                                   uint8_t signature[SC_SIGNATURE_LEN], uint8_t *signing_root);

/*
 * Signs object_root for message types that need no slashing protection:
 * RANDAO 0x02000000, selection proof 0x05000000, aggregate and proof
 * 0x06000000, sync committee 0x07000000, sync committee selection proof
 * 0x08000000, contribution and proof 0x09000000, and the Gloas types beacon
 * builder 0x0B000000 (payload envelope), PTC attester 0x0C000000 and
 * proposer preferences 0x0D000000. Any other domain type returns
 * SC_ERR_POLICY_DOMAIN, so this path can never sign a block, attestation,
 * exit, builder registration, deposit or builder deposit. The domain uses
 * the fork version active at epoch, and epoch must pass the clock horizon.
 * The Gloas types return SC_ERR_POLICY_FORK unless Gloas is in force at
 * epoch. As bare roots they skip the checks of the typed Gloas calls (one
 * PTC vote and one envelope per slot, the envelope's block, builder index,
 * fee recipient and gas limit); none of them is slashable.
 * For RANDAO, object_root must equal hash_tree_root(epoch) (SC_ERR_ARG
 * otherwise). For the other types the caller computes object_root, so
 * the core does not see their content. Only the cloud runner's generic path
 * uses it (a bare root from Dirk's generic Sign, behind the runner's
 * unverified switch); typed requests go through the sign calls above, in the
 * cloud runner and in the signer TA.
 */
int sc_sign_root(sc_signer *s, const uint8_t pubkey[SC_PUBKEY_LEN],
                 const uint8_t domain_type[SC_DOMAIN_TYPE_LEN], uint64_t epoch,
                 const uint8_t object_root[SC_ROOT_LEN],
                 uint8_t signature[SC_SIGNATURE_LEN]);

/* Signing roots the signer would use, for callers that want to log or verify. */
int sc_signer_signing_root(const sc_signer *s, const uint8_t domain_type[SC_DOMAIN_TYPE_LEN],
                           uint64_t epoch, const uint8_t object_root[SC_ROOT_LEN],
                           uint8_t out[SC_ROOT_LEN]);

#ifdef __cplusplus
}
#endif

#endif /* SIGNER_CORE_H */
