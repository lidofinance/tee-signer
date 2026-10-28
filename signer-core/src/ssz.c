/* SSZ encode/decode and hash_tree_root for the fixed-size containers the
 * signer needs, plus compute_domain and compute_signing_root. */
#include "sc_internal.h"

const uint8_t SC_DOMAIN_BEACON_PROPOSER[4] = {0x00, 0x00, 0x00, 0x00};
const uint8_t SC_DOMAIN_BEACON_ATTESTER[4] = {0x01, 0x00, 0x00, 0x00};
const uint8_t SC_DOMAIN_RANDAO[4] = {0x02, 0x00, 0x00, 0x00};
const uint8_t SC_DOMAIN_VOLUNTARY_EXIT[4] = {0x04, 0x00, 0x00, 0x00};
const uint8_t SC_DOMAIN_APPLICATION_BUILDER[4] = {0x00, 0x00, 0x00, 0x01};
const uint8_t SC_DOMAIN_BEACON_BUILDER[4] = {0x0b, 0x00, 0x00, 0x00};
const uint8_t SC_DOMAIN_PTC_ATTESTER[4] = {0x0c, 0x00, 0x00, 0x00};
const uint8_t SC_DOMAIN_PROPOSER_PREFERENCES[4] = {0x0d, 0x00, 0x00, 0x00};
const uint8_t SC_DOMAIN_BUILDER_REQUEST_AUTH[4] = {0x0b, 0x00, 0x00, 0x01};

void sc_wipe(void *p, size_t n)
{
    volatile uint8_t *v = (volatile uint8_t *)p;
    while (n--)
        *v++ = 0;
}

void sc_hash_pair(const uint8_t a[32], const uint8_t b[32], uint8_t out[32])
{
    uint8_t buf[64];
    memcpy(buf, a, 32);
    memcpy(buf + 32, b, 32);
    blst_sha256(out, buf, sizeof buf);
}

typedef uint8_t chunk_t[32];

/* Merkleizes n chunks (n <= 8) after padding with zero chunks to the next
 * power of two. chunks must have room for 8 entries and is clobbered. */
static void merkleize(chunk_t *chunks, size_t n, uint8_t out[32])
{
    size_t width = 1;
    while (width < n)
        width <<= 1;
    for (size_t i = n; i < width; i++)
        memset(chunks[i], 0, 32);
    for (; width > 1; width >>= 1)
        for (size_t i = 0; i < width / 2; i++)
            sc_hash_pair(chunks[2 * i], chunks[2 * i + 1], chunks[i]);
    memcpy(out, chunks[0], 32);
}

static void chunk_u64(chunk_t c, uint64_t v)
{
    memset(c, 0, 32);
    sc_put_u64(c, v);
}

static void chunk_bytes(chunk_t c, const uint8_t *b, size_t n)
{
    memset(c, 0, 32);
    memcpy(c, b, n);
}

/* hash_tree_root of Bytes48 (BLSPubkey): two chunks, the second zero padded. */
static void htr_bytes48(const uint8_t b[48], uint8_t out[32])
{
    chunk_t c[2];
    memcpy(c[0], b, 32);
    chunk_bytes(c[1], b + 32, 16);
    sc_hash_pair(c[0], c[1], out);
}

void sc_htr_uint64(uint64_t v, uint8_t out[32]) { chunk_u64(out, v); }

void sc_htr_checkpoint(const sc_checkpoint *v, uint8_t out[32])
{
    chunk_t c[8];
    chunk_u64(c[0], v->epoch);
    memcpy(c[1], v->root, 32);
    merkleize(c, 2, out);
}

void sc_htr_attestation_data(const sc_attestation_data *v, uint8_t out[32])
{
    chunk_t c[8];
    chunk_u64(c[0], v->slot);
    chunk_u64(c[1], v->index);
    memcpy(c[2], v->beacon_block_root, 32);
    sc_htr_checkpoint(&v->source, c[3]);
    sc_htr_checkpoint(&v->target, c[4]);
    merkleize(c, 5, out);
}

void sc_htr_beacon_block_header(const sc_beacon_block_header *v, uint8_t out[32])
{
    chunk_t c[8];
    chunk_u64(c[0], v->slot);
    chunk_u64(c[1], v->proposer_index);
    memcpy(c[2], v->parent_root, 32);
    memcpy(c[3], v->state_root, 32);
    memcpy(c[4], v->body_root, 32);
    merkleize(c, 5, out);
}

void sc_htr_voluntary_exit(const sc_voluntary_exit *v, uint8_t out[32])
{
    chunk_t c[8];
    chunk_u64(c[0], v->epoch);
    chunk_u64(c[1], v->validator_index);
    merkleize(c, 2, out);
}

void sc_htr_validator_registration(const sc_validator_registration *v, uint8_t out[32])
{
    chunk_t c[8];
    chunk_bytes(c[0], v->fee_recipient, SC_ADDRESS_LEN);
    chunk_u64(c[1], v->gas_limit);
    chunk_u64(c[2], v->timestamp);
    htr_bytes48(v->pubkey, c[3]);
    merkleize(c, 4, out);
}

void sc_htr_fork_data(const sc_fork_data *v, uint8_t out[32])
{
    chunk_t c[8];
    chunk_bytes(c[0], v->current_version, SC_VERSION_LEN);
    memcpy(c[1], v->genesis_validators_root, 32);
    merkleize(c, 2, out);
}

void sc_htr_signing_data(const sc_signing_data *v, uint8_t out[32])
{
    sc_hash_pair(v->object_root, v->domain, out);
}

/* ---- Gloas ---------------------------------------------------------------- */

/* Binary merkleization of n chunks padded with zero chunks to width (a power
 * of two, at most 64). The tree is built in place in a copy. */
static void merkleize_padded(const uint8_t (*chunks)[32], size_t n, size_t width, uint8_t out[32])
{
    chunk_t buf[64];
    /* Byte copy: a memcpy with a variable index here becomes __memcpy_chk
     * under _FORTIFY_SOURCE, a libc symbol the core must not need. */
    for (size_t i = 0; i < width; i++)
        for (size_t k = 0; k < 32; k++)
            buf[i][k] = i < n ? chunks[i][k] : 0;
    for (; width > 1; width >>= 1)
        for (size_t i = 0; i < width / 2; i++)
            sc_hash_pair(buf[2 * i], buf[2 * i + 1], buf[i]);
    memcpy(out, buf[0], 32);
}

/*
 * EIP-7916 merkleize_progressive as remerkleable's subtree_fill_progressive
 * computes it: PairNode(subtree_fill_to_contents(nodes[:base], depth),
 * subtree_fill_progressive(nodes[base:], depth + 2)), base = 1 << depth.
 */
static void progressive(const uint8_t (*chunks)[32], size_t n, size_t base, uint8_t out[32])
{
    uint8_t left[32], right[32];
    size_t first = n < base ? n : base;
    if (n == 0) {
        memset(out, 0, 32);
        return;
    }
    merkleize_padded(chunks, first, base, left);
    progressive(chunks + first, n - first, base * 4, right);
    sc_hash_pair(left, right, out);
}

int sc_merkleize_progressive(const uint8_t (*chunks)[SC_ROOT_LEN], size_t n,
                             uint8_t out[SC_ROOT_LEN])
{
    if (!out || (n && !chunks) || n > 85)
        return SC_ERR_ARG;
    progressive(chunks, n, 1, out);
    return SC_OK;
}

/* hash_tree_root of a ProgressiveContainer whose first n fields are all
 * active (EIP-7495): mix_in_active_fields(merkleize_progressive(fields),
 * active_fields), the bitvector packed little endian into one chunk. */
static void progressive_container(const chunk_t *fields, size_t n, uint8_t out[32])
{
    uint8_t root[32];
    chunk_t bits;
    memset(bits, 0, 32);
    for (size_t i = 0; i < n; i++)
        bits[i / 8] |= (uint8_t)(1u << (i % 8));
    progressive((const uint8_t (*)[32])fields, n, 1, root);
    sc_hash_pair(root, bits, out);
}

static void chunk_bool(chunk_t c, uint8_t b)
{
    memset(c, 0, 32);
    c[0] = b;
}

/* beacon-chain.md "PayloadAttestationData": a plain Container. */
void sc_htr_payload_attestation_data(const sc_payload_attestation_data *v, uint8_t out[32])
{
    chunk_t c[8];
    memcpy(c[0], v->beacon_block_root, 32);
    chunk_u64(c[1], v->slot);
    chunk_bool(c[2], v->payload_present);
    chunk_bool(c[3], v->blob_data_available);
    merkleize(c, 4, out);
}

/* p2p-interface.md "ProposerPreferences": a plain Container. */
void sc_htr_proposer_preferences(const sc_proposer_preferences *v, uint8_t out[32])
{
    chunk_t c[8];
    memcpy(c[0], v->dependent_root, 32);
    chunk_u64(c[1], v->proposal_slot);
    chunk_u64(c[2], v->validator_index);
    chunk_bytes(c[3], v->fee_recipient, SC_ADDRESS_LEN);
    chunk_u64(c[4], v->target_gas_limit);
    merkleize(c, 5, out);
}

/* beacon-chain.md "ExecutionPayload": ProgressiveContainer, active_fields(width=19). */
void sc_htr_execution_payload_summary(const sc_execution_payload_summary *v, uint8_t out[32])
{
    chunk_t c[19];
    memcpy(c[0], v->parent_hash, 32);
    chunk_bytes(c[1], v->fee_recipient, SC_ADDRESS_LEN);
    memcpy(c[2], v->state_root, 32);
    memcpy(c[3], v->receipts_root, 32);
    memcpy(c[4], v->logs_bloom_root, 32);
    memcpy(c[5], v->prev_randao, 32);
    chunk_u64(c[6], v->block_number);
    chunk_u64(c[7], v->gas_limit);
    chunk_u64(c[8], v->gas_used);
    chunk_u64(c[9], v->timestamp);
    memcpy(c[10], v->extra_data_root, 32);
    memcpy(c[11], v->base_fee_per_gas, 32);
    memcpy(c[12], v->block_hash, 32);
    memcpy(c[13], v->transactions_root, 32);
    memcpy(c[14], v->withdrawals_root, 32);
    chunk_u64(c[15], v->blob_gas_used);
    chunk_u64(c[16], v->excess_blob_gas);
    memcpy(c[17], v->block_access_list_root, 32);
    chunk_u64(c[18], v->slot_number);
    progressive_container(c, 19, out);
}

/* beacon-chain.md "ExecutionPayloadEnvelope": ProgressiveContainer, active_fields(width=5). */
void sc_htr_payload_envelope(const sc_payload_envelope *v, uint8_t out[32])
{
    chunk_t c[5];
    sc_htr_execution_payload_summary(&v->payload, c[0]);
    memcpy(c[1], v->execution_requests_root, 32);
    chunk_u64(c[2], v->builder_index);
    memcpy(c[3], v->beacon_block_root, 32);
    memcpy(c[4], v->parent_beacon_block_root, 32);
    progressive_container(c, 5, out);
}

/* ---- encode / decode ---------------------------------------------------- */

static void enc_checkpoint(const sc_checkpoint *v, uint8_t *p)
{
    sc_put_u64(p, v->epoch);
    memcpy(p + 8, v->root, 32);
}

static void dec_checkpoint(const uint8_t *p, sc_checkpoint *v)
{
    v->epoch = sc_get_u64(p);
    memcpy(v->root, p + 8, 32);
}

void sc_ssz_encode_checkpoint(const sc_checkpoint *v, uint8_t out[SC_SSZ_CHECKPOINT_LEN])
{
    enc_checkpoint(v, out);
}

int sc_ssz_decode_checkpoint(const uint8_t *in, size_t len, sc_checkpoint *out)
{
    if (!in || !out || len != SC_SSZ_CHECKPOINT_LEN)
        return SC_ERR_DECODE;
    dec_checkpoint(in, out);
    return SC_OK;
}

void sc_ssz_encode_attestation_data(const sc_attestation_data *v,
                                    uint8_t out[SC_SSZ_ATTESTATION_DATA_LEN])
{
    sc_put_u64(out, v->slot);
    sc_put_u64(out + 8, v->index);
    memcpy(out + 16, v->beacon_block_root, 32);
    enc_checkpoint(&v->source, out + 48);
    enc_checkpoint(&v->target, out + 88);
}

int sc_ssz_decode_attestation_data(const uint8_t *in, size_t len, sc_attestation_data *out)
{
    if (!in || !out || len != SC_SSZ_ATTESTATION_DATA_LEN)
        return SC_ERR_DECODE;
    out->slot = sc_get_u64(in);
    out->index = sc_get_u64(in + 8);
    memcpy(out->beacon_block_root, in + 16, 32);
    dec_checkpoint(in + 48, &out->source);
    dec_checkpoint(in + 88, &out->target);
    return SC_OK;
}

void sc_ssz_encode_beacon_block_header(const sc_beacon_block_header *v,
                                       uint8_t out[SC_SSZ_BEACON_BLOCK_HEADER_LEN])
{
    sc_put_u64(out, v->slot);
    sc_put_u64(out + 8, v->proposer_index);
    memcpy(out + 16, v->parent_root, 32);
    memcpy(out + 48, v->state_root, 32);
    memcpy(out + 80, v->body_root, 32);
}

int sc_ssz_decode_beacon_block_header(const uint8_t *in, size_t len, sc_beacon_block_header *out)
{
    if (!in || !out || len != SC_SSZ_BEACON_BLOCK_HEADER_LEN)
        return SC_ERR_DECODE;
    out->slot = sc_get_u64(in);
    out->proposer_index = sc_get_u64(in + 8);
    memcpy(out->parent_root, in + 16, 32);
    memcpy(out->state_root, in + 48, 32);
    memcpy(out->body_root, in + 80, 32);
    return SC_OK;
}

void sc_ssz_encode_voluntary_exit(const sc_voluntary_exit *v, uint8_t out[SC_SSZ_VOLUNTARY_EXIT_LEN])
{
    sc_put_u64(out, v->epoch);
    sc_put_u64(out + 8, v->validator_index);
}

int sc_ssz_decode_voluntary_exit(const uint8_t *in, size_t len, sc_voluntary_exit *out)
{
    if (!in || !out || len != SC_SSZ_VOLUNTARY_EXIT_LEN)
        return SC_ERR_DECODE;
    out->epoch = sc_get_u64(in);
    out->validator_index = sc_get_u64(in + 8);
    return SC_OK;
}

void sc_ssz_encode_validator_registration(const sc_validator_registration *v,
                                          uint8_t out[SC_SSZ_VALIDATOR_REGISTRATION_LEN])
{
    memcpy(out, v->fee_recipient, 20);
    sc_put_u64(out + 20, v->gas_limit);
    sc_put_u64(out + 28, v->timestamp);
    memcpy(out + 36, v->pubkey, 48);
}

int sc_ssz_decode_validator_registration(const uint8_t *in, size_t len,
                                         sc_validator_registration *out)
{
    if (!in || !out || len != SC_SSZ_VALIDATOR_REGISTRATION_LEN)
        return SC_ERR_DECODE;
    memcpy(out->fee_recipient, in, 20);
    out->gas_limit = sc_get_u64(in + 20);
    out->timestamp = sc_get_u64(in + 28);
    memcpy(out->pubkey, in + 36, 48);
    return SC_OK;
}

void sc_ssz_encode_fork_data(const sc_fork_data *v, uint8_t out[SC_SSZ_FORK_DATA_LEN])
{
    memcpy(out, v->current_version, 4);
    memcpy(out + 4, v->genesis_validators_root, 32);
}

int sc_ssz_decode_fork_data(const uint8_t *in, size_t len, sc_fork_data *out)
{
    if (!in || !out || len != SC_SSZ_FORK_DATA_LEN)
        return SC_ERR_DECODE;
    memcpy(out->current_version, in, 4);
    memcpy(out->genesis_validators_root, in + 4, 32);
    return SC_OK;
}

void sc_ssz_encode_signing_data(const sc_signing_data *v, uint8_t out[SC_SSZ_SIGNING_DATA_LEN])
{
    memcpy(out, v->object_root, 32);
    memcpy(out + 32, v->domain, 32);
}

int sc_ssz_decode_signing_data(const uint8_t *in, size_t len, sc_signing_data *out)
{
    if (!in || !out || len != SC_SSZ_SIGNING_DATA_LEN)
        return SC_ERR_DECODE;
    memcpy(out->object_root, in, 32);
    memcpy(out->domain, in + 32, 32);
    return SC_OK;
}

void sc_ssz_encode_payload_attestation_data(const sc_payload_attestation_data *v,
                                            uint8_t out[SC_SSZ_PAYLOAD_ATTESTATION_DATA_LEN])
{
    memcpy(out, v->beacon_block_root, 32);
    sc_put_u64(out + 32, v->slot);
    out[40] = v->payload_present;
    out[41] = v->blob_data_available;
}

int sc_ssz_decode_payload_attestation_data(const uint8_t *in, size_t len,
                                           sc_payload_attestation_data *out)
{
    if (!in || !out || len != SC_SSZ_PAYLOAD_ATTESTATION_DATA_LEN || in[40] > 1 || in[41] > 1)
        return SC_ERR_DECODE;
    memcpy(out->beacon_block_root, in, 32);
    out->slot = sc_get_u64(in + 32);
    out->payload_present = in[40];
    out->blob_data_available = in[41];
    return SC_OK;
}

void sc_ssz_encode_proposer_preferences(const sc_proposer_preferences *v,
                                        uint8_t out[SC_SSZ_PROPOSER_PREFERENCES_LEN])
{
    memcpy(out, v->dependent_root, 32);
    sc_put_u64(out + 32, v->proposal_slot);
    sc_put_u64(out + 40, v->validator_index);
    memcpy(out + 48, v->fee_recipient, 20);
    sc_put_u64(out + 68, v->target_gas_limit);
}

int sc_ssz_decode_proposer_preferences(const uint8_t *in, size_t len, sc_proposer_preferences *out)
{
    if (!in || !out || len != SC_SSZ_PROPOSER_PREFERENCES_LEN)
        return SC_ERR_DECODE;
    memcpy(out->dependent_root, in, 32);
    out->proposal_slot = sc_get_u64(in + 32);
    out->validator_index = sc_get_u64(in + 40);
    memcpy(out->fee_recipient, in + 48, 20);
    out->target_gas_limit = sc_get_u64(in + 68);
    return SC_OK;
}

/* Fixed layout of sc_payload_envelope: each field in order, roots and
 * addresses as raw bytes, integers as 8 bytes little endian. */
#define ENV_FIELDS(X)                                                                              \
    X(B, payload.parent_hash, 32)                                                                  \
    X(B, payload.fee_recipient, 20)                                                                \
    X(B, payload.state_root, 32)                                                                   \
    X(B, payload.receipts_root, 32)                                                                \
    X(B, payload.logs_bloom_root, 32)                                                              \
    X(B, payload.prev_randao, 32)                                                                  \
    X(U, payload.block_number, 8)                                                                  \
    X(U, payload.gas_limit, 8)                                                                     \
    X(U, payload.gas_used, 8)                                                                      \
    X(U, payload.timestamp, 8)                                                                     \
    X(B, payload.extra_data_root, 32)                                                              \
    X(B, payload.base_fee_per_gas, 32)                                                             \
    X(B, payload.block_hash, 32)                                                                   \
    X(B, payload.transactions_root, 32)                                                            \
    X(B, payload.withdrawals_root, 32)                                                             \
    X(U, payload.blob_gas_used, 8)                                                                 \
    X(U, payload.excess_blob_gas, 8)                                                               \
    X(B, payload.block_access_list_root, 32)                                                       \
    X(U, payload.slot_number, 8)                                                                   \
    X(B, execution_requests_root, 32)                                                              \
    X(U, builder_index, 8)                                                                         \
    X(B, beacon_block_root, 32)                                                                    \
    X(B, parent_beacon_block_root, 32)

void sc_encode_payload_envelope(const sc_payload_envelope *v,
                                uint8_t out[SC_PAYLOAD_ENVELOPE_ENCODED_LEN])
{
    uint8_t *p = out;
#define ENC_B(f, n) memcpy(p, v->f, n);
#define ENC_U(f, n) sc_put_u64(p, v->f);
#define ENC(kind, f, n) ENC_##kind(f, n) p += n;
    ENV_FIELDS(ENC)
#undef ENC
#undef ENC_U
#undef ENC_B
}

int sc_decode_payload_envelope(const uint8_t *in, size_t len, sc_payload_envelope *out)
{
    const uint8_t *p = in;
    if (!in || !out || len != SC_PAYLOAD_ENVELOPE_ENCODED_LEN)
        return SC_ERR_DECODE;
#define DEC_B(f, n) memcpy(out->f, p, n);
#define DEC_U(f, n) out->f = sc_get_u64(p);
#define DEC(kind, f, n) DEC_##kind(f, n) p += n;
    ENV_FIELDS(DEC)
#undef DEC
#undef DEC_U
#undef DEC_B
    return SC_OK;
}

/* ---- domains ------------------------------------------------------------ */

void sc_compute_fork_data_root(const uint8_t current_version[4],
                               const uint8_t genesis_validators_root[32], uint8_t out[32])
{
    sc_fork_data fd;
    memcpy(fd.current_version, current_version, 4);
    memcpy(fd.genesis_validators_root, genesis_validators_root, 32);
    sc_htr_fork_data(&fd, out);
}

void sc_compute_domain(const uint8_t domain_type[4], const uint8_t fork_version[4],
                       const uint8_t genesis_validators_root[32], uint8_t out[32])
{
    uint8_t fdr[32];
    sc_compute_fork_data_root(fork_version, genesis_validators_root, fdr);
    memcpy(out, domain_type, 4);
    memcpy(out + 4, fdr, 28);
}

void sc_compute_signing_root(const uint8_t object_root[32], const uint8_t domain[32],
                             uint8_t out[32])
{
    sc_hash_pair(object_root, domain, out);
}

void sc_compute_builder_domain(const uint8_t genesis_fork_version[4], uint8_t out[32])
{
    static const uint8_t zero_root[32] = {0};
    sc_compute_domain(SC_DOMAIN_APPLICATION_BUILDER, genesis_fork_version, zero_root, out);
}

/* ---- BuilderRequestAuth ---------------------------------------------------- */

int sc_ssz_decode_builder_request_auth(const uint8_t *in, size_t len, sc_builder_request_auth *out)
{
    if (!in || !out || len < SC_SSZ_BUILDER_REQUEST_AUTH_MIN_LEN ||
        len > SC_SSZ_BUILDER_REQUEST_AUTH_MAX_LEN)
        return SC_ERR_DECODE;
    if (in[0] != 12 || in[1] != 0 || in[2] != 0 || in[3] != 0)
        return SC_ERR_DECODE;
    out->slot = sc_get_u64(in + 4);
    out->data = in + 12;
    out->data_len = len - 12;
    return SC_OK;
}

/*
 * ByteList[4096]: 128 chunks, the data zero padded, merkleized to depth 7,
 * then mix_in_length. The first level is hashed straight from the data, so
 * the buffer holds 64 chunks (2 KiB) rather than 128.
 */
int sc_htr_builder_auth_data(const uint8_t *data, size_t len, uint8_t out[SC_ROOT_LEN])
{
    chunk_t buf[64], a, b, n;
    if ((!data && len) || !out || len > SC_BUILDER_AUTH_MAX_DATA)
        return SC_ERR_ARG;
    for (size_t i = 0; i < 64; i++) {
        for (size_t k = 0; k < 32; k++) {
            size_t ia = 64 * i + k, ib = 64 * i + 32 + k;
            a[k] = ia < len ? data[ia] : 0;
            b[k] = ib < len ? data[ib] : 0;
        }
        sc_hash_pair(a, b, buf[i]);
    }
    for (size_t width = 64; width > 1; width >>= 1)
        for (size_t i = 0; i < width / 2; i++)
            sc_hash_pair(buf[2 * i], buf[2 * i + 1], buf[i]);
    chunk_u64(n, (uint64_t)len);
    sc_hash_pair(buf[0], n, out);
    return SC_OK;
}

/* builder-specs gloas builder.md: a plain Container of two fields, so the
 * root is hash(root(data), slot chunk), as go-eth2-client v0.30.3 and the
 * Dirk fork hash it. (go-eth2-client v0.30.1 hashed it as a
 * ProgressiveContainer, which gives another root.) */
int sc_htr_builder_request_auth(const sc_builder_request_auth *v, uint8_t out[SC_ROOT_LEN])
{
    chunk_t f[2];
    int rc;
    if (!v || !out)
        return SC_ERR_ARG;
    if ((rc = sc_htr_builder_auth_data(v->data, v->data_len, f[0])) != SC_OK)
        return rc;
    chunk_u64(f[1], v->slot);
    sc_hash_pair(f[0], f[1], out);
    return SC_OK;
}
