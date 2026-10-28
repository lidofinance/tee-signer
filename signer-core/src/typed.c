/* SSZ decoding and hash_tree_root of the aggregate and sync committee
 * messages: AggregateAndProof (phase0, Electra, Gloas), ContributionAndProof
 * and SyncAggregatorSelectionData. Moved here from the signer TA
 * (ta/trusted-app/typed_ssz.c) so the TA and the cloud runner compute these
 * roots with the same code. See "Aggregates and sync committee messages" in
 * signer_core.h. */
#include "sc_internal.h"

const sc_preset SC_PRESET_MAINNET = {2048, 64, 512, 4};
const sc_preset SC_PRESET_MINIMAL = {2048, 4, 32, 4};

#define CHUNK 32

static uint32_t get_u32(const uint8_t *p)
{
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 |
           (uint32_t)p[3] << 24;
}

static void chunk_u64(uint8_t c[CHUNK], uint64_t v)
{
    memset(c, 0, CHUNK);
    sc_put_u64(c, v);
}

/*
 * Merkleizes n chunks padded with zero chunks to the next power of two of
 * limit (limit >= n, limit >= 1). Works in place: chunks is clobbered.
 */
static void merkleize(uint8_t *chunks, size_t n, size_t limit, uint8_t out[CHUNK])
{
    uint8_t zero[CHUNK] = {0}; /* root of an all-zero subtree at this level */
    size_t width = 1, i;

    while (width < limit)
        width <<= 1;
    for (; width > 1; width >>= 1) {
        size_t pairs = (n + 1) / 2;

        for (i = 0; i < pairs; i++) {
            const uint8_t *right = 2 * i + 1 < n ? chunks + (2 * i + 1) * CHUNK : zero;

            sc_hash_pair(chunks + 2 * i * CHUNK, right, chunks + i * CHUNK);
        }
        n = pairs;
        sc_hash_pair(zero, zero, zero);
    }
    memcpy(out, n ? chunks : zero, CHUNK);
}

/*
 * EIP-7916 merkleize_progressive, as remerkleable's subtree_fill_progressive:
 * hash(binary tree of the first base chunks, progressive rest with base * 4),
 * a zero chunk for none. Works in place: chunks is clobbered.
 */
static void progressive(uint8_t *chunks, size_t n, size_t base, uint8_t out[CHUNK])
{
    uint8_t left[CHUNK], right[CHUNK];
    size_t first = n < base ? n : base;

    if (n == 0) {
        memset(out, 0, CHUNK);
        return;
    }
    progressive(chunks + first * CHUNK, n - first, base * 4, right);
    merkleize(chunks, first, base, left);
    sc_hash_pair(left, right, out);
}

/* Root of a container whose fields have the given roots (at most 8 fields). */
static void container(uint8_t fields[][CHUNK], size_t n, uint8_t out[CHUNK])
{
    merkleize(&fields[0][0], n, n, out);
}

/* hash_tree_root of a Bytes96 (a BLS signature). */
static void bytes96_root(const uint8_t b[SC_SIGNATURE_LEN], uint8_t out[CHUNK])
{
    uint8_t c[4][CHUNK];

    memcpy(c, b, SC_SIGNATURE_LEN);
    merkleize(&c[0][0], 3, 3, out);
}

/*
 * hash_tree_root of an SSZ Bitlist[limit] given its encoding (with the
 * delimiter bit), or with progressive_list set of a ProgressiveBitList
 * (EIP-7916: the packed bits merkleized progressively, then the bit count
 * mixed in); limit then only bounds the input. scratch holds
 * SC_TYPED_SCRATCH_LEN bytes.
 */
static int bitlist_root(const uint8_t *b, size_t len, uint64_t limit, int progressive_list,
                        uint8_t *scratch, uint8_t out[CHUNK])
{
    uint8_t length[CHUNK], root[CHUNK];
    uint64_t bits;
    size_t bytes, chunks;
    int top = 7;

    if (len == 0 || b[len - 1] == 0 || len > (limit + 8) / 8 ||
        len + CHUNK > SC_TYPED_SCRATCH_LEN)
        return SC_ERR_DECODE;
    while (!(b[len - 1] >> top & 1))
        top--;
    bits = (uint64_t)(len - 1) * 8 + (uint64_t)top;
    if (bits > limit)
        return SC_ERR_DECODE;
    memcpy(scratch, b, len);
    scratch[len - 1] &= (uint8_t)~(1u << top); /* drop the delimiter */
    bytes = (size_t)((bits + 7) / 8);
    chunks = (bytes + CHUNK - 1) / CHUNK;
    memset(scratch + bytes, 0, chunks * CHUNK - bytes);
    if (progressive_list)
        progressive(scratch, chunks, 1, root);
    else
        merkleize(scratch, chunks, (size_t)((limit + 255) / 256), root);
    chunk_u64(length, bits);
    sc_hash_pair(root, length, out);
    return SC_OK;
}

/* hash_tree_root of an SSZ Bitvector[n] of at most 256 bits. */
static int bitvector_root(const uint8_t *b, size_t len, uint64_t n, uint8_t out[CHUNK])
{
    if (n == 0 || n > 256 || len != (n + 7) / 8)
        return SC_ERR_DECODE;
    if (n % 8 && (b[len - 1] >> (n % 8))) /* bits past n must be zero */
        return SC_ERR_DECODE;
    memset(out, 0, CHUNK);
    memcpy(out, b, len);
    return SC_OK;
}

/*
 * AggregateAndProof: aggregator_index (8) | offset of aggregate (4) |
 * selection_proof (96) | aggregate. Attestation: offset of aggregation_bits
 * (4) | data (128) | signature (96) [| committee_bits, Electra and Gloas] |
 * aggregation_bits.
 *
 * Gloas (beacon-chain.md "Attestation") keeps these bytes but makes
 * Attestation a ProgressiveContainer (active_fields width 4) and
 * aggregation_bits a ProgressiveBitList, so its root differs from Electra's.
 */
int sc_decode_aggregate_and_proof(const uint8_t *ssz, size_t len, int form,
                                  const sc_preset *p, uint8_t *scratch,
                                  sc_aggregate_info *out)
{
    int electra, gloas, rc;
    const size_t outer_fixed = 8 + 4 + SC_SIGNATURE_LEN;
    size_t cb_len, att_fixed, att_len;
    uint64_t bits_limit;
    const uint8_t *att;
    uint8_t att_fields[4][CHUNK], fields[3][CHUNK];

    if (!ssz || !p || !scratch || !out || form < SC_AGGREGATE_PHASE0 || form > SC_AGGREGATE_GLOAS)
        return SC_ERR_ARG;
    electra = form != SC_AGGREGATE_PHASE0;
    gloas = form == SC_AGGREGATE_GLOAS;
    cb_len = electra ? (size_t)((p->max_committees_per_slot + 7) / 8) : 0;
    att_fixed = 4 + SC_SSZ_ATTESTATION_DATA_LEN + SC_SIGNATURE_LEN + cb_len;
    bits_limit = p->max_validators_per_committee * (electra ? p->max_committees_per_slot : 1);
    if (len < outer_fixed + att_fixed || get_u32(ssz + 8) != outer_fixed)
        return SC_ERR_DECODE;
    att = ssz + outer_fixed;
    att_len = len - outer_fixed;
    if (get_u32(att) != att_fixed)
        return SC_ERR_DECODE;

    out->aggregator_index = sc_get_u64(ssz);
    memcpy(out->selection_proof, ssz + 12, SC_SIGNATURE_LEN);
    rc = sc_ssz_decode_attestation_data(att + 4, SC_SSZ_ATTESTATION_DATA_LEN, &out->data);
    if (rc != SC_OK)
        return rc;

    rc = bitlist_root(att + att_fixed, att_len - att_fixed, bits_limit, gloas, scratch,
                      att_fields[0]);
    if (rc != SC_OK)
        return rc;
    sc_htr_attestation_data(&out->data, att_fields[1]);
    bytes96_root(att + 4 + SC_SSZ_ATTESTATION_DATA_LEN, att_fields[2]);
    if (electra) {
        rc = bitvector_root(att + 4 + SC_SSZ_ATTESTATION_DATA_LEN + SC_SIGNATURE_LEN, cb_len,
                            p->max_committees_per_slot, att_fields[3]);
        if (rc != SC_OK)
            return rc;
    }

    chunk_u64(fields[0], out->aggregator_index);
    if (gloas) {
        /* mix_in_active_fields(progressive root, 0b1111) */
        uint8_t root[CHUNK], active[CHUNK] = {0x0f};

        progressive(&att_fields[0][0], 4, 1, root);
        sc_hash_pair(root, active, fields[1]);
    } else {
        container(att_fields, electra ? 4 : 3, fields[1]);
    }
    bytes96_root(out->selection_proof, fields[2]);
    container(fields, 3, out->object_root);
    return SC_OK;
}

size_t sc_contribution_and_proof_len(const sc_preset *p)
{
    size_t bits_len = (size_t)((p->sync_committee_size / p->sync_committee_subnet_count + 7) / 8);

    return 8 + (8 + SC_ROOT_LEN + 8 + bits_len + SC_SIGNATURE_LEN) + SC_SIGNATURE_LEN;
}

/*
 * ContributionAndProof: aggregator_index (8) | contribution | selection_proof (96).
 * SyncCommitteeContribution: slot (8) | beacon_block_root (32) | subcommittee_index (8)
 * | aggregation_bits (Bitvector[SYNC_COMMITTEE_SIZE / SYNC_COMMITTEE_SUBNET_COUNT])
 * | signature (96).
 */
int sc_decode_contribution_and_proof(const uint8_t *ssz, size_t len, const sc_preset *p,
                                     sc_contribution_info *out)
{
    uint64_t nbits;
    size_t bits_len;
    const uint8_t *c;
    uint8_t c_fields[5][CHUNK], fields[3][CHUNK];
    int rc;

    if (!ssz || !p || !out || p->sync_committee_subnet_count == 0)
        return SC_ERR_ARG;
    nbits = p->sync_committee_size / p->sync_committee_subnet_count;
    bits_len = (size_t)((nbits + 7) / 8);
    c = ssz + 8;
    if (len != sc_contribution_and_proof_len(p))
        return SC_ERR_DECODE;
    out->aggregator_index = sc_get_u64(ssz);
    out->slot = sc_get_u64(c);
    memcpy(out->beacon_block_root, c + 8, SC_ROOT_LEN);
    out->subcommittee_index = sc_get_u64(c + 40);
    memcpy(out->selection_proof, c + 48 + bits_len + SC_SIGNATURE_LEN, SC_SIGNATURE_LEN);

    chunk_u64(c_fields[0], out->slot);
    memcpy(c_fields[1], c + 8, SC_ROOT_LEN);
    chunk_u64(c_fields[2], out->subcommittee_index);
    rc = bitvector_root(c + 48, bits_len, nbits, c_fields[3]);
    if (rc != SC_OK)
        return rc;
    bytes96_root(c + 48 + bits_len, c_fields[4]);

    chunk_u64(fields[0], out->aggregator_index);
    container(c_fields, 5, fields[1]);
    bytes96_root(out->selection_proof, fields[2]);
    container(fields, 3, out->object_root);
    return SC_OK;
}

void sc_htr_sync_aggregator_selection_data(uint64_t slot, uint64_t subcommittee_index,
                                           uint8_t out[SC_ROOT_LEN])
{
    uint8_t fields[2][CHUNK];

    chunk_u64(fields[0], slot);
    chunk_u64(fields[1], subcommittee_index);
    container(fields, 2, out);
}
